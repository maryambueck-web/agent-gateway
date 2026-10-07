from datetime import datetime, timedelta, timezone
from typing import Any


AUTH_FAILURE_THRESHOLD = 3
AUTH_FAILURE_WINDOW = timedelta(minutes=5)
NIS2_SECURITY_AREAS = ["Access control", "Incident handling"]


def _parse_timestamp(value: Any) -> datetime | None:
	if not isinstance(value, str):
		return None
	try:
		timestamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
	except ValueError:
		return None
	if timestamp.tzinfo is None:
		return timestamp.replace(tzinfo=timezone.utc)
	return timestamp.astimezone(timezone.utc)


def _evidence(event: dict[str, Any], fields: tuple[str, ...]) -> dict[str, Any]:
	return {field: event[field] for field in fields if field in event}


def evaluate_sign_in_rules(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
	findings: list[dict[str, Any]] = []
	failures_by_user_ip: dict[tuple[str, str], list[tuple[datetime, dict[str, Any]]]] = {}

	for event in events:
		user = event.get("user")
		ip = event.get("ip")
		timestamp = event.get("timestamp")

		if event.get("result") == "failure":
			findings.append(
				{
					"rule_id": "AUTH-001",
					"finding": "Failed sign-in",
					"priority": "MEDIUM",
					"evidence": _evidence(
						event,
						("user", "timestamp", "ip", "country", "city", "app", "result", "conditional_access_status"),
					),
					"remediation": [
						"Verify whether the user attempted this login",
						"Review recent authentication activity",
					],
					"nis2_area": NIS2_SECURITY_AREAS.copy(),
				}
			)

		if (
			event.get("result") == "success"
			and (event.get("device_managed") is False or event.get("device_compliant") is False)
		):
			findings.append(
				{
					"rule_id": "DEVICE-001",
					"finding": "Successful sign-in from an unmanaged or non-compliant device",
					"priority": "HIGH",
					"evidence": _evidence(
						event,
						(
							"user", "timestamp", "ip", "country", "city", "app", "result",
							"device_managed", "device_compliant", "conditional_access_status",
						),
					),
					"remediation": [
						"Verify the sign-in with the user",
						"Review device management and compliance before allowing future access",
					],
					"nis2_area": NIS2_SECURITY_AREAS.copy(),
				}
			)

		parsed_timestamp = _parse_timestamp(timestamp)
		if (
			event.get("result") == "failure"
			and isinstance(user, str)
			and user
			and isinstance(ip, str)
			and ip
			and parsed_timestamp is not None
		):
			failures_by_user_ip.setdefault((user, ip), []).append((parsed_timestamp, event))

	for (user, ip), failures in sorted(failures_by_user_ip.items()):
		failures.sort(key=lambda item: item[0])
		start = 0
		while start <= len(failures) - AUTH_FAILURE_THRESHOLD:
			end = start
			while (
				end + 1 < len(failures)
				and failures[end + 1][0] - failures[start][0] <= AUTH_FAILURE_WINDOW
			):
				end += 1

			if end - start + 1 >= AUTH_FAILURE_THRESHOLD:
				burst = failures[start : end + 1]
				findings.append(
					{
						"rule_id": "AUTH-002",
						"finding": "Repeated failed sign-ins for the same user and IP",
						"priority": "HIGH",
						"evidence": {
							"user": user,
							"ip": ip,
							"result": "failure",
							"count": len(burst),
							"window_minutes": int(AUTH_FAILURE_WINDOW.total_seconds() // 60),
							"start_time": burst[0][1].get("timestamp"),
							"end_time": burst[-1][1].get("timestamp"),
						},
						"remediation": [
							"Confirm the repeated attempts with the user",
							"Review authentication activity for this account and IP",
						],
						"nis2_area": NIS2_SECURITY_AREAS.copy(),
					}
				)
				start = end + 1
			else:
				start += 1

	findings.sort(
		key=lambda finding: _finding_sort_key(finding)
	)
	return findings


def _finding_sort_key(finding: dict[str, Any]) -> tuple[str, str, str, str]:
	evidence = finding.get("evidence") or {}
	return (
		finding["rule_id"],
		evidence.get("user") or "",
		evidence.get("ip") or "",
		evidence.get("timestamp") or evidence.get("start_time") or "",
	)