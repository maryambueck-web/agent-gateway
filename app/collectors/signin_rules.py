from datetime import datetime, timedelta, timezone
from typing import Any


AUTH_FAILURE_THRESHOLD = 3
AUTH_FAILURE_WINDOW = timedelta(minutes=5)


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
					"severity": "medium",
					"title": "Failed sign-in",
					"user": user,
					"ip": ip,
					"timestamp": timestamp,
				}
			)

		if (
			event.get("result") == "success"
			and (event.get("device_managed") is False or event.get("device_compliant") is False)
		):
			findings.append(
				{
					"rule_id": "DEVICE-001",
					"severity": "high",
					"title": "Successful sign-in from an unmanaged or non-compliant device",
					"user": user,
					"ip": ip,
					"timestamp": timestamp,
					"device_managed": event.get("device_managed"),
					"device_compliant": event.get("device_compliant"),
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
						"severity": "high",
						"title": "Repeated failed sign-ins from the same user and IP",
						"user": user,
						"ip": ip,
						"count": len(burst),
						"window_minutes": int(AUTH_FAILURE_WINDOW.total_seconds() // 60),
						"start_time": burst[0][1].get("timestamp"),
						"end_time": burst[-1][1].get("timestamp"),
					}
				)
				start = end + 1
			else:
				start += 1

	findings.sort(
		key=lambda finding: (
			finding["rule_id"],
			finding.get("user") or "",
			finding.get("ip") or "",
			finding.get("timestamp") or finding.get("start_time") or "",
		)
	)
	return findings