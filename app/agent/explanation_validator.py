import ipaddress
import re
from typing import Any


ATTACK_NAME_PATTERN = re.compile(
	r"\b(?:phishing|ransomware|malware|brute[- ]force|password spray(?:ing)?|"
	r"credential stuffing|MFA fatigue|man[- ]in[- ]the[- ]middle|token theft|"
	r"session hijack(?:ing)?|impossible travel|account takeover|pass[- ]the[- ]hash|"
	r"kerberoast(?:ing)?|privilege escalation|lateral movement|data exfiltration)\b",
	re.IGNORECASE,
)
COMPROMISE_PATTERN = re.compile(
	r"\b(?:compromis(?:e|ed|ing)|hacked|breached|account takeover|"
	r"unauthori[sz]ed access|data exfiltration|stolen credentials|attacker has access)\b",
	re.IGNORECASE,
)
ATTACKER_INTENT_PATTERN = re.compile(
	r"\b(?:attacker|threat actor|malicious actor)\b.{0,100}\b"
	r"(?:intend(?:s|ed)?|plan(?:s|ned)?|aim(?:s|ed)?|try(?:ing|ied)?|"
	r"attempt(?:s|ed|ing)?|seek(?:s|ing)?|want(?:s|ed)?)\b|"
	r"\b(?:trying|attempting|planning|intending) to (?:steal|access|compromise|disrupt)\b",
	re.IGNORECASE,
)
ACTION_PATTERN = re.compile(
	r"\b(?:should|must|need to|recommend(?:s|ed|ation)?|consider|review|"
	r"investigate|reset|block|disable|revoke|enforce|require|enable|configure|"
	r"contact|notify|verify|check|change|update|implement|deploy|isolate|remediate)\b",
	re.IGNORECASE,
)
RULE_ID_PATTERN = re.compile(r"\b(?:AUTH|DEVICE)-\d{3}\b", re.IGNORECASE)
LABEL_PATTERN = re.compile(
	r"\b(severity|priority)\s*(?::|=|\bis\b)\s*([A-Za-z0-9_.-]+)", re.IGNORECASE
)
NIS2_MAPPING_PATTERN = re.compile(
	r"\bNIS2\s+(?:article|art\.?\s*)\s*\d+(?:\.\d+)*\b", re.IGNORECASE
)
EMAIL_PATTERN = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)
IPV4_PATTERN = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
USER_LABEL_PATTERN = re.compile(
	r"\b(?:user|account|identity)\s*[:=]\s*([^\s,;|]+)", re.IGNORECASE
)
LOCATION_LABEL_PATTERN = re.compile(
	r"\b(?:location|city|country)\s*[:=]\s*([^\n,;|]+)", re.IGNORECASE
)
LOCATION_PHRASE_PATTERN = re.compile(
	r"\b(?:from|in|near|located in)\s+([A-Z][A-Za-z-]*(?:\s+[A-Z][A-Za-z-]*)?)"
)
SENTENCE_PATTERN = re.compile(r"[^\n.!?]+(?:[.!?]+|$)")


def _text_values(value: Any):
	if isinstance(value, dict):
		for nested in value.values():
			yield from _text_values(nested)
	elif isinstance(value, (list, tuple, set)):
		for nested in value:
			yield from _text_values(nested)
	elif isinstance(value, str):
		yield value


def _canonical(value: str) -> str:
	return " ".join(value.casefold().strip(" \t\r\n.,;:!?*`_-").split())


def _approved_values(findings: list[dict[str, Any]], field: str) -> set[str]:
	return {
		_canonical(value)
		for finding in findings
		for value in _text_values(finding.get(field))
		if value.strip()
	}


def _extract_ips(text: str) -> set[str]:
	ips: set[str] = set()
	for candidate in IPV4_PATTERN.findall(text):
		try:
			ips.add(str(ipaddress.ip_address(candidate)))
		except ValueError:
			continue
	return ips


def validate_explanation(
	text: str,
	findings: list[dict[str, Any]],
	events: list[dict[str, Any]],
) -> tuple[str, ...]:
	reasons: set[str] = set()
	if ATTACK_NAME_PATTERN.search(text):
		reasons.add("attack_name")
	if COMPROMISE_PATTERN.search(text):
		reasons.add("compromise_claim")
	if ATTACKER_INTENT_PATTERN.search(text):
		reasons.add("attacker_intent")

	all_records = [*findings, *events]
	allowed_users = _approved_values(all_records, "user")
	allowed_ips = _approved_values(all_records, "ip")
	allowed_locations = {
		_canonical(value)
		for record in all_records
		for field in ("city", "country", "location")
		for value in _text_values(record.get(field))
		if value.strip()
	}

	if any(_canonical(value) not in allowed_users for value in EMAIL_PATTERN.findall(text)):
		reasons.add("new_user")
	if any(ip not in allowed_ips for ip in _extract_ips(text)):
		reasons.add("new_ip")

	for pattern, allowed, reason in (
		(USER_LABEL_PATTERN, allowed_users, "new_user"),
		(LOCATION_LABEL_PATTERN, allowed_locations, "new_location"),
		(LOCATION_PHRASE_PATTERN, allowed_locations, "new_location"),
	):
		for match in pattern.findall(text):
			value = _canonical(match)
			if value and value not in allowed:
				reasons.add(reason)

	approved_rule_ids = {
		str(finding.get("rule_id", "")).casefold()
		for finding in findings
		if finding.get("rule_id")
	}
	candidate_rule_ids = {rule_id.casefold() for rule_id in RULE_ID_PATTERN.findall(text)}
	if (
		any(rule_id not in approved_rule_ids for rule_id in candidate_rule_ids)
		or not approved_rule_ids.issubset(candidate_rule_ids)
	):
		reasons.add("changed_rule_id")

	approved_mappings = {
		_canonical(value)
		for finding in findings
		for key, field_value in finding.items()
		if "nis2" in key.casefold()
		for value in _text_values(field_value)
	}
	for mapping in NIS2_MAPPING_PATTERN.findall(text):
		if _canonical(mapping) not in approved_mappings:
			reasons.add("changed_nis2_mapping")

	findings_by_rule = {
		str(finding.get("rule_id", "")).casefold(): finding for finding in findings
	}
	rule_matches = list(RULE_ID_PATTERN.finditer(text))
	for index, rule_match in enumerate(rule_matches):
		rule_id = rule_match.group(0).casefold()
		end = rule_matches[index + 1].start() if index + 1 < len(rule_matches) else len(text)
		section = text[rule_match.start() : end]
		finding = findings_by_rule.get(rule_id)
		if finding is None:
			continue
		for label, reported_value in LABEL_PATTERN.findall(section):
			field = label.casefold()
			approved = finding.get(field)
			if not isinstance(approved, str) or _canonical(reported_value) != _canonical(approved):
				reasons.add(f"changed_{field}")

	for finding in findings:
		approved_remediations = {
			_canonical(sentence)
			for key, field_value in finding.items()
			if "remediation" in key.casefold()
			for value in _text_values(field_value)
			for sentence in SENTENCE_PATTERN.findall(value)
			if _canonical(sentence)
		}
		for sentence in SENTENCE_PATTERN.findall(text):
			candidate = _canonical(sentence)
			if ACTION_PATTERN.search(candidate) and candidate not in approved_remediations:
				reasons.add("new_remediation")
				break
		if "new_remediation" in reasons:
			break

	return tuple(sorted(reasons))


def build_safe_report(findings: list[dict[str, Any]]) -> str:
	if not findings:
		return "No deterministic finding was supplied. No Claude explanation is available."

	lines = ["IdentityGuard SME — Deterministic report"]
	for finding in findings:
		lines.append("")
		lines.append(
			"{} — {}".format(
				finding.get("rule_id", "Unknown rule"),
				finding.get("title", "Finding"),
			)
		)
		for field, label in (
			("severity", "Severity"),
			("priority", "Priority"),
			("user", "User"),
			("timestamp", "Timestamp"),
			("ip", "IP"),
			("country", "Country"),
			("city", "City"),
			("app", "App"),
			("count", "Count"),
			("window_minutes", "Window minutes"),
			("device_managed", "Device managed"),
			("device_compliant", "Device compliant"),
			("conditional_access_status", "Conditional Access status"),
			("nis2_mapping", "NIS2 mapping"),
			("remediation", "Approved remediation"),
		):
			value = finding.get(field)
			if value is not None:
				lines.append(f"{label}: {value}")
		if not finding.get("remediation"):
			lines.append("Approved remediation: Not supplied by the deterministic finding.")
		if not any("nis2" in key.casefold() for key in finding):
			lines.append("NIS2 mapping: Not supplied by the deterministic finding.")
	return "\n".join(lines)