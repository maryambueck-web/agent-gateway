import unittest

from app.agent.explanation_validator import build_safe_report, validate_explanation


class ExplanationValidatorTests(unittest.TestCase):
	def setUp(self):
		self.findings = [
			{
				"rule_id": "AUTH-001",
				"severity": "medium",
				"title": "Failed sign-in",
				"user": "alex@example.com",
				"ip": "203.0.113.7",
				"timestamp": "2026-10-05T12:00:00Z",
			}
		]
		self.events = [
			{
				"user": "alex@example.com",
				"ip": "203.0.113.7",
				"city": "Berlin",
				"country": "DE",
				"app": "Example App",
			}
		]

	def test_accepts_explanation_using_only_supplied_evidence(self):
		text = (
			"AUTH-001 — Failed sign-in. Severity: medium. "
			"User: alex@example.com. IP: 203.0.113.7. City: Berlin."
		)

		self.assertEqual(validate_explanation(text, self.findings, self.events), ())

	def test_rejects_attack_names(self):
		self.assertIn(
			"attack_name",
			validate_explanation("This may be credential stuffing.", self.findings, self.events),
		)

	def test_rejects_claims_of_compromise(self):
		self.assertIn(
			"compromise_claim",
			validate_explanation("The account is compromised.", self.findings, self.events),
		)

	def test_rejects_attacker_intent(self):
		self.assertIn(
			"attacker_intent",
			validate_explanation("An attacker is trying to access the account.", self.findings, self.events),
		)

	def test_rejects_new_ip(self):
		self.assertIn(
			"new_ip",
			validate_explanation("IP: 198.51.100.42", self.findings, self.events),
		)

	def test_rejects_new_user(self):
		self.assertIn(
			"new_user",
			validate_explanation("User: attacker@example.net", self.findings, self.events),
		)

	def test_rejects_new_location(self):
		self.assertIn(
			"new_location",
			validate_explanation("City: Paris", self.findings, self.events),
		)

	def test_rejects_new_remediation(self):
		self.assertIn(
			"new_remediation",
			validate_explanation(
				"The administrator should reset the password.", self.findings, self.events
			),
		)

	def test_rejects_changed_rule_id(self):
		self.assertIn(
			"changed_rule_id",
			validate_explanation("DEVICE-001 — Failed sign-in", self.findings, self.events),
		)

	def test_rejects_omitted_rule_id(self):
		self.assertIn(
			"changed_rule_id",
			validate_explanation("A failed sign-in was detected.", self.findings, self.events),
		)

	def test_rejects_changed_severity(self):
		self.assertIn(
			"changed_severity",
			validate_explanation(
				"AUTH-001 — Failed sign-in\nSeverity is high", self.findings, self.events
			),
		)

	def test_rejects_changed_priority(self):
		findings = [{**self.findings[0], "priority": "P2"}]
		self.assertIn(
			"changed_priority",
			validate_explanation("AUTH-001\nPriority: P1", findings, self.events),
		)

	def test_rejects_new_nis2_mapping(self):
		self.assertIn(
			"changed_nis2_mapping",
			validate_explanation(
				"NIS2 Article 5 applies.", self.findings, self.events
			),
		)

	def test_accepts_supplied_remediation_and_nis2_mapping(self):
		findings = [
			{
				**self.findings[0],
				"nis2_mapping": "NIS2 Article 21",
				"remediation": "The administrator should verify the sign-in with the user.",
			}
		]
		text = (
			"AUTH-001 — Failed sign-in. NIS2 Article 21. "
			"The administrator should verify the sign-in with the user."
		)

		self.assertEqual(validate_explanation(text, findings, self.events), ())

	def test_safe_report_uses_finding_values_and_no_claude_text(self):
		report = build_safe_report(self.findings)

		self.assertIn("AUTH-001 — Failed sign-in", report)
		self.assertIn("Severity: medium", report)
		self.assertIn("User: alex@example.com", report)
		self.assertIn("Approved remediation: Not supplied", report)
		self.assertNotIn("attacker", report)


if __name__ == "__main__":
	unittest.main()