import unittest

from app.agent.explanation_validator import (
	build_safe_report,
	format_security_report,
	validate_explanation,
)


class ExplanationValidatorTests(unittest.TestCase):
	def setUp(self):
		self.findings = [
			{
				"rule_id": "AUTH-001",
				"finding": "Failed sign-in",
				"priority": "MEDIUM",
				"evidence": {
					"user": "alex@example.com",
					"ip": "203.0.113.7",
					"timestamp": "2026-10-05T12:00:00Z",
					"city": "Berlin",
					"country": "DE",
					"result": "failure",
				},
				"remediation": [
					"The administrator should verify the sign-in with the user."
				],
				"nis2_area": ["Access control", "Incident handling"],
			}
		]

	def test_accepts_explanation_using_only_supplied_evidence(self):
		text = (
			"AUTH-001 — Failed sign-in. Priority: MEDIUM. "
			"User: alex@example.com. IP: 203.0.113.7. City: Berlin."
		)

		self.assertEqual(validate_explanation(text, self.findings), ())

	def test_rejects_attack_names(self):
		self.assertIn(
			"attack_name",
			validate_explanation("This may be credential stuffing.", self.findings),
		)

	def test_rejects_claims_of_compromise(self):
		self.assertIn(
			"compromise_claim",
			validate_explanation("The account is compromised.", self.findings),
		)

	def test_rejects_attacker_intent(self):
		self.assertIn(
			"attacker_intent",
			validate_explanation("An attacker is trying to access the account.", self.findings),
		)

	def test_rejects_new_ip(self):
		self.assertIn(
			"new_ip",
			validate_explanation("IP: 198.51.100.42", self.findings),
		)

	def test_rejects_new_user(self):
		self.assertIn(
			"new_user",
			validate_explanation("User: attacker@example.net", self.findings),
		)

	def test_rejects_new_location(self):
		self.assertIn(
			"new_location",
			validate_explanation("City: Paris", self.findings),
		)

	def test_rejects_new_remediation(self):
		self.assertIn(
			"new_remediation",
			validate_explanation(
				"The administrator should reset the password.", self.findings
			),
		)

	def test_rejects_changed_rule_id(self):
		self.assertIn(
			"changed_rule_id",
			validate_explanation("DEVICE-001 — Failed sign-in", self.findings),
		)

	def test_rejects_omitted_rule_id(self):
		self.assertIn(
			"changed_rule_id",
			validate_explanation("A failed sign-in was detected.", self.findings),
		)

	def test_rejects_changed_severity(self):
		self.assertIn(
			"changed_severity",
			validate_explanation("AUTH-001 — Failed sign-in\nSeverity is high", self.findings),
		)

	def test_rejects_changed_priority(self):
		findings = [{**self.findings[0], "priority": "P2"}]
		self.assertIn(
			"changed_priority",
			validate_explanation("AUTH-001\nPriority: P1", findings),
		)

	def test_rejects_new_nis2_mapping(self):
		self.assertIn(
			"changed_nis2_mapping",
			validate_explanation("NIS2 Article 5 applies.", self.findings),
		)

	def test_accepts_supplied_remediation_and_nis2_mapping(self):
		findings = [
			{
				**self.findings[0],
				"nis2_area": ["Access control", "Incident handling"],
				"remediation": ["The administrator should verify the sign-in with the user."],
			}
		]
		text = (
			"AUTH-001 — Failed sign-in. NIS2 areas: Access control and Incident handling. "
			"The administrator should verify the sign-in with the user."
		)

		self.assertEqual(validate_explanation(text, findings), ())

	def test_safe_report_uses_finding_values_and_no_claude_text(self):
		findings = [
			self.findings[0],
			{
				**self.findings[0],
				"rule_id": "DEVICE-001",
				"finding": "Successful sign-in from an unmanaged device",
				"priority": "HIGH",
				"evidence": {"result": "success"},
			},
		]
		report = build_safe_report(findings)

		self.assertIn("🛡 IdentityGuard SME", report)
		self.assertIn("AUTH-001\nFailed sign-in", report)
		self.assertIn("Priority: MEDIUM", report)
		self.assertIn("Occurrences: 1", report)
		self.assertIn("DEVICE-001\nSuccessful sign-in from an unmanaged device", report)
		self.assertIn("Recommended actions:\n• The administrator should verify the sign-in with the user.", report)
		self.assertIn("NIS2 areas:\n• Access control\n• Incident handling", report)
		self.assertIn('Ask: "Explain AUTH-001"', report)
		self.assertNotIn("attacker", report)

	def test_security_report_groups_occurrences_by_rule(self):
		findings = [
			{**self.findings[0], "evidence": {"count": 3}},
			{**self.findings[0], "evidence": {"count": 2}},
			{
				**self.findings[0],
				"rule_id": "DEVICE-001",
				"finding": "Unmanaged device",
				"priority": "HIGH",
				"evidence": {},
			},
		]

		report = format_security_report(findings, "Sign-in risks were identified.")

		self.assertIn("AUTH-001\nFailed sign-in\nPriority: MEDIUM\nOccurrences: 2", report)
		self.assertIn("DEVICE-001\nUnmanaged device\nPriority: HIGH\nOccurrences: 1", report)
		self.assertIn("Explanation:\nSign-in risks were identified.", report)


if __name__ == "__main__":
	unittest.main()