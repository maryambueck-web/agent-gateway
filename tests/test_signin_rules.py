import unittest

from app.collectors.signin_rules import evaluate_sign_in_rules


def sign_in(**overrides):
	event = {
		"user": "user@example.com",
		"timestamp": "2026-10-05T12:00:00Z",
		"ip": "203.0.113.7",
		"result": "failure",
		"device_managed": True,
		"device_compliant": True,
	}
	event.update(overrides)
	return event


class SignInRuleTests(unittest.TestCase):
	def test_auth_001_flags_each_failed_sign_in(self):
		findings = evaluate_sign_in_rules([sign_in()])

		self.assertEqual([finding["rule_id"] for finding in findings], ["AUTH-001"])
		self.assertEqual(findings[0]["user"], "user@example.com")

	def test_auth_002_flags_three_failures_for_same_user_and_ip_within_five_minutes(self):
		events = [
			sign_in(timestamp="2026-10-05T12:00:00Z"),
			sign_in(timestamp="2026-10-05T12:02:00Z"),
			sign_in(timestamp="2026-10-05T12:04:59Z"),
		]

		findings = evaluate_sign_in_rules(events)
		repeated = [finding for finding in findings if finding["rule_id"] == "AUTH-002"]

		self.assertEqual(len(repeated), 1)
		self.assertEqual(repeated[0]["count"], 3)
		self.assertEqual(repeated[0]["window_minutes"], 5)

	def test_auth_002_requires_matching_user_ip_and_window(self):
		events = [
			sign_in(timestamp="2026-10-05T12:00:00Z"),
			sign_in(timestamp="2026-10-05T12:01:00Z", ip="203.0.113.8"),
			sign_in(timestamp="2026-10-05T12:02:00Z", user="other@example.com"),
			sign_in(timestamp="2026-10-05T12:06:00Z"),
		]

		findings = evaluate_sign_in_rules(events)

		self.assertNotIn("AUTH-002", [finding["rule_id"] for finding in findings])

	def test_device_001_flags_success_on_unmanaged_or_non_compliant_device(self):
		events = [
			sign_in(result="success", device_managed=False),
			sign_in(result="success", device_compliant=False),
			sign_in(result="success", device_managed=None, device_compliant=None),
			sign_in(result="failure", device_managed=False),
		]

		findings = evaluate_sign_in_rules(events)
		device_findings = [
			finding for finding in findings if finding["rule_id"] == "DEVICE-001"
		]

		self.assertEqual(len(device_findings), 2)
		self.assertEqual(
			[(finding["device_managed"], finding["device_compliant"]) for finding in device_findings],
			[(False, True), (True, False)],
		)


if __name__ == "__main__":
	unittest.main()