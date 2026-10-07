import unittest
from unittest.mock import Mock, patch

import requests

from app.agent.orchestrator import respond
from app.config import Settings
from app.collectors.entra_signins import (
	GRAPH_SCOPE,
	GRAPH_SIGN_INS_URL,
	get_recent_sign_ins,
	normalize_sign_in_event,
)


class EntraSignInTests(unittest.TestCase):
	def setUp(self):
		self.settings = Settings(
			_env_file=None,
			azure_tenant_id="tenant-id",
			azure_client_id="client-id",
			azure_client_secret="client-secret",
		)

	@patch("app.collectors.entra_signins.requests.get")
	@patch("app.collectors.entra_signins.msal.ConfidentialClientApplication")
	def test_fetches_sign_ins_after_graph_returns_200(self, application_class, get):
		application = application_class.return_value
		application.acquire_token_for_client.return_value = {
			"access_token": "access-token"
		}

		graph_response = Mock(status_code=200)
		raw_events = [
			{
				"userPrincipalName": "user@example.com",
				"createdDateTime": "2026-10-05T12:00:00Z",
				"ipAddress": "203.0.113.4",
				"location": {"countryOrRegion": "DE", "city": "Berlin"},
				"appDisplayName": "Example App",
				"status": {"errorCode": 0},
				"deviceDetail": {
					"browser": "Edge 129",
					"operatingSystem": "Windows 11",
					"isManaged": True,
					"isCompliant": True,
				},
				"conditionalAccessStatus": "success",
			}
		]
		events = [normalize_sign_in_event(raw_events[0])]
		graph_response.json.return_value = {"value": raw_events}
		get.return_value = graph_response

		self.assertEqual(get_recent_sign_ins(self.settings), events)
		application_class.assert_called_once_with(
			"client-id",
			authority="https://login.microsoftonline.com/tenant-id",
			client_credential="client-secret",
		)
		application.acquire_token_for_client.assert_called_once_with(
			scopes=[GRAPH_SCOPE]
		)
		get.assert_called_once()
		request = get.call_args.kwargs
		self.assertEqual(get.call_args.args[0], GRAPH_SIGN_INS_URL)
		self.assertEqual(request["headers"], {"Authorization": "Bearer access-token"})
		self.assertEqual(request["params"]["$top"], 10)
		self.assertRegex(
			request["params"]["$filter"],
			r"^createdDateTime ge \d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$",
		)
		self.assertEqual(request["params"]["$orderby"], "createdDateTime desc")
		self.assertEqual(
			request["params"]["$select"],
			"createdDateTime,userDisplayName,userPrincipalName,appDisplayName,"
			"ipAddress,status,location,deviceDetail,conditionalAccessStatus",
		)
		self.assertEqual(request["timeout"], (10, 60))

	def test_normalizes_requested_fields_and_sign_in_result(self):
		event = normalize_sign_in_event(
			{
				"userDisplayName": "Example User",
				"createdDateTime": "2026-10-05T12:00:00Z",
				"ipAddress": "203.0.113.4",
				"location": {"countryOrRegion": "DE", "city": "Berlin"},
				"appDisplayName": "Example App",
				"status": {"errorCode": 50074},
				"deviceDetail": {
					"browser": "Edge 129",
					"operatingSystem": "Windows 11",
					"isManaged": True,
					"isCompliant": False,
				},
				"conditionalAccessStatus": "failure",
			}
		)

		self.assertEqual(
			event,
			{
				"user": "Example User",
				"timestamp": "2026-10-05T12:00:00Z",
				"ip": "203.0.113.4",
				"country": "DE",
				"city": "Berlin",
				"app": "Example App",
				"result": "failure",
				"browser": "Edge 129",
				"os": "Windows 11",
				"device_managed": True,
				"device_compliant": False,
				"authentication_requirement": None,
				"conditional_access_status": "failure",
			},
		)

	def test_missing_graph_fields_normalize_to_none_or_unknown(self):
		event = normalize_sign_in_event({"status": {}})

		self.assertEqual(event["result"], "unknown")
		self.assertIsNone(event["city"])
		self.assertIsNone(event["browser"])

	@patch("app.collectors.entra_signins.msal.ConfidentialClientApplication")
	def test_rejects_incomplete_credentials_without_token_request(self, application_class):
		settings = Settings(
			_env_file=None,
			azure_tenant_id="tenant-id",
			azure_client_id="",
			azure_client_secret="",
		)

		with self.assertRaisesRegex(RuntimeError, "not fully configured"):
			get_recent_sign_ins(settings)

		application_class.assert_not_called()

	@patch("app.collectors.entra_signins.requests.get")
	@patch("app.collectors.entra_signins.msal.ConfidentialClientApplication")
	def test_raises_when_graph_does_not_return_200(self, application_class, get):
		application_class.return_value.acquire_token_for_client.return_value = {
			"access_token": "access-token"
		}

		graph_response = Mock(status_code=403)
		graph_response.raise_for_status.side_effect = requests.HTTPError("Forbidden")
		get.return_value = graph_response

		with self.assertRaises(requests.HTTPError):
			get_recent_sign_ins(self.settings)

	@patch("app.agent.orchestrator.Anthropic")
	def test_passes_sign_ins_to_anthropic_as_untrusted_context(self, anthropic_class):
		history = [{"role": "user", "content": "Summarize these sign-ins"}]
		findings = [{
			"rule_id": "AUTH-001",
			"finding": "Failed sign-in",
			"priority": "MEDIUM",
			"evidence": {"user": "user@example.com", "result": "failure"},
			"remediation": ["Verify whether the user attempted this login"],
			"nis2_area": ["Access control"],
		}]
		client = anthropic_class.return_value
		client.messages.create.return_value.content = [
			Mock(type="text", text="AUTH-001 — Failed sign-in. Priority: MEDIUM.")
		]
		settings = Settings(_env_file=None, anthropic_api_key="test-api-key")

		report = respond(history, settings, findings)
		self.assertIn("🛡 IdentityGuard SME", report)
		self.assertIn("Explanation:\nAUTH-001 — Failed sign-in. Priority: MEDIUM.", report)
		self.assertIn("Recommended actions:", report)
		self.assertIn("NIS2 areas:", report)
		request = client.messages.create.call_args.kwargs
		self.assertEqual(request["messages"], history)
		self.assertIn("only deterministic security findings", request["system"])
		self.assertIn("user@example.com", request["system"])
		self.assertIn("AUTH-001", request["system"])
		self.assertIn('"finding": "Failed sign-in"', request["system"])
		self.assertIn('"priority": "MEDIUM"', request["system"])
		self.assertNotIn("userPrincipalName", request["system"])
		self.assertNotIn('"events"', request["system"])
		self.assertIn("You are the explanation layer of IdentityGuard SME.", request["system"])
		self.assertIn("- change the priority", request["system"])
		self.assertIn("- override remediation or NIS2 mappings", request["system"])

	@patch("app.agent.orchestrator.Anthropic")
	def test_identityguard_scope_applies_without_signin_data(self, anthropic_class):
		greeting = (
			"I'm IdentityGuard SME. I can analyze Microsoft Entra sign-in findings and "
			"explain the security risks and recommended actions."
		)
		client = anthropic_class.return_value
		client.messages.create.return_value.content = [Mock(type="text", text=greeting)]
		settings = Settings(_env_file=None, anthropic_api_key="test-api-key")

		self.assertEqual(
			respond([{"role": "user", "content": "hello"}], settings),
			greeting,
		)
		request = client.messages.create.call_args.kwargs
		self.assertIn("You are IdentityGuard SME, not a generic chatbot.", request["system"])
		self.assertIn(greeting, request["system"])

	@patch("app.agent.orchestrator.Anthropic")
	def test_replaces_unsafe_claude_explanation_with_deterministic_report(self, anthropic_class):
		history = [{"role": "user", "content": "/signins"}]
		findings = [
			{
				"rule_id": "AUTH-001",
				"finding": "Failed sign-in",
				"priority": "MEDIUM",
				"evidence": {
					"user": "alex@example.com",
					"ip": "203.0.113.7",
					"result": "failure",
				},
				"remediation": ["Verify whether the user attempted this login"],
				"nis2_area": ["Access control"],
			}
		]
		client = anthropic_class.return_value
		client.messages.create.return_value.content = [
			Mock(
				type="text",
				text=(
					"AUTH-001\nPriority: HIGH. This was phishing and the account is compromised. "
					"The administrator should reset the password."
				),
			)
		]
		settings = Settings(_env_file=None, anthropic_api_key="test-api-key")

		report = respond(history, settings, findings)

		self.assertIn("AUTH-001\nFailed sign-in", report)
		self.assertIn("Priority: MEDIUM", report)
		self.assertNotIn("alex@example.com", report)
		self.assertNotIn("phishing", report)
		self.assertNotIn("compromised", report)
		self.assertNotIn("reset the password", report)


if __name__ == "__main__":
	unittest.main()