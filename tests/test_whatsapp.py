import hashlib
import hmac
import json
import os
import unittest
from datetime import datetime, timezone
from unittest.mock import Mock, patch

from fastapi.testclient import TestClient

from app.adapters.whatsapp import parse_update, parse_updates, send_text, verify_webhook_signature
from app.config import Settings
from app.main import app
from app.models import IncomingMessage


def whatsapp_payload(message):
	return {
		"object": "whatsapp_business_account",
		"entry": [
			{
				"changes": [
					{
						"field": "messages",
						"value": {"messages": [message]},
					}
				]
			}
		],
	}


class WhatsAppAdapterTests(unittest.TestCase):
	def test_allowed_numbers_env_variable_is_supported(self):
		with patch.dict(os.environ, {"WHATSAPP_ALLOWED_NUMBERS": "+14155550123,442071234567"}):
			settings = Settings(_env_file=None)

		self.assertEqual(
			settings.whatsapp_allowed_user_id_set,
			frozenset({"14155550123", "442071234567"}),
		)

	def test_parses_text_message(self):
		message = parse_update(
			whatsapp_payload(
				{
					"from": "14155550123",
					"id": "wamid.message.1",
					"timestamp": "1760000000",
					"type": "text",
					"text": {"body": "security"},
				}
			)
		)

		self.assertIsNotNone(message)
		self.assertEqual(message.channel, "whatsapp")
		self.assertEqual(message.user_id, "14155550123")
		self.assertEqual(message.conversation_id, "14155550123")
		self.assertEqual(message.idempotency_key, "wamid.message.1")
		self.assertEqual(message.text, "security")

	def test_parses_media_message_as_attachment_note(self):
		message = parse_update(
			whatsapp_payload(
				{
					"from": "14155550123",
					"id": "wamid.message.2",
					"timestamp": "1760000000",
					"type": "image",
					"image": {"id": "media-id", "mime_type": "image/jpeg", "caption": "Review this"},
				}
			)
		)

		self.assertEqual(message.text, "Review this")
		self.assertEqual(message.attachments[0].kind, "image")
		self.assertEqual(message.attachments[0].file_id, "media-id")
		self.assertEqual(message.attachments[0].mime_type, "image/jpeg")

	def test_parses_multiple_messages_and_ignores_status_only_updates(self):
		payload = whatsapp_payload(
			{
				"from": "14155550123",
				"id": "wamid.message.3",
				"timestamp": "1760000000",
				"type": "text",
				"text": {"body": "hello"},
			}
		)
		payload["entry"][0]["changes"].append(
			{"field": "messages", "value": {"statuses": [{"id": "wamid.message.3"}]}}
		)
		payload["entry"][0]["changes"][0]["value"]["messages"].append(
			{
				"from": "14155550124",
				"id": "wamid.message.4",
				"timestamp": "1760000001",
				"type": "text",
				"text": {"body": "help"},
			}
		)

		messages = parse_updates(payload)

		self.assertEqual([message.idempotency_key for message in messages], ["wamid.message.3", "wamid.message.4"])
		self.assertEqual([message.text for message in messages], ["hello", "help"])
		self.assertIsNone(parse_update({"entry": []}))

	def test_verifies_meta_signature(self):
		body = b'{"object":"whatsapp_business_account"}'
		app_secret = "test-app-secret"
		digest = hmac.new(app_secret.encode(), body, hashlib.sha256).hexdigest()

		self.assertTrue(verify_webhook_signature(body, f"sha256={digest}", app_secret))
		self.assertFalse(verify_webhook_signature(body, "sha256=wrong", app_secret))
		self.assertFalse(verify_webhook_signature(body, f"sha256={digest}", ""))

	@patch("app.adapters.whatsapp.requests.post")
	@patch("app.adapters.whatsapp.Settings")
	def test_sends_text_through_cloud_api(self, settings_class, post):
		settings_class.return_value = Settings(
			_env_file=None,
			whatsapp_access_token="test-access-token",
			whatsapp_phone_number_id="phone-id",
			whatsapp_graph_api_version="v23.0",
		)
		post.return_value = Mock()

		send_text("14155550123", "reply")

		post.assert_called_once_with(
			"https://graph.facebook.com/v23.0/phone-id/messages",
			headers={"Authorization": "Bearer test-access-token"},
			json={
				"messaging_product": "whatsapp",
				"recipient_type": "individual",
				"to": "14155550123",
				"type": "text",
				"text": {"preview_url": False, "body": "reply"},
			},
			timeout=15,
		)
		post.return_value.raise_for_status.assert_called_once_with()


class WhatsAppWebhookTests(unittest.TestCase):
	def setUp(self):
		self.settings = Settings(
			_env_file=None,
			whatsapp_app_secret="test-app-secret",
			whatsapp_verify_token="test-verify-token",
			whatsapp_access_token="test-access-token",
			whatsapp_phone_number_id="phone-id",
			whatsapp_allowed_numbers="+14155550123",
			google_cloud_project_id="project",
			cloud_tasks_location="europe-west1",
			cloud_tasks_queue="messages",
			cloud_tasks_target_url="https://worker.example/tasks/process-message",
			cloud_tasks_service_account_email="tasks@example.iam.gserviceaccount.com",
		)
		self.client = TestClient(app)

	def tearDown(self):
		self.client.close()

	def test_get_verifies_meta_webhook_and_returns_challenge(self):
		with patch("app.main.Settings", return_value=self.settings):
			response = self.client.get(
				"/webhooks/whatsapp",
				params={
					"hub.mode": "subscribe",
					"hub.verify_token": "test-verify-token",
					"hub.challenge": "challenge-value",
				},
			)

		self.assertEqual(response.status_code, 200)
		self.assertEqual(response.text, "challenge-value")

	def test_post_verifies_signature_and_enqueues_allowed_sender(self):
		payload = whatsapp_payload(
			{
				"from": "14155550123",
				"id": "wamid.route.1",
				"timestamp": "1760000000",
				"type": "text",
				"text": {"body": "hello"},
			}
		)
		body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
		digest = hmac.new(b"test-app-secret", body, hashlib.sha256).hexdigest()
		with (
			patch("app.main.Settings", return_value=self.settings),
			patch("app.main.claim_update", return_value=("claimed", "owner")),
			patch("app.main.consume_user_rate_limit", return_value=True),
			patch("app.main._enqueue_message") as enqueue,
			patch("app.main.mark_update_enqueued", return_value=True) as mark,
		):
			response = self.client.post(
				"/webhooks/whatsapp",
				content=body,
				headers={
					"Content-Type": "application/json",
					"X-Hub-Signature-256": f"sha256={digest}",
				},
			)

		self.assertEqual(response.status_code, 200)
		message = enqueue.call_args.args[0]
		self.assertEqual(message.channel, "whatsapp")
		self.assertEqual(message.idempotency_key, "wamid.route.1")
		mark.assert_called_once_with("wamid.route.1", "owner", self.settings)

	def test_post_rejects_bad_signature_before_queueing(self):
		body = json.dumps(whatsapp_payload({})).encode("utf-8")
		with (
			patch("app.main.Settings", return_value=self.settings),
			patch("app.main.claim_update") as claim,
		):
			response = self.client.post(
				"/webhooks/whatsapp",
				content=body,
				headers={"X-Hub-Signature-256": "sha256=invalid"},
			)

		self.assertEqual(response.status_code, 403)
		claim.assert_not_called()

	def test_worker_sends_whatsapp_response(self):
		message = IncomingMessage(
			channel="whatsapp",
			user_id="14155550123",
			conversation_id="14155550123",
			text="/help",
			timestamp=datetime.now(timezone.utc),
			idempotency_key="wamid.worker.1",
		)
		with (
			patch("app.main.Settings", return_value=self.settings),
			patch("app.main._verify_cloud_tasks_request"),
			patch("app.main.claim_task_processing", return_value=("claimed", "owner", None)),
			patch("app.main.load_history", return_value=([], 0)),
			patch("app.main.save_response", return_value=True),
			patch("app.main.send_whatsapp_text") as send_whatsapp,
			patch("app.main.send_text") as send_telegram,
			patch("app.main.mark_update_completed", return_value=True),
		):
			response = self.client.post("/tasks/process-message", json=message.model_dump(mode="json"))

		self.assertEqual(response.status_code, 200)
		send_whatsapp.assert_called_once()
		self.assertEqual(send_whatsapp.call_args.args[0], "14155550123")
		send_telegram.assert_not_called()


if __name__ == "__main__":
	unittest.main()