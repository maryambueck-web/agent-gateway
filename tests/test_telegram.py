import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient

from app.adapters.telegram import parse_update, split_message
from app.config import Settings
from app.main import _enqueue_message, _verify_cloud_tasks_request, app


def telegram_update(user_id: int = 123) -> dict:
	return {
		"update_id": 789,
		"message": {
			"from": {"id": user_id},
			"chat": {"id": 456},
			"date": 1700000000,
			"text": "hello",
		},
	}


class TelegramAdapterTests(unittest.TestCase):
	def test_parse_update_normalizes_message_and_update_id(self):
		message = parse_update(telegram_update())

		self.assertIsNotNone(message)
		self.assertEqual(message.channel, "telegram")
		self.assertEqual(message.user_id, "123")
		self.assertEqual(message.conversation_id, "456")
		self.assertEqual(message.idempotency_key, "789")
		self.assertEqual(message.text, "hello")

	def test_parse_update_ignores_unsupported_updates(self):
		self.assertIsNone(parse_update({"update_id": 789, "callback_query": {}}))

	def test_split_message_preserves_text_within_telegram_limit(self):
		text = ("word " * 1000) + ("x" * 4097)
		parts = split_message(text)

		self.assertEqual("".join(parts), text)
		self.assertTrue(all(len(part) <= 4096 for part in parts))


class TelegramWebhookTests(unittest.TestCase):
	def setUp(self):
		self.settings = Settings(
			_env_file=None,
			telegram_webhook_secret="test-secret",
			telegram_allowed_user_ids="123, 789",
			google_cloud_project_id="project",
			cloud_tasks_location="us-central1",
			cloud_tasks_queue="telegram",
			cloud_tasks_target_url="https://worker.example/tasks/process-message",
			cloud_tasks_service_account_email="tasks@example.iam.gserviceaccount.com",
			anthropic_api_key="test-api-key",
		)
		self.client = TestClient(app)
		self.settings_patch = patch("app.main.Settings", return_value=self.settings)
		self.settings_patch.start()
		self.rate_limit_patch = patch("app.main.consume_user_rate_limit", return_value=True)
		self.rate_limit_patch.start()

	def tearDown(self):
		self.rate_limit_patch.stop()
		self.settings_patch.stop()
		self.client.close()

	def post_update(self, payload=None, secret="test-secret"):
		return self.client.post(
			"/webhooks/telegram",
			json=payload or telegram_update(),
			headers={"X-Telegram-Bot-Api-Secret-Token": secret},
		)

	def test_valid_update_is_enqueued_and_recorded(self):
		with (
			patch("app.main.claim_update", return_value=("claimed", "owner")),
			patch("app.main._enqueue_message") as enqueue,
			patch("app.main.mark_update_enqueued", return_value=True) as mark,
		):
			response = self.post_update()

		self.assertEqual(response.status_code, 200)
		self.assertEqual(enqueue.call_args.args[0].idempotency_key, "789")
		mark.assert_called_once_with("789", "owner", self.settings)

	def test_duplicate_update_is_acknowledged_without_another_task(self):
		with (
			patch("app.main.claim_update", return_value=("enqueued", None)),
			patch("app.main._enqueue_message") as enqueue,
		):
			response = self.post_update()

		self.assertEqual(response.status_code, 200)
		enqueue.assert_not_called()

	def test_concurrent_pending_update_is_retried(self):
		with (
			patch("app.main.claim_update", return_value=("pending", None)),
			patch("app.main._enqueue_message") as enqueue,
		):
			response = self.post_update()

		self.assertEqual(response.status_code, 503)
		enqueue.assert_not_called()

	def test_sender_outside_allowlist_is_ignored(self):
		with patch("app.main.claim_update") as claim:
			response = self.post_update(telegram_update(user_id=555))

		self.assertEqual(response.status_code, 200)
		claim.assert_not_called()

	def test_rate_limited_update_is_not_enqueued(self):
		with (
			patch("app.main.claim_update", return_value=("claimed", "owner")),
			patch("app.main.consume_user_rate_limit", return_value=False),
			patch("app.main.release_update_claim") as release,
			patch("app.main._enqueue_message") as enqueue,
		):
			response = self.post_update()

		self.assertEqual(response.status_code, 200)
		release.assert_called_once_with("789", "owner", self.settings)
		enqueue.assert_not_called()

	def test_invalid_secret_is_rejected(self):
		with patch("app.main.claim_update") as claim:
			response = self.post_update(secret="wrong")

		self.assertEqual(response.status_code, 403)
		claim.assert_not_called()

	def test_enqueue_failure_releases_claim_for_retry(self):
		with (
			patch("app.main.claim_update", return_value=("claimed", "owner")),
			patch("app.main._enqueue_message", side_effect=RuntimeError("queue unavailable")),
			patch("app.main.release_update_claim") as release,
			patch("app.main.logger.exception"),
		):
			response = self.post_update()

		self.assertEqual(response.status_code, 503)
		release.assert_called_once_with("789", "owner", self.settings)

	def test_cloud_task_uses_update_id_and_normalized_message(self):
		message = parse_update(telegram_update())
		with patch("app.main.tasks_v2.CloudTasksClient") as client_factory:
			client = client_factory.return_value
			client.queue_path.return_value = "queue-parent"
			client.task_path.return_value = "task-name"
			_enqueue_message(message, self.settings)

		request = client.create_task.call_args.kwargs["request"]
		self.assertEqual(request["parent"], "queue-parent")
		self.assertEqual(request["task"]["name"], "task-name")
		self.assertEqual(
			request["task"]["http_request"]["body"],
			b'{"channel": "telegram", "user_id": "123", "conversation_id": "456", "text": "hello", "attachments": [], "timestamp": "2023-11-14T22:13:20Z", "idempotency_key": "789"}',
		)
		self.assertEqual(
			request["task"]["http_request"]["oidc_token"]["service_account_email"],
			self.settings.cloud_tasks_service_account_email,
		)

	def test_worker_verifies_cloud_tasks_caller(self):
		with patch(
			"app.main.id_token.verify_oauth2_token",
			return_value={
				"email": self.settings.cloud_tasks_service_account_email,
				"email_verified": True,
			},
		) as verify:
			_verify_cloud_tasks_request("Bearer signed-token", self.settings)

		self.assertEqual(
			verify.call_args.kwargs["audience"],
			self.settings.cloud_tasks_target_url,
		)

	def test_worker_rejects_a_different_cloud_tasks_caller(self):
		payload = parse_update(telegram_update()).model_dump(mode="json")
		with patch(
			"app.main.id_token.verify_oauth2_token",
			return_value={"email": "other@example.com", "email_verified": True},
		):
			response = self.client.post(
				"/tasks/process-message",
				json=payload,
				headers={"Authorization": "Bearer signed-token"},
			)

		self.assertEqual(response.status_code, 403)

	def test_worker_processes_saves_and_sends_response(self):
		payload = parse_update(telegram_update()).model_dump(mode="json")
		seen_histories = []

		def generate_response(history, settings):
			seen_histories.append(list(history))
			return "reply"

		with (
			patch("app.main._verify_cloud_tasks_request"),
			patch("app.main.claim_task_processing", return_value=("claimed", "owner", None)),
			patch("app.main.load_history", return_value=([], 0)),
			patch("app.main.respond", side_effect=generate_response),
			patch("app.main.save_response", return_value=True) as save,
			patch("app.main.send_text") as send,
			patch("app.main.mark_update_completed", return_value=True) as complete,
		):
			response = self.client.post("/tasks/process-message", json=payload)

		self.assertEqual(response.status_code, 200)
		self.assertEqual(
			seen_histories[0],
			[{"role": "user", "content": "hello"}],
		)
		self.assertEqual(save.call_args.args[1][-1], {"role": "assistant", "content": "reply"})
		send.assert_called_once_with("456", "reply")
		complete.assert_called_once_with("789", "owner", self.settings)

	def test_worker_retry_reuses_saved_response_without_calling_agent(self):
		payload = parse_update(telegram_update()).model_dump(mode="json")
		with (
			patch("app.main._verify_cloud_tasks_request"),
			patch(
				"app.main.claim_task_processing",
				return_value=("response_ready", "owner", "cached reply"),
			),
			patch("app.main.respond") as respond_agent,
			patch("app.main.send_text") as send,
			patch("app.main.mark_update_completed", return_value=True),
		):
			response = self.client.post("/tasks/process-message", json=payload)

		self.assertEqual(response.status_code, 200)
		respond_agent.assert_not_called()
		send.assert_called_once_with("456", "cached reply")


if __name__ == "__main__":
	unittest.main()