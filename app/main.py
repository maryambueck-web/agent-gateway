import json
import logging
import secrets
from typing import Any

from fastapi import FastAPI, Header, HTTPException
from google.auth.transport.requests import Request as GoogleAuthRequest
from google.api_core.exceptions import AlreadyExists
from google.cloud import tasks_v2
from google.oauth2 import id_token
from pydantic import ValidationError

from app.adapters.telegram import parse_update, send_text
from app.agent.orchestrator import respond
from app.collectors.entra_signins import get_recent_sign_ins
from app.collectors.signin_rules import evaluate_sign_in_rules
from app.config import Settings
from app.models import IncomingMessage
from app.storage.idempotency import (
	claim_update,
	claim_task_processing,
	mark_update_completed,
	mark_update_enqueued,
	release_processing_claim,
	release_update_claim,
)
from app.storage.sessions import consume_user_rate_limit, load_history, save_response


logger = logging.getLogger(__name__)
app = FastAPI()


def _enqueue_message(message: IncomingMessage, settings: Settings) -> None:
	client = tasks_v2.CloudTasksClient()
	parent = client.queue_path(
		settings.google_cloud_project_id,
		settings.cloud_tasks_location,
		settings.cloud_tasks_queue,
	)
	task_id = f"telegram-{message.idempotency_key}"
	task = {
		"name": client.task_path(
			settings.google_cloud_project_id,
			settings.cloud_tasks_location,
			settings.cloud_tasks_queue,
			task_id,
		),
		"http_request": {
			"http_method": tasks_v2.HttpMethod.POST,
			"url": settings.cloud_tasks_target_url,
			"headers": {"Content-Type": "application/json"},
			"body": json.dumps(message.model_dump(mode="json")).encode("utf-8"),
		},
	}
	task["http_request"]["oidc_token"] = {
		"service_account_email": settings.cloud_tasks_service_account_email,
		"audience": settings.cloud_tasks_target_url,
	}

	try:
		client.create_task(request={"parent": parent, "task": task})
	except AlreadyExists:
		pass


def _verify_cloud_tasks_request(
	authorization: str | None,
	settings: Settings,
) -> None:
	if not settings.cloud_tasks_service_account_email or not settings.cloud_tasks_target_url:
		raise HTTPException(status_code=503, detail="Cloud Tasks authentication is not configured")
	if not authorization:
		raise HTTPException(
			status_code=401,
		detail="Cloud Tasks authentication required",
		headers={"WWW-Authenticate": "Bearer"},
		)
	parts = authorization.split()
	if len(parts) != 2 or parts[0].lower() != "bearer":
		raise HTTPException(status_code=401, detail="Invalid Cloud Tasks authorization")

	try:
		claims = id_token.verify_oauth2_token(
			parts[1],
			GoogleAuthRequest(),
			audience=settings.cloud_tasks_target_url,
		)
	except ValueError as error:
		raise HTTPException(status_code=401, detail="Invalid Cloud Tasks identity token") from error
	except Exception as error:
		logger.exception("Unable to verify Cloud Tasks identity token")
		raise HTTPException(status_code=503, detail="Unable to verify Cloud Tasks identity") from error

	caller_email = claims.get("email", "")
	if (
		claims.get("email_verified") is not True
		or not secrets.compare_digest(
			caller_email.encode("utf-8"),
			settings.cloud_tasks_service_account_email.encode("utf-8"),
		)
	):
		raise HTTPException(status_code=403, detail="Cloud Tasks caller is not allowed")


def _agent_message_content(message: IncomingMessage) -> str:
	attachment_notes = [f"[User attached {attachment.kind}]" for attachment in message.attachments]
	return "\n".join(part for part in [message.text, *attachment_notes] if part)


def _send_response(message: IncomingMessage, response: str) -> None:
	if message.channel == "telegram":
		send_text(message.conversation_id, response)
		return
	raise ValueError(f"Unsupported response channel: {message.channel}")


@app.post("/webhooks/telegram")
def telegram_webhook(
	payload: dict[str, Any],
	x_telegram_bot_api_secret_token: str | None = Header(
		default=None,
		alias="X-Telegram-Bot-Api-Secret-Token",
	),
) -> dict[str, bool]:
	settings = Settings()
	if not settings.telegram_webhook_secret:
		raise HTTPException(status_code=503, detail="Telegram webhook is not configured")
	if not x_telegram_bot_api_secret_token or not secrets.compare_digest(
		x_telegram_bot_api_secret_token.encode("utf-8"),
		settings.telegram_webhook_secret.encode("utf-8"),
	):
		raise HTTPException(status_code=403, detail="Invalid webhook secret")

	message = parse_update(payload)
	if message is None:
		return {"ok": True}
	if message.user_id not in settings.telegram_allowed_user_id_set:
		return {"ok": True}
	if not all(
		(
			settings.google_cloud_project_id,
			settings.cloud_tasks_location,
			settings.cloud_tasks_queue,
			settings.cloud_tasks_target_url,
			settings.cloud_tasks_service_account_email,
		)
	):
		raise HTTPException(status_code=503, detail="Cloud Tasks is not configured")

	try:
		claim_status, owner = claim_update(message.idempotency_key, settings)
	except Exception as error:
		logger.exception("Failed to claim Telegram update")
		raise HTTPException(status_code=503, detail="Unable to record Telegram update") from error

	if claim_status == "enqueued":
		return {"ok": True}
	if claim_status == "pending":
		raise HTTPException(status_code=503, detail="Telegram update enqueue is pending")

	try:
		if not consume_user_rate_limit(message.channel, message.user_id, settings):
			release_update_claim(message.idempotency_key, owner, settings)
			return {"ok": True}
	except Exception as error:
		if owner is not None:
			try:
				release_update_claim(message.idempotency_key, owner, settings)
			except Exception:
				logger.exception("Failed to release rate-limited Telegram update claim")
		logger.exception("Failed to apply Telegram rate limit")
		raise HTTPException(status_code=503, detail="Unable to apply Telegram rate limit") from error

	try:
		_enqueue_message(message, settings)
		if owner is None or not mark_update_enqueued(
			message.idempotency_key, owner, settings
		):
			raise RuntimeError("Telegram update claim is no longer owned")
	except Exception as error:
		if owner is not None:
			try:
				release_update_claim(message.idempotency_key, owner, settings)
			except Exception:
				logger.exception("Failed to release Telegram update claim")
		logger.exception("Failed to enqueue Telegram update")
		raise HTTPException(status_code=503, detail="Unable to enqueue Telegram update") from error

	return {"ok": True}


@app.post("/tasks/process-message")
def process_message_task(
	payload: dict[str, Any],
	authorization: str | None = Header(default=None, alias="Authorization"),
) -> dict[str, bool]:
	settings = Settings()
	_verify_cloud_tasks_request(authorization, settings)
	try:
		message = IncomingMessage.model_validate(payload)
	except ValidationError as error:
		raise HTTPException(status_code=400, detail="Invalid task message") from error
	if message.channel != "telegram":
		raise HTTPException(status_code=400, detail="Unsupported task channel")

	try:
		claim_status, owner, cached_response = claim_task_processing(
			message.idempotency_key,
			settings,
		)
	except Exception as error:
		logger.exception("Failed to claim Telegram task for processing")
		raise HTTPException(status_code=503, detail="Unable to claim task") from error

	if claim_status == "completed":
		return {"ok": True}
	if claim_status in {"pending", "missing"} or owner is None:
		raise HTTPException(status_code=503, detail="Telegram task is not ready for processing")

	if claim_status == "response_ready":
		response = cached_response
		if not response:
			raise HTTPException(status_code=503, detail="Saved task response is missing")
	else:
		try:
			history, version = load_history(message, settings)
			history.append({"role": "user", "content": _agent_message_content(message)})
			entra_signins = None
			sign_in_findings = None
			if message.text.strip().casefold().startswith("/signins"):
				entra_signins = get_recent_sign_ins(settings)
				sign_in_findings = evaluate_sign_in_rules(entra_signins)
			response = respond(history, settings, entra_signins, sign_in_findings)
			history.append({"role": "assistant", "content": response})
			if not save_response(
				message,
				history,
				version,
				response,
				owner,
				settings,
			):
				raise RuntimeError("Conversation changed while the task was being processed")
		except Exception as error:
			try:
				release_processing_claim(message.idempotency_key, owner, settings)
			except Exception:
				logger.exception("Failed to release Telegram processing claim")
			logger.exception("Failed to process Telegram message")
			raise HTTPException(status_code=503, detail="Unable to process Telegram message") from error

	try:
		_send_response(message, response)
		if not mark_update_completed(message.idempotency_key, owner, settings):
			raise RuntimeError("Unable to mark Telegram task complete")
	except Exception as error:
		try:
			release_processing_claim(message.idempotency_key, owner, settings)
		except Exception:
			logger.exception("Failed to release Telegram delivery claim")
		logger.exception("Failed to send Telegram response")
		raise HTTPException(status_code=503, detail="Unable to deliver Telegram response") from error

	return {"ok": True}
