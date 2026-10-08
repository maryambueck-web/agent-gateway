import json
import logging
import secrets
from typing import Any

from fastapi import FastAPI, Header, HTTPException, Query, Request
from fastapi.responses import PlainTextResponse
from google.auth.transport.requests import Request as GoogleAuthRequest
from google.api_core.exceptions import AlreadyExists
from google.cloud import tasks_v2
from google.oauth2 import id_token
from pydantic import ValidationError

from app.adapters.telegram import parse_update, send_text
from app.adapters.whatsapp import parse_updates as parse_whatsapp_updates
from app.adapters.whatsapp import send_text as send_whatsapp_text
from app.adapters.whatsapp import verify_webhook_signature
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
SIGNINS_COMMAND = "/signins"
SECURITY_COMMANDS = {
	"/signins",
	"security",
	"check signins",
	"show findings",
	"security report",
}
HELP_COMMANDS = {"/help", "/start"}
HELP_RESPONSE = (
	"IdentityGuard SME\n\n"
	"Commands:\n"
	"/signins - analyze recent Entra sign-ins\n"
	"/help - show available commands"
)
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


def _queue_incoming_message(message: IncomingMessage, settings: Settings) -> None:
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
		logger.exception("Unable to record %s update", message.channel)
		raise HTTPException(
			status_code=503,
			detail=f"Unable to record {message.channel} update",
		) from error

	if claim_status == "enqueued":
		return
	if claim_status == "pending":
		raise HTTPException(status_code=503, detail="Webhook update enqueue is pending")

	try:
		if not consume_user_rate_limit(message.channel, message.user_id, settings):
			release_update_claim(message.idempotency_key, owner, settings)
			return
	except Exception as error:
		if owner is not None:
			try:
				release_update_claim(message.idempotency_key, owner, settings)
			except Exception:
				logger.exception("Unable to release rate-limited %s update claim", message.channel)
		logger.exception("Unable to apply %s rate limit", message.channel)
		raise HTTPException(
			status_code=503,
			detail=f"Unable to apply {message.channel} rate limit",
		) from error

	try:
		_enqueue_message(message, settings)
		if owner is None or not mark_update_enqueued(
			message.idempotency_key, owner, settings
		):
			raise RuntimeError(f"Unable to mark {message.channel} update enqueued")
	except Exception as error:
		if owner is not None:
			try:
				release_update_claim(message.idempotency_key, owner, settings)
			except Exception:
				logger.exception("Unable to release %s update claim", message.channel)
		logger.exception("Unable to enqueue %s update", message.channel)
		raise HTTPException(
			status_code=503,
			detail=f"Unable to enqueue {message.channel} update",
		) from error


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


def _telegram_command(text: str) -> str | None:
	command = text.strip().split(maxsplit=1)
	if not command or not command[0].startswith("/"):
		return None
	return command[0].split("@", maxsplit=1)[0].casefold()


def _is_security_command(text: str) -> bool:
	normalized = " ".join(text.casefold().split())
	if normalized in SECURITY_COMMANDS:
		return True
	return " " not in normalized and normalized.startswith(f"{SIGNINS_COMMAND}@")


def _send_response(message: IncomingMessage, response: str) -> None:
	if message.channel == "telegram":
		send_text(message.conversation_id, response)
		return
	if message.channel == "whatsapp":
		send_whatsapp_text(message.conversation_id, response)
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
	_queue_incoming_message(message, settings)

	return {"ok": True}


@app.get("/webhooks/whatsapp")
def verify_whatsapp_webhook(
	hub_mode: str = Query(default="", alias="hub.mode"),
	hub_verify_token: str = Query(default="", alias="hub.verify_token"),
	hub_challenge: str = Query(default="", alias="hub.challenge"),
) -> PlainTextResponse:
	settings = Settings()
	if not settings.whatsapp_verify_token:
		raise HTTPException(status_code=503, detail="WhatsApp webhook is not configured")
	if hub_mode != "subscribe" or not secrets.compare_digest(
		hub_verify_token.encode("utf-8"), settings.whatsapp_verify_token.encode("utf-8")
	):
		raise HTTPException(status_code=403, detail="Invalid WhatsApp verification token")
	return PlainTextResponse(hub_challenge)


@app.post("/webhooks/whatsapp")
async def whatsapp_webhook(
	request: Request,
	x_hub_signature_256: str | None = Header(default=None, alias="X-Hub-Signature-256"),
) -> dict[str, bool]:
	settings = Settings()
	if not settings.whatsapp_app_secret:
		raise HTTPException(status_code=503, detail="WhatsApp webhook is not configured")
	body = await request.body()
	if not verify_webhook_signature(body, x_hub_signature_256, settings.whatsapp_app_secret):
		raise HTTPException(status_code=403, detail="Invalid WhatsApp webhook signature")
	try:
		payload = json.loads(body)
	except (json.JSONDecodeError, UnicodeDecodeError) as error:
		raise HTTPException(status_code=400, detail="Invalid WhatsApp webhook JSON") from error
	if not isinstance(payload, dict):
		raise HTTPException(status_code=400, detail="Invalid WhatsApp webhook payload")
	if not settings.whatsapp_allowed_user_id_set:
		raise HTTPException(status_code=503, detail="WhatsApp sender allowlist is not configured")

	for message in parse_whatsapp_updates(payload):
		if message.user_id.lstrip("+") not in settings.whatsapp_allowed_user_id_set:
			continue
		_queue_incoming_message(message, settings)
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
	if message.channel not in {"telegram", "whatsapp"}:
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
			command = _telegram_command(message.text)
			if command in HELP_COMMANDS:
				response = HELP_RESPONSE
			elif _is_security_command(message.text):
				normalized_events = get_recent_sign_ins(settings)
				security_findings = evaluate_sign_in_rules(normalized_events)
				response = respond(history, settings, security_findings)
			else:
				response = HELP_RESPONSE
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
