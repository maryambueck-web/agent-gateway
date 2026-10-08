import hashlib
import hmac
from datetime import datetime, timezone
from typing import Any

import requests

from app.config import Settings
from app.models import Attachment, IncomingMessage


def parse_updates(payload: dict[str, Any]) -> list[IncomingMessage]:
	messages: list[IncomingMessage] = []
	for entry in payload.get("entry", []):
		if not isinstance(entry, dict):
			continue
		for change in entry.get("changes", []):
			if not isinstance(change, dict):
				continue
			value = change.get("value")
			if not isinstance(value, dict):
				continue
			for item in value.get("messages", []):
				if not isinstance(item, dict):
					continue
				sender = item.get("from")
				message_id = item.get("id")
				message_type = item.get("type")
				try:
					timestamp = datetime.fromtimestamp(int(item.get("timestamp")), tz=timezone.utc)
				except (OverflowError, OSError, TypeError, ValueError):
					continue
				if not isinstance(sender, str) or not sender or not isinstance(message_id, str) or not message_id:
					continue

				content = item.get(message_type) if isinstance(message_type, str) else None
				text = ""
				attachments = []
				if message_type == "text" and isinstance(content, dict):
					text = content.get("body", "")
				elif message_type == "interactive" and isinstance(content, dict):
					interactive = content.get("button_reply") or content.get("list_reply") or {}
					text = interactive.get("title", "")
				elif message_type in {"image", "document", "audio", "video", "sticker"} and isinstance(content, dict):
					media_id = content.get("id")
					if isinstance(media_id, str) and media_id:
						attachments.append(
							Attachment(
								kind=message_type,
								file_id=media_id,
								mime_type=content.get("mime_type"),
							)
						)
					text = content.get("caption", "")
				if not isinstance(text, str) or (not text and not attachments):
					continue

				messages.append(
					IncomingMessage(
						channel="whatsapp",
						user_id=sender,
						conversation_id=sender,
						text=text,
						attachments=attachments,
						timestamp=timestamp,
						idempotency_key=message_id,
					)
				)
	return messages


def parse_update(payload: dict[str, Any]) -> IncomingMessage | None:
	messages = parse_updates(payload)
	return messages[0] if messages else None


def verify_webhook_signature(body: bytes, signature: str | None, app_secret: str) -> bool:
	if not app_secret or not signature or not signature.startswith("sha256="):
		return False
	expected = "sha256=" + hmac.new(
		app_secret.encode("utf-8"), body, hashlib.sha256
	).hexdigest()
	return hmac.compare_digest(expected, signature)


def send_text(recipient_id: str, text: str) -> None:
	settings = Settings()
	if not settings.whatsapp_access_token or not settings.whatsapp_phone_number_id:
		raise RuntimeError("WhatsApp Cloud API is not configured")

	url = (
		f"https://graph.facebook.com/{settings.whatsapp_graph_api_version}/"
		f"{settings.whatsapp_phone_number_id}/messages"
	)
	response = requests.post(
		url,
		headers={"Authorization": f"Bearer {settings.whatsapp_access_token}"},
		json={
			"messaging_product": "whatsapp",
			"recipient_type": "individual",
			"to": recipient_id,
			"type": "text",
			"text": {"preview_url": False, "body": text},
		},
		timeout=15,
	)
	response.raise_for_status()
