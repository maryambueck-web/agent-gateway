import json
from datetime import datetime, timezone
from typing import Any
from urllib.request import Request, urlopen

from app.config import Settings
from app.models import Attachment, IncomingMessage


TELEGRAM_MAX_MESSAGE_LENGTH = 4096


def parse_update(payload: dict[str, Any]) -> IncomingMessage | None:
	update_id = payload.get("update_id")
	message = payload.get("message")
	if (
		not isinstance(update_id, int)
		or isinstance(update_id, bool)
		or not isinstance(message, dict)
	):
		return None

	sender = message.get("from")
	chat = message.get("chat")
	message_date = message.get("date")
	if (
		not isinstance(sender, dict)
		or not isinstance(sender.get("id"), int)
		or isinstance(sender.get("id"), bool)
		or not isinstance(chat, dict)
		or not isinstance(chat.get("id"), int)
		or isinstance(chat.get("id"), bool)
		or not isinstance(message_date, int)
		or isinstance(message_date, bool)
	):
		return None

	try:
		timestamp = datetime.fromtimestamp(message_date, tz=timezone.utc)
	except (OverflowError, OSError, ValueError):
		return None

	text = message.get("text") or message.get("caption") or ""
	attachments = _parse_attachments(message)
	if not isinstance(text, str) or (not text and not attachments):
		return None

	return IncomingMessage(
		channel="telegram",
		user_id=str(sender["id"]),
		conversation_id=str(chat["id"]),
		text=text,
		attachments=attachments,
		timestamp=timestamp,
		idempotency_key=str(update_id),
	)


def send_text(chat_id: str | int, text: str) -> None:
	settings = Settings()
	if not settings.telegram_bot_token:
		raise RuntimeError("TELEGRAM_BOT_TOKEN is not configured")

	url = f"https://api.telegram.org/bot{settings.telegram_bot_token}/sendMessage"
	for part in split_message(text):
		request = Request(
			url,
			data=json.dumps({"chat_id": chat_id, "text": part}).encode("utf-8"),
			headers={"Content-Type": "application/json"},
		)
		with urlopen(request, timeout=10) as response:
			result = json.loads(response.read())
		if not isinstance(result, dict) or not result.get("ok"):
			raise RuntimeError("Telegram rejected the sendMessage request")


def split_message(text: str) -> list[str]:
	parts: list[str] = []
	remaining = text

	while len(remaining) > TELEGRAM_MAX_MESSAGE_LENGTH:
		split_at = remaining.rfind("\n", 0, TELEGRAM_MAX_MESSAGE_LENGTH)
		if split_at < 0:
			split_at = remaining.rfind(" ", 0, TELEGRAM_MAX_MESSAGE_LENGTH)
		if split_at < 0:
			split_at = TELEGRAM_MAX_MESSAGE_LENGTH
		else:
			split_at += 1

		parts.append(remaining[:split_at])
		remaining = remaining[split_at:]

	if remaining:
		parts.append(remaining)
	return parts


def _parse_attachments(message: dict[str, Any]) -> list[Attachment]:
	attachments: list[Attachment] = []

	photos = message.get("photo")
	if isinstance(photos, list) and photos:
		photo = max(
			(item for item in photos if isinstance(item, dict)),
			key=lambda item: item.get("file_size", 0),
			default=None,
		)
		if photo and isinstance(photo.get("file_id"), str):
			attachments.append(Attachment(kind="photo", file_id=photo["file_id"]))

	for kind in ("document", "audio", "video", "voice", "video_note", "animation", "sticker"):
		item = message.get(kind)
		if isinstance(item, dict) and isinstance(item.get("file_id"), str):
			attachments.append(
				Attachment(
					kind=kind,
					file_id=item["file_id"],
					mime_type=item.get("mime_type"),
				)
			)

	return attachments
