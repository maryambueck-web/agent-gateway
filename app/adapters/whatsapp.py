from typing import Any

from app.models import IncomingMessage


def parse_update(payload: dict[str, Any]) -> IncomingMessage | None:
	raise NotImplementedError("WhatsApp webhook parsing is not implemented yet")


def send_text(recipient_id: str, text: str) -> None:
	raise NotImplementedError("WhatsApp sending is not implemented yet")
