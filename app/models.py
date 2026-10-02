from datetime import datetime

from pydantic import BaseModel, Field


class Attachment(BaseModel):
    kind: str
    file_id: str
    mime_type: str | None = None


class IncomingMessage(BaseModel):
    channel: str
    user_id: str
    conversation_id: str
    text: str
    attachments: list[Attachment] = Field(default_factory=list)
    timestamp: datetime
    idempotency_key: str
