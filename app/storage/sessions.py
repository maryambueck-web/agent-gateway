from datetime import datetime, timedelta, timezone
from hashlib import sha256

from google.cloud import firestore

from app.config import Settings
from app.models import IncomingMessage
from app.storage.firestore import get_firestore_client


def _conversation_ref(message: IncomingMessage, settings: Settings):
	conversation_key = "\x1f".join(
		(message.channel, message.user_id, message.conversation_id)
	)
	document_id = sha256(conversation_key.encode("utf-8")).hexdigest()
	return get_firestore_client().collection(settings.conversation_collection).document(
		document_id
	)


def load_history(
	message: IncomingMessage,
	settings: Settings,
) -> tuple[list[dict[str, str]], int]:
	snapshot = _conversation_ref(message, settings).get()
	if not snapshot.exists:
		return [], 0
	data = snapshot.to_dict() or {}
	messages = data.get("messages", [])
	history = [
		{"role": item["role"], "content": item["content"]}
		for item in messages
		if isinstance(item, dict)
		and item.get("role") in {"user", "assistant"}
		and isinstance(item.get("content"), str)
	]
	return history, int(data.get("version", 0))


def save_response(
	message: IncomingMessage,
	history: list[dict[str, str]],
	expected_version: int,
	response: str,
	owner: str,
	settings: Settings,
) -> bool:
	client = get_firestore_client()
	conversation_ref = _conversation_ref(message, settings)
	update_ref = client.collection(settings.telegram_idempotency_collection).document(
		f"telegram-{message.idempotency_key}"
	)
	transaction = client.transaction()
	now = datetime.now(timezone.utc)

	@firestore.transactional
	def save(transaction):
		update_snapshot = update_ref.get(transaction=transaction)
		conversation_snapshot = conversation_ref.get(transaction=transaction)
		update_data = update_snapshot.to_dict() or {}
		conversation_data = conversation_snapshot.to_dict() or {}
		if (
			not update_snapshot.exists
			or update_data.get("status") != "processing"
			or update_data.get("owner") != owner
			or int(conversation_data.get("version", 0)) != expected_version
		):
			return False

		transaction.set(
			conversation_ref,
			{
				"messages": history[-settings.conversation_history_limit :],
				"version": expected_version + 1,
				"updated_at": now,
			},
		)
		transaction.update(
			update_ref,
			{
				"status": "response_ready",
				"response": response,
				"updated_at": now,
			},
		)
		return True

	return save(transaction)


def consume_user_rate_limit(
	channel: str,
	user_id: str,
	settings: Settings,
) -> bool:
	client = get_firestore_client()
	key = sha256(f"{channel}:{user_id}".encode("utf-8")).hexdigest()
	reference = client.collection(settings.telegram_rate_limit_collection).document(key)
	transaction = client.transaction()
	now = datetime.now(timezone.utc)
	window = timedelta(seconds=settings.telegram_rate_limit_window_seconds)

	@firestore.transactional
	def consume(transaction):
		snapshot = reference.get(transaction=transaction)
		data = snapshot.to_dict() or {}
		window_started_at = data.get("window_started_at")
		if isinstance(window_started_at, datetime) and window_started_at.tzinfo is None:
			window_started_at = window_started_at.replace(tzinfo=timezone.utc)

		if (
			snapshot.exists
			and isinstance(window_started_at, datetime)
			and now - window_started_at < window
		):
			count = int(data.get("count", 0))
			if count >= settings.telegram_rate_limit_requests:
				return False
			transaction.update(reference, {"count": count + 1, "updated_at": now})
			return True

		transaction.set(
			reference,
			{"count": 1, "window_started_at": now, "updated_at": now},
		)
		return True

	return consume(transaction)
