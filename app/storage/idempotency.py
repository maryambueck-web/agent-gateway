from datetime import datetime, timedelta, timezone
from functools import lru_cache
from uuid import uuid4

from google.cloud import firestore

from app.config import Settings
from app.storage.firestore import get_firestore_client


_PENDING_LEASE = timedelta(minutes=5)


def claim_update(update_id: str, settings: Settings) -> tuple[str, str | None]:
    client = get_firestore_client()
    reference = client.collection(settings.telegram_idempotency_collection).document(
        f"telegram-{update_id}"
    )
    transaction = client.transaction()
    now = datetime.now(timezone.utc)

    @firestore.transactional
    def claim(transaction):
        snapshot = reference.get(transaction=transaction)
        if snapshot.exists:
            data = snapshot.to_dict() or {}
            if data.get("status") in {
                "enqueued",
                "processing",
                "response_ready",
                "completed",
            }:
                return "enqueued", None

            updated_at = data.get("updated_at")
            if isinstance(updated_at, datetime) and updated_at.tzinfo is None:
                updated_at = updated_at.replace(tzinfo=timezone.utc)
            if (
                data.get("status") == "pending"
                and isinstance(updated_at, datetime)
                and now - updated_at < _PENDING_LEASE
            ):
                return "pending", None

        owner = uuid4().hex
        transaction.set(
            reference,
            {"status": "pending", "owner": owner, "updated_at": now},
        )
        return "claimed", owner

    return claim(transaction)


def mark_update_enqueued(update_id: str, owner: str, settings: Settings) -> bool:
    client = get_firestore_client()
    reference = client.collection(settings.telegram_idempotency_collection).document(
        f"telegram-{update_id}"
    )
    transaction = client.transaction()

    @firestore.transactional
    def mark(transaction):
        snapshot = reference.get(transaction=transaction)
        data = snapshot.to_dict() or {}
        if not snapshot.exists:
            return False
        if data.get("status") in {"processing", "response_ready", "completed"}:
            return True
        if data.get("owner") != owner:
            return False
        transaction.update(
            reference,
            {"status": "enqueued", "updated_at": datetime.now(timezone.utc)},
        )
        return True

    return mark(transaction)


def release_update_claim(update_id: str, owner: str, settings: Settings) -> None:
    client = get_firestore_client()
    reference = client.collection(settings.telegram_idempotency_collection).document(
        f"telegram-{update_id}"
    )
    transaction = client.transaction()

    @firestore.transactional
    def release(transaction):
        snapshot = reference.get(transaction=transaction)
        data = snapshot.to_dict() or {}
        if snapshot.exists and data.get("owner") == owner:
            transaction.delete(reference)

    release(transaction)


def claim_task_processing(
    update_id: str,
    settings: Settings,
) -> tuple[str, str | None, str | None]:
    client = get_firestore_client()
    reference = client.collection(settings.telegram_idempotency_collection).document(
        f"telegram-{update_id}"
    )
    transaction = client.transaction()
    now = datetime.now(timezone.utc)

    @firestore.transactional
    def claim(transaction):
        snapshot = reference.get(transaction=transaction)
        if not snapshot.exists:
            return "missing", None, None
        data = snapshot.to_dict() or {}
        status = data.get("status")
        if status == "completed":
            return "completed", None, None

        updated_at = data.get("updated_at")
        if isinstance(updated_at, datetime) and updated_at.tzinfo is None:
            updated_at = updated_at.replace(tzinfo=timezone.utc)
        lease_active = (
            isinstance(updated_at, datetime)
            and now - updated_at < _PENDING_LEASE
        )
        if status == "pending" and lease_active:
            return "pending", None, None
        if status in {"processing", "response_ready"} and lease_active:
            return "pending", None, None

        owner = uuid4().hex
        if status == "response_ready":
            transaction.update(
                reference,
                {"owner": owner, "updated_at": now},
            )
            return "response_ready", owner, data.get("response", "")
        if status not in {"enqueued", "pending", "processing"}:
            return "missing", None, None

        transaction.update(
            reference,
            {"status": "processing", "owner": owner, "updated_at": now},
        )
        return "claimed", owner, None

    return claim(transaction)


def mark_update_completed(update_id: str, owner: str, settings: Settings) -> bool:
    client = get_firestore_client()
    reference = client.collection(settings.telegram_idempotency_collection).document(
        f"telegram-{update_id}"
    )
    transaction = client.transaction()

    @firestore.transactional
    def mark(transaction):
        snapshot = reference.get(transaction=transaction)
        data = snapshot.to_dict() or {}
        if (
            not snapshot.exists
            or data.get("status") != "response_ready"
            or data.get("owner") != owner
        ):
            return False
        transaction.update(
            reference,
            {
                "status": "completed",
                "owner": firestore.DELETE_FIELD,
                "updated_at": datetime.now(timezone.utc),
            },
        )
        return True

    return mark(transaction)


def release_processing_claim(update_id: str, owner: str, settings: Settings) -> None:
    client = get_firestore_client()
    reference = client.collection(settings.telegram_idempotency_collection).document(
        f"telegram-{update_id}"
    )
    transaction = client.transaction()
    now = datetime.now(timezone.utc)

    @firestore.transactional
    def release(transaction):
        snapshot = reference.get(transaction=transaction)
        data = snapshot.to_dict() or {}
        if not snapshot.exists or data.get("owner") != owner:
            return
        if data.get("status") == "processing":
            transaction.update(
                reference,
                {
                    "status": "enqueued",
                    "owner": firestore.DELETE_FIELD,
                    "updated_at": now,
                },
            )
        elif data.get("status") == "response_ready":
            transaction.update(
                reference,
                {
                    "owner": firestore.DELETE_FIELD,
                    "updated_at": now - _PENDING_LEASE,
                },
            )

    release(transaction)