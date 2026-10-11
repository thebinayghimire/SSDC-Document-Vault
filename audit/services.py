import hashlib
import hmac
import time

from django.conf import settings
from django.db import transaction
from django.utils import timezone

from .models import Event, RateBucket

DETAIL_FIELDS = {
    "object_type",
    "object_id",
    "subject_id",
    "folder_id",
    "document_id",
    "before",
    "after",
    "policy_reference",
    "operation_id",
    "identity_hash",
}
STATE_FIELDS = {"user_id", "folder_id", "document_id", "manage", "restricted"}


def safe_details(details):
    details = details or {}
    if set(details) - DETAIL_FIELDS:
        raise ValueError("Unsupported audit detail field")
    result = {}
    for key, value in details.items():
        if key in {"before", "after"}:
            if value is not None and (not isinstance(value, dict) or set(value) - STATE_FIELDS):
                raise ValueError("Unsupported audit state")
            if value is not None and any(
                not isinstance(item, (str, int, bool, type(None))) for item in value.values()
            ):
                raise ValueError("Unsupported audit state value")
            result[key] = (
                {
                    name: item[:100] if isinstance(item, str) else item
                    for name, item in value.items()
                }
                if value is not None
                else None
            )
        elif isinstance(value, (str, int, bool)) or value is None:
            result[key] = value[:200] if isinstance(value, str) else value
        else:
            raise ValueError("Unsupported audit detail value")
    return result


def identity_reference(identity):
    return hmac.new(
        settings.SECRET_KEY.encode(),
        ("failed-auth:" + identity.strip().casefold()).encode(),
        hashlib.sha256,
    ).hexdigest()


def record(actor, kind, target="", outcome="success", *, details=None):
    Event.objects.create(
        actor=actor if actor and actor.is_authenticated else None,
        kind=kind,
        target=str(target)[:64],
        outcome=outcome,
        details=safe_details(details),
    )


def allow_rate(scope, identity, limit, seconds=300):
    key = hmac.new(
        settings.SECRET_KEY.encode(), f"{scope}:{identity}".encode(), hashlib.sha256
    ).hexdigest()
    window = int(time.time()) // seconds
    with transaction.atomic():
        RateBucket.objects.get_or_create(key=key, defaults={"window": window})
        bucket = RateBucket.objects.select_for_update().get(pk=key)
        if bucket.window != window:
            bucket.window = window
            bucket.count = 0
        bucket.count += 1
        bucket.updated_at = timezone.now()
        bucket.save(update_fields=["window", "count", "updated_at"])
        return bucket.count <= limit
