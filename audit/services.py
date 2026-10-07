import hashlib
import hmac
import time

from django.conf import settings
from django.db import transaction
from django.utils import timezone

from .models import Event, RateBucket


def record(actor, kind, target="", outcome="success"):
    Event.objects.create(
        actor=actor if actor and actor.is_authenticated else None,
        kind=kind,
        target=str(target)[:64],
        outcome=outcome,
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
