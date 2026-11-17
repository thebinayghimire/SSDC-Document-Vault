"""Database-backed, single-use, hashed verification tokens for staff registration."""

import hashlib
import secrets
from datetime import timedelta

from django.db import transaction
from django.urls import reverse
from django.utils import timezone

from accounts.models import StaffRegistrationRequest, StaffRegistrationToken


def hash_token(raw_token: str) -> str:
    """Compute constant-length SHA-256 hex digest of raw token."""
    # Mitigates plaintext credential exposure in database queries and storage
    if not isinstance(raw_token, str):
        return ""
    return hashlib.sha256(raw_token.strip().encode("ascii", errors="ignore")).hexdigest()


def create_registration_token(
    registration: StaffRegistrationRequest, *, lifetime_hours: int = 24
) -> str:
    """Generate a high-entropy random token and persist its SHA-256 hash."""
    # Mitigates token prediction and brute-force attacks via 256-bit cryptographically secure random secret
    raw_token = secrets.token_urlsafe(32)
    token_hash = hash_token(raw_token)
    now = timezone.now()
    # Mitigates stale link vulnerability by enforcing a strict 24-hour expiration window
    expires_at = now + timedelta(hours=lifetime_hours)
    # Mitigates token accumulation and replay attacks by invalidating earlier unused tokens upon reissuance
    StaffRegistrationToken.objects.filter(
        registration=registration,
        used_at__isnull=True,
    ).update(used_at=now)
    StaffRegistrationToken.objects.create(
        registration=registration,
        token_hash=token_hash,
        expires_at=expires_at,
    )
    return raw_token


def registration_token(registration: StaffRegistrationRequest) -> str:
    """Convenience alias for creating or retrieving a single-use database-backed token."""
    cached = getattr(registration, "_current_token", None)
    if cached:
        return cached
    token = create_registration_token(registration)
    registration._current_token = token
    return token


def registration_for_token(raw_token: str) -> StaffRegistrationRequest | None:
    """Return the registration behind a valid, unconsumed link token.

    The token proves control of the mailbox, but it is never sufficient to mark
    an address verified.  OTP verification alone performs that transition.
    """
    if not raw_token or not isinstance(raw_token, str):
        return None
    token_hash = hash_token(raw_token)
    now = timezone.now()
    token_record = (
        StaffRegistrationToken.objects.select_related("registration", "registration__user")
        .filter(token_hash=token_hash)
        .first()
    )
    if token_record is None or token_record.used_at is not None:
        return None
    if token_record.expires_at <= now:
        return None
    return token_record.registration


def validate_registration_token(raw_token: str) -> bool:
    """Read-only check of token validity without consuming or altering database state.

    Mitigates email security scanner prefetch consumption breaking human verification (Phase 2.1 Item 1).
    """
    return registration_for_token(raw_token) is not None


def consume_registration_token(raw_token: str) -> StaffRegistrationRequest | None:
    """Atomically consume a link token without changing verification state.

    Email verification is deliberately performed only by
    ``verify_registration_otp``.  This function is used to prove mailbox control
    for status access and to retire a link after the OTP succeeds, not to grant
    the verified state itself.
    """
    if not raw_token or not isinstance(raw_token, str):
        return None
    token_hash = hash_token(raw_token)
    now = timezone.now()

    with transaction.atomic():
        token_record = (
            StaffRegistrationToken.objects.select_for_update()
            .select_related("registration", "registration__user")
            .filter(token_hash=token_hash)
            .first()
        )
        if token_record is None:
            return None
        if token_record.used_at is not None:
            return None
        if token_record.expires_at <= now:
            return None

        token_record.used_at = now
        token_record.save(update_fields=["used_at"])
        return token_record.registration


def load_registration(token: str) -> StaffRegistrationRequest | None:
    """Legacy compatibility helper. Old signed tokens are rejected per Step 2 Item 8."""
    # Mitigates legacy signed token replay by returning None, forcing failure with generic page
    return None


def verification_url(registration: StaffRegistrationRequest, base_url: str = "") -> str:
    """Build verification URL with a fresh single-use database-backed token."""
    token = create_registration_token(registration, lifetime_hours=24)
    registration._current_token = token
    return base_url.rstrip("/") + reverse("staff_register_verify", args=[token])


def status_url(registration: StaffRegistrationRequest | None = None, base_url: str = "") -> str:
    """Build status URL without any token parameters."""
    # Mitigates URL token leakage and referrer harvesting by eliminating tokens from status links
    return base_url.rstrip("/") + reverse("staff_registration_status")
