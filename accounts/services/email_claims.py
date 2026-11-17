"""Authoritative email ownership and the canonical email write path."""

import unicodedata

from django.core.exceptions import ValidationError
from django.core.validators import validate_email
from django.db import connections, router, transaction
from django.db.models import CharField, Func
from django.db.models.functions import Lower, Trim

from accounts.models import (
    EmailChangeRequest,
    EmailClaim,
    StaffRegistrationRequest,
    User,
)
from audit.services import record

ADVISORY_LOCK_ID = 731011


class EmailConflict(Exception):
    """Raised when an address is already owned by another account."""


class EmailWriteBypass(Exception):
    """Raised when application code tries to write User.email directly."""


class _NormalizeNFKC(Func):
    """Apply the same Unicode normalization used by normalize_email in SQL."""

    function = "normalize"
    template = "%(function)s(%(expressions)s, NFKC)"
    output_field = CharField()


def normalize_email(value):
    """Return the canonical, case-insensitive representation of an address."""
    if value is None:
        return ""
    normalized = unicodedata.normalize("NFKC", str(value)).strip()
    if not normalized:
        return ""
    validate_email(normalized)
    normalized = normalized.casefold()
    if len(normalized) > 254:
        raise ValidationError("Email address must be at most 254 characters.")
    return normalized


def _legacy_key(value):
    """Normalize an existing row without rejecting historical invalid data."""
    return unicodedata.normalize("NFKC", str(value or "")).strip().casefold()


def _lock_advisory(using):
    with connections[using].cursor() as cursor:
        cursor.execute("SELECT pg_advisory_xact_lock(%s)", [ADVISORY_LOCK_ID])


def acquire_email_lock(*, using=None):
    """Acquire the email-authority advisory lock inside the caller's transaction."""
    using = using or router.db_for_write(EmailClaim)
    _lock_advisory(using)


def _lock_request(request, using):
    if request is None:
        return
    request_pk = getattr(request, "pk", request)
    if request_pk:
        StaffRegistrationRequest.objects.using(using).select_for_update().get(pk=request_pk)


def _lock_email_change_request(change_request, using):
    if change_request is None:
        return
    request_pk = getattr(change_request, "pk", change_request)
    if request_pk:
        EmailChangeRequest.objects.using(using).select_for_update().get(pk=request_pk)


def _legacy_collision(normalized, *, exclude_user_pk=None, using=None):
    rows = (
        User.objects.using(using)
        .annotate(_normalized_email=Lower(Trim(_NormalizeNFKC("email"))))
        .filter(_normalized_email=normalized)
    )
    if exclude_user_pk is not None:
        rows = rows.exclude(pk=exclude_user_pk)
    return rows.exists()


def _assert_address_available(locked_user, normalized, *, using, exclude_change_request_pk=None):
    other = (
        EmailClaim.objects.using(using)
        .select_for_update()
        .filter(normalized_email=normalized)
        .exclude(user_id=locked_user.pk)
        .first()
    )
    if other is not None:
        raise EmailConflict("That email address is already assigned to another account.")
    reservations = (
        EmailChangeRequest.objects.using(using)
        .select_for_update()
        .filter(status=EmailChangeRequest.Status.PENDING, new_email=normalized)
    )
    if exclude_change_request_pk is not None:
        reservations = reservations.exclude(pk=exclude_change_request_pk)
    if reservations.exists():
        raise EmailConflict("That email address is already reserved for verification.")
    if _legacy_collision(normalized, exclude_user_pk=locked_user.pk, using=using):
        raise EmailConflict("That email address is already used by another legacy account.")


def _record_claim(actor, kind, locked_user, claim, *, source=""):
    object_type = f"email_claim:{source}" if source else "email_claim"
    record(
        actor,
        kind,
        locked_user.pk,
        details={
            "object_type": object_type,
            "object_id": claim.pk,
            "subject_id": locked_user.pk,
        },
    )


def _sync_email(original, locked_user):
    original.email = locked_user.email
    original._remember_saved_values({"email"})


def _create_claim(
    locked_user,
    normalized,
    *,
    actor=None,
    source="",
    using=None,
    exclude_change_request_pk=None,
):
    _assert_address_available(
        locked_user,
        normalized,
        using=using,
        exclude_change_request_pk=exclude_change_request_pk,
    )
    claim = EmailClaim.objects.using(using).create(
        user_id=locked_user.pk,
        normalized_email=normalized,
    )
    _record_claim(actor, "email_claim_created", locked_user, claim, source=source)
    return claim


def claim_for_new_user(user, *, using=None):
    """Claim the normalized email of a newly-created user.

    The caller must have acquired the advisory lock before inserting the user row.
    Re-acquiring it here is safe because PostgreSQL advisory transaction locks are
    re-entrant within the same transaction.
    """
    normalized = normalize_email(user.email)
    if not normalized:
        return None
    using = using or router.db_for_write(User, instance=user)
    with transaction.atomic(using=using):
        _lock_advisory(using)
        locked_user = User.objects.using(using).select_for_update().get(pk=user.pk)
        existing = (
            EmailClaim.objects.using(using).select_for_update().filter(user_id=user.pk).first()
        )
        if existing is not None:
            if existing.normalized_email != normalized:
                raise EmailConflict("The account already owns a different email claim.")
            return existing
        return _create_claim(
            locked_user,
            normalized,
            source="user_create",
            using=using,
        )


def set_email(
    user,
    email,
    *,
    actor=None,
    source="",
    request=None,
    change_request=None,
    using=None,
):
    """Set, transfer, or clear a user's email through the authoritative claim."""
    normalized = normalize_email(email)
    using = using or router.db_for_write(User, instance=user)
    exclude_change_request_pk = getattr(change_request, "pk", change_request)
    with transaction.atomic(using=using):
        _lock_advisory(using)
        locked_user = User.objects.using(using).select_for_update().get(pk=user.pk)
        _lock_request(request, using)
        _lock_email_change_request(change_request, using)
        if not normalized:
            return _clear_locked(locked_user, actor=actor, source=source, using=using)

        current_normalized = _legacy_key(locked_user.email)
        claim = (
            EmailClaim.objects.using(using)
            .select_for_update()
            .filter(user_id=locked_user.pk)
            .first()
        )
        if current_normalized == normalized:
            claim_changed = False
            if claim is None:
                claim = _create_claim(
                    locked_user,
                    normalized,
                    actor=actor,
                    source=source,
                    using=using,
                    exclude_change_request_pk=exclude_change_request_pk,
                )
            elif claim.normalized_email != normalized:
                _assert_address_available(
                    locked_user,
                    normalized,
                    using=using,
                    exclude_change_request_pk=exclude_change_request_pk,
                )
                claim.normalized_email = normalized
                claim.save(update_fields=["normalized_email", "updated_at"], using=using)
                claim_changed = True
            if locked_user.email != normalized:
                User.objects.using(using).filter(pk=locked_user.pk).update(email=normalized)
                locked_user.email = normalized
            if claim_changed:
                _record_claim(actor, "email_claim_changed", locked_user, claim, source=source)
            _sync_email(user, locked_user)
            return claim

        _assert_address_available(
            locked_user,
            normalized,
            using=using,
            exclude_change_request_pk=exclude_change_request_pk,
        )
        claim_created = claim is None
        if claim_created:
            claim = EmailClaim.objects.using(using).create(
                user_id=locked_user.pk,
                normalized_email=normalized,
            )
            _record_claim(actor, "email_claim_created", locked_user, claim, source=source)
        else:
            claim.normalized_email = normalized
            claim.save(update_fields=["normalized_email", "updated_at"], using=using)
        User.objects.using(using).filter(pk=locked_user.pk).update(email=normalized)
        locked_user.email = normalized
        _sync_email(user, locked_user)
        if not claim_created:
            _record_claim(actor, "email_claim_changed", locked_user, claim, source=source)
        return claim


def _clear_locked(locked_user, *, actor=None, source="", using=None):
    claim = (
        EmailClaim.objects.using(using).select_for_update().filter(user_id=locked_user.pk).first()
    )
    if claim is not None:
        _record_claim(actor, "email_claim_released", locked_user, claim, source=source)
        claim.delete()
    if locked_user.email:
        User.objects.using(using).filter(pk=locked_user.pk).update(email="")
        locked_user.email = ""


def clear_email(user, *, actor=None, source="", request=None, using=None):
    """Clear a user's email and release its claim."""
    using = using or router.db_for_write(User, instance=user)
    with transaction.atomic(using=using):
        _lock_advisory(using)
        locked_user = User.objects.using(using).select_for_update().get(pk=user.pk)
        _lock_request(request, using)
        _clear_locked(locked_user, actor=actor, source=source, using=using)
        _sync_email(user, locked_user)


def repair_claim(user, *, actor=None, source="reconcile", using=None):
    """Create an unambiguous claim for an existing legacy email without changing it."""
    normalized = normalize_email(user.email)
    if not normalized:
        return None
    using = using or router.db_for_write(User, instance=user)
    with transaction.atomic(using=using):
        _lock_advisory(using)
        locked_user = User.objects.using(using).select_for_update().get(pk=user.pk)
        if _legacy_key(locked_user.email) != normalized:
            raise EmailConflict("The account email changed while it was being reconciled.")
        existing = (
            EmailClaim.objects.using(using).select_for_update().filter(user_id=user.pk).first()
        )
        if existing is not None:
            if existing.normalized_email != normalized:
                raise EmailConflict("The account already owns a different email claim.")
            return existing
        return _create_claim(
            locked_user,
            normalized,
            actor=actor,
            source=source,
            using=using,
        )


def check_availability(normalized_email, *, exclude_user_pk=None, using=None):
    """Validate an address without writing it, for admin form validation."""
    normalized = normalize_email(normalized_email)
    if not normalized:
        return
    using = using or router.db_for_read(EmailClaim)
    if exclude_user_pk is not None:
        current = (
            User.objects.using(using)
            .filter(pk=exclude_user_pk)
            .values_list("email", flat=True)
            .first()
        )
        if current is not None and _legacy_key(current) == normalized:
            return
    other = (
        EmailClaim.objects.using(using)
        .filter(normalized_email=normalized)
        .exclude(user_id=exclude_user_pk)
        .exists()
    )
    if other:
        raise EmailConflict("That email address is already assigned to another account.")
    reserved = EmailChangeRequest.objects.using(using).filter(
        status=EmailChangeRequest.Status.PENDING,
        new_email=normalized,
    )
    if exclude_user_pk is not None:
        reserved = reserved.exclude(user_id=exclude_user_pk)
    if reserved.exists():
        raise EmailConflict("That email address is already reserved for verification.")
    if _legacy_collision(normalized, exclude_user_pk=exclude_user_pk, using=using):
        raise EmailConflict("That email address is already used by another legacy account.")


def resolve(normalized_email):
    """Resolve an active user by normalized email for future email-login use."""
    try:
        normalized = normalize_email(normalized_email)
    except ValidationError:
        return None
    if not normalized:
        return None
    claim = (
        EmailClaim.objects.select_related("user")
        .filter(normalized_email=normalized, user__is_active=True)
        .first()
    )
    return claim.user if claim is not None else None
