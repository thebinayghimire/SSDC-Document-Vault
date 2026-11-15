"""Self-service email changes with reservation, OTP verification, and expiry."""

from dataclasses import dataclass
from datetime import timedelta

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import transaction
from django.db.models import F
from django.urls import reverse
from django.utils import timezone

from accounts.models import EmailChangeRequest, EmailClaim, EmailNotification, User
from audit.services import record

from .email_claims import (
    EmailConflict,
    acquire_email_lock,
    check_availability,
    normalize_email,
    set_email,
)
from .notifications import (
    enqueue_notification,
    schedule_delivery,
    supersede_notifications,
)
from .otp import (
    OtpCooldown,
    OtpRateLimited,
    encrypt_otp,
    generate_otp,
    otp_digest,
    verify_otp,
)

OTP_PURPOSE = "email_change"
OTP_KINDS = {"email_change_otp"}
NOTICE_KINDS = {
    "email_change_otp",
    "email_change_security_notice",
    "email_change_completed",
    "email_change_expired",
}


class EmailChangeError(Exception):
    """Base class for safe, user-facing email-change failures."""


class EmailChangeDisabled(EmailChangeError):
    pass


class EmailChangeConflict(EmailChangeError):
    pass


class EmailChangeStateError(EmailChangeError):
    pass


@dataclass(frozen=True)
class StartResult:
    request: EmailChangeRequest | None
    created: bool


@dataclass(frozen=True)
class VerifyResult:
    status: str
    request: EmailChangeRequest | None = None


@dataclass(frozen=True)
class ResendResult:
    status: str
    notification: EmailNotification | None = None


def _require_enabled():
    if not (
        settings.EMAIL_LOGIN_ENABLED
        and settings.SELF_REGISTERED_EMAIL_CHANGE_ENABLED
    ):
        raise EmailChangeDisabled("Self-service email changes are not enabled.")


def _normalized(value):
    try:
        normalized = normalize_email(value)
    except ValidationError as exc:
        raise EmailChangeConflict("Enter a valid email address.") from exc
    if not normalized:
        raise EmailChangeConflict("Enter a valid email address.")
    return normalized


def _base(base_url):
    return (base_url or getattr(settings, "PUBLIC_BASE_URL", "")).rstrip("/")


def mask_email(value):
    local, separator, domain = (value or "").partition("@")
    if not separator:
        return "***"
    return f"{local[:1]}***@{domain}"


def pending_for_user(user):
    return (
        EmailChangeRequest.objects.filter(
            user_id=user.pk,
            status=EmailChangeRequest.Status.PENDING,
        )
        .order_by("-created_at", "-pk")
        .first()
    )


def _issue_otp(request, *, base_url="", now=None):
    now = now or timezone.now()
    code = generate_otp()
    digest = otp_digest(OTP_PURPOSE, request.pk, code)
    request.otp_digest = digest
    request.otp_expires_at = now + timedelta(minutes=settings.EMAIL_CHANGE_OTP_MINUTES)
    request.otp_attempts = 0
    request.otp_sent_at = now
    request.save(
        update_fields=[
            "otp_digest",
            "otp_expires_at",
            "otp_attempts",
            "otp_sent_at",
            "updated_at",
        ]
    )
    supersede_notifications(
        kinds=OTP_KINDS,
        email_change_request=request,
        reason="A newer verification code replaced this one.",
    )
    base = _base(base_url)
    notification = enqueue_notification(
        kind="email_change_otp",
        recipient_email=request.new_email,
        user_id=request.user_id,
        email_change_request=request,
        dedupe_key=f"email-change-otp:{request.pk}:{digest}",
        language=request.language,
        context={
            "language": request.language,
            "otp_ciphertext": encrypt_otp(code),
            "expiry_minutes": settings.EMAIL_CHANGE_OTP_MINUTES,
            "change_url": base + reverse("email_change"),
            "new_email_masked": mask_email(request.new_email),
        },
    )
    schedule_delivery(notification)
    record(
        request.user,
        "email_change_verification_sent",
        request.user_id,
        details={
            "object_type": "email_change",
            "object_id": request.pk,
            "subject_id": request.user_id,
        },
    )
    return notification


def _security_notice(request, *, base_url=""):
    if not request.old_email:
        return None
    base = _base(base_url)
    notification = enqueue_notification(
        kind="email_change_security_notice",
        recipient_email=request.old_email,
        user_id=request.user_id,
        email_change_request=request,
        dedupe_key=f"email-change-notice:{request.pk}",
        language=request.language,
        context={
            "language": request.language,
            "new_email_masked": mask_email(request.new_email),
            "change_url": base + reverse("email_change"),
        },
    )
    schedule_delivery(notification)
    return notification


def start_email_change(user, new_email, *, language="en", base_url=""):
    """Reserve a new address and send the verification code.

    The old address stays authoritative until verification succeeds.
    """
    _require_enabled()
    normalized = _normalized(new_email)
    supported = {code for code, _name in settings.LANGUAGES}
    language = language if language in supported else settings.LANGUAGE_CODE
    with transaction.atomic():
        acquire_email_lock()
        now = timezone.now()
        locked_user = User.objects.select_for_update().filter(pk=user.pk).first()
        if locked_user is None or not locked_user.is_active:
            raise EmailChangeStateError("The account is not eligible for an email change.")
        existing = (
            EmailChangeRequest.objects.select_for_update()
            .filter(user=locked_user, status=EmailChangeRequest.Status.PENDING)
            .order_by("-created_at", "-pk")
            .first()
        )
        if existing is not None:
            return StartResult(existing, False)
        claim = (
            EmailClaim.objects.select_for_update().filter(user_id=locked_user.pk).first()
        )
        current = claim.normalized_email if claim else ""
        if normalized == current:
            raise EmailChangeConflict("Choose a different email address.")
        try:
            check_availability(normalized, exclude_user_pk=locked_user.pk)
        except EmailConflict as exc:
            raise EmailChangeConflict(str(exc)) from exc
        reservation = (
            EmailChangeRequest.objects.select_for_update()
            .filter(
                status=EmailChangeRequest.Status.PENDING,
                new_email=normalized,
            )
            .exclude(user_id=locked_user.pk)
            .exists()
        )
        if reservation:
            raise EmailChangeConflict("That email address is already reserved for verification.")
        recent = EmailNotification.objects.filter(
            user_id=locked_user.pk,
            kind="email_change_otp",
            created_at__gte=now - timedelta(hours=1),
        ).count()
        if recent >= settings.EMAIL_CHANGE_OTP_HOURLY_LIMIT:
            raise OtpRateLimited("Too many verification emails were requested.")
        request = EmailChangeRequest.objects.create(
            user=locked_user,
            old_email=current,
            new_email=normalized,
            status=EmailChangeRequest.Status.PENDING,
            language=language,
            otp_digest="0" * 64,
            otp_expires_at=now + timedelta(minutes=settings.EMAIL_CHANGE_OTP_MINUTES),
            otp_sent_at=now,
        )
        record(
            locked_user,
            "email_change_requested",
            locked_user.pk,
            details={
                "object_type": "email_change",
                "object_id": request.pk,
                "subject_id": locked_user.pk,
            },
        )
        _issue_otp(request, base_url=base_url, now=now)
        _security_notice(request, base_url=base_url)
        return StartResult(request, True)


def _lock_pending(user, request_id=None):
    row = User.objects.filter(pk=user.pk).values("pk").first()
    if row is None:
        return None, None
    locked_user = User.objects.select_for_update().filter(pk=user.pk).first()
    rows = EmailChangeRequest.objects.select_for_update().filter(
        user_id=user.pk,
        status=EmailChangeRequest.Status.PENDING,
    )
    if request_id is not None:
        rows = rows.filter(pk=request_id)
    request = rows.order_by("-created_at", "-pk").first()
    return locked_user, request


def _expire_locked(request, *, now, base_url=""):
    if request.status != EmailChangeRequest.Status.PENDING:
        return False
    request.status = EmailChangeRequest.Status.EXPIRED
    request.completed_at = now
    request.otp_digest = ""
    request.otp_expires_at = None
    request.otp_attempts = 0
    request.save(
        update_fields=[
            "status",
            "completed_at",
            "otp_digest",
            "otp_expires_at",
            "otp_attempts",
            "updated_at",
        ]
    )
    supersede_notifications(
        kinds=NOTICE_KINDS,
        email_change_request=request,
        reason="The email-change request expired.",
    )
    if request.old_email:
        notification = enqueue_notification(
            kind="email_change_expired",
            recipient_email=request.old_email,
            user_id=request.user_id,
            email_change_request=request,
            dedupe_key=f"email-change-expired:{request.pk}",
            language=request.language,
            context={
                "language": request.language,
                "new_email_masked": mask_email(request.new_email),
                "change_url": _base(base_url) + reverse("email_change"),
            },
        )
        schedule_delivery(notification)
    record(
        request.user,
        "email_change_expired",
        request.user_id,
        details={
            "object_type": "email_change",
            "object_id": request.pk,
            "subject_id": request.user_id,
        },
    )
    return True


def resend_email_change(user, request_id=None, *, base_url=""):
    now = timezone.now()
    with transaction.atomic():
        locked_user, request = _lock_pending(user, request_id)
        if locked_user is None or request is None:
            return ResendResult("not_pending")
        if request.created_at + timedelta(days=settings.EMAIL_CHANGE_EXPIRY_DAYS) <= now:
            _expire_locked(request, now=now, base_url=base_url)
            return ResendResult("expired")
        if request.otp_sent_at and now < request.otp_sent_at + timedelta(
            seconds=settings.EMAIL_CHANGE_OTP_RESEND_SECONDS
        ):
            retry_after = (
                request.otp_sent_at
                + timedelta(seconds=settings.EMAIL_CHANGE_OTP_RESEND_SECONDS)
                - now
            ).total_seconds()
            raise OtpCooldown(retry_after)
        recent = EmailNotification.objects.filter(
            email_change_request=request,
            kind="email_change_otp",
            created_at__gte=now - timedelta(hours=1),
        ).count()
        if recent >= settings.EMAIL_CHANGE_OTP_HOURLY_LIMIT:
            raise OtpRateLimited("Too many verification emails were requested.")
        notification = _issue_otp(request, base_url=base_url, now=now)
        return ResendResult("sent", notification)


def verify_email_change(user, code, request_id=None, *, base_url="", now=None):
    """Apply an email change exactly once after OTP verification."""
    now = now or timezone.now()
    with transaction.atomic():
        locked_user, request = _lock_pending(user, request_id)
        if locked_user is None or request is None:
            return VerifyResult("not_pending")
        if request.created_at + timedelta(days=settings.EMAIL_CHANGE_EXPIRY_DAYS) <= now:
            _expire_locked(request, now=now, base_url=base_url)
            return VerifyResult("expired", request)
        if request.otp_attempts >= settings.EMAIL_CHANGE_OTP_MAX_ATTEMPTS:
            return VerifyResult("locked", request)
        if not request.otp_digest or request.otp_expires_at is None:
            return VerifyResult("invalid", request)
        if request.otp_expires_at <= now:
            return VerifyResult("code_expired", request)
        if not verify_otp(OTP_PURPOSE, request.pk, request.otp_digest, (code or "").strip()):
            request.otp_attempts += 1
            request.save(update_fields=["otp_attempts", "updated_at"])
            status = (
                "locked"
                if request.otp_attempts >= settings.EMAIL_CHANGE_OTP_MAX_ATTEMPTS
                else "invalid"
            )
            return VerifyResult(status, request)
        claim = (
            EmailClaim.objects.select_for_update().filter(user_id=locked_user.pk).first()
        )
        current = claim.normalized_email if claim else ""
        if current != request.old_email or locked_user.email != request.old_email:
            request.status = EmailChangeRequest.Status.SUPERSEDED
            request.completed_at = now
            request.otp_digest = ""
            request.otp_expires_at = None
            request.otp_attempts = 0
            request.save(
                update_fields=[
                    "status",
                    "completed_at",
                    "otp_digest",
                    "otp_expires_at",
                    "otp_attempts",
                    "updated_at",
                ]
            )
            supersede_notifications(
                kinds=NOTICE_KINDS,
                email_change_request=request,
                reason="The account email changed before verification.",
            )
            record(
                locked_user,
                "email_change_superseded",
                locked_user.pk,
                details={
                    "object_type": "email_change",
                    "object_id": request.pk,
                    "subject_id": locked_user.pk,
                },
            )
            return VerifyResult("stale", request)
        try:
            set_email(
                locked_user,
                request.new_email,
                actor=locked_user,
                source="self_service",
                change_request=request,
            )
        except EmailConflict:
            request.status = EmailChangeRequest.Status.SUPERSEDED
            request.completed_at = now
            request.save(update_fields=["status", "completed_at", "updated_at"])
            supersede_notifications(
                kinds=NOTICE_KINDS,
                email_change_request=request,
                reason="The requested address was no longer available.",
            )
            return VerifyResult("conflict", request)
        User.objects.filter(pk=locked_user.pk).update(auth_version=F("auth_version") + 1)
        request.status = EmailChangeRequest.Status.APPLIED
        request.completed_at = now
        request.otp_digest = ""
        request.otp_expires_at = None
        request.otp_attempts = 0
        request.save(
            update_fields=[
                "status",
                "completed_at",
                "otp_digest",
                "otp_expires_at",
                "otp_attempts",
                "updated_at",
            ]
        )
        supersede_notifications(
            kinds=OTP_KINDS,
            email_change_request=request,
            reason="The verification code was used.",
        )
        notification = enqueue_notification(
            kind="email_change_completed",
            recipient_email=request.new_email,
            user_id=request.user_id,
            email_change_request=request,
            dedupe_key=f"email-change-completed:{request.pk}",
            language=request.language,
            context={
                "language": request.language,
                "new_email_masked": mask_email(request.new_email),
                "login_url": _base(base_url) + reverse("staff_login"),
            },
        )
        schedule_delivery(notification)
        record(
            locked_user,
            "email_change_completed",
            locked_user.pk,
            details={
                "object_type": "email_change",
                "object_id": request.pk,
                "subject_id": locked_user.pk,
            },
        )
        return VerifyResult("applied", request)


def cancel_email_change(user, request_id=None):
    now = timezone.now()
    with transaction.atomic():
        locked_user, request = _lock_pending(user, request_id)
        if locked_user is None or request is None:
            return False
        request.status = EmailChangeRequest.Status.CANCELLED
        request.completed_at = now
        request.otp_digest = ""
        request.otp_expires_at = None
        request.otp_attempts = 0
        request.save(
            update_fields=[
                "status",
                "completed_at",
                "otp_digest",
                "otp_expires_at",
                "otp_attempts",
                "updated_at",
            ]
        )
        supersede_notifications(
            kinds=NOTICE_KINDS,
            email_change_request=request,
            reason="The email-change request was cancelled.",
        )
        record(
            locked_user,
            "email_change_cancelled",
            locked_user.pk,
            details={
                "object_type": "email_change",
                "object_id": request.pk,
                "subject_id": locked_user.pk,
            },
        )
        return True


def expire_email_change(request_id, *, now=None, base_url=""):
    now = now or timezone.now()
    with transaction.atomic():
        row = (
            EmailChangeRequest.objects.filter(pk=request_id)
            .values("user_id")
            .first()
        )
        if row is None:
            return False
        user = User.objects.select_for_update().filter(pk=row["user_id"]).first()
        request = EmailChangeRequest.objects.select_for_update().filter(pk=request_id).first()
        if user is None or request is None or request.status != EmailChangeRequest.Status.PENDING:
            return False
        return _expire_locked(request, now=now, base_url=base_url)


def expire_due_email_changes(*, now=None, limit=100, base_url=""):
    now = now or timezone.now()
    cutoff = now - timedelta(days=settings.EMAIL_CHANGE_EXPIRY_DAYS)
    candidates = list(
        EmailChangeRequest.objects.filter(
            status=EmailChangeRequest.Status.PENDING,
            created_at__lte=cutoff,
        )
        .order_by("created_at", "pk")
        .values_list("pk", flat=True)[:limit]
    )
    expired = 0
    for request_id in candidates:
        if expire_email_change(request_id, now=now, base_url=base_url):
            expired += 1
    return expired
