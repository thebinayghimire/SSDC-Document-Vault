"""Staff self-registration, OTP verification, review decisions, and expiry."""

import hashlib
import hmac
import secrets
import uuid
from dataclasses import dataclass
from datetime import timedelta

from django.conf import settings
from django.contrib.auth.hashers import make_password
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import PermissionDenied, ValidationError
from django.db import transaction
from django.db.models import Q
from django.utils import timezone

from accounts.models import (
    EmailClaim,
    EmailNotification,
    StaffRegistrationRequest,
    User,
)
from audit.services import allow_rate, record

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
from .registration_tokens import status_url, verification_url

OTP_PURPOSE = "staff_registration"
ACTIVE_STATUSES = (
    StaffRegistrationRequest.Status.EMAIL_PENDING,
    StaffRegistrationRequest.Status.PENDING_REVIEW,
)
OTP_NOTIFICATION_KINDS = {"registration_otp"}
STATUS_NOTIFICATION_KINDS = {"registration_status_link"}
DECISION_NOTIFICATION_KINDS = {
    "registration_approved",
    "registration_declined",
    "registration_reapplication_allowed",
    "registration_expired",
}


class RegistrationError(Exception):
    """Base class for safe, user-facing registration failures."""


class RegistrationDisabled(RegistrationError):
    pass


class RegistrationConflict(RegistrationError):
    pass


class RegistrationInvalid(RegistrationError):
    def __init__(self, messages):
        self.messages = list(messages)
        super().__init__(" ".join(self.messages))


class RegistrationStateError(RegistrationError):
    pass


class DecisionConflict(RegistrationStateError):
    """A stale or conflicting administrator decision was rejected."""


@dataclass(frozen=True)
class RegistrationResult:
    request: StaffRegistrationRequest | None
    created: bool


@dataclass(frozen=True)
class VerifyResult:
    status: str
    request: StaffRegistrationRequest | None = None


@dataclass(frozen=True)
class ResendResult:
    status: str
    notification: EmailNotification | None = None


@dataclass(frozen=True)
class DecisionResult:
    request: StaffRegistrationRequest
    changed: bool


def _require_enabled():
    if not settings.STAFF_SELF_REGISTRATION_ENABLED:
        raise RegistrationDisabled("Staff self-registration is not enabled.")


def _normalized(value):
    try:
        normalized = normalize_email(value)
    except ValidationError as exc:
        raise RegistrationInvalid(exc.messages) from exc
    if not normalized:
        raise RegistrationInvalid(["Enter a valid email address."])
    return normalized


def _validated_password(password):
    try:
        validate_password(password)
    except ValidationError as exc:
        raise RegistrationInvalid(exc.messages) from exc


def _language(value):
    supported = {code for code, _name in settings.LANGUAGES}
    return value if value in supported else settings.LANGUAGE_CODE


def _internal_username():
    return f"applicant-{uuid.uuid4().hex[:20]}"


def _notification_base(base_url):
    return (base_url or getattr(settings, "PUBLIC_BASE_URL", "")).rstrip("/")


def _new_request(*, user, normalized, language, password_hash, now):
    """Insert the constraint-satisfying row before the real digest is issued.

    The placeholder digest is never usable and is replaced in the same
    transaction before the request can be observed by another connection.
    """
    return StaffRegistrationRequest.objects.create(
        user=user,
        status=StaffRegistrationRequest.Status.EMAIL_PENDING,
        applicant_email=normalized,
        language=language,
        pending_password_hash=password_hash,
        otp_digest="0" * 64,
        otp_expires_at=now + timedelta(minutes=settings.STAFF_REGISTRATION_OTP_MINUTES),
        otp_sent_at=now,
    )


def _issue_otp(request, *, base_url="", now=None):
    """Issue a fresh code, replacing any previous undelivered code."""
    now = now or timezone.now()
    code = generate_otp()
    digest = otp_digest(OTP_PURPOSE, request.pk, code)
    request.otp_digest = digest
    request.otp_expires_at = now + timedelta(minutes=settings.STAFF_REGISTRATION_OTP_MINUTES)
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
        kinds=OTP_NOTIFICATION_KINDS | STATUS_NOTIFICATION_KINDS,
        registration_request=request,
        reason="A newer verification code replaced this one.",
    )
    base = _notification_base(base_url)
    notification = enqueue_notification(
        kind="registration_otp",
        recipient_email=request.applicant_email,
        user_id=request.user_id,
        registration_request=request,
        dedupe_key=f"staff-registration-otp:{request.pk}:{digest}",
        language=request.language,
        context={
            "language": request.language,
            "recipient_email": request.applicant_email,
            "user_email": request.applicant_email,
            "app_name": "SSDC Document Vault",
            "purpose": "complete your staff registration",
            "otp_ciphertext": encrypt_otp(code),
            "expiry_minutes": settings.STAFF_REGISTRATION_OTP_MINUTES,
            "verification_url": verification_url(request, base),
            "status_url": status_url(request, base),
        },
    )
    schedule_delivery(notification)
    record(
        None,
        "staff_registration_otp_sent",
        request.user_id,
        details={
            "object_type": "staff_registration_otp",
            "object_id": request.pk,
            "subject_id": request.user_id,
        },
    )
    return notification


def _issue_status_link(request, *, base_url="", now=None):
    """Email a single-use link that lets an applicant reopen their status page.

    The link only binds the application to a new server-side session.  It does
    not verify an address and does not reveal the application state to anyone
    who merely knows the email address.
    """
    now = now or timezone.now()
    supersede_notifications(
        kinds=OTP_NOTIFICATION_KINDS | STATUS_NOTIFICATION_KINDS,
        registration_request=request,
        reason="A newer status link replaced this one.",
    )
    base = _notification_base(base_url)
    notification = enqueue_notification(
        kind="registration_status_link",
        recipient_email=request.applicant_email,
        user_id=request.user_id,
        registration_request=request,
        dedupe_key=None,
        language=request.language,
        context={
            "language": request.language,
            "recipient_email": request.applicant_email,
            "user_email": request.applicant_email,
            "app_name": "SSDC Document Vault",
            "status_url": status_url(request, base),
            "verification_url": verification_url(request, base),
            "expiry_hours": 24,
        },
    )
    schedule_delivery(notification)
    return notification


def _expire_locked(request, *, now, base_url=""):
    if request.status not in ACTIVE_STATUSES:
        return False
    request.status = StaffRegistrationRequest.Status.EXPIRED
    request.otp_digest = ""
    request.otp_expires_at = None
    request.otp_attempts = 0
    request.pending_password_hash = ""
    request.save(
        update_fields=[
            "status",
            "otp_digest",
            "otp_expires_at",
            "otp_attempts",
            "pending_password_hash",
            "updated_at",
        ]
    )
    supersede_notifications(
        kinds=OTP_NOTIFICATION_KINDS | STATUS_NOTIFICATION_KINDS | DECISION_NOTIFICATION_KINDS,
        registration_request=request,
        reason="The registration expired.",
    )
    base = _notification_base(base_url)
    notification = enqueue_notification(
        kind="registration_expired",
        recipient_email=request.applicant_email,
        user_id=request.user_id,
        registration_request=request,
        dedupe_key=f"staff-registration-expired:{request.pk}",
        language=request.language,
        context={
            "language": request.language,
            "status_url": status_url(request, base),
            "reapply_url": base + "/accounts/register/",
            "registration_enabled": settings.STAFF_SELF_REGISTRATION_ENABLED,
        },
    )
    schedule_delivery(notification)
    record(
        None,
        "staff_registration_expired",
        request.user_id,
        details={
            "object_type": "staff_registration",
            "object_id": request.pk,
            "subject_id": request.user_id,
        },
    )
    return True


def _eligible_for_reapplication(request):
    if request is None:
        return False
    if request.status == StaffRegistrationRequest.Status.EXPIRED:
        return True
    return (
        request.status == StaffRegistrationRequest.Status.DECLINED and request.reapplication_allowed
    )


def register_applicant(*, email, password, language="en", base_url=""):
    """Create a new application, or authorize an eligible reapplication.

    The public caller must render the same response whether this function
    created a request or deliberately declined to reveal an existing account.
    """
    _require_enabled()
    normalized = _normalized(email)
    _validated_password(password)
    language = _language(language)
    password_hash = make_password(password)
    with transaction.atomic():
        acquire_email_lock()
        now = timezone.now()
        claim = (
            EmailClaim.objects.select_for_update()
            .select_related("user")
            .filter(normalized_email=normalized)
            .first()
        )
        if claim is not None:
            user = User.objects.select_for_update().filter(pk=claim.user_id).first()
            if user is None:
                return RegistrationResult(None, False)
            active = (
                StaffRegistrationRequest.objects.select_for_update()
                .filter(user=user, status__in=ACTIVE_STATUSES)
                .exists()
            )
            if active:
                return RegistrationResult(None, False)
            latest = (
                StaffRegistrationRequest.objects.select_for_update()
                .filter(user=user)
                .order_by("-created_at", "-pk")
                .first()
            )
            if user.is_active or not _eligible_for_reapplication(latest):
                return RegistrationResult(None, False)
            supersede_notifications(
                kinds=OTP_NOTIFICATION_KINDS
                | STATUS_NOTIFICATION_KINDS
                | DECISION_NOTIFICATION_KINDS,
                user=user,
                reason="A new application superseded earlier messages.",
            )
            request = _new_request(
                user=user,
                normalized=normalized,
                language=language,
                password_hash=password_hash,
                now=now,
            )
            record(
                None,
                "staff_registration_started",
                user.pk,
                details={
                    "object_type": "staff_registration_reapplication",
                    "object_id": request.pk,
                    "subject_id": user.pk,
                },
            )
            _issue_otp(request, base_url=base_url, now=now)
            return RegistrationResult(request, True)
        try:
            check_availability(normalized)
        except EmailConflict as exc:
            raise RegistrationConflict(str(exc)) from exc
        user = User(
            username=_internal_username(),
            email="",
            is_active=False,
            is_staff=False,
            is_superuser=False,
            role=User.Role.STAFF,
        )
        user.set_unusable_password()
        user.save()
        try:
            set_email(user, normalized, source="staff_registration")
        except EmailConflict as exc:
            raise RegistrationConflict(str(exc)) from exc
        request = _new_request(
            user=user,
            normalized=normalized,
            language=language,
            password_hash=password_hash,
            now=now,
        )
        record(
            None,
            "staff_registration_started",
            user.pk,
            details={
                "object_type": "staff_registration",
                "object_id": request.pk,
                "subject_id": user.pk,
            },
        )
        _issue_otp(request, base_url=base_url, now=now)
        return RegistrationResult(request, True)


def _lock_registration(request):
    row = StaffRegistrationRequest.objects.filter(pk=request.pk).values("user_id").first()
    if row is None:
        return None, None
    user = User.objects.select_for_update().filter(pk=row["user_id"]).first()
    locked = StaffRegistrationRequest.objects.select_for_update().filter(pk=request.pk).first()
    return user, locked


def _resend_locked(request, *, base_url="", now=None):
    now = now or timezone.now()
    if request.status != StaffRegistrationRequest.Status.EMAIL_PENDING:
        return ResendResult("not_pending")
    lifetime = timedelta(days=settings.STAFF_REGISTRATION_EMAIL_EXPIRY_DAYS)
    if request.created_at + lifetime <= now:
        _expire_locked(request, now=now, base_url=base_url)
        return ResendResult("expired")
    if request.otp_sent_at and now < request.otp_sent_at + timedelta(
        seconds=settings.STAFF_REGISTRATION_OTP_RESEND_SECONDS
    ):
        retry_after = (
            request.otp_sent_at
            + timedelta(seconds=settings.STAFF_REGISTRATION_OTP_RESEND_SECONDS)
            - now
        ).total_seconds()
        raise OtpCooldown(retry_after)
    recent = EmailNotification.objects.filter(
        registration_request=request,
        kind="registration_otp",
        created_at__gte=now - timedelta(hours=1),
    ).count()
    if recent >= settings.STAFF_REGISTRATION_OTP_HOURLY_LIMIT:
        raise OtpRateLimited("Too many verification emails were requested.")
    notification = _issue_otp(request, base_url=base_url, now=now)
    return ResendResult("sent", notification)


def resend_registration_otp(request, *, base_url=""):
    with transaction.atomic():
        _user, locked = _lock_registration(request)
        if locked is None:
            return ResendResult("not_pending")
        return _resend_locked(locked, base_url=base_url)


def _dummy_constant_time_work():
    # Mitigates timing-based applicant existence probing by mimicking crypto hashing operations
    dummy_token = secrets.token_urlsafe(32)
    hashlib.sha256(dummy_token.encode("ascii")).hexdigest()
    hmac.new(
        settings.SECRET_KEY.encode(), b"staff_registration_otp:dummy:000000", hashlib.sha256
    ).hexdigest()


def resend_registration_for_email(email, *, base_url=""):
    """Send a fresh verification link to a registration on file (any state), without revealing existence.

    Mitigates user enumeration, account state oracle attacks, and status disclosure (Phase 2.1 Items 2 & 3).
    """
    try:
        normalized = normalize_email(email)
    except ValidationError:
        _dummy_constant_time_work()
        return ResendResult("not_pending")
    if not normalized:
        _dummy_constant_time_work()
        return ResendResult("not_pending")
    with transaction.atomic():
        user_id = (
            EmailClaim.objects.filter(normalized_email=normalized)
            .values_list("user_id", flat=True)
            .first()
        )
        if user_id is None:
            request = (
                StaffRegistrationRequest.objects.select_for_update()
                .filter(applicant_email__iexact=email.strip())
                .order_by("-created_at", "-pk")
                .first()
            )
        else:
            request = (
                StaffRegistrationRequest.objects.select_for_update()
                .filter(user_id=user_id)
                .order_by("-created_at", "-pk")
                .first()
            )
        if request is None:
            _dummy_constant_time_work()
            return ResendResult("not_pending")

        # Mitigates registration harassment via cooldown: 1 email per resend window and 5 per 24 hours
        now = timezone.now()
        cooldown = timedelta(seconds=settings.STAFF_REGISTRATION_OTP_RESEND_SECONDS)
        if request.status == StaffRegistrationRequest.Status.EMAIL_PENDING:
            if request.otp_sent_at and now < request.otp_sent_at + cooldown:
                return ResendResult("sent")
            recent_codes = EmailNotification.objects.filter(
                registration_request=request,
                kind="registration_otp",
                created_at__gte=now - timedelta(hours=1),
            ).count()
            if recent_codes >= settings.STAFF_REGISTRATION_OTP_HOURLY_LIMIT:
                return ResendResult("sent")
        else:
            latest = (
                EmailNotification.objects.filter(registration_request=request)
                .order_by("-created_at", "-pk")
                .first()
            )
            if latest and now < latest.created_at + cooldown:
                return ResendResult("sent")
        if not allow_rate(
            "staff-registration-resend-cooldown",
            str(request.pk),
            1,
            seconds=settings.STAFF_REGISTRATION_OTP_RESEND_SECONDS,
        ):
            return ResendResult("sent")
        if not allow_rate("staff-registration-resend-24hr", str(request.pk), 5, seconds=86400):
            return ResendResult("sent")

        if request.status == StaffRegistrationRequest.Status.EMAIL_PENDING:
            notification = _issue_otp(request, base_url=base_url)
        else:
            # Already verified or decided: the applicant needs a secure way to
            # reopen the status page, not another unusable verification code.
            notification = _issue_status_link(request, base_url=base_url)
        return ResendResult("sent", notification)


def verify_registration_otp(request, code, *, ip=None, now=None):
    """Verify one code exactly once under row locks.

    A successful verification moves the request into the review queue. It never
    authenticates the applicant or activates the account.
    """
    now = now or timezone.now()
    with transaction.atomic():
        user, locked = _lock_registration(request)
        if locked is None or user is None:
            return VerifyResult("not_pending")
        if locked.status == StaffRegistrationRequest.Status.PENDING_REVIEW:
            return VerifyResult("already_verified", locked)
        if locked.status != StaffRegistrationRequest.Status.EMAIL_PENDING:
            return VerifyResult("not_pending", locked)

        # Mitigates registration verification brute-forcing via per-IP and per-registration rate limits
        if ip and not allow_rate("staff-registration-otp-ip", ip, 60, seconds=3600):
            return VerifyResult("throttled", locked)
        if not allow_rate("staff-registration-otp-reg", str(locked.pk), 10, seconds=60):
            return VerifyResult("throttled", locked)

        lifetime = timedelta(days=settings.STAFF_REGISTRATION_EMAIL_EXPIRY_DAYS)
        if locked.created_at + lifetime <= now:
            _expire_locked(locked, now=now)
            return VerifyResult("expired", locked)

        # Mitigates brute-force guessing by invalidating code after maximum 5 attempts
        if locked.otp_attempts >= settings.STAFF_REGISTRATION_OTP_MAX_ATTEMPTS:
            return VerifyResult("locked", locked)

        if not locked.otp_digest or locked.otp_expires_at is None:
            return VerifyResult("invalid", locked)
        if locked.otp_expires_at <= now:
            return VerifyResult("code_expired", locked)

        # Constant-time comparison using hmac.compare_digest in verify_otp
        if not verify_otp(OTP_PURPOSE, locked.pk, locked.otp_digest, (code or "").strip()):
            locked.otp_attempts += 1
            if locked.otp_attempts >= settings.STAFF_REGISTRATION_OTP_MAX_ATTEMPTS:
                # Mitigates brute-force guessing by expiring and invalidating code upon 5th failure
                locked.otp_expires_at = now
                status = "locked"
            else:
                status = "invalid"
            locked.save(
                update_fields=[
                    "otp_attempts",
                    "otp_expires_at",
                    "updated_at",
                ]
            )
            return VerifyResult(status, locked)

        # Mitigates code replay via single-use atomic consumption and digest destruction
        locked.status = StaffRegistrationRequest.Status.PENDING_REVIEW
        locked.email_verified_at = now
        locked.otp_digest = ""
        locked.otp_expires_at = None
        locked.otp_attempts = 0
        locked.save(
            update_fields=[
                "status",
                "email_verified_at",
                "otp_digest",
                "otp_expires_at",
                "otp_attempts",
                "updated_at",
            ]
        )
        supersede_notifications(
            kinds=OTP_NOTIFICATION_KINDS | STATUS_NOTIFICATION_KINDS,
            registration_request=locked,
            reason="The verification code was used.",
        )
        details = {
            "object_type": "staff_registration",
            "object_id": locked.pk,
            "subject_id": locked.user_id,
        }
        record(None, "staff_registration_verified", locked.user_id, details=details)
        record(None, "staff_email_verified", locked.user_id, details=details)
        record(None, "staff_registration_submitted", locked.user_id, details=details)
        return VerifyResult("verified", locked)


def _require_admin(actor):
    if actor is None or not getattr(actor, "is_authenticated", False) or not actor.is_portal_admin:
        raise PermissionDenied("Administrator permission is required.")


def _locked_review_request(request_id):
    row = StaffRegistrationRequest.objects.filter(pk=request_id).values("user_id").first()
    if row is None:
        return None, None
    user = User.objects.select_for_update().filter(pk=row["user_id"]).first()
    request = StaffRegistrationRequest.objects.select_for_update().filter(pk=request_id).first()
    return user, request


def _staff_id_for(user):
    return f"SSDC-{user.pk:06d}"


def approve_registration(request_id, actor, *, note="", base_url=""):
    """Approve one request. Repeated approval of the same request is a no-op."""
    _require_admin(actor)
    now = timezone.now()
    with transaction.atomic():
        user, request = _locked_review_request(request_id)
        if request is None or user is None:
            raise RegistrationStateError("That registration request no longer exists.")
        if request.status == StaffRegistrationRequest.Status.APPROVED:
            return DecisionResult(request, False)
        if request.status != StaffRegistrationRequest.Status.PENDING_REVIEW:
            raise DecisionConflict("This application has already been decided.")
        if request.email_verified_at is None:
            raise DecisionConflict("The applicant has not verified their email address.")
        if user.is_active:
            raise DecisionConflict("The account is not eligible for approval.")
        claim_email = (
            EmailClaim.objects.select_for_update()
            .filter(user_id=user.pk)
            .values_list("normalized_email", flat=True)
            .first()
        )
        if not request.applicant_email or claim_email != request.applicant_email:
            raise DecisionConflict("The applicant email claim changed before approval.")

        assign_staff_id = bool(request.pending_password_hash) and user.username.startswith(
            "applicant-"
        )
        staff_id = _staff_id_for(user) if assign_staff_id else user.username
        if assign_staff_id and (
            User.objects.filter(username=staff_id).exclude(pk=user.pk).exists()
        ):
            raise DecisionConflict("The generated Staff ID is already in use.")

        update_fields = ["role", "is_active", "is_staff", "is_superuser"]
        user.role = User.Role.STAFF
        user.is_active = True
        user.is_staff = False
        user.is_superuser = False
        if request.pending_password_hash:
            user.password = request.pending_password_hash
            update_fields.append("password")
        if assign_staff_id:
            user.username = staff_id
            update_fields.append("username")
        user.save(update_fields=update_fields)

        request.status = StaffRegistrationRequest.Status.APPROVED
        request.reviewed_by = actor
        request.reviewed_at = now
        request.review_note = note or ""
        request.reapplication_allowed = False
        request.otp_digest = ""
        request.otp_expires_at = None
        request.otp_attempts = 0
        request.pending_password_hash = ""
        request.save(
            update_fields=[
                "status",
                "reviewed_by",
                "reviewed_at",
                "review_note",
                "reapplication_allowed",
                "otp_digest",
                "otp_expires_at",
                "otp_attempts",
                "pending_password_hash",
                "updated_at",
            ]
        )
        supersede_notifications(
            kinds=OTP_NOTIFICATION_KINDS | STATUS_NOTIFICATION_KINDS | DECISION_NOTIFICATION_KINDS,
            registration_request=request,
            reason="A newer approval decision superseded this message.",
        )
        base = _notification_base(base_url)
        notification = enqueue_notification(
            kind="registration_approved",
            recipient_email=request.applicant_email,
            user=user,
            registration_request=request,
            dedupe_key=f"staff-registration-approved:{request.pk}",
            language=request.language,
            context={
                "language": request.language,
                "staff_id": user.username,
                "login_url": base + "/accounts/staff/login/",
            },
        )
        schedule_delivery(notification)
        record(
            actor,
            "staff_registration_approved",
            user.pk,
            details={
                "object_type": "staff_registration",
                "object_id": request.pk,
                "subject_id": user.pk,
            },
        )
        return DecisionResult(request, True)


def decline_registration(
    request_id,
    actor,
    *,
    note="",
    allow_reapplication=False,
    base_url="",
):
    """Decline one pending request while keeping the account inactive."""
    _require_admin(actor)
    now = timezone.now()
    with transaction.atomic():
        user, request = _locked_review_request(request_id)
        if request is None or user is None:
            raise RegistrationStateError("That registration request no longer exists.")
        if request.status == StaffRegistrationRequest.Status.DECLINED:
            return DecisionResult(request, False)
        if request.status != StaffRegistrationRequest.Status.PENDING_REVIEW:
            raise DecisionConflict("This application has already been decided.")
        if user.is_active:
            raise DecisionConflict("The account is active and cannot be declined.")
        request.status = StaffRegistrationRequest.Status.DECLINED
        request.reviewed_by = actor
        request.reviewed_at = now
        request.review_note = note or ""
        request.reapplication_allowed = bool(allow_reapplication)
        request.otp_digest = ""
        request.otp_expires_at = None
        request.otp_attempts = 0
        request.pending_password_hash = ""
        request.save(
            update_fields=[
                "status",
                "reviewed_by",
                "reviewed_at",
                "review_note",
                "reapplication_allowed",
                "otp_digest",
                "otp_expires_at",
                "otp_attempts",
                "pending_password_hash",
                "updated_at",
            ]
        )
        supersede_notifications(
            kinds=OTP_NOTIFICATION_KINDS | STATUS_NOTIFICATION_KINDS | DECISION_NOTIFICATION_KINDS,
            registration_request=request,
            reason="A newer decline decision superseded this message.",
        )
        base = _notification_base(base_url)
        notification = enqueue_notification(
            kind="registration_declined",
            recipient_email=request.applicant_email,
            user=user,
            registration_request=request,
            dedupe_key=f"staff-registration-declined:{request.pk}",
            language=request.language,
            context={
                "language": request.language,
                "note": request.review_note,
                "reapplication_allowed": request.reapplication_allowed,
                "register_url": base + "/accounts/register/",
                "reapply_url": base + "/accounts/register/",
            },
        )
        schedule_delivery(notification)
        record(
            actor,
            "staff_registration_declined",
            user.pk,
            details={
                "object_type": "staff_registration",
                "object_id": request.pk,
                "subject_id": user.pk,
            },
        )
        return DecisionResult(request, True)


def allow_reapplication(request_id, actor, *, base_url=""):
    """Authorize a declined applicant to submit a fresh application."""
    _require_admin(actor)
    with transaction.atomic():
        user, request = _locked_review_request(request_id)
        if request is None or user is None:
            raise RegistrationStateError("That registration request no longer exists.")
        if request.status != StaffRegistrationRequest.Status.DECLINED:
            raise DecisionConflict("Only declined applications can be reopened.")
        if request.reapplication_allowed:
            return DecisionResult(request, False)
        request.reapplication_allowed = True
        request.save(update_fields=["reapplication_allowed", "updated_at"])
        base = _notification_base(base_url)
        notification = enqueue_notification(
            kind="registration_reapplication_allowed",
            recipient_email=request.applicant_email,
            user=user,
            registration_request=request,
            dedupe_key=f"staff-registration-reapplication:{request.pk}",
            language=request.language,
            context={
                "language": request.language,
                "register_url": base + "/accounts/register/",
                "reapply_url": base + "/accounts/register/",
            },
        )
        schedule_delivery(notification)
        record(
            actor,
            "staff_registration_reapplication_allowed",
            user.pk,
            details={
                "object_type": "staff_registration",
                "object_id": request.pk,
                "subject_id": user.pk,
            },
        )
        return DecisionResult(request, True)


def expire_registration(request_id, *, now=None, base_url=""):
    now = now or timezone.now()
    with transaction.atomic():
        user, request = _locked_review_request(request_id)
        if request is None or user is None or request.status not in ACTIVE_STATUSES:
            return False
        return _expire_locked(request, now=now, base_url=base_url)


def expire_due_registrations(*, now=None, limit=100, base_url="", dry_run=False):
    """Expire applications whose email or review window has elapsed."""
    now = now or timezone.now()
    email_cutoff = now - timedelta(days=settings.STAFF_REGISTRATION_EMAIL_EXPIRY_DAYS)
    review_cutoff = now - timedelta(days=settings.STAFF_REGISTRATION_REVIEW_EXPIRY_DAYS)
    candidates = list(
        StaffRegistrationRequest.objects.filter(
            Q(
                status=StaffRegistrationRequest.Status.EMAIL_PENDING,
                created_at__lte=email_cutoff,
            )
            | Q(
                status=StaffRegistrationRequest.Status.PENDING_REVIEW,
                email_verified_at__lte=review_cutoff,
            )
        )
        .order_by("created_at", "pk")
        .values_list("pk", flat=True)[:limit]
    )
    if dry_run:
        return len(candidates)
    expired = 0
    for request_id in candidates:
        if expire_registration(request_id, now=now, base_url=base_url):
            expired += 1
    return expired
