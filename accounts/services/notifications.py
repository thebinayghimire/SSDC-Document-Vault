"""Durable, retryable transactional email delivery."""

import os
import socket
from datetime import timedelta

from django.conf import settings
from django.core.mail import EmailMultiAlternatives
from django.db import transaction
from django.db.models import Q
from django.template.loader import render_to_string
from django.utils import timezone, translation
from django.utils.translation import gettext as _

from accounts.models import EmailNotification
from accounts.services.otp import decrypt_otp
from audit.services import record

KIND_TEMPLATES = {
    "registration_otp": (
        "email/registration_otp",
        "Verify your email - SSDC Document Vault",
    ),
    "registration_approved": (
        "email/registration_approved",
        "Your SSDC Document Vault access has been approved",
    ),
    "registration_declined": (
        "email/registration_declined",
        "Your SSDC Document Vault registration was declined",
    ),
    "registration_reapplication_allowed": (
        "email/registration_reapplication_allowed",
        "You may reapply for SSDC Document Vault access",
    ),
    "registration_expired": (
        "email/registration_expired",
        "Your SSDC Document Vault registration has expired",
    ),
    "email_change_otp": (
        "email/email_change_otp",
        "Confirm your new email - SSDC Document Vault",
    ),
    "email_change_security_notice": (
        "email/email_change_security_notice",
        "Email change requested for your SSDC Document Vault account",
    ),
    "email_change_completed": (
        "email/email_change_completed",
        "Your SSDC Document Vault email address changed",
    ),
    "email_change_expired": (
        "email/email_change_expired",
        "Your SSDC Document Vault email change expired",
    ),
}

# Notifications that describe a superseded decision should never be delivered
# after a newer decision has been recorded.
DECISION_KINDS = frozenset(
    {
        "registration_approved",
        "registration_declined",
        "registration_reapplication_allowed",
        "registration_expired",
        "email_change_otp",
        "email_change_security_notice",
        "email_change_expired",
    }
)

WORKER_ID = f"{socket.gethostname()[:40]}:{os.getpid()}"[:64]


def notification_subject(kind, language="en"):
    template_name, message = KIND_TEMPLATES[kind]
    with translation.override(language or settings.LANGUAGE_CODE):
        return template_name, str(_(message))


def enqueue_notification(
    *,
    kind,
    recipient_email,
    context,
    user=None,
    user_id=None,
    registration_request=None,
    email_change_request=None,
    dedupe_key=None,
    language="en",
):
    """Create one durable notification, deduplicating by an optional stable key.

    Callers must invoke this inside the same transaction as the state change it
    describes so an outbox row cannot survive a rolled-back decision.
    """
    template_name, subject = notification_subject(kind, language)
    values = {
        "kind": kind,
        "registration_request": registration_request,
        "email_change_request": email_change_request,
        "recipient_email": recipient_email,
        "subject": subject,
        "template_name": template_name,
        "context": context,
        "max_attempts": settings.EMAIL_NOTIFICATION_MAX_ATTEMPTS,
    }
    if user_id is not None:
        values["user_id"] = user_id
    else:
        values["user"] = user
    if dedupe_key:
        notification, _created = EmailNotification.objects.get_or_create(
            dedupe_key=dedupe_key,
            defaults=values,
        )
        return notification
    return EmailNotification.objects.create(dedupe_key=None, **values)


def schedule_delivery(notification):
    """Attempt best-effort delivery only after the surrounding transaction commits."""
    notification_id = notification.pk
    transaction.on_commit(lambda: deliver_notification(notification_id))


def supersede_notifications(
    *,
    kinds,
    user=None,
    registration_request=None,
    email_change_request=None,
    superseded_by=None,
    reason="A newer decision superseded this message.",
):
    """Mark undelivered messages from an older decision as superseded.

    A sender that is already in flight will notice the status change when it
    tries to record success, so a stale message cannot be reported as current.
    """
    now = timezone.now()
    rows = EmailNotification.objects.filter(
        kind__in=list(kinds),
        status__in=[
            EmailNotification.Status.PENDING,
            EmailNotification.Status.SENDING,
            EmailNotification.Status.FAILED,
        ],
    )
    if user is not None:
        rows = rows.filter(user=user)
    if registration_request is not None:
        rows = rows.filter(registration_request=registration_request)
    if email_change_request is not None:
        rows = rows.filter(email_change_request=email_change_request)
    count = rows.update(
        status=EmailNotification.Status.SUPERSEDED,
        superseded_by=superseded_by,
        locked_at=None,
        locked_by="",
        last_error=reason,
        next_attempt_at=now,
        updated_at=now,
    )
    return count


def _safe_error(exc):
    message = " ".join(str(exc).split())
    return f"{type(exc).__name__}: {message[:300]}"


def _render(notification):
    context = dict(notification.context or {})
    ciphertext = context.pop("otp_ciphertext", None)
    if ciphertext is not None:
        # A failed decrypt intentionally raises and becomes a retryable failure.
        context["otp"] = decrypt_otp(ciphertext)
    language = context.get("language") or settings.LANGUAGE_CODE
    with translation.override(language):
        text_body = render_to_string(f"{notification.template_name}.txt", context)
        html_body = render_to_string(f"{notification.template_name}.html", context)
    return text_body, html_body


def _audit_delivery(notification_id, kind):
    if kind not in {"registration_approved", "registration_declined"}:
        return
    notification = EmailNotification.objects.filter(pk=notification_id).first()
    if notification is None:
        return
    record(
        None,
        (
            "staff_approval_email_sent"
            if kind == "registration_approved"
            else "staff_decline_email_sent"
        ),
        target=notification.registration_request_id or notification.pk,
        details={
            "object_type": "email_notification",
            "object_id": notification.pk,
            "subject_id": notification.user_id,
        },
    )


def _audit_failure(notification_id, kind):
    if kind not in {"registration_approved", "registration_declined"}:
        return
    notification = EmailNotification.objects.filter(pk=notification_id).first()
    if notification is None:
        return
    record(
        None,
        "staff_approval_email_failed",
        target=notification.registration_request_id or notification.pk,
        outcome="failed",
        details={
            "object_type": "email_notification",
            "object_id": notification.pk,
            "subject_id": notification.user_id,
        },
    )


def _mark_dead_letter(notification, *, now, error):
    notification.status = EmailNotification.Status.DEAD_LETTER
    notification.last_error = error
    notification.locked_at = None
    notification.locked_by = ""
    notification.next_attempt_at = now
    notification.save(
        update_fields=[
            "attempts",
            "status",
            "last_error",
            "locked_at",
            "locked_by",
            "next_attempt_at",
            "updated_at",
        ]
    )


def deliver_notification(notification_id, *, now=None):
    """Attempt one delivery. Safe to call repeatedly; SMTP itself is not exactly-once."""
    if not settings.EMAIL_DELIVERY_ENABLED:
        return "disabled"
    now = now or timezone.now()
    with transaction.atomic():
        notification = (
            EmailNotification.objects.select_for_update().filter(pk=notification_id).first()
        )
        if notification is None:
            return "missing"
        if notification.status == EmailNotification.Status.SENT:
            return "sent"
        if notification.status in {
            EmailNotification.Status.SUPERSEDED,
            EmailNotification.Status.DEAD_LETTER,
        }:
            return notification.status
        if notification.attempts >= notification.max_attempts:
            # Defensive: a limiter must never allow an out-of-range increment.
            _mark_dead_letter(
                notification,
                now=now,
                error=notification.last_error or "Delivery attempts exhausted.",
            )
            return "dead_letter"
        if (
            notification.status
            in {
                EmailNotification.Status.PENDING,
                EmailNotification.Status.FAILED,
            }
            and notification.next_attempt_at
            and notification.next_attempt_at > now
        ):
            return "deferred"
        if (
            notification.status == EmailNotification.Status.SENDING
            and notification.locked_at
            and notification.locked_at
            > now - timedelta(seconds=settings.EMAIL_NOTIFICATION_LEASE_SECONDS)
        ):
            return "locked"
        notification.status = EmailNotification.Status.SENDING
        notification.locked_at = now
        notification.locked_by = WORKER_ID
        notification.save(update_fields=["status", "locked_at", "locked_by", "updated_at"])
        notification_kind = notification.kind
        notification_pk = notification.pk

    try:
        text_body, html_body = _render(notification)
        message = EmailMultiAlternatives(
            notification.subject,
            text_body,
            settings.DEFAULT_FROM_EMAIL,
            [notification.recipient_email],
        )
        message.attach_alternative(html_body, "text/html")
        sent = message.send()
        if sent != 1:
            raise RuntimeError("Email backend reported no delivery.")
    except Exception as exc:  # noqa: BLE001 - delivery failures must remain retryable
        error = _safe_error(exc)
        with transaction.atomic():
            notification = (
                EmailNotification.objects.select_for_update()
                .filter(pk=notification_pk)
                .first()
            )
            if notification is None or notification.status != EmailNotification.Status.SENDING:
                return "superseded"
            notification.attempts += 1
            notification.locked_at = None
            notification.locked_by = ""
            if notification.attempts >= notification.max_attempts:
                _mark_dead_letter(notification, now=now, error=error)
                transaction.on_commit(
                    lambda pk=notification_pk, kind=notification_kind: _audit_failure(
                        pk, kind
                    )
                )
            else:
                delay = min(
                    settings.EMAIL_NOTIFICATION_BACKOFF_BASE_SECONDS
                    * (2 ** (notification.attempts - 1)),
                    settings.EMAIL_NOTIFICATION_BACKOFF_MAX_SECONDS,
                )
                notification.status = EmailNotification.Status.FAILED
                notification.last_error = error
                notification.next_attempt_at = now + timedelta(seconds=delay)
                notification.save(
                    update_fields=[
                        "attempts",
                        "last_error",
                        "locked_at",
                        "locked_by",
                        "status",
                        "next_attempt_at",
                        "updated_at",
                    ]
                )
        return "failed"

    with transaction.atomic():
        notification = (
            EmailNotification.objects.select_for_update().filter(pk=notification_pk).first()
        )
        if notification is None or notification.status != EmailNotification.Status.SENDING:
            return "superseded"
        notification.status = EmailNotification.Status.SENT
        notification.sent_at = now
        notification.locked_at = None
        notification.locked_by = ""
        notification.last_error = ""
        notification.save(
            update_fields=[
                "status",
                "sent_at",
                "locked_at",
                "locked_by",
                "last_error",
                "updated_at",
            ]
        )
        transaction.on_commit(
            lambda pk=notification_pk, kind=notification_kind: _audit_delivery(pk, kind)
        )
    return "sent"


def recover_stale_leases(*, now=None):
    now = now or timezone.now()
    cutoff = now - timedelta(seconds=settings.EMAIL_NOTIFICATION_LEASE_SECONDS)
    return (
        EmailNotification.objects.filter(status=EmailNotification.Status.SENDING)
        .filter(Q(locked_at__lt=cutoff) | Q(locked_at__isnull=True))
        .update(
            status=EmailNotification.Status.PENDING,
            locked_at=None,
            locked_by="",
            next_attempt_at=now,
            last_error="Recovered stale delivery lease.",
            updated_at=now,
        )
    )


def due_notification_ids(*, limit=50, now=None):
    now = now or timezone.now()
    return list(
        EmailNotification.objects.filter(
            status__in=[
                EmailNotification.Status.PENDING,
                EmailNotification.Status.FAILED,
            ],
            next_attempt_at__lte=now,
            superseded_by__isnull=True,
        )
        .order_by("created_at", "pk")
        .values_list("pk", flat=True)[:limit]
    )


def process_notifications(*, limit=50, dry_run=False, now=None):
    now = now or timezone.now()
    recovered = 0 if dry_run else recover_stale_leases(now=now)
    ids = due_notification_ids(limit=limit, now=now)
    if dry_run:
        return {"due": len(ids), "recovered": 0, "sent": 0, "failed": 0}
    outcomes = [deliver_notification(pk, now=now) for pk in ids]
    return {
        "due": len(ids),
        "recovered": recovered,
        "sent": outcomes.count("sent"),
        "failed": outcomes.count("failed"),
    }
