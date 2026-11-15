"""Operational commands for notification retries and registration expiry."""

import io
from datetime import timedelta

import pytest
from django.core.management import call_command
from django.core.management.base import CommandError
from django.utils import timezone

from accounts.models import EmailNotification, StaffRegistrationRequest
from accounts.services.otp import decrypt_otp
from accounts.services.registration import (
    approve_registration,
    register_applicant,
    verify_registration_otp,
)
from audit.models import Event

PASSWORD = "Strong-Applicant-Password-42"


@pytest.fixture
def registration_enabled(settings):
    settings.STAFF_SELF_REGISTRATION_ENABLED = True
    settings.EMAIL_DELIVERY_ENABLED = False
    settings.PUBLIC_BASE_URL = "http://testserver"
    return settings


def _pending_request(email="operations@example.test"):
    registration = register_applicant(email=email, password=PASSWORD).request
    notification = (
        EmailNotification.objects.filter(
            registration_request=registration,
            kind="registration_otp",
            status=EmailNotification.Status.PENDING,
        )
        .order_by("-created_at", "-pk")
        .first()
    )
    assert notification is not None
    code = decrypt_otp(notification.context["otp_ciphertext"])
    assert verify_registration_otp(registration, code).status == "verified"
    registration.refresh_from_db()
    return registration


@pytest.mark.django_db
def test_process_notifications_command_delivers_and_reports(registration_enabled, users, settings):
    registration = _pending_request("deliver.command@example.test")
    approve_registration(
        registration.pk,
        users["admin"],
        base_url="http://testserver",
    )
    settings.EMAIL_DELIVERY_ENABLED = True
    notification = EmailNotification.objects.get(
        registration_request=registration,
        kind="registration_approved",
    )
    assert notification.status == EmailNotification.Status.PENDING

    stdout = io.StringIO()
    call_command("process_notifications", stdout=stdout)

    assert "due=1 recovered=0 sent=1 failed=0" in stdout.getvalue()
    notification.refresh_from_db()
    assert notification.status == EmailNotification.Status.SENT
    assert notification.sent_at is not None


@pytest.mark.django_db
def test_process_notifications_dry_run_keeps_notifications_pending(
    registration_enabled, users, settings
):
    registration = _pending_request("dryrun.command@example.test")
    approve_registration(registration.pk, users["admin"], base_url="http://testserver")
    settings.EMAIL_DELIVERY_ENABLED = True
    notification = EmailNotification.objects.get(
        registration_request=registration,
        kind="registration_approved",
    )

    stdout = io.StringIO()
    call_command("process_notifications", dry_run=True, stdout=stdout)

    assert "due=1 recovered=0 sent=0 failed=0" in stdout.getvalue()
    notification.refresh_from_db()
    assert notification.status == EmailNotification.Status.PENDING


@pytest.mark.django_db
def test_expire_registrations_command_closes_due_requests(registration_enabled, settings):
    registration = _pending_request("expire.command@example.test")
    StaffRegistrationRequest.objects.filter(pk=registration.pk).update(
        email_verified_at=timezone.now()
        - timedelta(days=settings.STAFF_REGISTRATION_REVIEW_EXPIRY_DAYS + 1)
    )

    stdout = io.StringIO()
    call_command(
        "expire_registrations",
        base_url="http://testserver",
        stdout=stdout,
    )

    assert "expired=1" in stdout.getvalue()
    registration.refresh_from_db()
    assert registration.status == StaffRegistrationRequest.Status.EXPIRED
    assert EmailNotification.objects.filter(
        registration_request=registration,
        kind="registration_expired",
    ).exists()
    assert Event.objects.filter(kind="staff_registration_expired").exists()


@pytest.mark.django_db
def test_expire_registrations_dry_run_does_not_change_state(registration_enabled, settings):
    registration = _pending_request("expire.dryrun@example.test")
    StaffRegistrationRequest.objects.filter(pk=registration.pk).update(
        email_verified_at=timezone.now()
        - timedelta(days=settings.STAFF_REGISTRATION_REVIEW_EXPIRY_DAYS + 1)
    )

    stdout = io.StringIO()
    call_command("expire_registrations", dry_run=True, stdout=stdout)

    assert "due=1" in stdout.getvalue()
    registration.refresh_from_db()
    assert registration.status == StaffRegistrationRequest.Status.PENDING_REVIEW


@pytest.mark.django_db
def test_expire_registrations_requires_a_base_url(registration_enabled, settings):
    settings.PUBLIC_BASE_URL = ""
    with pytest.raises(CommandError, match="PUBLIC_BASE_URL"):
        call_command("expire_registrations")
