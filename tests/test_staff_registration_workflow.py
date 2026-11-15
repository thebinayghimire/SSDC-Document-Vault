"""Service-level tests for the staff registration lifecycle."""

import json
import threading
from concurrent.futures import ThreadPoolExecutor

import pytest
from django.contrib.auth.hashers import check_password
from django.core.exceptions import PermissionDenied
from django.db import connections
from django.utils import timezone

from accounts.models import EmailClaim, EmailNotification, StaffRegistrationRequest, User
from accounts.services.notifications import deliver_notification
from accounts.services.otp import OtpCooldown, OtpRateLimited, decrypt_otp
from accounts.services.registration import (
    DecisionConflict,
    RegistrationDisabled,
    RegistrationInvalid,
    allow_reapplication,
    approve_registration,
    decline_registration,
    expire_due_registrations,
    register_applicant,
    resend_registration_for_email,
    resend_registration_otp,
    verify_registration_otp,
)
from audit.models import Event

PASSWORD = "Strong-Applicant-Password-42"


@pytest.fixture
def registration_enabled(settings):
    settings.STAFF_SELF_REGISTRATION_ENABLED = True
    settings.EMAIL_DELIVERY_ENABLED = False
    return settings


def latest_otp(request):
    notification = (
        EmailNotification.objects.filter(
            registration_request=request,
            kind="registration_otp",
            status=EmailNotification.Status.PENDING,
        )
        .order_by("-created_at", "-pk")
        .first()
    )
    assert notification is not None
    return decrypt_otp(notification.context["otp_ciphertext"])


def register(email="New.Staff@Example.TEST", password=PASSWORD):
    return register_applicant(email=email, password=password).request


@pytest.mark.django_db
def test_registration_creates_inactive_unauthenticated_applicant(registration_enabled):
    result = register_applicant(
        email="New.Staff@Example.TEST",
        password=PASSWORD,
        language="ne",
    )
    assert result.created is True
    request = result.request
    user = User.objects.get(pk=request.user_id)
    assert user.is_active is False
    assert user.is_staff is False
    assert user.is_superuser is False
    assert user.role == User.Role.STAFF
    assert user.has_usable_password() is False
    assert user.email == "new.staff@example.test"
    assert EmailClaim.objects.get(user=user).normalized_email == user.email
    assert request.status == StaffRegistrationRequest.Status.EMAIL_PENDING
    assert request.applicant_email == user.email
    assert request.language == "ne"
    assert check_password(PASSWORD, request.pending_password_hash)
    assert request.otp_sent_at is not None
    assert request.otp_expires_at > request.otp_sent_at
    assert Event.objects.filter(kind="staff_registration_started").exists()
    assert Event.objects.filter(kind="staff_registration_otp_sent").exists()


@pytest.mark.django_db
def test_registration_otp_is_encrypted_in_the_outbox(registration_enabled):
    request = register()
    notification = EmailNotification.objects.get(
        registration_request=request, kind="registration_otp"
    )
    assert notification.status == EmailNotification.Status.PENDING
    assert notification.recipient_email == request.applicant_email
    assert "otp_ciphertext" in notification.context
    otp = decrypt_otp(notification.context["otp_ciphertext"])
    assert len(otp) == 6 and otp.isdigit()
    assert otp not in json.dumps(notification.context)
    assert otp not in json.dumps(list(Event.objects.values("details", "target", "kind")))


@pytest.mark.django_db
def test_weak_password_and_invalid_email_are_rejected(registration_enabled):
    with pytest.raises(RegistrationInvalid):
        register_applicant(email="not-an-email", password=PASSWORD)
    with pytest.raises(RegistrationInvalid):
        register_applicant(email="weak@example.test", password="short")
    assert not User.objects.filter(email__contains="example.test").exists()


@pytest.mark.django_db
def test_registration_refuses_to_create_a_second_account_for_the_same_address(
    registration_enabled, users
):
    register()
    duplicate = register_applicant(email="NEW.STAFF@example.test", password=PASSWORD)
    assert duplicate.request is None
    assert User.objects.filter(email="new.staff@example.test").count() == 1


@pytest.mark.django_db
def test_registration_is_disabled_by_default(settings):
    settings.STAFF_SELF_REGISTRATION_ENABLED = False
    with pytest.raises(RegistrationDisabled):
        register_applicant(email="closed@example.test", password=PASSWORD)


@pytest.mark.django_db
def test_verification_moves_to_review_without_authentication(registration_enabled):
    request = register()
    otp = latest_otp(request)
    result = verify_registration_otp(request, otp)
    assert result.status == "verified"
    request.refresh_from_db()
    assert request.status == StaffRegistrationRequest.Status.PENDING_REVIEW
    assert request.email_verified_at is not None
    assert request.otp_digest == ""
    assert Event.objects.filter(kind="staff_email_verified").exists()
    assert Event.objects.filter(kind="staff_registration_submitted").exists()
    assert not Event.objects.filter(kind="login").exists()


@pytest.mark.django_db
def test_wrong_otp_increments_attempts_and_locks_after_the_limit(registration_enabled):
    request = register()
    for attempt in range(1, registration_enabled.STAFF_REGISTRATION_OTP_MAX_ATTEMPTS + 1):
        result = verify_registration_otp(request, "000000")
        request.refresh_from_db()
        assert result.status in {"invalid", "locked"}
        assert request.otp_attempts == attempt
    assert verify_registration_otp(request, "000000").status == "locked"
    assert verify_registration_otp(request, latest_otp(request)).status == "locked"
    request.refresh_from_db()
    assert request.status == StaffRegistrationRequest.Status.EMAIL_PENDING


@pytest.mark.django_db
def test_otp_replay_and_replaced_codes_are_rejected(registration_enabled):
    request = register()
    first = latest_otp(request)
    assert verify_registration_otp(request, first).status == "verified"
    assert verify_registration_otp(request, first).status == "already_verified"
    request.refresh_from_db()
    assert request.status == StaffRegistrationRequest.Status.PENDING_REVIEW


@pytest.mark.django_db
def test_resend_enforces_cooldown_and_replaces_the_previous_code(registration_enabled):
    request = register()
    first = latest_otp(request)
    with pytest.raises(OtpCooldown):
        resend_registration_otp(request)
    old_sent_at = request.otp_sent_at
    StaffRegistrationRequest.objects.filter(pk=request.pk).update(
        otp_sent_at=old_sent_at
        - timezone.timedelta(seconds=registration_enabled.STAFF_REGISTRATION_OTP_RESEND_SECONDS)
    )
    request.refresh_from_db()
    result = resend_registration_otp(request)
    assert result.status == "sent"
    request.refresh_from_db()
    second = latest_otp(request)
    assert second != first
    assert verify_registration_otp(request, first).status == "invalid"
    assert verify_registration_otp(request, second).status == "verified"


@pytest.mark.django_db
def test_hourly_send_limit_is_enforced(registration_enabled):
    request = register()
    for _ in range(registration_enabled.STAFF_REGISTRATION_OTP_HOURLY_LIMIT - 1):
        StaffRegistrationRequest.objects.filter(pk=request.pk).update(
            otp_sent_at=timezone.now() - timezone.timedelta(hours=2)
        )
        request.refresh_from_db()
        assert resend_registration_otp(request).status == "sent"
    StaffRegistrationRequest.objects.filter(pk=request.pk).update(
        otp_sent_at=timezone.now() - timezone.timedelta(hours=2)
    )
    request.refresh_from_db()
    with pytest.raises(OtpRateLimited):
        resend_registration_otp(request)


@pytest.mark.django_db
def test_expired_otp_can_be_replaced_until_the_application_lifetime(registration_enabled):
    request = register()
    StaffRegistrationRequest.objects.filter(pk=request.pk).update(
        otp_expires_at=timezone.now() - timezone.timedelta(seconds=1)
    )
    request.refresh_from_db()
    assert verify_registration_otp(request, latest_otp(request)).status == "code_expired"
    StaffRegistrationRequest.objects.filter(pk=request.pk).update(
        otp_sent_at=timezone.now() - timezone.timedelta(hours=1)
    )
    request.refresh_from_db()
    assert resend_registration_otp(request).status == "sent"
    assert verify_registration_otp(request, latest_otp(request)).status == "verified"


@pytest.mark.django_db
def test_expired_application_is_closed_and_notifies_the_applicant(registration_enabled):
    request = register()
    StaffRegistrationRequest.objects.filter(pk=request.pk).update(
        created_at=timezone.now()
        - timezone.timedelta(days=registration_enabled.STAFF_REGISTRATION_EMAIL_EXPIRY_DAYS + 1)
    )
    request.refresh_from_db()
    result = resend_registration_otp(request)
    assert result.status == "expired"
    request.refresh_from_db()
    assert request.status == StaffRegistrationRequest.Status.EXPIRED
    assert request.pending_password_hash == ""
    assert EmailNotification.objects.filter(
        registration_request=request, kind="registration_expired"
    ).exists()
    assert Event.objects.filter(kind="staff_registration_expired").exists()


@pytest.mark.django_db
def test_expiry_command_closes_due_email_and_review_windows(registration_enabled):
    pending = register(email="pending@example.test")
    reviewing = register(email="reviewing@example.test")
    StaffRegistrationRequest.objects.filter(pk=reviewing.pk).update(
        status=StaffRegistrationRequest.Status.PENDING_REVIEW,
        email_verified_at=timezone.now()
        - timezone.timedelta(days=registration_enabled.STAFF_REGISTRATION_REVIEW_EXPIRY_DAYS + 1),
    )
    StaffRegistrationRequest.objects.filter(pk=pending.pk).update(
        created_at=timezone.now()
        - timezone.timedelta(days=registration_enabled.STAFF_REGISTRATION_EMAIL_EXPIRY_DAYS + 1)
    )
    assert expire_due_registrations() == 2
    assert set(
        StaffRegistrationRequest.objects.filter(pk__in=[pending.pk, reviewing.pk]).values_list(
            "status", flat=True
        )
    ) == {StaffRegistrationRequest.Status.EXPIRED}


@pytest.mark.django_db
def test_approval_activates_only_the_staff_role_and_stages_the_password(
    registration_enabled, users
):
    request = register()
    verify_registration_otp(request, latest_otp(request))
    request.refresh_from_db()
    user = request.user
    result = approve_registration(request.pk, users["admin"])
    assert result.changed is True
    request.refresh_from_db()
    user.refresh_from_db()
    assert request.status == StaffRegistrationRequest.Status.APPROVED
    assert request.reviewed_by == users["admin"]
    assert request.reviewed_at is not None
    assert request.pending_password_hash == ""
    assert user.is_active is True
    assert user.is_staff is False
    assert user.is_superuser is False
    assert user.role == User.Role.STAFF
    assert user.username == f"SSDC-{user.pk:06d}"
    assert user.has_usable_password() is True
    assert check_password(PASSWORD, user.password)
    assert EmailNotification.objects.filter(
        registration_request=request, kind="registration_approved"
    ).exists()
    assert Event.objects.filter(kind="staff_registration_approved").exists()


@pytest.mark.django_db
def test_approval_is_idempotent_and_does_not_duplicate_notifications(registration_enabled, users):
    request = register()
    verify_registration_otp(request, latest_otp(request))
    first = approve_registration(request.pk, users["admin"])
    second = approve_registration(request.pk, users["admin"])
    assert first.changed is True
    assert second.changed is False
    assert (
        EmailNotification.objects.filter(
            registration_request=request, kind="registration_approved"
        ).count()
        == 1
    )


@pytest.mark.django_db
def test_decline_keeps_the_account_inactive_and_can_allow_reapplication(
    registration_enabled, users
):
    request = register()
    verify_registration_otp(request, latest_otp(request))
    request.refresh_from_db()
    result = decline_registration(
        request.pk,
        users["admin"],
        note="Synthetic policy reason",
        allow_reapplication=True,
    )
    assert result.changed is True
    request.refresh_from_db()
    request.user.refresh_from_db()
    assert request.status == StaffRegistrationRequest.Status.DECLINED
    assert request.reapplication_allowed is True
    assert request.pending_password_hash == ""
    assert request.user.is_active is False
    assert EmailNotification.objects.filter(
        registration_request=request, kind="registration_declined"
    ).exists()
    assert Event.objects.filter(kind="staff_registration_declined").exists()
    assert decline_registration(request.pk, users["admin"]).changed is False


@pytest.mark.django_db
def test_stale_approval_cannot_overwrite_a_decline(registration_enabled, users):
    request = register()
    verify_registration_otp(request, latest_otp(request))
    decline_registration(request.pk, users["admin"])
    with pytest.raises(DecisionConflict):
        approve_registration(request.pk, users["admin"])
    request.refresh_from_db()
    assert request.status == StaffRegistrationRequest.Status.DECLINED


@pytest.mark.django_db
def test_stale_decline_cannot_overwrite_an_approval(registration_enabled, users):
    request = register()
    verify_registration_otp(request, latest_otp(request))
    approve_registration(request.pk, users["admin"])
    with pytest.raises(DecisionConflict):
        decline_registration(request.pk, users["admin"])
    request.refresh_from_db()
    assert request.status == StaffRegistrationRequest.Status.APPROVED


@pytest.mark.django_db
def test_only_administrators_can_decide_applications(registration_enabled, users):
    request = register()
    verify_registration_otp(request, latest_otp(request))
    with pytest.raises(PermissionDenied):
        approve_registration(request.pk, users["alice"])
    with pytest.raises(PermissionDenied):
        decline_registration(request.pk, users["manager"])


@pytest.mark.django_db
def test_authorized_reapplication_reuses_the_account_and_binds_the_new_code(
    registration_enabled, users
):
    first = register()
    verify_registration_otp(first, latest_otp(first))
    decline_registration(first.pk, users["admin"], allow_reapplication=True)
    first.refresh_from_db()
    user = first.user
    result = register_applicant(email="new.staff@example.test", password="Other-Strong-Password-84")
    assert result.created is True
    second = result.request
    assert second.user_id == user.pk
    assert second.status == StaffRegistrationRequest.Status.EMAIL_PENDING
    first.refresh_from_db()
    assert first.pending_password_hash == ""
    assert check_password("Other-Strong-Password-84", second.pending_password_hash)
    assert verify_registration_otp(second, latest_otp(second)).status == "verified"
    approval = approve_registration(second.pk, users["admin"])
    assert approval.changed is True
    user.refresh_from_db()
    assert check_password("Other-Strong-Password-84", user.password)


@pytest.mark.django_db
def test_reapplication_is_denied_without_explicit_admin_authorization(registration_enabled, users):
    request = register()
    verify_registration_otp(request, latest_otp(request))
    decline_registration(request.pk, users["admin"], allow_reapplication=False)
    result = register_applicant(email="new.staff@example.test", password=PASSWORD)
    assert result.request is None
    assert StaffRegistrationRequest.objects.filter(user=request.user).count() == 1


@pytest.mark.django_db
def test_allow_reapplication_only_applies_to_declined_requests(registration_enabled, users):
    request = register()
    verify_registration_otp(request, latest_otp(request))
    with pytest.raises(DecisionConflict):
        allow_reapplication(request.pk, users["admin"])
    decline_registration(request.pk, users["admin"])
    assert allow_reapplication(request.pk, users["admin"]).changed is True
    assert allow_reapplication(request.pk, users["admin"]).changed is False
    request.refresh_from_db()
    assert request.reapplication_allowed is True


@pytest.mark.django_db
def test_approved_account_can_use_the_staged_password_once(registration_enabled, users):
    request = register()
    verify_registration_otp(request, latest_otp(request))
    approve_registration(request.pk, users["admin"])
    user = User.objects.get(pk=request.user_id)
    assert user.check_password(PASSWORD) is True
    assert user.check_password("wrong-password") is False


@pytest.mark.django_db
def test_resend_by_email_is_identical_for_missing_and_pending_addresses(registration_enabled):
    request = register(email="pending@example.test")
    StaffRegistrationRequest.objects.filter(pk=request.pk).update(
        otp_sent_at=timezone.now() - timezone.timedelta(hours=2)
    )
    assert resend_registration_for_email("missing@example.test").status == "not_pending"
    result = resend_registration_for_email("PENDING@example.test")
    assert result.status == "sent"
    request.refresh_from_db()
    assert request.status == StaffRegistrationRequest.Status.EMAIL_PENDING


@pytest.mark.django_db
def test_delivery_failure_does_not_roll_back_approval(registration_enabled, users, settings):
    request = register()
    verify_registration_otp(request, latest_otp(request))
    settings.EMAIL_DELIVERY_ENABLED = True

    def explode(*args, **kwargs):
        raise RuntimeError("synthetic SMTP outage")

    from unittest.mock import patch

    with patch("accounts.services.notifications.EmailMultiAlternatives", explode):
        approve_registration(request.pk, users["admin"])
        notification = EmailNotification.objects.get(
            registration_request=request, kind="registration_approved"
        )
        assert deliver_notification(notification.pk) == "failed"
    request.refresh_from_db()
    assert request.status == StaffRegistrationRequest.Status.APPROVED
    assert request.user.is_active is True


@pytest.mark.django_db(transaction=True)
def test_concurrent_registrations_for_the_same_address_create_one_account(
    registration_enabled, users
):
    barrier = threading.Barrier(2)

    def attempt(index):
        try:
            barrier.wait(timeout=20)
            result = register_applicant(
                email="race.registration@example.test",
                password=f"Concurrent-Password-{index}-42",
            )
            return "created" if result.created else "ignored"
        finally:
            connections.close_all()

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = sorted(
            future.result(timeout=30)
            for future in [executor.submit(attempt, 1), executor.submit(attempt, 2)]
        )
    assert results == ["created", "ignored"]
    assert User.objects.filter(email="race.registration@example.test").count() == 1
    assert (
        StaffRegistrationRequest.objects.filter(
            applicant_email="race.registration@example.test"
        ).count()
        == 1
    )


@pytest.mark.django_db(transaction=True)
def test_concurrent_otp_verification_accepts_the_code_exactly_once(registration_enabled):
    request = register()
    otp = latest_otp(request)
    barrier = threading.Barrier(2)

    def verify():
        try:
            barrier.wait(timeout=20)
            return verify_registration_otp(
                StaffRegistrationRequest.objects.get(pk=request.pk), otp
            ).status
        finally:
            connections.close_all()

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = sorted(
            future.result(timeout=30)
            for future in [executor.submit(verify), executor.submit(verify)]
        )
    assert results.count("verified") == 1
    assert results.count("already_verified") == 1
    request.refresh_from_db()
    assert request.status == StaffRegistrationRequest.Status.PENDING_REVIEW


@pytest.mark.django_db
def test_otp_delivery_failure_leaves_a_retryable_pending_registration(
    registration_enabled, settings, monkeypatch
):
    settings.EMAIL_DELIVERY_ENABLED = True
    monkeypatch.setattr(
        "accounts.services.notifications.EmailMultiAlternatives",
        lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("synthetic SMTP outage")),
    )
    request = register_applicant(email="otp.failure@example.test", password=PASSWORD).request
    notification = EmailNotification.objects.get(
        registration_request=request, kind="registration_otp"
    )

    assert deliver_notification(notification.pk) == "failed"
    notification.refresh_from_db()
    request.refresh_from_db()
    assert notification.status == EmailNotification.Status.FAILED
    assert notification.attempts == 1
    assert notification.next_attempt_at is not None
    assert request.status == StaffRegistrationRequest.Status.EMAIL_PENDING

    monkeypatch.undo()
    EmailNotification.objects.filter(pk=notification.pk).update(
        next_attempt_at=timezone.now() - timezone.timedelta(seconds=1)
    )
    assert deliver_notification(notification.pk) == "sent"
    notification.refresh_from_db()
    assert notification.status == EmailNotification.Status.SENT
