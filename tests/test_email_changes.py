"""Service-level tests for the self-service email change lifecycle."""

import pytest
from django.utils import timezone

from accounts.models import EmailChangeRequest, EmailClaim, EmailNotification
from accounts.services.email_changes import (
    EmailChangeConflict,
    EmailChangeDisabled,
    cancel_email_change,
    expire_due_email_changes,
    pending_for_user,
    resend_email_change,
    start_email_change,
    verify_email_change,
)
from accounts.services.email_claims import set_email
from accounts.services.otp import OtpCooldown, decrypt_otp


@pytest.fixture
def email_change_enabled(settings):
    settings.EMAIL_LOGIN_ENABLED = True
    settings.SELF_REGISTERED_EMAIL_CHANGE_ENABLED = True
    settings.EMAIL_DELIVERY_ENABLED = False
    return settings


def latest_change_otp(user):
    notification = (
        EmailNotification.objects.filter(
            user_id=user.pk,
            kind="email_change_otp",
            status=EmailNotification.Status.PENDING,
        )
        .order_by("-created_at", "-pk")
        .first()
    )
    assert notification is not None
    return decrypt_otp(notification.context["otp_ciphertext"])


@pytest.mark.django_db
def test_email_change_disabled_by_default(settings, users):
    settings.EMAIL_LOGIN_ENABLED = False
    settings.SELF_REGISTERED_EMAIL_CHANGE_ENABLED = False
    with pytest.raises(EmailChangeDisabled):
        start_email_change(users["alice"], "alice.new@example.test")


@pytest.mark.django_db
def test_start_email_change_reserves_new_email_and_enqueues_notifications(
    email_change_enabled, users
):
    alice = users["alice"]
    set_email(alice, "alice.old@example.test", actor=alice, source="admin")

    result = start_email_change(alice, "Alice.New@example.test")
    assert result.created is True
    request = result.request
    assert request.status == EmailChangeRequest.Status.PENDING
    assert request.old_email == "alice.old@example.test"
    assert request.new_email == "alice.new@example.test"

    # Verifies OTP notification was created for new email
    otp_notif = EmailNotification.objects.get(email_change_request=request, kind="email_change_otp")
    assert otp_notif.recipient_email == "alice.new@example.test"

    # Verifies security notice notification was created for old email
    security_notif = EmailNotification.objects.get(
        email_change_request=request, kind="email_change_security_notice"
    )
    assert security_notif.recipient_email == "alice.old@example.test"


@pytest.mark.django_db
def test_start_email_change_rejects_conflict_with_existing_account(email_change_enabled, users):
    alice = users["alice"]
    bob = users["bob"]
    set_email(bob, "bob@example.test", actor=bob, source="admin")

    with pytest.raises(EmailChangeConflict):
        start_email_change(alice, "BOB@example.test")


@pytest.mark.django_db
def test_verify_email_change_applies_new_address_and_revokes_sessions(email_change_enabled, users):
    alice = users["alice"]
    set_email(alice, "alice.initial@example.test", actor=alice, source="admin")
    initial_auth_version = alice.auth_version

    start_email_change(alice, "alice.verified@example.test")
    code = latest_change_otp(alice)

    verify_result = verify_email_change(alice, code)
    assert verify_result.status == "applied"

    alice.refresh_from_db()
    assert alice.email == "alice.verified@example.test"
    assert alice.auth_version > initial_auth_version

    claim = EmailClaim.objects.get(user=alice)
    assert claim.normalized_email == "alice.verified@example.test"

    # Check completed notification
    assert EmailNotification.objects.filter(
        user_id=alice.pk, kind="email_change_completed"
    ).exists()


@pytest.mark.django_db
def test_wrong_otp_increments_attempts_and_locks(email_change_enabled, users):
    alice = users["alice"]
    set_email(alice, "alice.attempts@example.test", actor=alice, source="admin")

    start_email_change(alice, "alice.target@example.test")
    for _ in range(4):
        res = verify_email_change(alice, "000000")
        assert res.status == "invalid"

    # 5th attempt locks
    res = verify_email_change(alice, "000000")
    assert res.status == "locked"


@pytest.mark.django_db
def test_resend_email_change_cooldown(email_change_enabled, users):
    alice = users["alice"]
    set_email(alice, "alice.cooldown@example.test", actor=alice, source="admin")

    start_email_change(alice, "alice.cool@example.test")
    with pytest.raises(OtpCooldown):
        resend_email_change(alice)


@pytest.mark.django_db
def test_cancel_email_change(email_change_enabled, users):
    alice = users["alice"]
    set_email(alice, "alice.cancel@example.test", actor=alice, source="admin")

    start_email_change(alice, "alice.cancelnew@example.test")
    assert pending_for_user(alice) is not None

    assert cancel_email_change(alice) is True
    assert pending_for_user(alice) is None

    req = EmailChangeRequest.objects.get(user=alice)
    assert req.status == EmailChangeRequest.Status.CANCELLED


@pytest.mark.django_db
def test_expire_due_email_changes(email_change_enabled, users):
    alice = users["alice"]
    set_email(alice, "alice.expire@example.test", actor=alice, source="admin")

    start_email_change(alice, "alice.expirednew@example.test")
    past = timezone.now() - timezone.timedelta(days=10)
    EmailChangeRequest.objects.filter(user=alice).update(created_at=past)

    count = expire_due_email_changes()
    assert count == 1
    req = EmailChangeRequest.objects.get(user=alice)
    assert req.status == EmailChangeRequest.Status.EXPIRED
