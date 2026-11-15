"""Integration tests for staff registration views, email change views, and email login."""

import pytest
from django.test import Client
from django.urls import reverse

from accounts.models import EmailNotification, StaffRegistrationRequest
from accounts.services.email_claims import set_email
from accounts.services.otp import decrypt_otp
from accounts.services.registration import (
    approve_registration,
    decline_registration,
    register_applicant,
    verify_registration_otp,
)
from accounts.services.registration_tokens import registration_token

from .conftest import authenticate_client

PASSWORD = "Strong-Password-42"


@pytest.fixture
def phase2_enabled(settings):
    settings.STAFF_SELF_REGISTRATION_ENABLED = True
    settings.EMAIL_LOGIN_ENABLED = True
    settings.SELF_REGISTERED_EMAIL_CHANGE_ENABLED = True
    settings.EMAIL_DELIVERY_ENABLED = False
    settings.MFA_ENABLED = False
    return settings


def get_latest_reg_otp(request_obj):
    notification = (
        EmailNotification.objects.filter(
            registration_request=request_obj,
            kind="registration_otp",
            status=EmailNotification.Status.PENDING,
        )
        .order_by("-created_at", "-pk")
        .first()
    )
    assert notification is not None
    return decrypt_otp(notification.context["otp_ciphertext"])


def get_latest_change_otp(user):
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
def test_registration_view_get_and_post(phase2_enabled, client):
    # GET renders form
    response = client.get(reverse("staff_register"))
    assert response.status_code == 200
    assert "form" in response.context

    # POST valid form
    post_data = {
        "email": "applicant1@example.test",
        "password1": PASSWORD,
        "password2": PASSWORD,
    }
    response = client.post(reverse("staff_register"), post_data)
    assert response.status_code == 200
    assert "accounts/registration_submitted.html" in [t.name for t in response.templates]

    reg = StaffRegistrationRequest.objects.get(applicant_email="applicant1@example.test")
    assert reg.status == StaffRegistrationRequest.Status.EMAIL_PENDING


@pytest.mark.django_db
def test_registration_view_validation_errors(phase2_enabled, client):
    # Passwords do not match
    response = client.post(
        reverse("staff_register"),
        {"email": "valid@example.test", "password1": PASSWORD, "password2": "mismatch-pass"},
    )
    assert response.status_code == 200
    assert "password2" in response.context["form"].errors


@pytest.mark.django_db
def test_verification_view_get_and_post(phase2_enabled, client):
    result = register_applicant(email="verify.test@example.test", password=PASSWORD)
    reg = result.request
    token = registration_token(reg)
    code = get_latest_reg_otp(reg)

    verify_url = reverse("staff_register_verify", kwargs={"token": token})

    # GET verification page
    response = client.get(verify_url)
    assert response.status_code == 200

    # POST invalid code
    bad_post = client.post(verify_url, {"code": "000000"})
    assert bad_post.status_code == 200
    assert "form" in bad_post.context
    assert bad_post.context["form"].errors

    # POST valid code
    good_post = client.post(verify_url, {"code": code})
    assert good_post.status_code == 302
    assert good_post.url == reverse("staff_registration_status", kwargs={"token": token})

    reg.refresh_from_db()
    assert reg.status == StaffRegistrationRequest.Status.PENDING_REVIEW


@pytest.mark.django_db
def test_registration_status_view(phase2_enabled, client, users):
    result = register_applicant(email="status.test@example.test", password=PASSWORD)
    reg = result.request
    token = registration_token(reg)
    status_url = reverse("staff_registration_status", kwargs={"token": token})

    # Status: EMAIL_PENDING
    response = client.get(status_url)
    assert response.status_code == 200
    assert response.context["status"] == "email_pending"

    # Status: PENDING_REVIEW
    code = get_latest_reg_otp(reg)
    client.post(reverse("staff_register_verify", kwargs={"token": token}), {"code": code})
    response = client.get(status_url)
    assert response.status_code == 200
    assert response.context["status"] == "pending_review"

    # Status: APPROVED
    approve_registration(reg.pk, users["admin"])
    response = client.get(status_url)
    assert response.status_code == 200
    assert response.context["status"] == "approved"


@pytest.mark.django_db
def test_email_login_for_approved_staff(phase2_enabled, client, users):
    result = register_applicant(email="login.staff@example.test", password=PASSWORD)
    reg = result.request
    token = registration_token(reg)
    code = get_latest_reg_otp(reg)
    client.post(reverse("staff_register_verify", kwargs={"token": token}), {"code": code})

    # Try signing in before approval -> MUST FAIL
    login_response = client.post(
        reverse("staff_login"),
        {"staff_id": "login.staff@example.test", "password": PASSWORD},
    )
    assert login_response.status_code == 200
    assert "_auth_user_id" not in client.session

    # Approve registration
    approve_registration(reg.pk, users["admin"])

    # Sign in with email address (case-insensitive)
    login_response = client.post(
        reverse("staff_login"),
        {"staff_id": "LOGIN.STAFF@EXAMPLE.TEST", "password": PASSWORD},
    )
    assert login_response.status_code == 302
    assert client.session.get("_auth_user_id") is not None


@pytest.mark.django_db
def test_email_change_view_workflow(phase2_enabled, client, users):
    alice = users["alice"]
    set_email(alice, "alice.view@example.test", actor=alice, source="admin")

    # Login alice
    client.post(
        reverse("staff_login"),
        {"staff_id": "alice", "password": "Strong-Staff-Password-42"},
    )

    change_url = reverse("email_change")

    # GET email change view
    response = client.get(change_url)
    assert response.status_code == 200
    assert response.context["pending"] is None

    # POST start change
    post_res = client.post(
        change_url,
        {"action": "start", "new_email": "alice.brandnew@example.test"},
    )
    assert post_res.status_code == 302
    assert post_res.url == change_url

    # Check pending
    response = client.get(change_url)
    assert response.context["pending"] is not None

    code = get_latest_change_otp(alice)

    # POST verify change
    verify_res = client.post(
        change_url,
        {"action": "verify", "code": code},
    )
    assert verify_res.status_code == 302
    assert verify_res.url == reverse("staff_login")

    # Verify email updated
    alice.refresh_from_db()
    assert alice.email == "alice.brandnew@example.test"
    # User was logged out because auth_version updated
    assert "_auth_user_id" not in client.session


@pytest.mark.django_db
def test_declined_account_cannot_sign_in_with_email_or_staff_id(phase2_enabled, client, users):
    result = register_applicant(email="declined.login@example.test", password=PASSWORD)
    registration = result.request
    verify_registration_otp(registration, get_latest_reg_otp(registration))
    decline_registration(registration.pk, users["admin"])
    registration.refresh_from_db()
    registration.user.refresh_from_db()
    assert registration.status == StaffRegistrationRequest.Status.DECLINED
    assert registration.user.is_active is False

    for identity in ("declined.login@example.test", registration.user.username):
        response = client.post(
            reverse("staff_login"),
            {"staff_id": identity, "password": PASSWORD},
        )
        assert response.status_code == 200
        assert "_auth_user_id" not in client.session
        assert "Unable to sign in" in response.content.decode()


@pytest.mark.django_db
def test_pending_account_cannot_reach_authenticated_pages(phase2_enabled, client):
    result = register_applicant(email="pending.access@example.test", password=PASSWORD)
    applicant = result.request.user
    assert applicant.is_active is False

    authenticate_client(client, applicant)
    for path, login_prefix in (
        (reverse("staff_portal"), "/accounts/staff/login/"),
        (reverse("management"), "/accounts/login/"),
        (reverse("email_change"), "/accounts/login/"),
    ):
        response = client.get(path)
        assert response.status_code == 302
        assert response["Location"].startswith(login_prefix)


@pytest.mark.django_db
def test_registration_and_verification_require_csrf(phase2_enabled):
    enforcing = Client(enforce_csrf_checks=True)
    response = enforcing.post(
        reverse("staff_register"),
        {"email": "csrf.register@example.test", "password1": PASSWORD, "password2": PASSWORD},
    )
    assert response.status_code == 403
    assert not StaffRegistrationRequest.objects.filter(
        applicant_email="csrf.register@example.test"
    ).exists()

    result = register_applicant(email="csrf.verify@example.test", password=PASSWORD)
    token = registration_token(result.request)
    response = enforcing.post(
        reverse("staff_register_verify", kwargs={"token": token}),
        {"code": get_latest_reg_otp(result.request)},
    )
    assert response.status_code == 403
    result.request.refresh_from_db()
    assert result.request.status == StaffRegistrationRequest.Status.EMAIL_PENDING


@pytest.mark.django_db
def test_registration_ip_rate_limit_returns_429(phase2_enabled, settings):
    settings.STAFF_REGISTRATION_IP_LIMIT = 1
    client = Client()
    first = client.post(
        reverse("staff_register"),
        {"email": "limit.first@example.test", "password1": PASSWORD, "password2": PASSWORD},
    )
    assert first.status_code == 200
    assert StaffRegistrationRequest.objects.filter(
        applicant_email="limit.first@example.test"
    ).exists()

    second = client.post(
        reverse("staff_register"),
        {"email": "limit.second@example.test", "password1": PASSWORD, "password2": PASSWORD},
    )
    assert second.status_code == 429
    assert "Too many registration attempts" in second.content.decode()
    assert not StaffRegistrationRequest.objects.filter(
        applicant_email="limit.second@example.test"
    ).exists()
