"""Integration tests for staff registration views, email change views, and email login."""

import re

import pytest
from django.test import Client
from django.urls import reverse

from accounts.models import EmailNotification, StaffRegistrationRequest, StaffRegistrationToken
from accounts.services.email_claims import set_email
from accounts.services.otp import decrypt_otp
from accounts.services.registration import approve_registration, register_applicant
from accounts.services.registration_tokens import hash_token, registration_token

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

    verify_url = reverse("staff_register_verify", kwargs={"token": token})

    # GET is read-only prefetch-safe: returns the code entry page without consuming the token.
    get_response = client.get(verify_url)
    assert get_response.status_code == 200
    assert "accounts/registration_verify.html" in [t.name for t in get_response.templates]
    assert "Six-digit verification code" in get_response.content.decode()

    # A link click alone binds the session but never verifies the address.
    bind_response = client.post(verify_url)
    assert bind_response.status_code == 200
    assert "accounts/registration_verify.html" in [t.name for t in bind_response.templates]
    token_record = StaffRegistrationToken.objects.get(token_hash=hash_token(token))
    assert token_record.used_at is None
    reg.refresh_from_db()
    assert reg.status == StaffRegistrationRequest.Status.EMAIL_PENDING
    assert client.session.get("registration_request_id") == reg.pk

    # The six-digit code completes verification and consumes the link token.
    response = client.post(verify_url, {"code": get_latest_reg_otp(reg)})
    assert response.status_code == 302
    assert response.url == reverse("staff_registration_status")

    reg.refresh_from_db()
    token_record.refresh_from_db()
    assert reg.status == StaffRegistrationRequest.Status.PENDING_REVIEW
    assert reg.email_verified_at is not None
    assert token_record.used_at is not None

    # Replaying used token fails generically
    replay = client.get(verify_url)
    assert replay.status_code == 200
    assert "accounts/registration_link_invalid.html" in [t.name for t in replay.templates]


@pytest.mark.django_db
def test_registration_status_view(phase2_enabled, client, users):
    result = register_applicant(email="status.test@example.test", password=PASSWORD)
    reg = result.request
    token = registration_token(reg)
    status_url = reverse("staff_registration_status")

    # Status: EMAIL_PENDING (using session)
    session = client.session
    session["registration_request_id"] = reg.pk
    session.save()
    response = client.get(status_url)
    assert response.status_code == 200
    assert response.context["status"] == "email_pending"

    # Status: PENDING_REVIEW (after OTP verification)
    client.post(
        reverse("staff_register_verify", kwargs={"token": token}),
        {"code": get_latest_reg_otp(reg)},
    )
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
    client.post(
        reverse("staff_register_verify", kwargs={"token": token}),
        {"code": get_latest_reg_otp(reg)},
    )

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
def test_registration_view_resubmission_keeps_otp_box(phase2_enabled, client):
    post_data = {
        "email": "reapplicant@example.test",
        "password1": PASSWORD,
        "password2": PASSWORD,
    }
    # Initial submission establishes session
    res1 = client.post(reverse("staff_register"), post_data)
    assert res1.status_code == 200
    assert "registration_request_id" in client.session
    assert f'action="{reverse("staff_register_verify_session")}"' in res1.content.decode()

    # Resubmission with same email while pending
    res2 = client.post(reverse("staff_register"), post_data)
    assert res2.status_code == 200
    assert "Enter 6-digit verification code" in res2.content.decode()

    # A duplicate submission from another browser must not bind that browser to
    # the application or reveal a link token.
    other = Client()
    duplicate = other.post(reverse("staff_register"), post_data)
    assert duplicate.status_code == 200
    assert "registration_request_id" not in other.session
    content = duplicate.content.decode()
    assert "Enter 6-digit verification code" in content
    assert f'action="{reverse("staff_register_verify_session")}"' in content
    assert not re.search(r"/register/verify/[A-Za-z0-9_-]+/", content)

    # Resend email view never emits a token or binds a new session.
    res3 = other.post(
        reverse("staff_register_resend_email"),
        {"email": "reapplicant@example.test"},
    )
    assert res3.status_code == 200
    assert "registration_request_id" not in other.session
    assert f'action="{reverse("staff_register_verify_session")}"' in res3.content.decode()


@pytest.mark.django_db
def test_session_otp_form_verifies_without_a_link_token(phase2_enabled, client):
    response = client.post(
        reverse("staff_register"),
        {
            "email": "session.otp@example.test",
            "password1": PASSWORD,
            "password2": PASSWORD,
        },
    )
    assert response.status_code == 200
    reg = StaffRegistrationRequest.objects.get(applicant_email="session.otp@example.test")

    verify_response = client.post(
        reverse("staff_register_verify_session"),
        {"code": get_latest_reg_otp(reg)},
    )
    assert verify_response.status_code == 302
    assert verify_response.url == reverse("staff_registration_status")
    reg.refresh_from_db()
    assert reg.status == StaffRegistrationRequest.Status.PENDING_REVIEW


@pytest.mark.django_db
def test_email_only_code_does_not_bind_a_decided_application(phase2_enabled, client, users):
    result = register_applicant(email="decided.oracle@example.test", password=PASSWORD)
    reg = result.request
    client.post(
        reverse("staff_register_verify", kwargs={"token": registration_token(reg)}),
        {"code": get_latest_reg_otp(reg)},
    )
    approve_registration(reg.pk, users["admin"])

    anonymous = Client()
    response = anonymous.post(
        reverse("staff_register_verify_session"),
        {"email": "decided.oracle@example.test", "code": "000000"},
    )
    assert response.status_code == 200
    assert "accounts/registration_submitted.html" in [t.name for t in response.templates]
    assert "registration_request_id" not in anonymous.session
    assert "Application approved" not in response.content.decode()


@pytest.mark.django_db
def test_status_lookup_never_binds_a_session(phase2_enabled, client):
    result = register_applicant(email="lookup.bind@example.test", password=PASSWORD)
    reg = result.request

    anonymous = Client()
    response = anonymous.post(
        reverse("staff_registration_status"),
        {"email": "lookup.bind@example.test"},
    )
    assert response.status_code == 200
    assert response.context["submitted"] is True
    assert "registration_request_id" not in anonymous.session

    status = anonymous.get(reverse("staff_registration_status"))
    assert status.status_code == 200
    assert "accounts/registration_status_lookup.html" in [t.name for t in status.templates]
    assert reg.status == StaffRegistrationRequest.Status.EMAIL_PENDING
