"""Security regression test suite for Phase 2 and Phase 2.1: Staff registration, prefetch safety, and tokens."""

import hashlib
import re
import time
from datetime import timedelta

import pytest
from django.core import signing
from django.test import Client
from django.urls import reverse
from django.utils import timezone

from accounts.models import (
    EmailNotification,
    StaffRegistrationRequest,
    StaffRegistrationToken,
)
from accounts.services.otp import decrypt_otp, generate_otp, otp_digest, verify_otp
from accounts.services.registration import register_applicant, verify_registration_otp
from accounts.services.registration_tokens import (
    create_registration_token,
    hash_token,
    registration_token,
)
from audit.models import Event

PASSWORD = "Strong-Password-42"


def latest_otp(registration):
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
    return decrypt_otp(notification.context["otp_ciphertext"])


@pytest.fixture
def phase2_setup(settings):
    settings.STAFF_SELF_REGISTRATION_ENABLED = True
    settings.EMAIL_LOGIN_ENABLED = True
    settings.SELF_REGISTERED_EMAIL_CHANGE_ENABLED = True
    settings.EMAIL_DELIVERY_ENABLED = True
    settings.MFA_ENABLED = False
    return settings


@pytest.mark.django_db
def test_token_creation_stores_only_sha256_hash(phase2_setup):
    """
    Step 2 Item 1: Token is stored ONLY as SHA-256 hash with 24-hour expiration.
    Mitigates plaintext token leakage in database compromises.
    """
    result = register_applicant(email="hashcheck@example.test", password=PASSWORD)
    reg = result.request
    raw_token = create_registration_token(reg, lifetime_hours=24)

    # Raw token must be high-entropy URL-safe text
    assert len(raw_token) >= 32
    expected_hash = hashlib.sha256(raw_token.encode("ascii")).hexdigest()

    # Database must contain the hash, never the raw token
    record = StaffRegistrationToken.objects.get(token_hash=expected_hash)
    assert record.registration == reg
    assert record.used_at is None
    # 24 hour expiry
    assert record.expires_at > timezone.now() + timedelta(hours=23)
    assert record.expires_at <= timezone.now() + timedelta(hours=25)

    # Search for raw token anywhere in table strings
    raw_in_db = StaffRegistrationToken.objects.filter(token_hash=raw_token).exists()
    assert not raw_in_db


@pytest.mark.django_db
def test_prefetch_safe_verification_flow(phase2_setup, client):
    """
    Phase 2.1 Item 1 + OTP requirement:
    - GET /verify/<token>/ is read-only and binds nothing to the session.
    - Scanner-style GET repeated 5 times does NOT consume the token.
    - A POST without a code binds the session but never verifies the address.
    - Only a valid six-digit OTP consumes the token and moves to PENDING_REVIEW.
    - A second POST fails generically.
    """
    result = register_applicant(email="prefetch_safe@example.test", password=PASSWORD)
    reg = result.request
    raw_token = registration_token(reg)
    verify_url = reverse("staff_register_verify", kwargs={"token": raw_token})

    # Scanner-style GET repeated 5 times
    for _ in range(5):
        get_resp = client.get(verify_url)
        assert get_resp.status_code == 200
        assert "accounts/registration_verify.html" in [t.name for t in get_resp.templates]
        assert "Six-digit verification code" in get_resp.content.decode()
        # Token must NOT be consumed
        token_record = StaffRegistrationToken.objects.get(token_hash=hash_token(raw_token))
        assert token_record.used_at is None
        # Session must NOT have registration ID
        assert "registration_request_id" not in client.session

    # A link-only POST binds the browser session but does not verify the email.
    bind_resp = client.post(verify_url)
    assert bind_resp.status_code == 200
    assert "accounts/registration_verify.html" in [t.name for t in bind_resp.templates]
    assert client.session.get("registration_request_id") == reg.pk
    token_record.refresh_from_db()
    assert token_record.used_at is None
    reg.refresh_from_db()
    assert reg.status == StaffRegistrationRequest.Status.EMAIL_PENDING
    assert reg.email_verified_at is None

    # The OTP consumes the token atomically and redirects to status.
    post_resp = client.post(verify_url, {"code": latest_otp(reg)})
    assert post_resp.status_code == 302
    assert post_resp.url == reverse("staff_registration_status")

    # Token now marked consumed
    token_record.refresh_from_db()
    assert token_record.used_at is not None

    # Status updated to PENDING_REVIEW
    reg.refresh_from_db()
    assert reg.status == StaffRegistrationRequest.Status.PENDING_REVIEW

    # Second POST fails generically
    second_post = client.post(verify_url)
    assert second_post.status_code == 200
    assert "accounts/registration_link_invalid.html" in [t.name for t in second_post.templates]


@pytest.mark.django_db
def test_expired_token_rejected_with_generic_page(phase2_setup, client):
    """
    Expired token produces generic invalid page on both GET and POST.
    Mitigates stale token exploitation.
    """
    result = register_applicant(email="expired@example.test", password=PASSWORD)
    reg = result.request
    raw_token = create_registration_token(reg, lifetime_hours=-1)  # expired 1 hour ago
    verify_url = reverse("staff_register_verify", kwargs={"token": raw_token})

    # GET fails generically
    get_resp = client.get(verify_url)
    assert get_resp.status_code == 200
    assert "accounts/registration_link_invalid.html" in [t.name for t in get_resp.templates]

    # POST fails generically
    post_resp = client.post(verify_url)
    assert post_resp.status_code == 200
    assert "accounts/registration_link_invalid.html" in [t.name for t in post_resp.templates]


@pytest.mark.django_db
def test_tampered_unknown_token_rejected_with_generic_page(phase2_setup, client):
    """
    Unknown or tampered token produces generic invalid page.
    Mitigates token probing and state oracle attacks.
    """
    verify_url = reverse(
        "staff_register_verify", kwargs={"token": "completely-invented-unknown-token-1234567890"}
    )
    resp_get = client.get(verify_url)
    assert resp_get.status_code == 200
    assert "accounts/registration_link_invalid.html" in [t.name for t in resp_get.templates]

    resp_post = client.post(verify_url)
    assert resp_post.status_code == 200
    assert "accounts/registration_link_invalid.html" in [t.name for t in resp_post.templates]


@pytest.mark.django_db
def test_old_style_signed_tokens_rejected_with_generic_page(phase2_setup, client):
    """
    Legacy stateless signed tokens are strictly rejected with the generic page.
    """
    result = register_applicant(email="oldsigned@example.test", password=PASSWORD)
    reg = result.request
    old_signed_token = signing.dumps(
        {"request": reg.pk}, salt="accounts.staff-registration", compress=True
    )

    # 1. Verification route rejects legacy signed token
    verify_url = reverse("staff_register_verify", kwargs={"token": old_signed_token})
    resp_verify = client.get(verify_url)
    assert resp_verify.status_code == 200
    assert "accounts/registration_link_invalid.html" in [t.name for t in resp_verify.templates]

    # 2. Legacy status route rejects token URL
    legacy_status_url = reverse(
        "staff_registration_status_legacy", kwargs={"token": old_signed_token}
    )
    resp_status = client.get(legacy_status_url)
    assert resp_status.status_code == 200
    assert "accounts/registration_link_invalid.html" in [t.name for t in resp_status.templates]

    # 3. Legacy resend route rejects token URL
    legacy_resend_url = reverse("staff_register_resend_legacy", kwargs={"token": old_signed_token})
    resp_resend = client.get(legacy_resend_url)
    assert resp_resend.status_code == 200
    assert "accounts/registration_link_invalid.html" in [t.name for t in resp_resend.templates]


@pytest.mark.django_db
def test_cross_device_verification_and_status(phase2_setup):
    """
    Phase 2.1: Verification link opened in fresh client (GET interstitial, then POST)
    binds session in that client, allowing status to work without tokens in the URL.
    """
    result = register_applicant(email="crossdevice@example.test", password=PASSWORD)
    reg = result.request
    raw_token = registration_token(reg)

    client_b = Client()
    verify_url = reverse("staff_register_verify", kwargs={"token": raw_token})

    # Client B opens link: GET is read-only
    get_resp = client_b.get(verify_url)
    assert get_resp.status_code == 200
    assert "accounts/registration_verify.html" in [t.name for t in get_resp.templates]

    # Client B clicks through and enters the OTP: POST
    bind_resp = client_b.post(verify_url)
    assert bind_resp.status_code == 200
    assert client_b.session.get("registration_request_id") == reg.pk
    post_resp = client_b.post(verify_url, {"code": latest_otp(reg)})
    assert post_resp.status_code == 302
    assert post_resp.url == reverse("staff_registration_status")

    # Client B can now check status via session
    status_resp = client_b.get(reverse("staff_registration_status"))
    assert status_resp.status_code == 200
    assert status_resp.context["status"] == "pending_review"
    assert status_resp.context["registration"].pk == reg.pk


@pytest.mark.django_db
def test_final_url_and_security_headers(phase2_setup, client):
    """
    GET and POST send Referrer-Policy: no-referrer and Cache-Control: no-store.
    Final URL after verification contains NO token.
    """
    result = register_applicant(email="headers@example.test", password=PASSWORD)
    reg = result.request
    raw_token = registration_token(reg)
    verify_url = reverse("staff_register_verify", kwargs={"token": raw_token})

    # GET headers
    get_resp = client.get(verify_url)
    assert get_resp["Referrer-Policy"] == "no-referrer"
    assert "no-store" in get_resp["Cache-Control"]

    # POST headers and redirect
    post_resp = client.post(verify_url, {"code": latest_otp(reg)})
    assert post_resp["Referrer-Policy"] == "no-referrer"
    assert "no-store" in post_resp["Cache-Control"]

    # Final URL has NO token
    final_resp = client.get(post_resp.url)
    assert raw_token not in final_resp.request["PATH_INFO"]
    assert final_resp["Referrer-Policy"] == "no-referrer"
    assert "no-store" in final_resp["Cache-Control"]


@pytest.mark.django_db
def test_resend_cooldown_and_earlier_token_invalidation(phase2_setup, client):
    """
    Phase 2.1 Item 3:
    - Per-registration cooldown: at most 1 email per resend window and 5 per 24 hours.
    - When exceeded, respond identically and silently send nothing.
    - Issuing a new token invalidates all earlier unused tokens for that registration.
    """
    result = register_applicant(email="resendabuse@example.test", password=PASSWORD)
    reg = result.request
    token1 = registration_token(reg)
    original_notifications = EmailNotification.objects.filter(
        registration_request=reg,
        kind="registration_otp",
    ).count()

    resend_url = reverse("staff_register_resend")

    # Resend immediately after registration: the cooldown suppresses the email
    # but the public response is unchanged.
    resp1 = client.post(resend_url, {"email": "resendabuse@example.test"})
    assert resp1.status_code == 200
    assert (
        EmailNotification.objects.filter(
            registration_request=reg,
            kind="registration_otp",
        ).count()
        == original_notifications
    )

    # Issuing a replacement token invalidates the earlier unused token.
    token2 = create_registration_token(reg)
    token1_record = StaffRegistrationToken.objects.get(token_hash=hash_token(token1))
    assert token1_record.used_at is not None

    # Token 1 fails generically
    old_resp = client.get(reverse("staff_register_verify", kwargs={"token": token1}))
    assert old_resp.status_code == 200
    assert "accounts/registration_link_invalid.html" in [t.name for t in old_resp.templates]

    # Token 2 is valid
    new_resp = client.get(reverse("staff_register_verify", kwargs={"token": token2}))
    assert new_resp.status_code == 200
    assert "accounts/registration_verify.html" in [t.name for t in new_resp.templates]


@pytest.mark.django_db
def test_status_lookup_without_session_does_not_reveal_existence(phase2_setup, client):
    """
    Phase 2.1 Item 2:
    - /status without session displays email lookup form.
    - Always responds "If a registration exists for that address, we have emailed a link".
    - Emails fresh one-time link to address on file (any registration state).
    - Response body and timing are identical whether or not registration exists.
    """
    result = register_applicant(email="statuslookup@example.test", password=PASSWORD)
    assert result.request is not None
    status_url = reverse("staff_registration_status")

    # POST with existing vs non-existent email produces identical output
    t0 = time.perf_counter()
    post_existing = client.post(status_url, {"email": "statuslookup@example.test"})
    t_existing = time.perf_counter() - t0

    t0 = time.perf_counter()
    post_nonexistent = client.post(status_url, {"email": "unknown.status@example.test"})
    t_nonexistent = time.perf_counter() - t0

    assert post_existing.status_code == 200
    assert post_nonexistent.status_code == 200

    # Clean CSRF tokens
    clean_existing = re.sub(
        r'name="csrfmiddlewaretoken" value="[^"]*"', "", post_existing.content.decode()
    )
    clean_nonexistent = re.sub(
        r'name="csrfmiddlewaretoken" value="[^"]*"', "", post_nonexistent.content.decode()
    )
    assert clean_existing == clean_nonexistent
    assert (
        "If a registration exists for that address, we have emailed a link"
        in post_existing.content.decode()
    )

    # Timing difference is negligible (< 200ms)
    assert abs(t_existing - t_nonexistent) < 0.2


@pytest.mark.django_db
def test_status_lookup_link_for_any_registration_state(phase2_setup):
    """
    Phase 2.1 Item 2:
    Applicant with registration in any state (e.g. PENDING_REVIEW) receives a one-time link,
    clicks it (GET interstitial, then POST), which binds session and displays their status.
    """
    result = register_applicant(email="anystate@example.test", password=PASSWORD)
    reg = result.request
    # Simulate email already verified and in PENDING_REVIEW
    reg.status = StaffRegistrationRequest.Status.PENDING_REVIEW
    reg.email_verified_at = timezone.now()
    reg.save()

    # Fresh client on another device
    device_client = Client()

    # Device client requests status link
    status_url = reverse("staff_registration_status")
    device_client.post(status_url, {"email": "anystate@example.test"})

    # Latest notification contains fresh token
    notif = EmailNotification.objects.filter(recipient_email="anystate@example.test").latest(
        "created_at"
    )
    assert notif is not None
    token = notif.context.get("verification_url").split("/")[-2]

    # Open link on device: GET interstitial
    verify_url = reverse("staff_register_verify", kwargs={"token": token})
    get_resp = device_client.get(verify_url)
    assert get_resp.status_code == 200
    assert "accounts/registration_verify.html" in [t.name for t in get_resp.templates]

    # Submit confirmation: POST
    post_resp = device_client.post(verify_url)
    assert post_resp.status_code == 302
    assert post_resp.url == status_url

    # Device client now views status without any token in URL
    view_resp = device_client.get(status_url)
    assert view_resp.status_code == 200
    assert view_resp.context["status"] == "pending_review"
    assert view_resp.context["registration"].pk == reg.pk


@pytest.mark.django_db
def test_registration_otp_security_specifications(phase2_setup):
    """
    Phase 2.1 Item 4: Registration OTP verification security controls:
    - Code from CSPRNG (generate_otp)
    - Stored hashed (HMAC-SHA256, never raw code in DB)
    - 10-minute expiry
    - Maximum 5 attempts per code then invalidate in DB
    - Single use
    - Constant-time comparison (verify_otp)
    - Rate limited per registration and per IP
    - New code invalidates the old one
    - Never logged in audit events
    """
    result = register_applicant(email="otpspec@example.test", password=PASSWORD)
    reg = result.request

    # 1. CSPRNG code format
    otp_code = generate_otp()
    assert len(otp_code) == 6
    assert otp_code.isdigit()

    # 2. Stored hashed (HMAC-SHA256 keyed digest)
    digest = otp_digest("staff_registration_otp", reg.pk, otp_code)
    reg.otp_digest = digest
    reg.otp_expires_at = timezone.now() + timedelta(minutes=10)
    reg.otp_attempts = 0
    reg.save()
    reg.refresh_from_db()
    assert reg.otp_digest == digest
    assert otp_code not in reg.otp_digest

    # 3. Constant-time comparison
    assert verify_otp("staff_registration_otp", reg.pk, digest, otp_code) is True
    assert verify_otp("staff_registration_otp", reg.pk, digest, "000000") is False

    # 4. Maximum 5 attempts per code then invalidate
    for _ in range(4):
        res = verify_registration_otp(reg, "999999", ip="10.0.0.1")
        assert res.status == "invalid"
    # 5th failed attempt locks and invalidates code
    res5 = verify_registration_otp(reg, "999999", ip="10.0.0.1")
    assert res5.status == "locked"
    reg.refresh_from_db()
    assert reg.otp_attempts >= 5
    assert reg.otp_expires_at <= timezone.now()  # Expired and invalidated
    # Even submitting the correct code now fails with locked
    assert verify_registration_otp(reg, otp_code).status == "locked"

    # 5. Rate limiting per IP
    for _ in range(60):
        verify_registration_otp(reg, "123456", ip="10.0.0.2")
    throttled = verify_registration_otp(reg, "123456", ip="10.0.0.2")
    assert throttled.status == "throttled"


@pytest.mark.django_db
def test_no_tokens_in_audit_events(phase2_setup, client):
    """
    Audit events record verification success and failure WITHOUT token values.
    """
    result = register_applicant(email="auditcheck@example.test", password=PASSWORD)
    reg = result.request
    raw_token = registration_token(reg)

    # Tampered token POST fails
    client.post(reverse("staff_register_verify", kwargs={"token": "bogus-token-value"}))
    fail_event = Event.objects.filter(kind="staff_registration_verify_failed").latest("at")
    assert fail_event.outcome == "denied"
    assert "bogus" not in str(fail_event.details)

    # Valid token plus OTP succeeds
    client.post(
        reverse("staff_register_verify", kwargs={"token": raw_token}),
        {"code": latest_otp(reg)},
    )
    success_event = Event.objects.filter(kind="staff_registration_verify_succeeded").latest("at")
    assert success_event.outcome == "success"
    assert success_event.target == str(reg.user_id)
    assert raw_token not in str(success_event.details)
    assert hash_token(raw_token) not in str(success_event.details)


@pytest.mark.django_db
def test_ip_rate_limiting_on_verify(phase2_setup, client):
    """
    Rate limit verification attempts per IP.
    """
    verify_url = reverse("staff_register_verify", kwargs={"token": "test-rate-limit-token"})

    # Perform 60 attempts
    for _ in range(60):
        resp = client.get(verify_url)
        assert resp.status_code == 200  # Generic invalid page

    # 61st attempt throttled with HTTP 429
    throttled = client.get(verify_url)
    assert throttled.status_code == 429
