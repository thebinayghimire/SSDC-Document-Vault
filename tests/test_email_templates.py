"""Tests for OTP email templates and rendering."""

from unittest.mock import MagicMock

from django.core.mail import EmailMultiAlternatives
from django.template.loader import render_to_string
from django.utils import translation

from accounts.services.notifications import _render
from accounts.services.otp import encrypt_otp


def test_registration_otp_html_rendering():
    context = {
        "otp": "482915",
        "otp_code": "482915",
        "app_name": "SSDC Document Vault",
        "user_name": "Alex",
        "user_email": "alex@example.com",
        "purpose": "complete your staff registration",
        "expiry_minutes": 10,
        "accent": "#3D5AFE",
        "year": 2026,
        "company_address": "Kathmandu, Nepal",
        "verification_url": "https://vault.example.com/verify?token=123",
    }
    with translation.override("en"):
        html = render_to_string("email/registration_otp.html", context)

    # Core elements from the new design
    assert "482915 is your SSDC Document Vault code" in html
    assert "Your SSDC Document Vault code is 482915" in html
    assert (
        "Hi Alex, enter this code in SSDC Document Vault to complete your staff registration."
        in html
    )
    assert "482915" in html
    assert "Single use. Expires in 10 minutes." in html
    assert "Didn&rsquo;t request this?" in html
    assert "SSDC Document Vault will never ask you for this code by phone, chat, or email." in html
    assert "Sent to alex@example.com." in html
    assert "&copy; 2026 SSDC Document Vault, Kathmandu, Nepal" in html
    assert "https://vault.example.com/verify?token=123" in html
    assert "Enter verification code" in html
    assert (
        "Opening the link alone does not verify your email address. "
        "You must enter the six-digit code to finish your registration."
    ) in html


def test_registration_otp_txt_rendering():
    context = {
        "otp": "482915",
        "app_name": "SSDC Document Vault",
        "purpose": "complete your staff registration",
        "expiry_minutes": 10,
        "verification_url": "https://vault.example.com/verify?token=123",
    }
    with translation.override("en"):
        text = render_to_string("email/registration_otp.txt", context)

    assert "Your SSDC Document Vault code is: 482915" in text
    assert (
        "Enter it to complete your staff registration. It works once and expires in 10 minutes."
        in text
    )
    assert "https://vault.example.com/verify?token=123" in text
    assert (
        "Opening the link alone does not verify your email address. "
        "You must enter the six-digit code to finish your registration."
    ) in text
    assert "SSDC Document Vault will never ask you for this code by phone, chat, or email." in text


def test_email_change_otp_html_and_txt_rendering():
    context = {
        "otp_code": "123456",
        "app_name": "SSDC Document Vault",
        "user_name": "Sita",
        "user_email": "sita@example.com",
        "purpose": "confirm your new email address",
        "expiry_minutes": 10,
        "change_url": "https://vault.example.com/email/change",
    }
    with translation.override("en"):
        html = render_to_string("email/email_change_otp.html", context)
        text = render_to_string("email/email_change_otp.txt", context)

    assert "123456 is your SSDC Document Vault code" in html
    assert (
        "Hi Sita, enter this code in SSDC Document Vault to confirm your new email address." in html
    )
    assert "Confirm Email Change" in html
    assert "Your SSDC Document Vault code is: 123456" in text
    assert "https://vault.example.com/email/change" in text


def test_notification_render_helper_populates_otp_and_context():
    notification = MagicMock()
    notification.template_name = "email/registration_otp"
    notification.kind = "registration_otp"
    notification.recipient_email = "ramesh.shrestha@example.org"
    notification.user = None
    notification.registration_request = MagicMock()
    notification.registration_request.applicant_email = "ramesh.shrestha@example.org"
    notification.context = {
        "otp_ciphertext": encrypt_otp("789012"),
        "expiry_minutes": 15,
        "verification_url": "https://vault.example.com/verify",
    }

    text_body, html_body = _render(notification)
    assert "789012" in text_body
    assert "789012" in html_body
    assert "Ramesh" in html_body
    assert "SSDC Document Vault" in html_body

    msg = EmailMultiAlternatives(
        "789012 is your SSDC Document Vault code",
        text_body,
        "noreply@ssdc.org.np",
        [notification.recipient_email],
    )
    msg.attach_alternative(html_body, "text/html")
    assert len(msg.alternatives) == 1
    assert msg.alternatives[0][1] == "text/html"


def test_registration_status_link_html_and_txt_rendering():
    context = {
        "app_name": "SSDC Document Vault",
        "user_name": "Sita",
        "user_email": "sita@example.com",
        "verification_url": "https://vault.example.com/accounts/register/verify/token/",
        "status_url": "https://vault.example.com/accounts/register/status/",
        "expiry_hours": 24,
    }
    with translation.override("en"):
        html = render_to_string("email/registration_status_link.html", context)
        text = render_to_string("email/registration_status_link.txt", context)

    assert "Use the secure link below" in html
    assert "https://vault.example.com/accounts/register/verify/token/" in html
    assert "can only be used once and expires in 24 hours" in html
    assert "does not verify your email address or sign you in" in html
    assert "https://vault.example.com/accounts/register/verify/token/" in text
    assert "can only be used once and expires in 24 hours" in text
