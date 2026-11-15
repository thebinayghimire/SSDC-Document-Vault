"""Nepali coverage for the registration, review, and email journeys."""

import pytest
from django.utils import translation

from accounts.models import EmailNotification
from accounts.services.notifications import _render
from accounts.services.registration import register_applicant

PASSWORD = "Strong-Applicant-Password-42"

REGISTRATION_STRINGS = (
    "Register for staff access",
    "Register for staff access.",
    "Submit your work email and create a password. An administrator will review your request before access is granted.",
    "Email verification pending.",
    "Your email has been verified.",
    "Application approved.",
    "Application declined.",
    "Application expired.",
    "Check application status",
    "Staff registration requests",
    "Review pending applications",
    "Approve staff registration",
    "Decline staff registration",
    "Allow reapplication",
    "Administrator note:",
)


@pytest.mark.parametrize("message", REGISTRATION_STRINGS)
def test_nepali_catalogue_translates_registration_ui(message):
    with translation.override("ne"):
        translated = translation.gettext(message)
    assert translated
    assert translated != message


@pytest.mark.django_db
def test_registration_email_renders_in_the_applicant_language(settings):
    settings.STAFF_SELF_REGISTRATION_ENABLED = True
    settings.EMAIL_DELIVERY_ENABLED = False
    registration = register_applicant(
        email="nepali.registration@example.test",
        password=PASSWORD,
        language="ne",
    ).request
    notification = EmailNotification.objects.get(
        registration_request=registration,
        kind="registration_otp",
    )

    text_body, html_body = _render(notification)

    assert "आफ्नो इमेल प्रमाणित गर्नुहोस्" in html_body
    assert "इमेल प्रमाणीकरण" in text_body
    assert "प्रमाणीकरण कोड" in text_body
    assert "SSDC कागजात भण्डार" in text_body
