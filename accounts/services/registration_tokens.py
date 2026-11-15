"""Signed, narrowly scoped links for registration status and verification."""

from django.conf import settings
from django.core import signing
from django.urls import reverse

from accounts.models import StaffRegistrationRequest

SALT = "accounts.staff-registration"


def registration_token(registration):
    return signing.dumps({"request": registration.pk}, salt=SALT, compress=True)


def load_registration(token):
    try:
        payload = signing.loads(
            token,
            salt=SALT,
            max_age=settings.STAFF_REGISTRATION_LINK_MAX_AGE_DAYS * 86400,
        )
    except (signing.BadSignature, signing.SignatureExpired, TypeError, ValueError):
        return None
    request_id = payload.get("request")
    if not isinstance(request_id, int):
        return None
    return StaffRegistrationRequest.objects.select_related("user").filter(pk=request_id).first()


def verification_url(registration, base_url=""):
    return base_url.rstrip("/") + reverse(
        "staff_register_verify", args=[registration_token(registration)]
    )


def status_url(registration, base_url=""):
    return base_url.rstrip("/") + reverse(
        "staff_registration_status", args=[registration_token(registration)]
    )
