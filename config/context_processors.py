from django.conf import settings

from accounts.services.account_tag import compute_account_tag


def feature_flags(request):
    """Expose server-side feature flags without trusting client-supplied values."""
    return {
        "staff_registration_enabled": settings.STAFF_SELF_REGISTRATION_ENABLED,
        "email_login_enabled": settings.EMAIL_LOGIN_ENABLED,
        "self_registered_email_change_enabled": (settings.SELF_REGISTERED_EMAIL_CHANGE_ENABLED),
    }


def account_tag(request):
    # Mitigates session secret exposure in HTML by providing an irreversible salted HMAC tag
    tag = compute_account_tag(getattr(request, "user", None), getattr(request, "session", None))
    return {"account_tag": tag or ""}
