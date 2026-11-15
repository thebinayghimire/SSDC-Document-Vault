from django.conf import settings


def feature_flags(request):
    """Expose server-side feature flags without trusting client-supplied values."""
    return {
        "staff_registration_enabled": settings.STAFF_SELF_REGISTRATION_ENABLED,
        "email_login_enabled": settings.EMAIL_LOGIN_ENABLED,
        "self_registered_email_change_enabled": (
            settings.SELF_REGISTERED_EMAIL_CHANGE_ENABLED
        ),
    }
