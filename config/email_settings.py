"""Email backend selection and delivery guardrails shared with settings tests."""

from django.core.exceptions import ImproperlyConfigured

SMTP_BACKEND = "django.core.mail.backends.smtp.EmailBackend"
LOCMEM_BACKEND = "django.core.mail.backends.locmem.EmailBackend"


def resolve_email_backend(
    *,
    production,
    delivery_enabled,
    backend,
    host,
    user,
    password,
    use_tls,
    use_ssl,
    features_enabled,
    from_email,
    public_base_url,
):
    """Return the effective backend after enforcing safe delivery configuration."""
    backend = backend or (SMTP_BACKEND if delivery_enabled else LOCMEM_BACKEND)
    if use_tls and use_ssl:
        raise ImproperlyConfigured("EMAIL_USE_TLS and EMAIL_USE_SSL are mutually exclusive")
    if delivery_enabled:
        if not backend.endswith("smtp.EmailBackend"):
            raise ImproperlyConfigured(
                "EMAIL_DELIVERY_ENABLED requires the SMTP email backend"
            )
        if not host:
            raise ImproperlyConfigured("EMAIL_DELIVERY_ENABLED requires EMAIL_HOST")
        if bool(user) != bool(password):
            raise ImproperlyConfigured(
                "EMAIL_HOST_USER and EMAIL_HOST_PASSWORD must be configured together"
            )
        if production and not (use_tls or use_ssl):
            raise ImproperlyConfigured("Production SMTP delivery requires TLS or SSL")
        if production and "localhost" in from_email:
            raise ImproperlyConfigured(
                "Production email delivery requires a real EMAIL_FROM_ADDRESS"
            )
    if production and features_enabled and not delivery_enabled:
        raise ImproperlyConfigured(
            "Staff registration and email change require EMAIL_DELIVERY_ENABLED=1 in production"
        )
    if production and features_enabled and not public_base_url:
        raise ImproperlyConfigured(
            "Staff registration and email change require PUBLIC_BASE_URL in production"
        )
    return backend
