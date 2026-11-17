"""Irreversible account-switch tags for privacy-preserving session synchronization."""

from django.utils.crypto import salted_hmac


def compute_account_tag(user, session):
    # Mitigates session identifier disclosure and enables privacy-preserving cross-tab account-switch detection
    if not user or not user.is_authenticated:
        return None
    portal_session = session.get("portal_session", "") if session else ""
    auth_version = (
        session.get("auth_version", getattr(user, "auth_version", 1))
        if session
        else getattr(user, "auth_version", 1)
    )
    payload = f"{user.pk}:{auth_version}:{portal_session}"
    return salted_hmac("ssdc.account-tag", payload).hexdigest()[:16]
