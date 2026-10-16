"""Malware scanning mode selection.

Scanning is normally mandatory in production. SSDC has accepted the risk of
running this vault without a malware scanner on the Oracle Always Free ARM
host; `docs/SECURITY.md` records that decision. "disabled" implements it, but
production additionally requires an explicit `ACCEPT_NO_MALWARE_SCANNING=1`, so
an absent, mistyped or inherited `SCAN_MODE` can never silently turn scanning
off on a production host.
"""

from django.core.exceptions import ImproperlyConfigured

MODES = {"clamav", "skip-development", "disabled"}


def scan_mode(environ, production=False):
    if "ENABLE_CLAMAV" in environ:
        enabled = environ["ENABLE_CLAMAV"].strip().lower()
        if enabled in {"1", "true", "yes", "on"}:
            return "clamav"
        if enabled in {"0", "false", "no", "off"}:
            return "disabled"
        raise ImproperlyConfigured("ENABLE_CLAMAV must be a boolean")
    # Render's 512 MB free service cannot safely run the ClamAV daemon. Keep
    # the established fail-closed default for every other production target.
    if production and environ.get("RENDER"):
        return "disabled"
    mode = environ.get("SCAN_MODE", "clamav")
    if mode not in MODES:
        raise ImproperlyConfigured("Unknown SCAN_MODE")
    if production and mode == "skip-development":
        raise ImproperlyConfigured("Production cannot use the development scan bypass")
    if mode == "disabled" and production and environ.get("ACCEPT_NO_MALWARE_SCANNING", "0") != "1":
        raise ImproperlyConfigured(
            "SCAN_MODE=disabled requires ACCEPT_NO_MALWARE_SCANNING=1 in production"
        )
    return mode
