"""PostgreSQL transport settings shared by development and hosted deployments."""

from pathlib import Path

from django.core.exceptions import ImproperlyConfigured


def database_transport(environment, production=False):
    mode = environment.get("POSTGRES_CONNECTION_MODE", "direct")
    if mode not in {"direct", "session"}:
        raise ImproperlyConfigured(
            "POSTGRES_CONNECTION_MODE must be direct or session; scanning requires session locks"
        )
    if environment.get("POSTGRES_PORT", "5432") == "6543":
        raise ImproperlyConfigured("Transaction pooler port 6543 cannot preserve scanner locks")
    sslmode = environment.get("POSTGRES_SSLMODE", "verify-full" if production else "prefer")
    if sslmode not in {"disable", "allow", "prefer", "require", "verify-ca", "verify-full"}:
        raise ImproperlyConfigured("Invalid POSTGRES_SSLMODE")
    internal_compose = environment.get("POSTGRES_HOST") == "db" and sslmode == "disable"
    if production and sslmode != "verify-full" and not internal_compose:
        raise ImproperlyConfigured("Production PostgreSQL requires POSTGRES_SSLMODE=verify-full")
    options = {"connect_timeout": 5, "sslmode": sslmode}
    rootcert = environment.get("POSTGRES_SSLROOTCERT")
    if rootcert:
        if not Path(rootcert).is_file():
            raise ImproperlyConfigured("POSTGRES_SSLROOTCERT must name a readable certificate file")
        options["sslrootcert"] = rootcert
    # Without an explicit file libpq uses its default root certificate path.
    try:
        age = int(environment.get("POSTGRES_CONN_MAX_AGE", "60" if production else "0"))
    except ValueError:
        raise ImproperlyConfigured("POSTGRES_CONN_MAX_AGE must be an integer") from None
    if not 0 <= age <= 600:
        raise ImproperlyConfigured("POSTGRES_CONN_MAX_AGE must be between 0 and 600")
    return {"OPTIONS": options, "CONN_MAX_AGE": age, "CONN_HEALTH_CHECKS": True}
