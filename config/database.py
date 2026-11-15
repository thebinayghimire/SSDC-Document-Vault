"""PostgreSQL transport settings shared by development and hosted deployments."""

from pathlib import Path

import certifi
import dj_database_url
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
    if rootcert and rootcert != "system":
        if not Path(rootcert).is_file():
            raise ImproperlyConfigured("POSTGRES_SSLROOTCERT must name a readable certificate file")
    if rootcert:
        options["sslrootcert"] = rootcert
    # Without an explicit file libpq uses its default root certificate path.
    try:
        age = int(environment.get("POSTGRES_CONN_MAX_AGE", "60" if production else "0"))
    except ValueError:
        raise ImproperlyConfigured("POSTGRES_CONN_MAX_AGE must be an integer") from None
    if not 0 <= age <= 600:
        raise ImproperlyConfigured("POSTGRES_CONN_MAX_AGE must be between 0 and 600")
    return {"OPTIONS": options, "CONN_MAX_AGE": age, "CONN_HEALTH_CHECKS": True}


def database_from_url(url, environment, production=False, debug=False):
    """Apply the same transport and session-lock safeguards to hosted URLs."""
    try:
        database = dj_database_url.parse(
            url, conn_max_age=600, ssl_require=not production and not debug
        )
    except (ValueError, KeyError):
        raise ImproperlyConfigured("DATABASE_URL must be a valid PostgreSQL URL") from None
    if database["ENGINE"] != "django.db.backends.postgresql":
        raise ImproperlyConfigured("DATABASE_URL must use PostgreSQL")
    host = database.get("HOST", "")
    if "-pooler." in host:
        raise ImproperlyConfigured(
            "Use DATABASE_URL_UNPOOLED; transaction pooling cannot preserve session locks"
        )
    options = database.get("OPTIONS", {})
    transport_environment = {
        **environment,
        "POSTGRES_HOST": host,
        "POSTGRES_PORT": str(database.get("PORT") or 5432),
    }
    for option, name in (("sslmode", "POSTGRES_SSLMODE"), ("sslrootcert", "POSTGRES_SSLROOTCERT")):
        if option in options:
            transport_environment[name] = options[option]
    if production:
        if host != "db" and not transport_environment.get("POSTGRES_SSLROOTCERT"):
            transport_environment["POSTGRES_SSLROOTCERT"] = certifi.where()
        transport = database_transport(transport_environment, production=True)
        database.update(transport)
        database["OPTIONS"] = {**options, **transport["OPTIONS"]}
    else:
        # Still reject unsupported pooler modes and invalid connection settings.
        database_transport(transport_environment)
    database["CONN_HEALTH_CHECKS"] = True
    return database
