import pytest
from django.core.exceptions import ImproperlyConfigured

from config.database import database_transport


def test_development_keeps_local_postgres_compatible():
    config = database_transport({})
    assert config["OPTIONS"] == {"connect_timeout": 5, "sslmode": "prefer"}
    assert config["CONN_MAX_AGE"] == 0


@pytest.mark.parametrize("mode", ["direct", "session"])
def test_production_verifies_tls_and_recovers_stale_connections(tmp_path, mode):
    certificate = tmp_path / "root.crt"
    certificate.write_text("synthetic certificate; no connection made")
    config = database_transport(
        {"POSTGRES_CONNECTION_MODE": mode, "POSTGRES_SSLROOTCERT": str(certificate)}, True
    )
    assert config["OPTIONS"]["sslmode"] == "verify-full"
    assert config["OPTIONS"]["sslrootcert"] == str(certificate)
    assert config["CONN_HEALTH_CHECKS"]


@pytest.mark.parametrize(
    "environment",
    [
        {"POSTGRES_CONNECTION_MODE": "transaction"},
        {"POSTGRES_PORT": "6543"},
        {"POSTGRES_SSLMODE": "require"},
        {"POSTGRES_SSLMODE": "disable"},
        {"POSTGRES_SSLMODE": "typo"},
        {"POSTGRES_SSLROOTCERT": "/missing/ssdc/root.crt"},
        {"POSTGRES_CONN_MAX_AGE": "-1"},
        {"POSTGRES_CONN_MAX_AGE": "601"},
        {"POSTGRES_CONN_MAX_AGE": "secret-canary"},
    ],
)
def test_unsafe_or_invalid_database_settings_fail_without_values(environment):
    with pytest.raises(ImproperlyConfigured) as error:
        database_transport(environment, True)
    assert "secret-canary" not in str(error.value)
