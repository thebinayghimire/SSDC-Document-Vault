"""Database tests must never silently target a remote PostgreSQL host."""

import pytest

from .conftest import require_local_test_database

POSTGRES = "django.db.backends.postgresql"


@pytest.mark.parametrize(
    "host",
    ["", "localhost", "127.0.0.1", "::1", "[::1]", "db", "/var/run/postgresql"],
)
def test_local_or_socket_hosts_are_allowed(host):
    require_local_test_database({"ENGINE": POSTGRES, "HOST": host}, {})


@pytest.mark.parametrize("engine", ["django.db.backends.sqlite3", "sqlite3"])
def test_sqlite_is_allowed(engine):
    require_local_test_database({"ENGINE": engine, "HOST": "example.invalid"}, {})


def test_remote_host_is_refused_without_explicit_override():
    with pytest.raises(RuntimeError, match="non-local host"):
        require_local_test_database({"ENGINE": POSTGRES, "HOST": "ep-example.neon.tech"}, {})


def test_remote_host_is_allowed_only_with_explicit_opt_in():
    require_local_test_database(
        {"ENGINE": POSTGRES, "HOST": "ep-example.neon.tech"},
        {"ALLOW_REMOTE_TEST_DB": "1"},
    )


@pytest.mark.parametrize("value", ["true", "yes", "0", ""])
def test_remote_override_requires_the_exact_value(value):
    with pytest.raises(RuntimeError, match="non-local host"):
        require_local_test_database(
            {"ENGINE": POSTGRES, "HOST": "ep-example.neon.tech"},
            {"ALLOW_REMOTE_TEST_DB": value},
        )
