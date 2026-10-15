from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from django.core.management import call_command
from django.core.management.base import CommandError


def configure(monkeypatch):
    databases = {
        "default": {
            "HOST": "synthetic.pooler.supabase.com",
            "NAME": "postgres",
            "USER": "ssdc_migrator.synthetic",
            "OPTIONS": {"sslmode": "verify-full"},
        }
    }
    monkeypatch.setattr(
        "vault.management.commands.check_pilot_database.settings",
        SimpleNamespace(DATABASES=databases),
    )
    return databases


def check():
    call_command(
        "check_pilot_database",
        expected_host="synthetic.pooler.supabase.com",
        expected_database="postgres",
        expected_user="ssdc_migrator.synthetic",
        skip_checks=True,
    )


def test_wrong_target_is_rejected_before_network(monkeypatch):
    databases = configure(monkeypatch)
    databases["default"]["HOST"] = "other-project"
    with patch("vault.management.commands.check_pilot_database.connection") as connection:
        with pytest.raises(CommandError, match="differs"):
            check()
        connection.cursor.assert_not_called()


@pytest.mark.parametrize("failure", ["network", "identity", "tls", None])
def test_check_verifies_identity_tls_and_hides_errors(monkeypatch, failure):
    configure(monkeypatch)
    with patch("vault.management.commands.check_pilot_database.connection") as connection:
        cursor = MagicMock()
        connection.cursor.return_value.__enter__.return_value = cursor
        connection.connection.pgconn.ssl_in_use = failure != "tls"
        cursor.fetchone.side_effect = [
            ("other" if failure == "identity" else "postgres", "ssdc_migrator"),
            (1,),
        ]
        if failure == "network":
            connection.cursor.side_effect = OSError("password=secret-canary")
        if failure:
            with pytest.raises(CommandError) as error:
                check()
            assert "secret-canary" not in str(error.value)
        else:
            check()
        connection.close.assert_called_once()
