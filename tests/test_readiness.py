import io
from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock, patch

import pytest
from django.core.management import call_command
from django.core.management.base import CommandError
from django.utils import timezone

from config.readiness import readiness_failures
from vault.drive_auth import StorageError
from vault.models import Version


@pytest.mark.django_db
def test_readiness_reports_storage_failure_and_live_is_available(client, settings, tmp_path):
    path = tmp_path / "unusable"
    path.write_bytes(b"Not a directory")
    settings.PRIVATE_STORAGE_ROOT = path
    assert "storage_unavailable" in readiness_failures()
    assert client.get("/health/").status_code == 503
    assert client.get("/live/").status_code == 200


@pytest.mark.django_db
def test_readiness_detects_stale_scanner_signatures(settings):
    settings.SCAN_MODE = "clamav"
    date = (datetime.now(UTC) - timedelta(days=7)).strftime("%a %b %d %H:%M:%S %Y")
    with patch("config.readiness.scanner_version", return_value="ClamAV 1.5/123/" + date):
        assert "scanner_signatures_stale" in readiness_failures()


@pytest.mark.django_db
def test_readiness_detects_scanner_outage(settings):
    settings.SCAN_MODE = "clamav"
    with patch("config.readiness.scanner_version", side_effect=OSError):
        assert "scanner_unavailable" in readiness_failures()


@pytest.mark.django_db
def test_readiness_skips_scanner_checks_when_scanning_is_disabled(settings):
    settings.SCAN_MODE = "disabled"
    settings.PRODUCTION = True
    with patch("config.readiness.scanner_version", side_effect=AssertionError("not called")):
        failures = readiness_failures()
    assert "scanner_unavailable" not in failures
    assert "scanner_signatures_stale" not in failures


def test_readiness_attempts_probe_cleanup_after_write_failure(settings):
    probe = MagicMock()
    probe.open.side_effect = OSError("synthetic write failure")
    with patch("config.readiness.path_for", return_value=probe):
        failures = readiness_failures()
    assert "storage_unavailable" in failures
    probe.unlink.assert_called_once_with(missing_ok=True)


def test_readiness_reports_probe_cleanup_failure(settings, tmp_path):
    probe = tmp_path / "private" / "probe"
    with (
        patch("config.readiness.path_for", return_value=probe),
        patch("pathlib.Path.unlink", side_effect=OSError("synthetic cleanup failure")) as unlink,
    ):
        failures = readiness_failures()
    assert "storage_unavailable" in failures
    unlink.assert_called_once_with(missing_ok=True)


def test_operations_check_reports_shared_readiness_failures():
    with (
        patch(
            "vault.management.commands.operations_check.readiness_failures",
            return_value=["database_unavailable", "scanner_unavailable"],
        ),
        patch("vault.management.commands.operations_check.Version.objects.filter") as versions,
    ):
        versions.return_value.exists.return_value = False
        with pytest.raises(CommandError, match="database_unavailable; scanner_unavailable"):
            call_command("operations_check", stdout=io.StringIO(), stderr=io.StringIO())


def test_operations_check_retains_drive_folder_check(settings):
    settings.DOCUMENT_STORAGE_PROVIDER = "gdrive"
    with (
        patch("vault.management.commands.operations_check.readiness_failures", return_value=[]),
        patch(
            "vault.drive_storage.ensure_folder", side_effect=StorageError("configuration")
        ) as ensure_folder,
        patch("vault.management.commands.operations_check.Version.objects.filter") as versions,
    ):
        versions.return_value.exists.return_value = False
        with pytest.raises(CommandError, match="storage setup is incomplete"):
            call_command("operations_check", stdout=io.StringIO(), stderr=io.StringIO())
    ensure_folder.assert_called_once_with()


@pytest.mark.django_db
def test_operations_check_retains_quarantine_backlog_check(document):
    Version.objects.filter(pk=document.active_version_id).update(
        status=Version.Status.QUARANTINED,
        uploaded_at=timezone.now() - timedelta(minutes=16),
    )
    with patch("vault.management.commands.operations_check.readiness_failures", return_value=[]):
        with pytest.raises(CommandError, match="quarantined versions older than 15 minutes"):
            call_command("operations_check", stdout=io.StringIO(), stderr=io.StringIO())
