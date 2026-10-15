from datetime import UTC, datetime, timedelta
from unittest.mock import patch

import pytest

from config.readiness import readiness_failures


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
