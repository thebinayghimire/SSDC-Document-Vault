"""Safe operational readiness shared by HTTP and operator checks."""

import secrets
import shutil
from datetime import UTC, datetime, timedelta

from django.conf import settings
from django.db import connection

from vault.scanner import scanner_version
from vault.storage import path_for


def readiness_failures():
    failures = []
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1")
    except Exception:
        failures.append("database_unavailable")
    probe = None
    try:
        root = settings.PRIVATE_STORAGE_ROOT
        root.mkdir(parents=True, exist_ok=True, mode=0o700)
        probe = path_for("health-" + secrets.token_hex(8))
        with probe.open("xb") as stream:
            stream.write(b"probe")
        if probe.read_bytes() != b"probe":
            raise OSError("Storage probe mismatch")
        usage = shutil.disk_usage(root)
        if usage.free < max(settings.MAX_UPLOAD_BYTES * 4, usage.total // 10):
            failures.append("storage_headroom_low")
    except OSError:
        failures.append("storage_unavailable")
    finally:
        if probe is not None:
            try:
                probe.unlink(missing_ok=True)
            except OSError:
                if "storage_unavailable" not in failures:
                    failures.append("storage_unavailable")
    if settings.SCAN_MODE != "disabled" and (settings.SCAN_MODE == "clamav" or settings.PRODUCTION):
        try:
            version = scanner_version()
            date = version.rsplit("/", 1)[-1].strip()
            generated = datetime.strptime(date, "%a %b %d %H:%M:%S %Y").replace(tzinfo=UTC)
            age = datetime.now(UTC) - generated
            if age > timedelta(hours=settings.SCANNER_MAX_SIGNATURE_HOURS) or age < -timedelta(
                hours=1
            ):
                failures.append("scanner_signatures_stale")
        except Exception:
            failures.append("scanner_unavailable")
    return failures
