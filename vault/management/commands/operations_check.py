import secrets
import shutil
from datetime import timedelta

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError
from django.db import connection
from django.utils import timezone

from vault.models import Version
from vault.storage import StorageError, path_for


class Command(BaseCommand):
    help = "Operator checks: DB, private storage, disk headroom and scan backlog."

    def handle(self, *args, **options):
        from config.readiness import readiness_failures

        failures = readiness_failures()
        if settings.DOCUMENT_STORAGE_PROVIDER == "gdrive":
            from vault.drive_storage import ensure_folder

            try:
                ensure_folder()
            except StorageError as exc:
                failures.append(str(exc))
        try:
            with connection.cursor() as cursor:
                cursor.execute("SELECT 1")
        except Exception:
            failures.append("database unavailable")
        root = settings.PRIVATE_STORAGE_ROOT
        root.mkdir(parents=True, exist_ok=True, mode=0o700)
        probe = path_for("health-" + secrets.token_hex(8))
        try:
            with probe.open("xb") as stream:
                stream.write(b"probe")
            probe.unlink()
        except OSError:
            failures.append("private storage is not writable")
        usage = shutil.disk_usage(root)
        if usage.free < max(settings.MAX_UPLOAD_BYTES * 4, usage.total // 10):
            failures.append("private volume has less than 10% free space or upload headroom")
        try:
            if Version.objects.filter(
                status=Version.Status.QUARANTINED,
                uploaded_at__lt=timezone.now() - timedelta(minutes=15),
            ).exists():
                failures.append("quarantined versions older than 15 minutes")
        except Exception:
            failures.append("scan backlog could not be checked")
        if failures:
            raise CommandError("; ".join(failures))
        self.stdout.write("Database, private storage, disk headroom and scan backlog checks passed")
