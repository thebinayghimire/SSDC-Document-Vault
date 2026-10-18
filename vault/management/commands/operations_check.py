from datetime import timedelta

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone

from config.readiness import readiness_failures
from vault.models import Version
from vault.storage import StorageError


class Command(BaseCommand):
    help = "Operator checks: readiness, document storage folder and scan backlog."

    def handle(self, *args, **options):
        failures = readiness_failures()
        if settings.DOCUMENT_STORAGE_PROVIDER == "gdrive":
            from vault.drive_storage import ensure_folder

            try:
                ensure_folder()
            except StorageError as exc:
                failures.append(str(exc))
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
        self.stdout.write("Readiness, document storage folder and scan backlog checks passed")
