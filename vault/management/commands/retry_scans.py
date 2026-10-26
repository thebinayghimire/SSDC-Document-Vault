from django.core.management.base import BaseCommand

from vault.maintenance import operator_job
from vault.models import Document, Version
from vault.services import process_version
from vault.storage import path_for


class Command(BaseCommand):
    help = "Retry validation and scanning of quarantined versions (bounded batch)."

    def add_arguments(self, parser):
        parser.add_argument("--limit", type=int, default=20)

    @operator_job
    def handle(self, *args, **options):
        for version in Version.objects.filter(status=Version.Status.QUARANTINED).order_by(
            "uploaded_at"
        )[: max(1, min(options["limit"], 100))]:
            if not path_for(version.storage_key).is_file():
                self.stdout.write(
                    f"{version.pk}: staging missing; run cleanup_orphans after the retention cutoff"
                )
                continue
            try:
                result = process_version(version)
            except (Document.DoesNotExist, Version.DoesNotExist):
                self.stdout.write(f"{version.pk}: removed; skipped")
                continue
            self.stdout.write(f"{result.pk}: {result.status}")
