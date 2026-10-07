from django.core.management.base import BaseCommand

from vault.models import Version
from vault.services import process_version


class Command(BaseCommand):
    help = "Retry validation and scanning of quarantined versions (bounded batch)."

    def add_arguments(self, parser):
        parser.add_argument("--limit", type=int, default=20)

    def handle(self, *args, **options):
        for version in Version.objects.filter(status=Version.Status.QUARANTINED).order_by(
            "uploaded_at"
        )[: max(1, min(options["limit"], 100))]:
            result = process_version(version)
            self.stdout.write(f"{result.pk}: {result.status}")
