import hashlib

from django.core.management.base import BaseCommand, CommandError
from django.db import transaction

from audit.services import record
from vault.models import Version
from vault.storage import path_for


class Command(BaseCommand):
    help = "Verify restored paired-backup files and switch versions to private filesystem. Stop writers first."

    def add_arguments(self, parser):
        parser.add_argument("--execute", action="store_true")

    def handle(self, *args, **options):
        with transaction.atomic():
            versions = list(
                Version.objects.select_for_update().exclude(status=Version.Status.REJECTED)
            )
            for version in versions:
                path = path_for(version.storage_key)
                try:
                    with path.open("rb") as stream:
                        digest = hashlib.file_digest(stream, "sha256").hexdigest()
                    valid = path.stat().st_size == version.size and digest == version.sha256
                    if version.thumbnail_key:
                        valid = valid and path_for(version.thumbnail_key).is_file()
                except OSError:
                    valid = False
                if not valid:
                    raise CommandError(f"Restored version failed integrity checks: {version.pk}")
            if options["execute"]:
                Version.objects.filter(pk__in=[v.pk for v in versions]).update(
                    storage_provider="filesystem"
                )
                record(None, "storage_restored_to_filesystem", outcome="success")
        self.stdout.write(
            f"Verified {len(versions)} versions; "
            + (
                "switched to private filesystem"
                if options["execute"]
                else "dry run; no changes made"
            )
        )
