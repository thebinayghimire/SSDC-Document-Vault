import hashlib

from django.core.management.base import BaseCommand, CommandError

from vault.models import Version
from vault.storage import path_for


class Command(BaseCommand):
    help = "Verify private file hashes after restoration; never prints document contents."

    def handle(self, *args, **options):
        failures = 0
        checked = 0
        for version in Version.objects.exclude(status=Version.Status.REJECTED).iterator():
            path = path_for(version.storage_key)
            checked += 1
            try:
                with path.open("rb") as stream:
                    digest = hashlib.file_digest(stream, "sha256").hexdigest()
                valid = digest == version.sha256 and path.stat().st_size == version.size
                if version.thumbnail_key:
                    valid = valid and path_for(version.thumbnail_key).is_file()
            except OSError:
                valid = False
            if not valid:
                failures += 1
                self.stderr.write(f"Integrity check failed: {version.pk}")
        if failures:
            raise CommandError(f"{failures}/{checked} versions failed integrity checks")
        self.stdout.write(f"Verified {checked} versions")
