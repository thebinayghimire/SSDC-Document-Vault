import hashlib

from django.core.management.base import BaseCommand, CommandError

from vault.models import Version
from vault.storage import StorageError, provider


class Command(BaseCommand):
    help = "Verify private file hashes after restoration; never prints document contents."

    def handle(self, *args, **options):
        failures = 0
        checked = 0
        for version in Version.objects.exclude(status=Version.Status.REJECTED).iterator():
            storage = provider(version.storage_provider)
            checked += 1
            try:
                digest = hashlib.sha256()
                size = 0
                content = storage.open(version.storage_key)
                try:
                    for block in content:
                        digest.update(block)
                        size += len(block)
                finally:
                    content.close()
                valid = digest.hexdigest() == version.sha256 and size == version.size
                if version.thumbnail_key:
                    digest, size = hashlib.sha256(), 0
                    content = storage.open(version.thumbnail_key)
                    try:
                        for block in content:
                            digest.update(block)
                            size += len(block)
                    finally:
                        content.close()
                    valid = (
                        valid
                        and size == version.thumbnail_size
                        and digest.hexdigest() == version.thumbnail_sha256
                    )
            except (OSError, StorageError):
                valid = False
            if not valid:
                failures += 1
                self.stderr.write(f"Integrity check failed: {version.pk}")
        if failures:
            raise CommandError(f"{failures}/{checked} versions failed integrity checks")
        self.stdout.write(f"Verified {checked} versions")
