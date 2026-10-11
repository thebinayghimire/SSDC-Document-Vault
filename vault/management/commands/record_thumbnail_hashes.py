"""Record integrity metadata for existing previews during quiesced maintenance."""

import hashlib

from django.core.management.base import BaseCommand, CommandError
from django.db import transaction

from audit.services import record
from vault.maintenance import maintenance_lock
from vault.models import Version
from vault.storage import provider


class Command(BaseCommand):
    help = __doc__

    def add_arguments(self, parser):
        parser.add_argument("--execute", action="store_true")

    def handle(self, **options):
        with maintenance_lock(exclusive=True):
            candidates = Version.objects.filter(
                status=Version.Status.READY, thumbnail_sha256=""
            ).exclude(thumbnail_key="")
            self.stdout.write(f"Previews without integrity hashes: {candidates.count()}")
            for version in candidates.iterator():
                digest, size = hashlib.sha256(), 0
                content = provider(version.storage_provider).open(version.thumbnail_key)
                try:
                    for block in content:
                        digest.update(block)
                        size += len(block)
                finally:
                    content.close()
                if size != version.thumbnail_size:
                    raise CommandError("Existing preview does not match its recorded size")
                if options["execute"]:
                    with transaction.atomic():
                        current = Version.objects.select_for_update().get(pk=version.pk)
                        if (
                            current.thumbnail_sha256
                            or current.thumbnail_key != version.thumbnail_key
                        ):
                            raise CommandError("Preview changed during integrity recording")
                        current.thumbnail_sha256 = digest.hexdigest()
                        current.save(update_fields=["thumbnail_sha256"])
                        record(None, "preview_integrity_recorded", current.pk)
