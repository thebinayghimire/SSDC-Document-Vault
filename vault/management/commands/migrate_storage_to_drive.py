import hashlib

from django.core.management.base import BaseCommand, CommandError
from django.db import transaction

from audit.services import record
from vault.drive_storage import network_budget
from vault.models import Version
from vault.processing import processing_claim
from vault.storage import StorageError, path_for, provider


class Command(BaseCommand):
    help = (
        "Copy verified READY filesystem versions into owner Drive. Stop all writers; back up first."
    )

    def add_arguments(self, parser):
        parser.add_argument("--execute", action="store_true")

    def handle(self, *args, **options):
        identifiers = list(
            Version.objects.filter(
                storage_provider="filesystem", status=Version.Status.READY
            ).values_list("pk", flat=True)
        )
        self.stdout.write(f"Eligible filesystem versions: {len(identifiers)}")
        if not options["execute"]:
            self.stdout.write("Dry run; no changes made")
            return
        for identifier in identifiers:
            with processing_claim(identifier) as claimed:
                if not claimed:
                    raise CommandError("A version is still being processed; stop writers first")
                version = Version.objects.get(pk=identifier)
                if (
                    version.storage_provider != "filesystem"
                    or version.status != Version.Status.READY
                ):
                    continue
                path = path_for(version.storage_key)
                try:
                    with path.open("rb") as stream:
                        digest = hashlib.file_digest(stream, "sha256").hexdigest()
                    if digest != version.sha256 or path.stat().st_size != version.size:
                        raise CommandError(f"Integrity check failed: {version.pk}")
                    storage = provider("gdrive")
                    with network_budget():
                        storage.put(
                            version.storage_key, path, version.mime_type, version.original_name
                        )
                        if version.thumbnail_key:
                            storage.put(
                                version.thumbnail_key,
                                path_for(version.thumbnail_key),
                                "image/jpeg",
                                "preview.jpg",
                            )
                    with transaction.atomic():
                        current = Version.objects.select_for_update().get(pk=identifier)
                        if (
                            current.storage_provider != "filesystem"
                            or current.status != Version.Status.READY
                        ):
                            raise CommandError("Version changed during maintenance")
                        current.storage_provider = "gdrive"
                        current.save(update_fields=["storage_provider"])
                        record(None, "storage_migrated_to_drive", identifier)
                        keys = (current.storage_key, current.thumbnail_key)
                        transaction.on_commit(
                            lambda keys=keys: [
                                path_for(key).unlink(missing_ok=True) for key in keys if key
                            ]
                        )
                except (OSError, StorageError) as exc:
                    raise CommandError(
                        str(exc)
                        if isinstance(exc, StorageError)
                        else "Private storage is unavailable"
                    ) from None
        self.stdout.write("Storage migration completed")
