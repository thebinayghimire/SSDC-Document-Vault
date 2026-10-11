"""Quiesced paired-backup snapshot; Drive is a primary store, not a backup."""

import hashlib
import sys
import tarfile
import tempfile

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError

from vault.models import Version
from vault.storage import StorageError, path_for, provider


class Command(BaseCommand):
    help = (
        "Stream a private tar snapshot, including referenced Drive blobs. Stop all writers first."
    )

    def add_arguments(self, parser):
        parser.add_argument("--stdout", dest="stream", action="store_true", required=True)

    def handle(self, *args, **options):
        # Validate legacy and quarantined local originals before claiming a paired snapshot.
        local_versions = Version.objects.exclude(status=Version.Status.REJECTED).exclude(
            storage_provider="gdrive",
            status=Version.Status.READY,
        )
        for version in local_versions.iterator():
            path = path_for(version.storage_key)
            try:
                with path.open("rb") as stream:
                    digest = hashlib.file_digest(stream, "sha256").hexdigest()
                valid = digest == version.sha256 and path.stat().st_size == version.size
                if version.thumbnail_key:
                    thumbnail = path_for(version.thumbnail_key)
                    with thumbnail.open("rb") as stream:
                        thumbnail_hash = hashlib.file_digest(stream, "sha256").hexdigest()
                    valid = (
                        valid
                        and thumbnail.stat().st_size == version.thumbnail_size
                        and thumbnail_hash == version.thumbnail_sha256
                    )
            except OSError:
                valid = False
            if not valid:
                raise CommandError(f"Backup local integrity check failed: {version.pk}")
        versions = list(
            Version.objects.filter(storage_provider="gdrive", status=Version.Status.READY)
        )
        keys = {
            key
            for version in versions
            for key in (version.storage_key, version.thumbnail_key)
            if key
        }
        try:
            with tarfile.open(fileobj=sys.stdout.buffer, mode="w|") as archive:
                root = settings.PRIVATE_STORAGE_ROOT
                if root.exists():
                    for path in root.rglob("*"):
                        key = path.relative_to(root).as_posix()
                        if key in {".maintenance.lock", ".operator.lock"}:
                            continue
                        checked = path_for(key)
                        if checked.is_file() and key not in keys:
                            archive.add(checked, arcname=f"private/{key}", recursive=False)
                for version in versions:
                    storage = provider(version.storage_provider)
                    for key in (version.storage_key, version.thumbnail_key):
                        if not key:
                            continue
                        size = storage.size(key)
                        digest, received = hashlib.sha256(), 0
                        # One bounded upload-sized spool, discarded immediately after archiving.
                        with tempfile.TemporaryFile() as temporary:
                            content = storage.open(key)
                            try:
                                for block in content:
                                    received += len(block)
                                    digest.update(block)
                                    temporary.write(block)
                            finally:
                                content.close()
                            if (
                                received != size
                                or (
                                    key == version.storage_key
                                    and (
                                        received != version.size
                                        or digest.hexdigest() != version.sha256
                                    )
                                )
                                or (
                                    key == version.thumbnail_key
                                    and (
                                        received != version.thumbnail_size
                                        or digest.hexdigest() != version.thumbnail_sha256
                                    )
                                )
                            ):
                                raise CommandError("Backup document integrity check failed")
                            temporary.seek(0)
                            info = tarfile.TarInfo(f"private/{key}")
                            info.size, info.mode = received, 0o600
                            archive.addfile(info, temporary)
        except StorageError as exc:
            raise CommandError(str(exc)) from None
