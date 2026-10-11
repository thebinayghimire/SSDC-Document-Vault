import uuid

from django.core.management.base import BaseCommand, CommandError
from django.db import connection, transaction
from django.utils.dateparse import parse_datetime

from audit.services import record
from vault.maintenance import operator_job
from vault.models import DriveObject, Version
from vault.storage import key_is_referenced, path_for, provider


def checkpoint(identifier, outcome):
    with transaction.atomic(durable=True):
        record(None, "operator_orphan_cleanup", identifier, outcome)


class Command(BaseCommand):
    help = "Dry-run cleanup of unreferenced files from interrupted uploads."

    def add_arguments(self, parser):
        parser.add_argument("--before", required=True)
        parser.add_argument("--execute", action="store_true")

    @operator_job
    def handle(self, *args, **options):
        cutoff = parse_datetime(options["before"])
        if cutoff is None or cutoff.tzinfo is None:
            raise CommandError("Provide a timezone-aware cutoff older than any in-flight upload")
        if options["execute"] and (connection.in_atomic_block or not connection.get_autocommit()):
            raise CommandError("Run file cleanup outside an existing database transaction")
        referenced = {
            key
            for row in Version.objects.values_list("storage_key", "thumbnail_key")
            for key in row
            if key
        }
        referenced.update(
            f"thumbnails/{identifier}.jpg"
            for identifier in Version.objects.filter(status=Version.Status.QUARANTINED).values_list(
                "pk", flat=True
            )
        )
        candidates = []
        staging = list(
            Version.objects.filter(
                storage_provider="gdrive",
                status=Version.Status.READY,
                uploaded_at__lt=cutoff,
            )
        )
        self.stdout.write(f"Published Drive versions eligible for staging cleanup: {len(staging)}")
        remote = list(DriveObject.objects.filter(created_at__lt=cutoff).exclude(key__in=referenced))
        self.stdout.write(f"Unreferenced Drive intents eligible: {len(remote)}")
        for directory in ("originals", "thumbnails"):
            parent = path_for(directory)
            if not parent.exists():
                continue
            for path in parent.iterdir():
                key = f"{directory}/{path.name}"
                checked = path_for(key)
                if (
                    checked.is_file()
                    and key not in referenced
                    and checked.stat().st_mtime < cutoff.timestamp()
                ):
                    candidates.append((key, checked))
        self.stdout.write(f"Unreferenced files eligible: {len(candidates)}")
        if options["execute"]:
            identifier = uuid.uuid4().hex
            checkpoint(identifier, "started")
            self.stdout.write(f"Cleanup operation: {identifier}")
            try:
                for key, path in candidates:
                    # Operator must stop uploads; recheck reference before unlink.
                    if not key_is_referenced(key):
                        path.unlink(missing_ok=True)
                for obj in remote:
                    # Quiesce all writers first; provider rechecks reference, ownership and hash.
                    provider("gdrive").delete_orphan(obj.key)
                for version in staging:
                    current = Version.objects.filter(
                        pk=version.pk, storage_provider="gdrive", status=Version.Status.READY
                    ).first()
                    if not current:
                        continue
                    for key in (current.storage_key, current.thumbnail_key):
                        if key and path_for(key).is_file():
                            # Verify the remote copy before removing interrupted post-commit staging.
                            provider("gdrive").size(key)
                            path_for(key).unlink(missing_ok=True)
            except Exception:
                checkpoint(identifier, "failed")
                raise
            checkpoint(identifier, "success")
        else:
            self.stdout.write("Dry run; no changes made")
