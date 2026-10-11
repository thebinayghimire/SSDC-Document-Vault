from django.core.management.base import BaseCommand, CommandError
from django.db import transaction
from django.utils.dateparse import parse_datetime

from audit.services import record
from vault.maintenance import operator_job
from vault.models import Document
from vault.mutations import lock_policy_writes
from vault.storage import path_for, provider


def complete_purge(identifier, keys):
    try:
        for name, key in keys:
            if name == "filesystem":
                path_for(key).unlink(missing_ok=True)
            else:
                provider(name).delete_orphan(key)
                path_for(key).unlink(missing_ok=True)
    except Exception:
        record(None, "operator_purge", identifier, "failed")
        raise
    record(None, "operator_purge", identifier, "success")


class Command(BaseCommand):
    help = "Dry-run physical purge of soft-deleted documents before an approved UTC cutoff."

    def add_arguments(self, parser):
        parser.add_argument("--before", required=True)
        parser.add_argument("--execute", action="store_true")
        parser.add_argument("--policy-reference")

    @operator_job
    def handle(self, *args, **options):
        cutoff = parse_datetime(options["before"])
        if cutoff is None or cutoff.tzinfo is None:
            raise CommandError("Provide a timezone-aware ISO timestamp")
        if options["execute"] and not options["policy_reference"]:
            raise CommandError("Execution requires an approved --policy-reference")
        ids = list(Document.objects.filter(deleted_at__lt=cutoff).values_list("pk", flat=True))
        self.stdout.write(f"Eligible documents: {len(ids)}")
        if not options["execute"]:
            self.stdout.write("Dry run; no changes made")
            return
        for identifier in ids:
            with transaction.atomic():
                lock_policy_writes()
                document = (
                    Document.objects.select_for_update()
                    .filter(pk=identifier, deleted_at__lt=cutoff)
                    .first()
                )
                if not document:
                    continue
                keys = [
                    (version.storage_provider, key)
                    for version in document.versions.all()
                    for key in (version.storage_key, version.thumbnail_key)
                    if key
                ]
                document.delete()
                record(
                    None,
                    "operator_purge",
                    identifier,
                    "scheduled",
                    details={
                        "policy_reference": options["policy_reference"],
                        "object_type": "vault.document",
                        "object_id": str(identifier),
                    },
                )
                transaction.on_commit(
                    lambda identifier=identifier, keys=keys: complete_purge(identifier, keys)
                )
