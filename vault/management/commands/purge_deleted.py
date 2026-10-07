from django.core.management.base import BaseCommand, CommandError
from django.db import transaction
from django.utils.dateparse import parse_datetime

from audit.services import record
from vault.models import Document
from vault.storage import path_for


class Command(BaseCommand):
    help = "Dry-run physical purge of soft-deleted documents before an approved UTC cutoff."

    def add_arguments(self, parser):
        parser.add_argument("--before", required=True)
        parser.add_argument("--execute", action="store_true")
        parser.add_argument("--policy-reference")

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
                document = (
                    Document.objects.select_for_update()
                    .filter(pk=identifier, deleted_at__lt=cutoff)
                    .first()
                )
                if not document:
                    continue
                keys = [
                    key
                    for version in document.versions.all()
                    for key in (version.storage_key, version.thumbnail_key)
                    if key
                ]
                document.delete()
                record(None, "operator_purge", identifier)
                transaction.on_commit(
                    lambda keys=keys: [path_for(key).unlink(missing_ok=True) for key in keys]
                )
