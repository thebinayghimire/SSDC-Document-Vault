from django.core.management.base import BaseCommand, CommandError
from django.utils.dateparse import parse_datetime

from audit.services import record
from vault.models import Version
from vault.storage import path_for


class Command(BaseCommand):
    help = "Dry-run cleanup of unreferenced files from interrupted uploads."

    def add_arguments(self, parser):
        parser.add_argument("--before", required=True)
        parser.add_argument("--execute", action="store_true")

    def handle(self, *args, **options):
        cutoff = parse_datetime(options["before"])
        if cutoff is None or cutoff.tzinfo is None:
            raise CommandError("Provide a timezone-aware cutoff older than any in-flight upload")
        referenced = {
            key
            for row in Version.objects.values_list("storage_key", "thumbnail_key")
            for key in row
            if key
        }
        candidates = []
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
            for key, path in candidates:
                # Operator must stop uploads for cleanup; recheck reference immediately before unlink.
                if (
                    not Version.objects.filter(storage_key=key).exists()
                    and not Version.objects.filter(thumbnail_key=key).exists()
                ):
                    path.unlink(missing_ok=True)
            record(None, "operator_orphan_cleanup")
        else:
            self.stdout.write("Dry run; no changes made")
