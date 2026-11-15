"""Deliver due transactional email notifications with bounded retries."""

from django.core.management.base import BaseCommand

from accounts.services.notifications import process_notifications


class Command(BaseCommand):
    help = "Recover stale email leases and deliver due transactional notifications."

    def add_arguments(self, parser):
        parser.add_argument(
            "--limit", type=int, default=50, help="Maximum notifications to process."
        )
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Report due notifications without changing delivery state.",
        )

    def handle(self, *args, **options):
        limit = options["limit"]
        if limit < 1:
            self.stderr.write("--limit must be at least 1")
            return
        result = process_notifications(limit=limit, dry_run=options["dry_run"])
        self.stdout.write(
            "due={due} recovered={recovered} sent={sent} failed={failed}".format(**result)
        )
