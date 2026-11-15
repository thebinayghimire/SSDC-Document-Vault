"""Close staff registration applications whose email or review window elapsed."""

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError

from accounts.services.registration import expire_due_registrations


class Command(BaseCommand):
    help = "Expire stale staff registration applications and enqueue notifications."

    def add_arguments(self, parser):
        parser.add_argument("--limit", type=int, default=100, help="Maximum requests to expire.")
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Report how many requests are due without expiring them.",
        )
        parser.add_argument(
            "--base-url",
            default="",
            help="Absolute site origin for email links; defaults to PUBLIC_BASE_URL.",
        )

    def handle(self, *args, **options):
        limit = options["limit"]
        if limit < 1:
            raise CommandError("--limit must be at least 1")
        base_url = (options["base_url"] or settings.PUBLIC_BASE_URL).rstrip("/")
        if not options["dry_run"] and not base_url:
            raise CommandError("Configure PUBLIC_BASE_URL or pass --base-url for email links.")
        expired = expire_due_registrations(
            limit=limit,
            base_url=base_url,
            dry_run=options["dry_run"],
        )
        label = "due" if options["dry_run"] else "expired"
        self.stdout.write(f"{label}={expired}")
