"""Expire staff applications that passed their verification or review window."""

from django.conf import settings
from django.core.management.base import BaseCommand

from accounts.services.registration import expire_due_registrations


class Command(BaseCommand):
    help = "Expire due email-pending and pending-review staff registration requests."

    def add_arguments(self, parser):
        parser.add_argument(
            "--limit",
            type=int,
            default=100,
            help="Maximum number of applications to expire in this run (default: 100).",
        )
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Report how many applications are due without changing them.",
        )
        parser.add_argument(
            "--base-url",
            default="",
            help="Public base URL used to build links in expiry notifications.",
        )

    def handle(self, *args, **options):
        base_url = options["base_url"] or getattr(settings, "PUBLIC_BASE_URL", "")
        count = expire_due_registrations(
            limit=options["limit"],
            base_url=base_url,
            dry_run=options["dry_run"],
        )
        if options["dry_run"]:
            self.stdout.write(f"due={count}")
        else:
            self.stdout.write(f"expired={count}")
