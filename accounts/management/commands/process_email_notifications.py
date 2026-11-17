"""Deliver due transactional email and retry failed outbox rows."""

from django.conf import settings
from django.core.management.base import BaseCommand
from django.utils import timezone

from accounts.models import EmailNotification
from accounts.services.notifications import process_notifications


class Command(BaseCommand):
    help = (
        "Deliver due email notifications from the durable outbox. "
        "Use --requeue-dead-letter or --requeue ID to retry exhausted messages."
    )

    def add_arguments(self, parser):
        parser.add_argument(
            "--limit",
            type=int,
            default=50,
            help="Maximum number of notifications to attempt in this run (default: 50).",
        )
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Report how many messages are due without sending or updating anything.",
        )
        parser.add_argument(
            "--requeue-dead-letter",
            action="store_true",
            help="Reset every dead-letter notification to pending before processing.",
        )
        parser.add_argument(
            "--requeue",
            type=int,
            action="append",
            default=[],
            metavar="ID",
            help="Reset one failed or dead-letter notification ID to pending. May be repeated.",
        )

    def handle(self, *args, **options):
        if not settings.EMAIL_DELIVERY_ENABLED:
            self.stderr.write(
                self.style.WARNING(
                    "EMAIL_DELIVERY_ENABLED is disabled; notifications will remain queued."
                )
            )

        now = timezone.now()
        if not options["dry_run"]:
            requeued = 0
            queryset = EmailNotification.objects.filter(
                status__in=[
                    EmailNotification.Status.FAILED,
                    EmailNotification.Status.DEAD_LETTER,
                ]
            )
            if options["requeue"]:
                queryset = queryset.filter(pk__in=options["requeue"])
            elif not options["requeue_dead_letter"]:
                queryset = queryset.none()
            requeued = queryset.update(
                status=EmailNotification.Status.PENDING,
                attempts=0,
                next_attempt_at=now,
                locked_at=None,
                locked_by="",
                last_error="",
                updated_at=now,
            )
            if requeued:
                self.stdout.write(f"Requeued {requeued} notification(s).")

        summary = process_notifications(limit=options["limit"], dry_run=options["dry_run"])
        self.stdout.write(
            "due={due} recovered={recovered} sent={sent} failed={failed}".format(**summary)
        )
