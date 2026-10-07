from datetime import timedelta

from django.core.management.base import BaseCommand
from django.utils import timezone

from audit.models import RateBucket


class Command(BaseCommand):
    help = "Remove rate buckets unused for at least 24 hours; audit events are retained."

    def handle(self, *args, **options):
        count, _ = RateBucket.objects.filter(
            updated_at__lt=timezone.now() - timedelta(hours=24)
        ).delete()
        self.stdout.write(f"Removed {count} stale rate buckets")
