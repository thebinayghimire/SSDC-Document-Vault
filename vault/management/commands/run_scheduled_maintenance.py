"""Run bounded background tasks and readiness checks under the snapshot protocol."""

from django.core.management import call_command
from django.core.management.base import BaseCommand

from vault.maintenance import operator_job


class Command(BaseCommand):
    help = __doc__

    @operator_job
    def handle(self, **options):
        call_command("retry_scans", limit=20, stdout=self.stdout)
        call_command("clearsessions", stdout=self.stdout)
        call_command("clear_rates", stdout=self.stdout)
        call_command("operations_check", stdout=self.stdout)
