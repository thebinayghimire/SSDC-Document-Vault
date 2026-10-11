"""Hold the snapshot lock across host-side stop/dump/export/encryption/restart."""

import sys

from django.core.management.base import BaseCommand, CommandError

from vault.maintenance import MaintenanceBusy, maintenance_lock


class Command(BaseCommand):
    help = __doc__

    def handle(self, **options):
        try:
            with maintenance_lock(exclusive=True):
                self.stdout.write("SSDC_MAINTENANCE_READY")
                self.stdout.flush()
                sys.stdin.buffer.read()
        except MaintenanceBusy as exc:
            raise CommandError(str(exc)) from exc
