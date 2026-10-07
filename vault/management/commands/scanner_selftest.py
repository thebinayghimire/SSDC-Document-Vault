import tempfile
from pathlib import Path

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError

from vault.scanner import scan


class Command(BaseCommand):
    help = "Verify real antivirus INSTREAM with harmless clean and EICAR test fixtures."

    def handle(self, *args, **options):
        if settings.SCAN_MODE != "clamav":
            raise CommandError("Self-test requires real ClamAV scanning")
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "fixture"
            path.write_bytes(b"Synthetic clean test fixture")
            if scan(path) != "clean":
                raise CommandError("Scanner failed clean-file check")
            path.write_bytes(
                b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
            )
            if scan(path) != "infected":
                raise CommandError("Scanner failed EICAR detection check")
        self.stdout.write(
            "ClamAV INSTREAM self-test passed: clean fixture accepted, EICAR detected."
        )
