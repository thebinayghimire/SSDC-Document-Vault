"""Generate a Fernet key suitable for DRIVE_TOKEN_ENCRYPTION_KEY."""

from cryptography.fernet import Fernet
from django.core.management.base import BaseCommand


class Command(BaseCommand):
    help = "Print a new DRIVE_TOKEN_ENCRYPTION_KEY value."

    def handle(self, *args, **options):
        self.stdout.write(Fernet.generate_key().decode("ascii"))
