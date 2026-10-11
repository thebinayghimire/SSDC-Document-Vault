"""Verify recovered MFA ciphertext with the mounted key without exposing seeds."""

from cryptography.fernet import InvalidToken
from django.core.management.base import BaseCommand, CommandError

from accounts.mfa import decrypt
from accounts.models import User


class Command(BaseCommand):
    help = __doc__

    def handle(self, **options):
        count = 0
        for user in User.objects.exclude(mfa_secret="").iterator():
            try:
                decrypt(user.mfa_secret)
            except InvalidToken as exc:
                raise CommandError("A stored MFA seed does not match the mounted key") from exc
            count += 1
        self.stdout.write(f"Verified {count} MFA seeds; no seed values printed")
