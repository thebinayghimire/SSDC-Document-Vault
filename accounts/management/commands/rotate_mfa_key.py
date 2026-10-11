"""Atomically re-encrypt MFA seeds under an independently generated replacement key."""

from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken
from django.conf import settings
from django.core.management.base import BaseCommand, CommandError
from django.db import transaction
from django.db.models import F

from accounts.models import User
from audit.services import record
from vault.maintenance import maintenance_lock


class Command(BaseCommand):
    help = __doc__

    def add_arguments(self, parser):
        parser.add_argument("--new-key-file", type=Path, required=True)
        parser.add_argument("--policy-reference", required=True)
        parser.add_argument("--execute", action="store_true")

    def handle(self, **options):
        try:
            new_key = options["new_key_file"].read_bytes().strip()
            replacement = Fernet(new_key)
            previous = Fernet(settings.MFA_ENCRYPTION_KEY.encode())
        except (OSError, ValueError) as exc:
            raise CommandError(
                "Replacement key must be a readable private Fernet key file"
            ) from exc
        if new_key == settings.MFA_ENCRYPTION_KEY.encode():
            raise CommandError("Replacement key must differ from the current key")
        if not options["policy_reference"].strip() or len(options["policy_reference"]) > 200:
            raise CommandError("Provide a non-secret rotation approval reference")
        with maintenance_lock(exclusive=True), transaction.atomic():
            users = list(User.objects.select_for_update().exclude(mfa_secret="").order_by("pk"))
            try:
                changes = [
                    (user, replacement.encrypt(previous.decrypt(user.mfa_secret.encode())).decode())
                    for user in users
                ]
            except InvalidToken as exc:
                try:
                    for user in users:
                        replacement.decrypt(user.mfa_secret.encode())
                except InvalidToken:
                    pass
                else:
                    self.stdout.write(
                        "All seeds already use the replacement key. No changes made; mount that key before restarting writers."
                    )
                    return
                raise CommandError(
                    "An existing seed cannot be decrypted; no changes committed"
                ) from exc
            if not options["execute"]:
                self.stdout.write(f"Dry run: {len(changes)} seeds validated; no changes committed")
                return
            for user, encrypted in changes:
                User.objects.filter(pk=user.pk).update(
                    mfa_secret=encrypted, auth_version=F("auth_version") + 1
                )
            record(
                None,
                "operator_mfa_key_rotated",
                details={"policy_reference": options["policy_reference"]},
            )
        self.stdout.write(
            "Seed rotation committed. Keep writers stopped until the new key is mounted and verified."
        )
