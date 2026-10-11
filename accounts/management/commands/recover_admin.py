"""Audited operator MFA recovery after independently verified account ownership."""

from getpass import getpass

from django.conf import settings
from django.contrib.auth.password_validation import validate_password
from django.core.management.base import BaseCommand, CommandError
from django.db import connection, transaction
from django.db.models import F

from accounts.models import User
from audit.services import record
from vault.maintenance import operator_job


class Command(BaseCommand):
    help = __doc__

    def add_arguments(self, parser):
        parser.add_argument("staff_id")
        parser.add_argument("--verified-identity", action="store_true", required=True)
        parser.add_argument("--policy-reference", required=True)
        parser.add_argument("--reset-password", action="store_true")

    @operator_job
    def handle(self, **options):
        if not options["policy_reference"].strip() or len(options["policy_reference"]) > 200:
            raise CommandError(
                "Provide a non-secret recovery approval reference of at most 200 characters"
            )
        with transaction.atomic():
            if settings.PRODUCTION:
                with connection.cursor() as cursor:
                    cursor.execute("SELECT current_user")
                    if cursor.fetchone()[0] != "ssdc_migrator":
                        raise CommandError(
                            "Production recovery requires the operator migration identity"
                        )
            user = (
                User.objects.select_for_update()
                .filter(username=options["staff_id"], is_active=True)
                .first()
            )
            if user is None or not user.is_portal_admin:
                raise CommandError("Recovery requires an existing active administrator")
            if options["reset_password"]:
                password = getpass("New administrator password: ")
                if password != getpass("Confirm new administrator password: "):
                    raise CommandError("Passwords did not match; no changes committed")
                validate_password(password, user)
                user.set_password(password)
                user.save(update_fields=["password"])
            User.objects.filter(pk=user.pk).update(
                mfa_secret="",
                mfa_confirmed=False,
                mfa_last_step=-1,
                recovery_hashes=[],
                auth_version=F("auth_version") + 1,
            )
            record(
                None,
                "operator_admin_recovery",
                user.pk,
                details={"subject_id": user.pk, "policy_reference": options["policy_reference"]},
            )
        self.stdout.write(
            "MFA reset and sessions/challenges revoked. Administrator must sign in and enroll again."
        )
