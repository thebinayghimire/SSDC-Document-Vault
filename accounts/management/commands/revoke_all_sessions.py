"""Revoke all authenticated sessions and pending challenges after host restoration."""

from django.contrib.sessions.models import Session
from django.core.management.base import BaseCommand
from django.db import transaction
from django.db.models import F

from accounts.models import User
from audit.services import record


class Command(BaseCommand):
    help = __doc__

    def add_arguments(self, parser):
        parser.add_argument("--policy-reference", required=True)

    def handle(self, **options):
        with transaction.atomic():
            User.objects.update(auth_version=F("auth_version") + 1)
            Session.objects.all().delete()
            record(
                None,
                "operator_sessions_revoked",
                details={"policy_reference": options["policy_reference"]},
            )
        self.stdout.write("All sessions and pending account challenges revoked")
