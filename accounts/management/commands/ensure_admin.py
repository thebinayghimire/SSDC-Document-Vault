"""Create the initial portal administrator from deployment environment variables."""

import os

from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.core.management.base import BaseCommand, CommandError
from django.db import transaction

from accounts.models import User
from audit.services import record


class Command(BaseCommand):
    help = "Create the deployment administrator once, preserving existing account decisions."

    def handle(self, *args, **options):
        username = os.getenv("DJANGO_SUPERUSER_USERNAME", "").strip()
        email = os.getenv("DJANGO_SUPERUSER_EMAIL", "").strip()
        password = os.getenv("DJANGO_SUPERUSER_PASSWORD", "")
        if not username or not password:
            raise CommandError(
                "DJANGO_SUPERUSER_USERNAME and DJANGO_SUPERUSER_PASSWORD are required"
            )

        with transaction.atomic():
            user = User.objects.select_for_update().filter(username=username).first()
            if user is None:
                candidate = User(username=username, email=email, role=User.Role.ADMIN)
                try:
                    validate_password(password, candidate)
                except ValidationError as exc:
                    raise CommandError("DJANGO_SUPERUSER_PASSWORD: " + "; ".join(exc.messages))
                user = User.objects.create_superuser(
                    username=username,
                    email=email,
                    password=password,
                    role=User.Role.ADMIN,
                )
                record(None, "deployment_admin_created", user.pk)
                created = True
            else:
                created = False
                if not user.is_portal_admin or not user.is_superuser:
                    raise CommandError(
                        "The bootstrap username already exists without active administrator "
                        "access. Use account administration or recover_admin; deployment "
                        "will not reactivate or promote an existing account."
                    )

        action = "created" if created else "already exists; account settings preserved"
        self.stdout.write(self.style.SUCCESS(f"Administrator {username!r} {action}."))
