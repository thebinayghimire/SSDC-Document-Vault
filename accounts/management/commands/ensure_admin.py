"""Create the initial portal administrator from deployment environment variables."""

import os

from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.core.management.base import BaseCommand, CommandError
from django.db import transaction

from accounts.models import User


class Command(BaseCommand):
    help = "Idempotently create or promote the deployment administrator."

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
                created = True
            else:
                created = False
                changed = []
                desired = {
                    "is_active": True,
                    "is_staff": True,
                    "is_superuser": True,
                    "role": User.Role.ADMIN,
                }
                if email and user.email != email:
                    desired["email"] = email
                for field, value in desired.items():
                    if getattr(user, field) != value:
                        setattr(user, field, value)
                        changed.append(field)
                if changed:
                    user.save(update_fields=changed)

        action = "created" if created else "already exists and is configured"
        self.stdout.write(self.style.SUCCESS(f"Administrator {username!r} {action}."))
