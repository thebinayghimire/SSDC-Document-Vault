"""Verify an explicitly identified pilot target without changing database contents."""

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError
from django.db import connection


class Command(BaseCommand):
    help = __doc__

    def add_arguments(self, parser):
        for field in ("host", "database", "user"):
            parser.add_argument(f"--expected-{field}", required=True)

    def handle(self, **options):
        config = settings.DATABASES["default"]
        for field, key in (("host", "HOST"), ("database", "NAME"), ("user", "USER")):
            if config[key] != options[f"expected_{field}"]:
                raise CommandError("Configured database target differs from the expected pilot")
        if config["OPTIONS"].get("sslmode") != "verify-full":
            raise CommandError("Pilot database check requires verified TLS")
        try:
            with connection.cursor() as cursor:
                cursor.execute("SELECT current_database(), current_user")
                database, user = cursor.fetchone()
                # Supavisor removes the project suffix from the authenticated role name.
                role = options["expected_user"].split(".", 1)[0]
                if database != options["expected_database"] or user != role:
                    raise CommandError("Server database identity differs from the expected pilot")
                if not connection.connection.pgconn.ssl_in_use:
                    raise CommandError("Pilot connection is not using TLS")
                cursor.execute("SELECT 1")
                assert cursor.fetchone() == (1,)
        except CommandError:
            raise
        except Exception:
            # libpq exceptions can contain connection details. Never echo them here.
            raise CommandError(
                "Pilot database check failed; inspect private network/TLS settings"
            ) from None
        finally:
            connection.close()
        self.stdout.write(
            "Pilot database identity and verified TLS connection passed; no data changed."
        )
