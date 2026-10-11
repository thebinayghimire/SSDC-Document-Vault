"""Apply runtime grants after every migration using the schema-owner identity."""

from django.core.management.base import BaseCommand, CommandError
from django.db import connection, transaction


class Command(BaseCommand):
    help = __doc__

    def handle(self, **options):
        with transaction.atomic(), connection.cursor() as cursor:
            cursor.execute("SELECT current_user")
            if cursor.fetchone()[0] != "ssdc_migrator":
                raise CommandError("Run using the dedicated ssdc_migrator identity")
            cursor.execute(
                "SELECT rolsuper, rolcreatedb, rolcreaterole, rolreplication, rolbypassrls "
                "FROM pg_roles WHERE rolname = 'ssdc_runtime'"
            )
            role = cursor.fetchone()
            if role is None or any(role):
                raise CommandError("Runtime role is missing or has forbidden privileges")
            cursor.execute(
                "SELECT EXISTS (SELECT 1 FROM pg_auth_members "
                "WHERE member = 'ssdc_runtime'::regrole)"
            )
            if cursor.fetchone()[0]:
                raise CommandError("Runtime role must not be a member of another role")
            cursor.execute(
                "SELECT EXISTS (SELECT 1 FROM pg_namespace "
                "WHERE nspowner = 'ssdc_runtime'::regrole) "
                "OR EXISTS (SELECT 1 FROM pg_class WHERE relowner = 'ssdc_runtime'::regrole) "
                "OR EXISTS (SELECT 1 FROM pg_database WHERE datdba = 'ssdc_runtime'::regrole) "
                "OR EXISTS (SELECT 1 FROM pg_proc WHERE proowner = 'ssdc_runtime'::regrole)"
            )
            if cursor.fetchone()[0]:
                raise CommandError(
                    "Runtime role must not own database, schema or application objects"
                )
            cursor.execute("REVOKE ALL ON ALL TABLES IN SCHEMA public FROM ssdc_runtime")
            cursor.execute("REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM ssdc_runtime")
            for table in connection.introspection.table_names(cursor):
                quoted = connection.ops.quote_name(table)
                privileges = (
                    "SELECT"
                    if table == "django_migrations"
                    else "SELECT, INSERT"
                    if table == "audit_event"
                    else "SELECT, INSERT, UPDATE, DELETE"
                )
                cursor.execute(f"GRANT {privileges} ON {quoted} TO ssdc_runtime")
            cursor.execute("GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO ssdc_runtime")
        self.stdout.write("Runtime grants applied; audit events are insert/read-only.")
