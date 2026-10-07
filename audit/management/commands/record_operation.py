from django.core.management.base import BaseCommand

from audit.services import record


class Command(BaseCommand):
    help = "Record a host operator backup/recovery action without secrets or file paths."

    def add_arguments(self, parser):
        parser.add_argument("action", choices=["backup", "restore_drill", "restore"])
        parser.add_argument("--reference", default="", type=str)

    def handle(self, *args, **options):
        record(None, "operator_" + options["action"], options["reference"][:64])
