"""Restore a private archive only into an empty isolated data volume."""

import sys
import tarfile
import tempfile
from pathlib import PurePosixPath

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError


class Command(BaseCommand):
    help = __doc__

    def add_arguments(self, parser):
        parser.add_argument("--check-empty", action="store_true")

    def handle(self, **options):
        root = settings.PRIVATE_STORAGE_ROOT
        root.mkdir(parents=True, exist_ok=True, mode=0o700)
        if any(path.name != ".maintenance.lock" for path in root.iterdir()):
            raise CommandError("Restore requires an empty private volume")
        if options["check_empty"]:
            self.stdout.write("Private restore volume is empty")
            return
        # Disk-backed staging on the destination volume, not the bounded /tmp.
        with tempfile.TemporaryFile(dir=root) as incoming:
            while block := sys.stdin.buffer.read(1024 * 1024):
                incoming.write(block)
            incoming.seek(0)
            with tarfile.open(fileobj=incoming) as archive:
                members = archive.getmembers()
                for member in members:
                    path = PurePosixPath(member.name)
                    if (
                        path.is_absolute()
                        or ".." in path.parts
                        or not path.parts
                        or path.parts[0] != "private"
                        or not (member.isfile() or member.isdir())
                        or path.name in {".maintenance.lock", ".operator.lock"}
                    ):
                        raise CommandError("Restore archive contains an unsafe member")
                    member.name = str(PurePosixPath(*path.parts[1:]))
                if sum(member.size for member in members) > settings.MAX_STORAGE_BYTES * 2:
                    raise CommandError(
                        "Restored private files exceed the configured restore budget"
                    )
                archive.extractall(root, members=members, filter="data")
        self.stdout.write("Private files restored; verify integrity before opening traffic")
