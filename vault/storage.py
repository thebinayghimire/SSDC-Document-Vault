import os
import re
import uuid
from pathlib import Path

from django.conf import settings
from django.core.exceptions import SuspiciousFileOperation

from .drive_auth import StorageError


def path_for(key):
    root = settings.PRIVATE_STORAGE_ROOT.resolve()
    relative = Path(key)
    if relative.is_absolute() or ".." in relative.parts or not relative.parts:
        raise SuspiciousFileOperation("Invalid storage identifier")
    target = root / relative
    # Reject symlinks at every component, including links that resolve inside root.
    current = root
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            raise SuspiciousFileOperation("Symlinks are not permitted")
    if not target.resolve().is_relative_to(root):
        raise SuspiciousFileOperation("Invalid storage identifier")
    return target


def write_exclusive(key, chunks):
    path = path_for(key)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    with os.fdopen(os.open(path, flags, 0o600), "wb") as stream:
        for chunk in chunks:
            stream.write(chunk)
    return path


def write_atomic(key, chunks):
    """Replace a generated preview only after its complete contents are written."""
    path = path_for(key)
    staging_key = str(Path(key).with_name(f".{path.name}.{uuid.uuid4().hex}.tmp"))
    staging = path_for(staging_key)
    try:
        write_exclusive(staging_key, chunks)
        os.replace(staging, path_for(key))
    finally:
        staging.unlink(missing_ok=True)
    return path


class LocalStream:
    def __init__(self, path, start, length):
        self.stream = path.open("rb")
        self.stream.seek(start)
        self.remaining = length

    def __iter__(self):
        try:
            while self.remaining:
                block = self.stream.read(min(65536, self.remaining))
                if not block:
                    raise StorageError("integrity")
                self.remaining -= len(block)
                yield block
        finally:
            self.close()

    def close(self):
        self.stream.close()


class PrivateFilesystemStorage:
    def put(self, key, path, mime, name):
        if path != path_for(key):
            with path.open("rb") as stream:
                write_atomic(key, iter(lambda: stream.read(65536), b""))

    def size(self, key):
        try:
            return path_for(key).stat().st_size
        except FileNotFoundError:
            raise StorageError("missing") from None

    def exists(self, key):
        return path_for(key).is_file()

    def open(self, key, start=0, end=None):
        try:
            length = self.size(key) if end is None else end - start + 1
            return LocalStream(path_for(key), start, length)
        except FileNotFoundError:
            raise StorageError("missing") from None

    def delete_orphan(self, key):
        path_for(key).unlink(missing_ok=True)


def provider(name=None):
    name = name or settings.DOCUMENT_STORAGE_PROVIDER
    if name == "filesystem":
        return PrivateFilesystemStorage()
    if name == "gdrive":
        from .drive_storage import GoogleDriveStorage

        return GoogleDriveStorage()
    raise StorageError("configuration")


def key_is_referenced(key):
    from .models import Version

    if (
        Version.objects.filter(storage_key=key).exists()
        or Version.objects.filter(thumbnail_key=key).exists()
    ):
        return True
    match = re.fullmatch(r"thumbnails/([0-9a-f-]{36})\.jpg", key)
    if not match:
        return False
    try:
        identifier = uuid.UUID(match[1])
    except ValueError:
        return False
    return Version.objects.filter(pk=identifier, status=Version.Status.QUARANTINED).exists()
