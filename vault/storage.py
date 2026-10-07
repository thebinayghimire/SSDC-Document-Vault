import os
from pathlib import Path

from django.conf import settings
from django.core.exceptions import SuspiciousFileOperation


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
