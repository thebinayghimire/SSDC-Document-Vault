"""Shared file lock coordinates requests/operator jobs with paired snapshots."""

import os
from contextlib import contextmanager
from functools import wraps

from django.conf import settings


class MaintenanceBusy(Exception):
    pass


@contextmanager
def maintenance_lock(exclusive=False):
    # Windows is a development host; production requires the Linux flock protocol.
    if os.name != "posix":
        if settings.PRODUCTION:
            raise MaintenanceBusy("Production maintenance requires Linux")
        yield
        return
    import fcntl

    root = settings.PRIVATE_STORAGE_ROOT
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    flags = os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW
    descriptor = os.open(root / ".maintenance.lock", flags, 0o600)
    try:
        try:
            fcntl.flock(descriptor, (fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH) | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise MaintenanceBusy("Maintenance or another operator job is in progress") from exc
        yield
    finally:
        os.close(descriptor)


def operator_job(function):
    @wraps(function)
    def wrapped(*args, **kwargs):
        from django.core.management.base import CommandError

        try:
            with maintenance_lock():
                return function(*args, **kwargs)
        except MaintenanceBusy as exc:
            raise CommandError(str(exc)) from exc

    return wrapped
