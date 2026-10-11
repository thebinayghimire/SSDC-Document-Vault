"""Claim one version without holding a transaction during parsing or scanning."""

import hashlib
from contextlib import contextmanager

from django.conf import settings
from django.db import DatabaseError, connection


@contextmanager
def parser_slot():
    # Separate session keys bound simultaneous 512 MiB parser children across
    # all workers; do not hold a policy lock or write transaction while parsing.
    key = None
    for slot in range(settings.PARSER_CONCURRENCY):
        candidate = 731100 + slot
        with connection.cursor() as cursor:
            cursor.execute("SELECT pg_try_advisory_lock(%s)", [candidate])
            if cursor.fetchone()[0]:
                key = candidate
                break
    if key is None:
        from .validation import ProcessingBusy

        raise ProcessingBusy("File processing is busy. Please retry the upload shortly.")
    try:
        yield
    finally:
        if connection.connection is not None:
            try:
                with connection.cursor() as cursor:
                    cursor.execute("SELECT pg_advisory_unlock(%s)", [key])
            except DatabaseError:
                connection.close()


@contextmanager
def processing_claim(identifier):
    # Negative UUID-derived keys cannot overlap the positive policy/quota keys.
    digest = hashlib.blake2b(identifier.bytes, digest_size=8).digest()
    key = -1 - (int.from_bytes(digest, "big") & ((1 << 63) - 1))
    active = getattr(connection, "_vault_processing_claims", set())
    connection._vault_processing_claims = active
    # PostgreSQL session locks are reentrant; also exclude nested calls on this
    # connection so they cannot start another attempt for the same version.
    if key in active:
        yield False
        return
    with connection.cursor() as cursor:
        cursor.execute("SELECT pg_try_advisory_lock(%s)", [key])
        claimed = cursor.fetchone()[0]
    if not claimed:
        yield False
        return
    active.add(key)
    try:
        yield True
    finally:
        active.remove(key)
        # The direct database session owns the lock. Closing/loss of that session
        # releases it automatically; never reconnect merely to release a lock.
        if connection.connection is not None:
            try:
                with connection.cursor() as cursor:
                    cursor.execute("SELECT pg_advisory_unlock(%s)", [key])
            except DatabaseError:
                # Includes a failed surrounding transaction. Dropping the session
                # prevents a claimed version from remaining stuck on a reused one.
                connection.close()
