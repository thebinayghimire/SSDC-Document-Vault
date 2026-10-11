"""Serialize permission changes with the short, authorized part of vault writes."""

from contextlib import contextmanager

from django.contrib.auth import get_user_model
from django.core.exceptions import PermissionDenied
from django.db import connection, transaction


def lock_policy_writes():
    # Keep this key in sync with migration 0004's statement-level triggers.
    # Acquire before document/folder rows, including publication and admin writes.
    with connection.cursor() as cursor:
        cursor.execute("SELECT pg_advisory_xact_lock(731012)")


@contextmanager
def mutation_access(actor, *, administrator=False):
    with transaction.atomic():
        lock_policy_writes()
        if actor is None:
            raise PermissionDenied
        # NO KEY UPDATE blocks role/state/session changes while permitting grant
        # and audit foreign-key checks. Refresh rather than trust the request's user.
        user = (
            get_user_model()
            .objects.select_for_update(no_key=True)
            .filter(pk=actor.pk, is_active=True)
            .first()
        )
        if (
            user is None
            or not user.can_manage
            or user.auth_version != getattr(actor, "auth_version", None)
            or (administrator and not user.is_portal_admin)
        ):
            raise PermissionDenied
        yield user
