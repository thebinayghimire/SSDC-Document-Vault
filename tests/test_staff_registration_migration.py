"""Migration behavior against synthetic legacy account data on PostgreSQL."""

import pytest
from django.db import connection
from django.db.migrations.executor import MigrationExecutor

from accounts.models import EmailClaim, StaffRegistrationRequest, User

BASE = [("accounts", "0001_initial")]
TARGET = [("accounts", "0002_staff_registration_core")]


def email_of_length(length):
    local = "a" * 64
    domain = ".".join(["b" * 63, "c" * 63, "d" * (length - 65 - 128)])
    assert len(local) + 1 + len(domain) == length
    return f"{local}@{domain}"


def migrate(targets):
    executor = MigrationExecutor(connection)
    executor.migrate(targets)
    executor.loader.build_graph()
    return executor


def historical_user(apps):
    return apps.get_model("accounts", "User")


def create_legacy(User, username, email, **fields):
    return User.objects.create(
        username=username,
        email=email,
        password="synthetic-legacy-password-hash",
        **fields,
    )


@pytest.mark.django_db(transaction=True)
def test_legacy_account_matrix_survives_migration_without_backfill_or_claim_creation():
    try:
        executor = migrate(BASE)
        apps = executor.loader.project_state(BASE).apps
        LegacyUser = historical_user(apps)

        create_legacy(
            LegacyUser,
            "legacy-admin-confirmed",
            "Admin.Confirmed@Example.TEST",
            role="admin",
            is_staff=True,
            is_superuser=True,
            mfa_secret="synthetic-encrypted-secret",
            mfa_confirmed=True,
            mfa_last_step=42,
            recovery_hashes=["synthetic-recovery-hash"],
        )
        create_legacy(
            LegacyUser,
            "legacy-manager-inactive",
            "manager.inactive@example.test",
            role="manager",
            is_active=False,
            mfa_secret="synthetic-encrypted-secret",
            mfa_confirmed=False,
        )
        create_legacy(LegacyUser, "legacy-staff-blank", "", role="staff")
        create_legacy(LegacyUser, "legacy-staff-whitespace", "   ", role="staff")
        create_legacy(
            LegacyUser,
            "legacy-restricted-plus",
            "staff+registrations@example.test",
            role="restricted",
        )
        create_legacy(
            LegacyUser,
            "legacy-duplicate-mixed-a",
            "Duplicate@Example.test",
            role="staff",
        )
        create_legacy(
            LegacyUser,
            "legacy-duplicate-mixed-b",
            "duplicate@EXAMPLE.TEST",
            role="restricted",
        )
        create_legacy(
            LegacyUser,
            "legacy-duplicate-exact-a",
            "exact.duplicate@example.test",
            role="staff",
        )
        create_legacy(
            LegacyUser,
            "legacy-duplicate-exact-b",
            "exact.duplicate@example.test",
            role="staff",
        )
        create_legacy(
            LegacyUser,
            "legacy-maximum-length",
            email_of_length(254),
            role="staff",
        )
        create_legacy(
            LegacyUser,
            "legacy-invalid-address",
            "not-an-email",
            role="staff",
            mfa_secret="",
            mfa_confirmed=False,
        )
        create_legacy(
            LegacyUser,
            "legacy-mfa-unconfirmed",
            "unconfirmed@example.test",
            role="manager",
            mfa_secret="synthetic-encrypted-secret",
            mfa_confirmed=False,
        )

        selected_fields = (
            "username",
            "email",
            "role",
            "is_active",
            "is_staff",
            "is_superuser",
            "mfa_secret",
            "mfa_confirmed",
            "mfa_last_step",
            "recovery_hashes",
        )
        before = list(LegacyUser.objects.order_by("username").values(*selected_fields))
        assert {row["role"] for row in before} == {"admin", "manager", "staff", "restricted"}
        assert any(row["is_active"] is False for row in before)
        assert any(row["mfa_confirmed"] is True for row in before)
        assert any(row["mfa_confirmed"] is False and row["mfa_secret"] for row in before)
        assert any(row["mfa_confirmed"] is False and not row["mfa_secret"] for row in before)

        migrate(TARGET)

        tables = set(connection.introspection.table_names())
        assert {"accounts_emailclaim", "accounts_staffregistrationrequest"} <= tables
        assert EmailClaim.objects.count() == 0
        assert StaffRegistrationRequest.objects.count() == 0
        assert list(User.objects.order_by("username").values(*selected_fields)) == before

        migrate(BASE)
        tables = set(connection.introspection.table_names())
        assert "accounts_emailclaim" not in tables
        assert "accounts_staffregistrationrequest" not in tables
        assert User.objects.count() == len(before)

        migrate(TARGET)
        assert EmailClaim.objects.count() == 0
        assert StaffRegistrationRequest.objects.count() == 0
        assert list(User.objects.order_by("username").values(*selected_fields)) == before
    finally:
        migrate(TARGET)
