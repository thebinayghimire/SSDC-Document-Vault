"""EmailClaim authority, normalized uniqueness, and canonical lock ordering."""

import io
import json
import threading
from concurrent.futures import ThreadPoolExecutor

import pytest
from django.core.exceptions import ValidationError
from django.core.management import call_command
from django.core.management.base import CommandError
from django.db import IntegrityError, connection, connections, transaction
from django.utils import timezone

from accounts.models import EmailClaim, StaffRegistrationRequest, User
from accounts.services.email_claims import (
    ADVISORY_LOCK_ID,
    EmailConflict,
    EmailWriteBypass,
    check_availability,
    clear_email,
    normalize_email,
    repair_claim,
    resolve,
    set_email,
)
from audit.models import Event

from .conftest import authenticate_client


def test_email_authority_uses_the_canonical_advisory_lock_id():
    assert ADVISORY_LOCK_ID == 731011


def email_of_length(length):
    local = "a" * 64
    domain = ".".join(["b" * 63, "c" * 63, "d" * (length - 65 - 128)])
    assert len(local) + 1 + len(domain) == length
    return f"{local}@{domain}"


def create_legacy_user(username, email, **fields):
    """Insert a legacy row without invoking the authoritative User.save path."""
    return User.objects.bulk_create(
        [
            User(
                username=username,
                email=email,
                password="synthetic-legacy-password-hash",
                **fields,
            )
        ]
    )[0]


def pending_request(user, **fields):
    return StaffRegistrationRequest.objects.create(
        user=user,
        status=StaffRegistrationRequest.Status.PENDING_REVIEW,
        email_verified_at=timezone.now(),
        **fields,
    )


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("  Alice+Team@Example.TEST  ", "alice+team@example.test"),
        ("Ａlice@Example.test", "alice@example.test"),
        ("first.last@example.test", "first.last@example.test"),
    ],
)
def test_email_normalization_is_case_insensitive_and_preserves_plus_addressing(raw, expected):
    assert normalize_email(raw) == expected


def test_email_normalization_accepts_maximum_length_and_rejects_longer():
    maximum = email_of_length(254)
    assert normalize_email(maximum) == maximum
    with pytest.raises(ValidationError, match="at most 254"):
        normalize_email(email_of_length(255))


@pytest.mark.parametrize("value", ["not-an-email", "@example.test", "person@", "   person"])
def test_email_normalization_rejects_invalid_addresses(value):
    with pytest.raises(ValidationError):
        normalize_email(value)


def test_email_normalization_treats_blank_values_as_empty():
    assert normalize_email(None) == ""
    assert normalize_email("") == ""
    assert normalize_email(" \t\n ") == ""


@pytest.mark.django_db
@pytest.mark.parametrize("factory", ["create_user", "create_superuser"])
def test_supported_user_managers_claim_normalized_email_atomically(factory):
    user = getattr(User.objects, factory)(
        f"synthetic-{factory}",
        email="  Mixed.Case+Tag@Example.TEST ",
        password="Synthetic-Manager-Password-42",
    )
    user.refresh_from_db()
    claim = EmailClaim.objects.get(user=user)
    assert user.email == "mixed.case+tag@example.test"
    assert claim.normalized_email == user.email
    assert user.email_claim == claim
    assert Event.objects.filter(kind="email_claim_created", target=str(user.pk)).exists()


@pytest.mark.django_db
@pytest.mark.parametrize("email", ["", "   ", None])
def test_user_creation_without_email_does_not_create_a_claim(email):
    user = User.objects.create_user(
        f"synthetic-blank-{User.objects.count()}",
        email=email,
        password="Synthetic-Blank-Password-42",
    )
    user.refresh_from_db()
    assert user.email == ""
    assert not EmailClaim.objects.filter(user=user).exists()


@pytest.mark.django_db
def test_duplicate_case_insensitive_creation_rolls_back_the_second_user():
    User.objects.create_user(
        "synthetic-first", email="Same.Address@Example.test", password="Synthetic-Password-42"
    )
    with pytest.raises(EmailConflict):
        User.objects.create_user(
            "synthetic-second",
            email="same.address@EXAMPLE.TEST",
            password="Synthetic-Password-42",
        )
    assert not User.objects.filter(username="synthetic-second").exists()
    assert EmailClaim.objects.filter(normalized_email="same.address@example.test").count() == 1


@pytest.mark.django_db
def test_creation_cannot_reuse_an_unclaimed_legacy_address():
    create_legacy_user("synthetic-legacy-owner", "Legacy.Owner@Example.test")
    with pytest.raises(EmailConflict):
        User.objects.create_user(
            "synthetic-new-owner",
            email="legacy.owner@example.test",
            password="Synthetic-Password-42",
        )
    assert not User.objects.filter(username="synthetic-new-owner").exists()
    assert not EmailClaim.objects.exists()


@pytest.mark.django_db
@pytest.mark.parametrize(
    ("update_fields", "full_save"),
    [(None, True), (["email"], False), (["first_name", "email"], False)],
)
def test_direct_email_writes_are_rejected_without_partial_profile_changes(update_fields, full_save):
    user = User.objects.create_user("synthetic-guarded", password="Synthetic-Password-42")
    user.first_name = "Must not persist"
    user.email = "direct.write@example.test"
    with pytest.raises(EmailWriteBypass, match="set_email"):
        user.save(update_fields=update_fields)
    user.refresh_from_db()
    assert user.email == ""
    if full_save:
        assert user.first_name == ""
    assert not EmailClaim.objects.filter(user=user).exists()


@pytest.mark.django_db
def test_set_email_normalizes_updates_claim_and_audits_without_address_details(users):
    user = users["alice"]
    claim = set_email(
        user,
        "  Mixed.Case+Tag@Example.TEST ",
        actor=users["admin"],
        source="test",
    )
    user.refresh_from_db()
    assert user.email == "mixed.case+tag@example.test"
    assert claim.normalized_email == user.email
    event = Event.objects.get(kind="email_claim_created", target=str(user.pk))
    assert "mixed.case" not in json.dumps(event.details)
    assert event.details["object_type"] == "email_claim:test"


@pytest.mark.django_db
def test_set_email_repairs_and_audits_a_stale_claim_without_changing_the_user_address(users):
    user = users["alice"]
    set_email(user, "stable@example.test")
    EmailClaim.objects.filter(user=user).update(normalized_email="stale@example.test")
    set_email(user, "stable@example.test")
    user.refresh_from_db()
    assert user.email == "stable@example.test"
    assert user.email_claim.normalized_email == "stable@example.test"
    assert Event.objects.filter(kind="email_claim_changed", target=str(user.pk)).count() == 1


@pytest.mark.django_db
def test_set_email_transfers_ownership_and_releases_the_previous_address(users):
    user = users["alice"]
    set_email(user, "first@example.test", actor=users["admin"])
    set_email(user, "second@example.test", actor=users["admin"])
    user.refresh_from_db()
    assert user.email == "second@example.test"
    assert list(
        EmailClaim.objects.filter(user=user).values_list("normalized_email", flat=True)
    ) == ["second@example.test"]
    assert not EmailClaim.objects.filter(normalized_email="first@example.test").exists()
    assert Event.objects.filter(kind="email_claim_changed", target=str(user.pk)).exists()


@pytest.mark.django_db
def test_clear_email_releases_the_claim_and_blank_clears_are_idempotent(users):
    user = users["alice"]
    set_email(user, "clear.me@example.test", actor=users["admin"])
    clear_email(user, actor=users["admin"], source="test")
    assert user.email == ""
    assert not EmailClaim.objects.filter(user=user).exists()
    clear_email(user, actor=users["admin"], source="test")
    assert Event.objects.filter(kind="email_claim_released", target=str(user.pk)).count() == 1


@pytest.mark.django_db
def test_setting_a_legacy_address_creates_its_claim_without_changing_legacy_duplicates(users):
    user = users["alice"]
    duplicate = create_legacy_user("synthetic-duplicate", "Shared@Example.test")
    User.objects.filter(pk=user.pk).update(email="Shared@Example.test")
    user.refresh_from_db()
    with pytest.raises(EmailConflict):
        set_email(user, "shared@example.test")
    user.refresh_from_db()
    duplicate.refresh_from_db()
    assert user.email == "Shared@Example.test"
    assert duplicate.email == "Shared@Example.test"
    assert not EmailClaim.objects.exists()


@pytest.mark.django_db
def test_setting_the_same_legacy_address_normalizes_it_and_creates_the_claim(users):
    user = users["alice"]
    User.objects.filter(pk=user.pk).update(email="Legacy.Address@Example.test")
    user.refresh_from_db()
    claim = set_email(user, "legacy.address@example.test")
    user.refresh_from_db()
    assert user.email == "legacy.address@example.test"
    assert claim.normalized_email == "legacy.address@example.test"


@pytest.mark.django_db
def test_nonblank_legacy_address_collision_blocks_a_different_account(users):
    create_legacy_user("synthetic-legacy-collision", "Taken@Example.test")
    with pytest.raises(EmailConflict):
        set_email(users["alice"], "taken@example.test")
    assert not EmailClaim.objects.exists()


@pytest.mark.django_db
def test_legacy_full_width_address_collides_with_its_normalized_form(users):
    create_legacy_user("synthetic-legacy-full-width", "Ａlice@Example.test")
    with pytest.raises(EmailConflict):
        set_email(users["alice"], "alice@example.test")
    assert not EmailClaim.objects.exists()


@pytest.mark.django_db
def test_check_availability_allows_current_address_and_rejects_claimed_or_legacy_addresses(users):
    user = users["alice"]
    check_availability("available@example.test", exclude_user_pk=user.pk)
    set_email(users["bob"], "claimed@example.test")
    with pytest.raises(EmailConflict):
        check_availability("CLAIMED@example.test", exclude_user_pk=user.pk)
    assert check_availability("claimED@example.test", exclude_user_pk=users["bob"].pk) is None
    create_legacy_user("synthetic-legacy-availability", "legacy.available@example.test")
    with pytest.raises(EmailConflict):
        check_availability("legacy.available@example.test", exclude_user_pk=user.pk)


@pytest.mark.django_db
def test_repair_claim_claims_only_one_address_and_does_not_rewrite_it(users):
    user = users["alice"]
    User.objects.filter(pk=user.pk).update(email="Legacy.Repair@Example.test")
    user.refresh_from_db()
    claim = repair_claim(user, source="test")
    user.refresh_from_db()
    assert user.email == "Legacy.Repair@Example.test"
    assert claim.normalized_email == "legacy.repair@example.test"
    assert repair_claim(user).pk == claim.pk
    assert EmailClaim.objects.filter(user=user).count() == 1


@pytest.mark.django_db
def test_blank_legacy_address_is_never_automatically_claimed(users):
    user = users["alice"]
    User.objects.filter(pk=user.pk).update(email="   ")
    user.refresh_from_db()
    assert repair_claim(user) is None
    assert not EmailClaim.objects.exists()


@pytest.mark.django_db
def test_resolve_requires_an_active_claimed_account_and_valid_address(users):
    active = users["alice"]
    inactive = users["bob"]
    set_email(active, "Active.User@Example.test")
    set_email(inactive, "inactive.user@example.test")
    User.objects.filter(pk=inactive.pk).update(is_active=False)
    assert resolve("ACTIVE.USER@example.test") == active
    assert resolve("inactive.user@example.test") is None
    assert resolve("not-an-email") is None
    assert resolve("") is None


@pytest.mark.django_db
def test_email_claim_constraints_reject_noncanonical_and_duplicate_rows(users):
    with pytest.raises(IntegrityError):
        with transaction.atomic():
            EmailClaim.objects.create(user=users["alice"], normalized_email=" Mixed@example.test")
    with pytest.raises(IntegrityError):
        with transaction.atomic():
            EmailClaim.objects.create(user=users["alice"], normalized_email="")
    EmailClaim.objects.create(user=users["alice"], normalized_email="unique@example.test")
    with pytest.raises(IntegrityError):
        with transaction.atomic():
            EmailClaim.objects.create(user=users["bob"], normalized_email="unique@example.test")


@pytest.mark.django_db
def test_admin_can_edit_and_clear_email_through_the_authority(users, client):
    user = users["alice"]
    authenticate_client(client, users["admin"])
    response = client.post(
        f"/admin/accounts/user/{user.pk}/change/",
        {
            "username": user.username,
            "first_name": "",
            "last_name": "",
            "email": "Admin.Edit@Example.TEST",
            "role": user.role,
            "is_active": "on",
            "_save": "Save",
        },
    )
    assert response.status_code == 302
    user.refresh_from_db()
    assert user.email == "admin.edit@example.test"
    assert EmailClaim.objects.filter(user=user, normalized_email=user.email).exists()

    response = client.post(
        f"/admin/accounts/user/{user.pk}/change/",
        {
            "username": user.username,
            "first_name": "",
            "last_name": "",
            "email": "",
            "role": user.role,
            "is_active": "on",
            "_save": "Save",
        },
    )
    assert response.status_code == 302
    user.refresh_from_db()
    assert user.email == ""
    assert not EmailClaim.objects.filter(user=user).exists()


@pytest.mark.django_db
def test_admin_email_conflict_is_shown_without_changing_either_account(users, client):
    owner = users["alice"]
    target = users["bob"]
    set_email(owner, "Taken.Address@Example.test")
    authenticate_client(client, users["admin"])
    response = client.post(
        f"/admin/accounts/user/{target.pk}/change/",
        {
            "username": target.username,
            "first_name": "",
            "last_name": "",
            "email": "TAKEN.ADDRESS@example.TEST",
            "role": target.role,
            "is_active": "on",
            "_save": "Save",
        },
    )
    assert response.status_code == 200
    assert b"already assigned" in response.content
    target.refresh_from_db()
    owner.refresh_from_db()
    assert target.email == ""
    assert owner.email == "taken.address@example.test"
    assert not EmailClaim.objects.filter(user=target).exists()


@pytest.mark.django_db
def test_admin_email_change_rolls_back_if_audit_fails(users, client, monkeypatch):
    user = users["alice"]
    authenticate_client(client, users["admin"])

    def fail_audit(*args, **kwargs):
        raise RuntimeError("synthetic audit failure")

    monkeypatch.setattr("accounts.admin.record", fail_audit)
    with pytest.raises(RuntimeError, match="synthetic audit failure"):
        client.post(
            f"/admin/accounts/user/{user.pk}/change/",
            {
                "username": user.username,
                "first_name": "",
                "last_name": "",
                "email": "Audit.Rollback@Example.test",
                "role": user.role,
                "is_active": "on",
                "_save": "Save",
            },
        )
    user.refresh_from_db()
    assert user.email == ""
    assert not EmailClaim.objects.filter(user=user).exists()
    assert not Event.objects.filter(target=str(user.pk)).exists()


@pytest.mark.django_db
def test_ensure_admin_claims_email_and_preserves_idempotency(monkeypatch):
    monkeypatch.setenv("DJANGO_SUPERUSER_USERNAME", "synthetic-bootstrap")
    monkeypatch.setenv("DJANGO_SUPERUSER_EMAIL", "Bootstrap.Admin@Example.TEST")
    monkeypatch.setenv("DJANGO_SUPERUSER_PASSWORD", "Q7#vL2!mR9@xP4")
    call_command("ensure_admin")
    user = User.objects.get(username="synthetic-bootstrap")
    assert user.email == "bootstrap.admin@example.test"
    assert user.email_claim.normalized_email == user.email
    call_command("ensure_admin")
    user.refresh_from_db()
    assert user.email == "bootstrap.admin@example.test"
    assert EmailClaim.objects.filter(user=user).count() == 1


@pytest.mark.django_db
def test_ensure_admin_refuses_an_email_claimed_by_another_account_without_mutation(monkeypatch):
    existing = User.objects.create_user(
        "synthetic-existing",
        email="claimed.bootstrap@example.test",
        password="Existing-Password-42",
    )
    monkeypatch.setenv("DJANGO_SUPERUSER_USERNAME", "synthetic-new-bootstrap")
    monkeypatch.setenv("DJANGO_SUPERUSER_EMAIL", "CLAIMED.BOOTSTRAP@example.TEST")
    monkeypatch.setenv("DJANGO_SUPERUSER_PASSWORD", "Q7#vL2!mR9@xP4")
    with pytest.raises(CommandError, match="already claimed"):
        call_command("ensure_admin")
    assert not User.objects.filter(username="synthetic-new-bootstrap").exists()
    existing.refresh_from_db()
    assert existing.email == "claimed.bootstrap@example.test"
    assert EmailClaim.objects.filter(user=existing).count() == 1


@pytest.mark.django_db
def test_ensure_admin_reports_an_invalid_email_without_creating_the_account(monkeypatch):
    monkeypatch.setenv("DJANGO_SUPERUSER_USERNAME", "synthetic-invalid-bootstrap")
    monkeypatch.setenv("DJANGO_SUPERUSER_EMAIL", "not-an-email")
    monkeypatch.setenv("DJANGO_SUPERUSER_PASSWORD", "Q7#vL2!mR9@xP4")
    with pytest.raises(CommandError, match="DJANGO_SUPERUSER_EMAIL"):
        call_command("ensure_admin")
    assert not User.objects.filter(username="synthetic-invalid-bootstrap").exists()


@pytest.mark.django_db
def test_reconciliation_is_report_only_then_claims_only_unambiguous_addresses(users):
    unique = users["alice"]
    plus = users["bob"]
    duplicate_a = create_legacy_user("synthetic-duplicate-a", "Duplicate@Example.test")
    duplicate_b = create_legacy_user("synthetic-duplicate-b", "duplicate@EXAMPLE.TEST")
    blank = create_legacy_user("synthetic-blank", "")
    whitespace = create_legacy_user("synthetic-whitespace", "   ")
    maximum = create_legacy_user("synthetic-maximum", email_of_length(254))
    User.objects.filter(pk=unique.pk).update(email="Unique@Example.test")
    User.objects.filter(pk=plus.pk).update(email="staff+registrations@example.test")
    before = {
        user.pk: user.email
        for user in User.objects.filter(
            pk__in=[
                unique.pk,
                plus.pk,
                duplicate_a.pk,
                duplicate_b.pk,
                blank.pk,
                whitespace.pk,
                maximum.pk,
            ]
        )
    }

    buffer = io.StringIO()
    call_command("reconcile_email_claims", stdout=buffer)
    output = buffer.getvalue()
    assert "duplicate_groups=1" in output
    assert "created=0" in output
    assert not EmailClaim.objects.exists()

    buffer = io.StringIO()
    call_command("reconcile_email_claims", apply=True, stdout=buffer)
    output = buffer.getvalue()
    assert "created=3" in output
    assert EmailClaim.objects.count() == 3
    assert EmailClaim.objects.filter(user=unique).exists()
    assert EmailClaim.objects.filter(user=plus).exists()
    assert EmailClaim.objects.filter(user=maximum).exists()
    for user_pk in (duplicate_a.pk, duplicate_b.pk, blank.pk, whitespace.pk):
        assert not EmailClaim.objects.filter(user_id=user_pk).exists()
    after = {user.pk: user.email for user in User.objects.filter(pk__in=before)}
    assert after == before
    with pytest.raises(CommandError, match="Unresolved email claim conflicts"):
        call_command("reconcile_email_claims", strict=True, stdout=io.StringIO())


@pytest.mark.django_db(transaction=True)
def test_concurrent_creation_of_the_same_email_yields_exactly_one_account():
    barrier = threading.Barrier(2)

    def create(username):
        try:
            barrier.wait(timeout=20)
            User.objects.create_user(
                username, email="concurrent.claim@example.test", password="Concurrent-Password-42"
            )
            return "created"
        except EmailConflict:
            return "conflict"
        finally:
            connections.close_all()

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = sorted(
            future.result(timeout=30)
            for future in [executor.submit(create, "race-a"), executor.submit(create, "race-b")]
        )
    assert results == ["conflict", "created"]
    assert User.objects.filter(email="concurrent.claim@example.test").count() == 1
    assert EmailClaim.objects.filter(normalized_email="concurrent.claim@example.test").count() == 1


@pytest.mark.django_db(transaction=True)
def test_concurrent_email_transfer_yields_exactly_one_claim(users):
    first = users["alice"].pk
    second = users["bob"].pk
    barrier = threading.Barrier(2)

    def assign(user_pk):
        try:
            user = User.objects.get(pk=user_pk)
            barrier.wait(timeout=20)
            set_email(user, "concurrent.transfer@example.test")
            return "claimed"
        except EmailConflict:
            return "conflict"
        finally:
            connections.close_all()

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = sorted(
            future.result(timeout=30)
            for future in [executor.submit(assign, first), executor.submit(assign, second)]
        )
    assert results == ["claimed", "conflict"]
    assert (
        EmailClaim.objects.filter(normalized_email="concurrent.transfer@example.test").count() == 1
    )


def first_statement(statements, marker):
    return next(index for index, sql in enumerate(statements) if marker in sql)


@pytest.mark.django_db
def test_set_email_acquires_canonical_locks_before_claim_write(users):
    statements = []

    def recorder(execute, sql, params, many, context):
        statements.append(sql)
        return execute(sql, params, many, context)

    request = pending_request(users["alice"])
    with connection.execute_wrapper(recorder):
        set_email(users["alice"], "lock.order@example.test", request=request)

    advisory = first_statement(statements, "pg_advisory_xact_lock")
    user_lock = first_statement(statements, 'FROM "accounts_user"')
    request_lock = first_statement(statements, 'FROM "accounts_staffregistrationrequest"')
    claim_lock = first_statement(statements, 'FROM "accounts_emailclaim"')
    assert advisory < user_lock < request_lock < claim_lock
    assert "FOR UPDATE" in statements[user_lock]
    assert "FOR UPDATE" in statements[request_lock]
    assert "FOR UPDATE" in statements[claim_lock]


@pytest.mark.django_db
def test_clear_email_acquires_canonical_locks_before_releasing_the_claim(users):
    user = users["alice"]
    set_email(user, "lock.clear@example.test")
    request = pending_request(user)
    statements = []

    def recorder(execute, sql, params, many, context):
        statements.append(sql)
        return execute(sql, params, many, context)

    with connection.execute_wrapper(recorder):
        clear_email(user, request=request)

    assert (
        first_statement(statements, "pg_advisory_xact_lock")
        < first_statement(statements, 'FROM "accounts_user"')
        < first_statement(statements, 'FROM "accounts_staffregistrationrequest"')
        < first_statement(statements, 'FROM "accounts_emailclaim"')
    )


@pytest.mark.django_db
def test_claim_creation_rolls_back_with_the_user_email_when_audit_fails(users, monkeypatch):
    user = users["alice"]
    monkeypatch.setattr(
        "accounts.services.email_claims._record_claim",
        lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("synthetic event failure")),
    )
    with pytest.raises(RuntimeError, match="synthetic event failure"):
        set_email(user, "atomic.claim@example.test")
    user.refresh_from_db()
    assert user.email == ""
    assert not EmailClaim.objects.filter(user=user).exists()
