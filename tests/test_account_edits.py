"""Overlapping account edits must not revive sessions or one-use MFA codes."""

import threading
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace

import pyotp
import pytest
from django.contrib.auth.forms import PasswordChangeForm
from django.contrib.auth.hashers import make_password
from django.db import connections
from django.test import Client

from accounts.admin import PortalUserAdmin
from accounts.mfa import encrypt, verify
from accounts.models import User
from config.admin import site

from .conftest import authenticate_client


def enable_mfa(user):
    secret = pyotp.random_base32()
    user.mfa_secret = encrypt(secret)
    user.mfa_confirmed = True
    user.recovery_hashes = [make_password("one-use-recovery")]
    user.save()
    return secret


@pytest.mark.django_db
def test_profile_save_cannot_revive_revoked_session(users):
    user = users["alice"]
    client = authenticate_client(Client(), user)
    stale = User.objects.get(pk=user.pk)
    admin = PortalUserAdmin(User, site)
    admin.revoke_sessions(SimpleNamespace(user=users["admin"]), User.objects.filter(pk=user.pk))

    stale.first_name = "Updated name"
    stale.save()

    user.refresh_from_db()
    assert user.first_name == "Updated name"
    assert user.auth_version == stale.auth_version == 2
    assert client.get("/documents/import/").status_code == 302


@pytest.mark.django_db
def test_profile_save_cannot_restore_used_mfa_codes(users):
    user = users["manager"]
    secret = enable_mfa(user)
    stale = User.objects.get(pk=user.pk)
    token = pyotp.TOTP(secret).now()
    assert verify(user, token)
    assert verify(user, "one-use-recovery")

    stale.email = "updated@example.test"
    stale.save()

    user.refresh_from_db()
    assert user.email == "updated@example.test"
    assert not user.recovery_hashes
    assert not verify(user, token)
    assert not verify(user, "one-use-recovery")


@pytest.mark.django_db
@pytest.mark.parametrize("action", ["consume", "reset", "revoke", "disable"])
def test_password_change_preserves_intervening_security_changes(users, action):
    user = users["alice"]
    secret = enable_mfa(user)
    stale = User.objects.get(pk=user.pk)
    form = PasswordChangeForm(
        stale,
        {
            "old_password": "Strong-Staff-Password-42",
            "new_password1": "New-Unique-Staff-Password-83",
            "new_password2": "New-Unique-Staff-Password-83",
        },
    )
    assert form.is_valid()
    admin = PortalUserAdmin(User, site)
    request = SimpleNamespace(user=users["admin"])
    token = pyotp.TOTP(secret).now()
    if action == "consume":
        assert verify(user, token)
        assert verify(user, "one-use-recovery")
    elif action == "reset":
        admin.reset_mfa(request, User.objects.filter(pk=user.pk))
    elif action == "revoke":
        admin.revoke_sessions(request, User.objects.filter(pk=user.pk))
    else:
        user.is_active = False
        user.role = User.Role.RESTRICTED
        user.save(update_fields=["is_active", "role"])
    previous = User.objects.get(pk=user.pk)

    saved = form.save()

    user.refresh_from_db()
    assert user.check_password("New-Unique-Staff-Password-83")
    assert user.auth_version == saved.auth_version == previous.auth_version + 1
    for field in (
        "mfa_secret",
        "mfa_confirmed",
        "mfa_last_step",
        "recovery_hashes",
        "role",
        "is_active",
    ):
        assert getattr(user, field) == getattr(previous, field)
    if action in {"consume", "reset", "disable"}:
        assert not verify(user, "one-use-recovery")
        assert not verify(user, token)


@pytest.mark.django_db
def test_partial_profile_save_does_not_apply_unsaved_role_or_revoke_sessions(users):
    user = users["alice"]
    version = user.auth_version
    user.role = User.Role.MANAGER
    user.first_name = "Name only"
    user.save(update_fields=["first_name"])

    current = User.objects.get(pk=user.pk)
    assert current.first_name == "Name only"
    assert current.role == User.Role.STAFF
    assert current.auth_version == version
    user.save(update_fields=["role"])
    current.refresh_from_db()
    assert current.role == User.Role.MANAGER
    assert current.auth_version == version + 1


@pytest.mark.django_db(transaction=True)
@pytest.mark.parametrize("action", ["consume", "reset", "revoke", "disable", "password"])
def test_admin_profile_request_preserves_overlapping_security_action(users, monkeypatch, action):
    user = users["alice"]
    secret = enable_mfa(user)
    administrator = authenticate_client(Client(), users["admin"])
    validated, resume = threading.Event(), threading.Event()
    original = PortalUserAdmin.save_model

    def pause_before_save(admin, request, obj, form, change):
        validated.set()
        assert resume.wait(20), "Security action did not finish"
        return original(admin, request, obj, form, change)

    def edit_profile():
        try:
            return administrator.post(
                f"/admin/accounts/user/{user.pk}/change/",
                {
                    "username": user.username,
                    "first_name": "Edited by administrator",
                    "last_name": "",
                    "email": "",
                    "role": user.role,
                    "is_active": "on",
                    "_save": "Save",
                },
            )
        finally:
            connections.close_all()

    monkeypatch.setattr(PortalUserAdmin, "save_model", pause_before_save)
    token = pyotp.TOTP(secret).now()
    with ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(edit_profile)
        try:
            assert validated.wait(20), "Admin did not validate the profile form"
            admin = PortalUserAdmin(User, site)
            request = SimpleNamespace(user=users["admin"])
            if action == "consume":
                assert verify(user, token)
                assert verify(user, "one-use-recovery")
            elif action == "reset":
                admin.reset_mfa(request, User.objects.filter(pk=user.pk))
            elif action == "revoke":
                admin.revoke_sessions(request, User.objects.filter(pk=user.pk))
            elif action == "disable":
                user.is_active = False
                user.role = User.Role.RESTRICTED
                user.save(update_fields=["is_active", "role"])
            else:
                user.set_password("Admin-Reset-Password-82")
                user.save(update_fields=["password"])
            previous = User.objects.get(pk=user.pk)
        finally:
            resume.set()
        assert future.result(timeout=20).status_code == 302

    user.refresh_from_db()
    assert user.first_name == "Edited by administrator"
    for field in (
        "auth_version",
        "password",
        "role",
        "is_active",
        "mfa_secret",
        "mfa_confirmed",
        "mfa_last_step",
        "recovery_hashes",
    ):
        assert getattr(user, field) == getattr(previous, field)
    if action in {"consume", "reset", "disable"}:
        assert not verify(user, token)
        assert not verify(user, "one-use-recovery")


@pytest.mark.django_db(transaction=True)
def test_simultaneous_role_and_password_changes_both_revoke_sessions(users):
    user = users["alice"]
    barrier = threading.Barrier(2)

    def change_security(field):
        try:
            stale = User.objects.get(pk=user.pk)
            if field == "role":
                stale.role = User.Role.RESTRICTED
            else:
                stale.set_password("Concurrent-New-Password-84")
            barrier.wait(timeout=20)
            stale.save()
        finally:
            connections.close_all()

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [executor.submit(change_security, field) for field in ("role", "password")]
        for future in futures:
            future.result(timeout=20)

    user.refresh_from_db()
    assert user.role == User.Role.RESTRICTED
    assert user.check_password("Concurrent-New-Password-84")
    assert user.auth_version == 3


@pytest.mark.django_db(transaction=True)
@pytest.mark.parametrize("kind", ["recovery", "totp"])
def test_simultaneous_mfa_verifications_accept_code_once(users, kind):
    user = users["manager"]
    secret = enable_mfa(user)
    token = "one-use-recovery" if kind == "recovery" else pyotp.TOTP(secret).now()
    barrier = threading.Barrier(2)

    def consume():
        try:
            barrier.wait(timeout=20)
            return verify(user, token)
        finally:
            connections.close_all()

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [executor.submit(consume) for _ in range(2)]
        assert sorted(future.result(timeout=20) for future in futures) == [False, True]


@pytest.mark.django_db
def test_deferred_and_refreshed_profile_saves_preserve_security_changes(users):
    user = users["alice"]
    stale = User.objects.only("id", "first_name").get(pk=user.pk)
    admin = PortalUserAdmin(User, site)
    admin.revoke_sessions(SimpleNamespace(user=users["admin"]), User.objects.filter(pk=user.pk))
    stale.first_name = "Deferred profile"
    stale.save()
    stale.refresh_from_db()
    stale.last_name = "Refreshed profile"
    stale.save()

    user.refresh_from_db()
    assert user.first_name == "Deferred profile"
    assert user.last_name == "Refreshed profile"
    assert user.auth_version == 2


@pytest.mark.django_db
def test_auth_version_cannot_be_lowered_by_an_explicit_save(users):
    user = users["alice"]
    admin = PortalUserAdmin(User, site)
    admin.revoke_sessions(SimpleNamespace(user=users["admin"]), User.objects.filter(pk=user.pk))
    user.auth_version = 0
    user.save(update_fields=["auth_version"])

    user.refresh_from_db()
    assert user.auth_version == 2


@pytest.mark.django_db
def test_mutable_recovery_list_edit_and_partial_refresh_keep_correct_save_baseline(users):
    user = users["alice"]
    enable_mfa(user)
    user.recovery_hashes.pop()
    user.save()
    assert not User.objects.get(pk=user.pk).recovery_hashes

    # Refreshing one field must not forget an unrelated, unsaved profile edit.
    user.first_name = "Pending edit"
    User.objects.filter(pk=user.pk).update(last_name="Another request")
    user.refresh_from_db(fields=["last_name"])
    user.save()
    user.refresh_from_db()
    assert user.first_name == "Pending edit"
    assert user.last_name == "Another request"
