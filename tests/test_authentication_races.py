"""Authentication must stay bound to the account state that proved the password."""

import threading
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace

import pyotp
import pytest
from django.contrib.auth.hashers import make_password
from django.db import OperationalError, connection, connections, transaction
from django.test import Client

from accounts import views
from accounts.admin import PortalUserAdmin
from accounts.mfa import decrypt, encrypt, verify
from accounts.models import User
from audit.models import Event
from config.admin import site

from .conftest import authenticate_client

REVOCATIONS = ("password", "role", "disable", "mfa_reset", "revoke")
PENDING_FIELDS = ("pending_user", "pending_at", "pending_auth_version", "enrollment_secret")


def enroll(user):
    secret = pyotp.random_base32()
    user.mfa_secret = encrypt(secret)
    user.mfa_confirmed = True
    user.recovery_hashes = [make_password("one-use-recovery")]
    user.save(update_fields=["mfa_secret", "mfa_confirmed", "recovery_hashes"])
    return secret


def revoke(user_id, action, administrator):
    user = User.objects.get(pk=user_id)
    if action == "password":
        user.set_password("Administrator-Reset-Password-82")
        user.save(update_fields=["password"])
    elif action == "role":
        user.role = User.Role.RESTRICTED
        user.save(update_fields=["role"])
    elif action == "disable":
        user.is_active = False
        user.save(update_fields=["is_active"])
    else:
        admin = PortalUserAdmin(User, site)
        getattr(admin, "reset_mfa" if action == "mfa_reset" else "revoke_sessions")(
            SimpleNamespace(user=administrator), User.objects.filter(pk=user_id)
        )


def post_in_thread(client, url, data):
    try:
        return client.post(url, data)
    finally:
        connections.close_all()


def assert_signed_out(client):
    session = client.session
    assert "_auth_user_id" not in session
    assert not session.get("mfa_verified")
    assert all(field not in session for field in PENDING_FIELDS)
    assert client.get("/").status_code == 302


@pytest.mark.django_db(transaction=True)
@pytest.mark.parametrize("action", REVOCATIONS)
@pytest.mark.parametrize("kind", ["totp", "recovery"])
def test_challenge_rejects_revocation_after_pending_lookup(users, monkeypatch, action, kind):
    user = users["manager"]
    secret = enroll(user)
    client = Client()
    assert (
        client.post(
            "/accounts/login/",
            {"staff_id": user.username, "password": "Strong-Manager-Password-42"},
        ).url
        == "/accounts/mfa/"
    )
    loaded, resume = threading.Event(), threading.Event()
    original = views.pending_user

    def pause_after_lookup(request):
        result = original(request)
        loaded.set()
        assert resume.wait(20), "Account change did not finish"
        return result

    monkeypatch.setattr(views, "pending_user", pause_after_lookup)
    token = pyotp.TOTP(secret).now() if kind == "totp" else "one-use-recovery"
    with ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(post_in_thread, client, "/accounts/mfa/", {"code": token})
        try:
            assert loaded.wait(20), "Challenge did not load the account"
            revoke(user.pk, action, users["admin"])
        finally:
            resume.set()
        future.result(timeout=20)

    assert_signed_out(client)
    assert not Event.objects.filter(actor=user, kind="login", outcome="success").exists()
    current = User.objects.get(pk=user.pk)
    if action != "mfa_reset":
        assert current.mfa_last_step == -1
        assert len(current.recovery_hashes) == 1


@pytest.mark.django_db(transaction=True)
@pytest.mark.parametrize("action", ["password", "revoke"])
def test_enrollment_rejects_revocation_after_pending_lookup(users, monkeypatch, action):
    user = users["manager"]
    client = Client()
    client.post(
        "/accounts/login/", {"staff_id": user.username, "password": "Strong-Manager-Password-42"}
    )
    client.get("/accounts/mfa/enroll/")
    secret = decrypt(client.session["enrollment_secret"])
    loaded, resume = threading.Event(), threading.Event()
    original = views.pending_user

    def pause_after_lookup(request):
        result = original(request)
        loaded.set()
        assert resume.wait(20), "Account change did not finish"
        return result

    monkeypatch.setattr(views, "pending_user", pause_after_lookup)
    with ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(
            post_in_thread, client, "/accounts/mfa/enroll/", {"code": pyotp.TOTP(secret).now()}
        )
        try:
            assert loaded.wait(20), "Enrollment did not load the account"
            revoke(user.pk, action, users["admin"])
        finally:
            resume.set()
        response = future.result(timeout=20)

    assert response.status_code == 302
    assert_signed_out(client)
    user.refresh_from_db()
    assert not user.mfa_confirmed and not user.recovery_hashes
    assert not Event.objects.filter(actor=user, kind="mfa_enrolled").exists()


@pytest.mark.django_db(transaction=True)
@pytest.mark.parametrize("action", REVOCATIONS)
def test_reauthentication_rejects_revocation_during_request(users, monkeypatch, action):
    user = users["manager"]
    secret = enroll(user)
    client = authenticate_client(Client(), user)
    session = client.session
    session["reauth_at"] = 0
    session.save()
    checked, resume = threading.Event(), threading.Event()
    original = views.allow_rate

    def pause_before_password_check(scope, *args, **kwargs):
        result = original(scope, *args, **kwargs)
        if scope == "reauth":
            checked.set()
            assert resume.wait(20), "Account change did not finish"
        return result

    monkeypatch.setattr(views, "allow_rate", pause_before_password_check)
    with ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(
            post_in_thread,
            client,
            "/accounts/confirm/",
            {"password": "Strong-Manager-Password-42", "code": pyotp.TOTP(secret).now()},
        )
        try:
            assert checked.wait(20), "Reauthentication did not reach the password check"
            revoke(user.pk, action, users["admin"])
        finally:
            resume.set()
        future.result(timeout=20)

    assert_signed_out(client)
    assert not Event.objects.filter(actor=user, kind="reauthentication", outcome="success").exists()


@pytest.mark.django_db(transaction=True)
@pytest.mark.parametrize("action", ["password", "revoke"])
def test_staff_reauthentication_without_mfa_rejects_revocation(users, monkeypatch, action):
    user = users["alice"]
    client = authenticate_client(Client(), user, mfa=False)
    original = views.allow_rate

    def revoke_before_password_check(scope, *args, **kwargs):
        result = original(scope, *args, **kwargs)
        if scope == "reauth":
            revoke(user.pk, action, users["admin"])
        return result

    monkeypatch.setattr(views, "allow_rate", revoke_before_password_check)
    client.post("/accounts/confirm/", {"password": "Strong-Staff-Password-42", "code": ""})

    assert_signed_out(client)
    assert not Event.objects.filter(actor=user, kind="reauthentication", outcome="success").exists()


@pytest.mark.django_db(transaction=True)
@pytest.mark.parametrize("action", ["password", "role", "revoke"])
def test_staff_login_rejects_revocation_after_password_authentication(users, monkeypatch, action):
    user = users["alice"]
    client = Client()
    original = views.authenticate

    def revoke_after_password(*args, **kwargs):
        result = original(*args, **kwargs)
        assert result is not None
        revoke(user.pk, action, users["admin"])
        return result

    monkeypatch.setattr(views, "authenticate", revoke_after_password)
    client.post(
        "/accounts/login/", {"staff_id": user.username, "password": "Strong-Staff-Password-42"}
    )

    assert_signed_out(client)
    assert not Event.objects.filter(actor=user, kind="login", outcome="success").exists()


@pytest.mark.django_db(transaction=True)
@pytest.mark.parametrize("action", ["password", "revoke"])
def test_password_change_rejects_revoked_password_proof(users, monkeypatch, action):
    user = users["alice"]
    client = authenticate_client(Client(), user)
    original = views.allow_rate

    def revoke_before_form_check(scope, *args, **kwargs):
        result = original(scope, *args, **kwargs)
        if scope == "password-change":
            revoke(user.pk, action, users["admin"])
        return result

    monkeypatch.setattr(views, "allow_rate", revoke_before_form_check)
    client.post(
        "/accounts/password/",
        {
            "old_password": "Strong-Staff-Password-42",
            "new_password1": "New-Unique-Staff-Password-83",
            "new_password2": "New-Unique-Staff-Password-83",
        },
    )

    assert_signed_out(client)
    user.refresh_from_db()
    assert not user.check_password("New-Unique-Staff-Password-83")
    assert not Event.objects.filter(actor=user, kind="password_changed", outcome="success").exists()


@pytest.mark.django_db(transaction=True)
@pytest.mark.parametrize("flow", ["challenge", "enrollment", "reauthentication"])
def test_verification_and_completion_share_account_lock(users, monkeypatch, flow):
    user = users["manager"]
    client = Client()
    if flow != "enrollment":
        secret = enroll(user)
    if flow == "reauthentication":
        authenticate_client(client, user)
        url = "/accounts/confirm/"
        data = {"password": "Strong-Manager-Password-42", "code": pyotp.TOTP(secret).now()}
    else:
        client.post(
            "/accounts/login/",
            {"staff_id": user.username, "password": "Strong-Manager-Password-42"},
        )
        if flow == "enrollment":
            client.get("/accounts/mfa/enroll/")
            secret = decrypt(client.session["enrollment_secret"])
        url = "/accounts/mfa/" if flow == "challenge" else "/accounts/mfa/enroll/"
        data = {"code": pyotp.TOTP(secret).now()}
    verified, resume = threading.Event(), threading.Event()
    original_login, original_record = views.finish_login, views.record

    def pause():
        verified.set()
        assert resume.wait(20), "Concurrent lock check did not finish"

    def pause_before_login(*args, **kwargs):
        pause()
        return original_login(*args, **kwargs)

    def pause_before_record(actor, kind, *args, **kwargs):
        if kind == "reauthentication":
            pause()
        return original_record(actor, kind, *args, **kwargs)

    monkeypatch.setattr(views, "finish_login", pause_before_login)
    monkeypatch.setattr(views, "record", pause_before_record)
    with ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(post_in_thread, client, url, data)
        try:
            assert verified.wait(20), "Authentication did not reach completion"
            # A real PostgreSQL write must wait for verification AND completion,
            # including enrollment's intentional auth-version increment.
            with pytest.raises(OperationalError) as failure:
                with transaction.atomic():
                    with connection.cursor() as cursor:
                        cursor.execute("SET LOCAL lock_timeout = '500ms'")
                    revoke(user.pk, "revoke", users["admin"])
            assert failure.value.__cause__.sqlstate == "55P03"
        finally:
            resume.set()
        response = future.result(timeout=20)
    assert response.status_code == (200 if flow == "enrollment" else 302)
    assert client.get("/").status_code == 200
    # A later revocation invalidates the established session on its next use.
    revoke(user.pk, "revoke", users["admin"])
    assert client.get("/").status_code == 302


@pytest.mark.django_db
def test_pending_challenge_expiring_after_lookup_cannot_finish(users, monkeypatch):
    user = users["manager"]
    secret = enroll(user)
    client = Client()
    client.post(
        "/accounts/login/", {"staff_id": user.username, "password": "Strong-Manager-Password-42"}
    )
    initial = views.time.time()
    original = views.pending_user

    def expire_after_lookup(request):
        result = original(request)
        monkeypatch.setattr(views.time, "time", lambda: initial + 301)
        return result

    monkeypatch.setattr(views, "pending_user", expire_after_lookup)
    client.post("/accounts/mfa/", {"code": pyotp.TOTP(secret).at(initial + 301)})

    assert_signed_out(client)
    assert not Event.objects.filter(actor=user, kind="login", outcome="success").exists()


@pytest.mark.django_db
@pytest.mark.parametrize("flow", ["challenge", "enrollment"])
def test_expiry_at_completion_rolls_back_verification_or_setup(users, monkeypatch, flow):
    user = users["manager"]
    client = Client()
    if flow == "challenge":
        secret = enroll(user)
    client.post(
        "/accounts/login/", {"staff_id": user.username, "password": "Strong-Manager-Password-42"}
    )
    if flow == "enrollment":
        client.get("/accounts/mfa/enroll/")
        secret = decrypt(client.session["enrollment_secret"])
    original = views.finish_login
    initial = views.time.time()
    version = user.auth_version

    def expire_at_completion(*args, **kwargs):
        monkeypatch.setattr(views.time, "time", lambda: initial + 301)
        return original(*args, **kwargs)

    monkeypatch.setattr(views, "finish_login", expire_at_completion)
    url = "/accounts/mfa/" if flow == "challenge" else "/accounts/mfa/enroll/"
    response = client.post(url, {"code": pyotp.TOTP(secret).at(initial)})

    assert response.status_code == 302
    assert_signed_out(client)
    user.refresh_from_db()
    assert user.auth_version == version
    assert user.mfa_last_step == -1
    assert user.mfa_confirmed == (flow == "challenge")
    assert not Event.objects.filter(actor=user, kind="login", outcome="success").exists()
    assert not Event.objects.filter(actor=user, kind="mfa_enrolled", outcome="success").exists()


@pytest.mark.django_db
def test_standalone_verification_is_bound_to_expected_account_version(users):
    user = users["manager"]
    secret = enroll(user)
    version = user.auth_version
    revoke(user.pk, "revoke", users["admin"])
    token = pyotp.TOTP(secret).now()

    assert not verify(user, token)
    assert not verify(user, "one-use-recovery")
    user.refresh_from_db()
    assert not verify(user, token, expected_auth_version=version)
    assert not verify(user, "one-use-recovery", expected_auth_version=version)
    assert user.mfa_last_step == -1
    assert len(user.recovery_hashes) == 1
    assert verify(user, token)


@pytest.mark.django_db(transaction=True)
def test_password_hash_upgrade_cannot_overwrite_concurrent_admin_reset(users, monkeypatch):
    user = users["alice"]
    user.password = make_password("Strong-Staff-Password-42", hasher="pbkdf2_sha256")
    user.save(update_fields=["password"])
    client = Client()
    checking, resume = threading.Event(), threading.Event()
    original = User.check_password

    def pause_before_password_check(instance, password):
        if instance.pk == user.pk and password == "Strong-Staff-Password-42":
            checking.set()
            assert resume.wait(20), "Concurrent reset check did not finish"
        return original(instance, password)

    monkeypatch.setattr(User, "check_password", pause_before_password_check)
    with ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(
            post_in_thread,
            client,
            "/accounts/login/",
            {"staff_id": user.username, "password": "Strong-Staff-Password-42"},
        )
        try:
            assert checking.wait(20), "Login did not reach the password check"
            with pytest.raises(OperationalError) as failure:
                with transaction.atomic():
                    with connection.cursor() as cursor:
                        cursor.execute("SET LOCAL lock_timeout = '500ms'")
                    revoke(user.pk, "password", users["admin"])
            assert failure.value.__cause__.sqlstate == "55P03"
        finally:
            resume.set()
        assert future.result(timeout=20).status_code == 302

    user.refresh_from_db()
    assert user.password.startswith("argon2$")
    assert client.get("/").status_code == 200
    revoke(user.pk, "password", users["admin"])
    assert client.get("/").status_code == 302
    user.refresh_from_db()
    assert user.check_password("Administrator-Reset-Password-82")
    assert not user.check_password("Strong-Staff-Password-42")
