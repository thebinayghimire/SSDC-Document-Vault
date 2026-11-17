import time

import pyotp
import pytest
from django.contrib.auth.hashers import make_password
from django.test import Client

from accounts.mfa import decrypt, encrypt, verify
from accounts.models import User
from audit.models import Event

from .conftest import authenticate_client

pytestmark = pytest.mark.django_db


def test_staff_login_and_logout(client, users):
    response = client.post(
        "/accounts/login/", {"staff_id": "alice", "password": "Strong-Staff-Password-42"}
    )
    assert response.status_code == 302
    assert client.get("/").status_code == 200
    assert client.session["auth_version"] == users["alice"].auth_version
    assert client.get("/accounts/logout/").status_code == 405
    assert client.post("/accounts/logout/").status_code == 302
    response = client.get("/")
    assert response.status_code == 200
    assert b"SSDC Document Vault" in response.content
    assert Event.objects.filter(kind="login", actor=users["alice"]).exists()


@pytest.mark.parametrize("staff_id", ["alice", "unknown"])
def test_generic_login_error(client, users, staff_id):
    response = client.post("/accounts/login/", {"staff_id": staff_id, "password": "wrong"})
    assert b"Unable to sign in. Check your credentials." in response.content
    assert "_auth_user_id" not in client.session


def test_throttle(client, users):
    for _ in range(11):
        response = client.post("/accounts/login/", {"staff_id": "alice", "password": "wrong"})
    assert b"Please try again later" in response.content


def test_disabled_existing_session(client, users):
    authenticate_client(client, users["alice"])
    users["alice"].is_active = False
    users["alice"].save()
    assert client.get("/documents/import/").status_code == 302


@pytest.mark.parametrize("field", ["last_seen", "auth_started"])
def test_session_expiry(client, users, field):
    authenticate_client(client, users["alice"])
    session = client.session
    session[field] = time.time() - 100000
    session.save()
    assert client.get("/documents/import/").status_code == 302


def test_role_change_revokes_session(client, users):
    user = users["alice"]
    authenticate_client(client, user)
    user.role = User.Role.MANAGER
    user.save()
    assert client.get("/documents/import/").status_code == 302


def test_privileged_login_requires_enrollment(client, users):
    response = client.post(
        "/accounts/login/", {"staff_id": "manager", "password": "Strong-Manager-Password-42"}
    )
    assert response.url == "/accounts/mfa/enroll/"
    assert "_auth_user_id" not in client.session
    response = client.get(response.url)
    assert response.status_code == 200
    secret = decrypt(client.session["enrollment_secret"])
    response = client.post("/accounts/mfa/enroll/", {"code": pyotp.TOTP(secret).now()})
    assert response.status_code == 200
    assert b"Save your recovery codes" in response.content
    user = User.objects.get(pk=users["manager"].pk)
    assert user.mfa_confirmed and user.mfa_secret != secret
    assert len(user.recovery_hashes) == 8
    assert client.session["mfa_verified"]


def test_totp_replay_and_recovery(users):
    user = users["manager"]
    secret = pyotp.random_base32()
    user.mfa_secret, user.mfa_confirmed = encrypt(secret), True
    user.recovery_hashes = [make_password("one-use-code")]
    user.save()
    token = pyotp.TOTP(secret).now()
    assert verify(user, token)
    assert not verify(user, token)
    assert verify(user, "one-use-code")
    assert not verify(user, "one-use-code")


def test_mfa_challenge_does_not_authenticate_password_alone(client, users):
    user = users["admin"]
    secret = pyotp.random_base32()
    user.mfa_secret, user.mfa_confirmed = encrypt(secret), True
    user.save()
    response = client.post(
        "/accounts/login/", {"staff_id": "admin", "password": "Strong-Admin-Password-42"}
    )
    assert response.url == "/accounts/mfa/"
    assert client.get("/admin/").status_code == 302
    response = client.post("/accounts/mfa/", {"code": pyotp.TOTP(secret).now()})
    assert response.url == "/"
    assert client.get("/admin/").status_code == 200


def test_expired_mfa_challenge(client, users):
    client.post(
        "/accounts/login/", {"staff_id": "manager", "password": "Strong-Manager-Password-42"}
    )
    session = client.session
    session["pending_at"] = 0
    session.save()
    assert client.get("/accounts/mfa/enroll/").url == "/accounts/login/"


def test_password_change_revokes_other_sessions(client, users):
    other = Client()
    user = users["alice"]
    authenticate_client(client, user)
    authenticate_client(other, user)
    response = client.post(
        "/accounts/password/",
        {
            "old_password": "Strong-Staff-Password-42",
            "new_password1": "New-Unique-Staff-Password-83",
            "new_password2": "New-Unique-Staff-Password-83",
        },
    )
    assert response.status_code == 302
    assert client.get("/").status_code == 200
    assert other.get("/documents/import/").status_code == 302


def test_admin_needs_recent_mfa_session(client, users):
    authenticate_client(client, users["admin"])
    assert client.get("/admin/").status_code == 200
    session = client.session
    session["reauth_at"] = 0
    session.save()
    assert client.get("/admin/").status_code == 302


def test_staff_cannot_access_admin(client, users):
    authenticate_client(client, users["alice"])
    assert client.get("/admin/").status_code == 302


def test_csrf_login_and_logout(users):
    client = Client(enforce_csrf_checks=True)
    assert (
        client.post(
            "/accounts/login/", {"staff_id": "alice", "password": "Strong-Staff-Password-42"}
        ).status_code
        == 403
    )
    client.get("/accounts/login/")
    token = client.cookies["csrftoken"].value
    assert (
        client.post(
            "/accounts/login/",
            {
                "staff_id": "alice",
                "password": "Strong-Staff-Password-42",
                "csrfmiddlewaretoken": token,
            },
        ).status_code
        == 302
    )
    assert client.post("/accounts/logout/").status_code == 403
