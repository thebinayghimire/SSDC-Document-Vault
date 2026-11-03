from urllib.parse import urlencode

import pyotp
import pytest
from django.conf import settings as django_settings
from django.test import Client

from accounts.mfa import decrypt, encrypt
from audit.models import Event

from .conftest import authenticate_client

pytestmark = pytest.mark.django_db


@pytest.mark.parametrize(
    ("account", "password", "destination"),
    [
        ("admin", "Strong-Admin-Password-42", "/admin/"),
        ("alice", "Strong-Staff-Password-42", "/staff/"),
        ("manager", "Strong-Manager-Password-42", "/staff/"),
    ],
)
def test_shared_sign_in_uses_server_account_role(
    client, users, settings, account, password, destination
):
    settings.MFA_ENABLED = False
    response = client.post(
        "/accounts/login/", {"staff_id": account, "password": password, "role": "admin"}
    )
    assert response.url == destination
    assert client.get(destination).status_code == 200


@pytest.mark.parametrize(
    ("portal", "account", "password", "allowed", "destination"),
    [
        ("admin", "admin", "Strong-Admin-Password-42", True, "/admin/"),
        ("staff", "alice", "Strong-Staff-Password-42", True, "/staff/"),
        ("staff", "manager", "Strong-Manager-Password-42", True, "/staff/"),
        ("admin", "alice", "Strong-Staff-Password-42", False, None),
        ("admin", "manager", "Strong-Manager-Password-42", False, None),
        ("staff", "admin", "Strong-Admin-Password-42", False, None),
    ],
)
def test_dedicated_sign_in_rejects_accounts_from_other_portal(
    client, users, settings, portal, account, password, allowed, destination
):
    settings.MFA_ENABLED = False
    response = client.post(
        f"/accounts/{portal}/login/", {"staff_id": account, "password": password}
    )
    if allowed:
        assert response.url == destination
    else:
        assert response.status_code == 200
        assert b"Unable to sign in. Check your credentials." in response.content
        assert "_auth_user_id" not in client.session
        assert "pending_user" not in client.session
        assert Event.objects.filter(kind="login", outcome="denied").exists()


@pytest.mark.parametrize(
    "destination",
    [
        "https://example.com/admin/",
        "//example.com/staff/",
        "/admin/",
        "/manage/",
        "/storage/google/",
        "/accounts/logout/",
        "/accounts/login/",
        "/accounts/mfa/",
        "/staff/../admin/",
        "/staff/%2e%2e/admin/",
        "/staff/%2f/admin/",
    ],
)
def test_staff_sign_in_cannot_be_redirected_outside_its_portal(
    client, users, settings, destination
):
    settings.MFA_ENABLED = False
    response = client.post(
        "/accounts/staff/login/?" + urlencode({"next": destination}),
        {"staff_id": "alice", "password": "Strong-Staff-Password-42"},
    )
    assert response.url == "/staff/"


def test_valid_document_return_is_preserved_and_still_authorized(client, users, settings, document):
    settings.MFA_ENABLED = False
    destination = f"/documents/{document.pk}/?source=library"
    response = client.post(
        "/accounts/staff/login/?" + urlencode({"next": destination}),
        {"staff_id": "alice", "password": "Strong-Staff-Password-42"},
    )
    assert response.url == destination
    assert client.get(destination).status_code == 200
    client.post("/accounts/logout/")
    response = client.post(
        "/accounts/staff/login/?" + urlencode({"next": destination}),
        {"staff_id": "bob", "password": "Strong-Staff-Password-43"},
    )
    assert response.url == destination
    assert client.get(destination).status_code == 404


def test_portal_boundaries_and_staff_controls(client, users, document):
    assert client.get("/staff/").url.startswith("/accounts/staff/login/")
    response = client.get("/admin/login/?next=/admin/accounts/user/")
    assert response.url == "/accounts/admin/login/?next=%2Fadmin%2Faccounts%2Fuser%2F"
    authenticate_client(client, users["alice"])
    response = client.get("/staff/")
    assert response.status_code == 200
    assert b"Staff portal" in response.content
    for label in (b"Admin portal", b"Add documents", b"Manage documents", b"Document storage"):
        assert label not in response.content
    assert client.get("/admin/", follow=True).redirect_chain[-1][0] == "/staff/"
    assert client.get("/manage/").status_code == 404
    assert client.get("/storage/google/").status_code == 403
    assert client.post("/documents/import/", {}).status_code == 404
    assert client.get(f"/documents/{document.pk}/manage/").status_code == 404
    authenticate_client(client, users["admin"])
    assert client.get("/staff/").url == "/admin/"


@pytest.mark.parametrize(("account", "portal"), [("alice", "staff"), ("admin", "admin")])
def test_sign_out_clears_session_and_replayed_cookie_cannot_authorize(
    client, users, account, portal
):
    authenticate_client(client, users[account])
    stolen = Client()
    stolen.cookies[django_settings.SESSION_COOKIE_NAME] = client.cookies[
        django_settings.SESSION_COOKIE_NAME
    ].value
    response = client.post("/accounts/logout/")
    assert response.url == f"/accounts/{portal}/login/"
    assert "_auth_user_id" not in client.session
    assert not client.get("/accounts/session/").json()["authenticated"]
    assert not stolen.get("/accounts/session/").json()["authenticated"]
    assert stolen.get("/staff/").status_code == 302
    assert client.get("/accounts/password/").status_code == 302
    assert Event.objects.filter(kind="logout", actor=users[account]).exists()


def test_admin_logout_uses_the_same_session_revocation(client, users):
    authenticate_client(client, users["admin"])
    assert client.get("/admin/logout/").status_code == 405
    assert client.post("/admin/logout/").url == "/accounts/admin/login/"
    assert not client.get("/accounts/session/").json()["authenticated"]


def test_session_status_is_private_and_obeys_revocation(client, users):
    response = client.get("/accounts/session/")
    assert response.json() == {"authenticated": False, "marker": "", "home_url": "/accounts/login/"}
    assert "no-store" in response["Cache-Control"]
    authenticate_client(client, users["alice"])
    response = client.get("/accounts/session/")
    assert response.json()["authenticated"]
    assert response.json()["home_url"] == "/staff/"
    assert response.json()["marker"] in client.get("/staff/").content.decode()
    users["alice"].role = "manager"
    users["alice"].save(update_fields=["role"])
    assert not client.get("/accounts/session/").json()["authenticated"]


def test_admin_mfa_keeps_safe_return_and_session_marker(client, users):
    user = users["admin"]
    secret = pyotp.random_base32()
    user.mfa_secret, user.mfa_confirmed = encrypt(secret), True
    user.save(update_fields=["mfa_secret", "mfa_confirmed"])
    response = client.post(
        "/accounts/admin/login/?next=/admin/accounts/user/",
        {"staff_id": "admin", "password": "Strong-Admin-Password-42"},
    )
    assert response.url == "/accounts/mfa/"
    assert not client.get("/accounts/session/").json()["authenticated"]
    response = client.post("/accounts/mfa/", {"code": pyotp.TOTP(secret).now()})
    assert response.url == "/admin/accounts/user/"
    assert client.session["portal_session"]
    assert "login_destination" not in client.session


def test_mfa_enrollment_continues_to_correct_portal(client, users):
    client.post(
        "/accounts/admin/login/", {"staff_id": "admin", "password": "Strong-Admin-Password-42"}
    )
    client.get("/accounts/mfa/enroll/")
    secret = decrypt(client.session["enrollment_secret"])
    response = client.post("/accounts/mfa/enroll/", {"code": pyotp.TOTP(secret).now()})
    assert response.status_code == 200
    assert response.context["continue_url"] == "/admin/"
    assert client.session["mfa_verified"]
