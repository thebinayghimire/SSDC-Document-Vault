import pyotp
import pytest

from accounts.mfa import encrypt

pytestmark = pytest.mark.django_db


@pytest.mark.parametrize("enrolled", [False, True])
def test_local_admin_password_login_and_reauthentication(client, users, settings, enrolled):
    settings.MFA_ENABLED = False
    user = users["admin"]
    if enrolled:
        user.mfa_secret = encrypt(pyotp.random_base32())
        user.mfa_confirmed = True
        user.save(update_fields=["mfa_secret", "mfa_confirmed"])
    response = client.post(
        "/accounts/login/", {"staff_id": "admin", "password": "Strong-Admin-Password-42"}
    )
    assert response.url == "/"
    assert not client.session["mfa_verified"]
    assert client.get("/").status_code == 200
    assert client.get("/documents/import/").status_code == 200
    assert client.get("/admin/").status_code == 200
    assert b"MFA code" not in client.get("/accounts/confirm/").content
    response = client.post("/accounts/confirm/", {"password": "Strong-Admin-Password-42"})
    assert response.url == "/"
    user.refresh_from_db()
    assert user.mfa_confirmed == enrolled
    settings.MFA_ENABLED = True
    assert client.get("/documents/import/").url == "/accounts/login/?next=/documents/import/"


def test_disabled_authenticator_routes_return_to_login_and_wrong_password_fails(
    client, users, settings
):
    settings.MFA_ENABLED = False
    for url in ("/accounts/mfa/", "/accounts/mfa/enroll/"):
        assert client.get(url).url == "/accounts/login/"
        assert client.post(url, {"code": "000000"}).url == "/accounts/login/"
    response = client.post("/accounts/login/", {"staff_id": "admin", "password": "wrong"})
    assert b"Unable to sign in" in response.content
    assert "_auth_user_id" not in client.session
