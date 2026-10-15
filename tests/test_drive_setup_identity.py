from urllib.parse import urlencode

import pytest

from .conftest import authenticate_client

pytestmark = pytest.mark.django_db


def test_storage_setup_returns_to_connection_after_password_confirmation(client, users, settings):
    settings.MFA_ENABLED = False
    authenticate_client(client, users["admin"], mfa=False)
    session = client.session
    session["reauth_at"] = 0
    session.save()
    response = client.get("/storage/google/")
    assert response.url == "/accounts/confirm/?next=/storage/google/"
    response = client.post(response.url, {"password": "Strong-Admin-Password-42"})
    assert response.url == "/storage/google/"
    assert client.get(response.url).status_code == 200


@pytest.mark.parametrize(
    "destination",
    ["https://example.com/", "//example.com/", "/\\example.com/", "/\n/example.com/"],
)
def test_password_confirmation_does_not_redirect_outside_the_vault(
    client, users, settings, destination
):
    settings.MFA_ENABLED = False
    authenticate_client(client, users["admin"], mfa=False)
    response = client.post(
        "/accounts/confirm/",
        {"password": "Strong-Admin-Password-42"},
        QUERY_STRING=urlencode({"next": destination}),
    )
    assert response.url == "/"
