"""Exercise the installed OAuth library with fully synthetic HTTP responses."""

import json
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

import pytest
import requests
from cryptography.fernet import Fernet

from vault.drive_auth import SCOPE, cipher, decrypt, hashed
from vault.models import DriveConnection, DriveOAuthAttempt

from .conftest import authenticate_client


@pytest.mark.django_db
def test_real_oauth_exchange_uses_exact_redirect_and_pkce(client, users, settings):
    settings.GOOGLE_DRIVE_CLIENT_ID = "synthetic-client"
    settings.GOOGLE_DRIVE_CLIENT_SECRET = "synthetic-secret"
    settings.GOOGLE_DRIVE_CREDENTIAL_KEY = Fernet.generate_key().decode()
    settings.GOOGLE_DRIVE_REDIRECT_URI = "http://localhost:8080/storage/google/callback/"
    authenticate_client(client, users["admin"])
    response = client.post("/storage/google/", {"action": "connect"})
    query = parse_qs(urlsplit(response.url).query)
    state = query["state"][0]
    attempt = DriveOAuthAttempt.objects.get(state_hash=hashed(state))
    verifier = cipher().decrypt(attempt.encrypted_verifier.encode()).decode()
    calls = []

    def transport(session, method, url, **kwargs):
        calls.append((method, url, kwargs))
        response = requests.Response()
        response.status_code, response.url = 200, url
        response.request = requests.Request(method, url).prepare()
        response.headers["Content-Type"] = "application/json"
        if url == "https://oauth2.googleapis.com/token":
            data = kwargs["data"]
            data = parse_qs(data) if isinstance(data, str) else data

            def value(key):
                result = data[key]
                return result[0] if isinstance(result, list) else result

            assert value("redirect_uri") == settings.GOOGLE_DRIVE_REDIRECT_URI
            assert value("code_verifier") == verifier
            assert value("code") == "synthetic-one-use-code"
            assert kwargs["auth"].password == "synthetic-secret"
            response._content = json.dumps(
                {
                    "access_token": "synthetic-access",
                    "refresh_token": "synthetic-refresh",
                    "expires_in": 3600,
                    "token_type": "Bearer",
                    "scope": SCOPE,
                }
            ).encode()
        elif url == "https://www.googleapis.com/drive/v3/about":
            assert kwargs["headers"]["Authorization"] == "Bearer synthetic-access"
            response._content = b'{"user":{"permissionId":"synthetic-owner"}}'
        else:
            pytest.fail("Unexpected outbound HTTP request")
        return response

    with patch.object(requests.Session, "request", transport):
        response = client.get(
            "/storage/google/callback/", {"state": state, "code": "synthetic-one-use-code"}
        )
    assert response.status_code == 302 and response.url == "/storage/google/"
    assert len(calls) == 2
    assert not DriveOAuthAttempt.objects.filter(state_hash=hashed(state)).exists()
    stored = DriveConnection.objects.get(pk=1)
    assert stored.owner_id == "synthetic-owner"
    assert decrypt(stored.encrypted_credentials)["refresh_token"] == "synthetic-refresh"
    assert "synthetic-secret" not in stored.encrypted_credentials
