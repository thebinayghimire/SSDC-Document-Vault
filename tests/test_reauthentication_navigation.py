from urllib.parse import parse_qs, quote, urlsplit

import pytest
from django.test import RequestFactory

from accounts.navigation import (
    safe_admin_destination,
    safe_return_destination,
)
from vault.models import Document, Folder

from .conftest import authenticate_client, pdf_upload


def expire_identity(client):
    session = client.session
    session["reauth_at"] = 0
    session.save()


def reauthentication_destination(response):
    redirect = urlsplit(response.url)
    assert redirect.path == "/accounts/confirm/"
    return parse_qs(redirect.query)["next"][0]


def test_safe_return_destination_rejects_control_characters():
    rf = RequestFactory()
    request = rf.get("/")
    for bad_char in ("\n", "\r", "\t", "\x00", "\x1f", "\x7f"):
        assert (
            safe_return_destination(request, f"/manage/{bad_char}test", "/fallback/")
            == "/fallback/"
        )
    assert safe_return_destination(request, "/manage/?page=2", "/fallback/") == "/manage/?page=2"


@pytest.mark.parametrize(
    "ambiguous_or_invalid",
    [
        "/admin/../admin/login/",
        "/admin/%2e%2e/admin/login/",
        "/admin/%2E%2E/admin/login/",
        "/admin/../accounts/password/",
        "/admin/%2e%2e/accounts/password/",
        "/admin/%2E%2E/accounts/password/",
        "/admin/%2e/login/",
        "/admin/%2e%2flogin/",
        "/admin/%2flogin/",
        "/admin/..",
        "/admin/../",
        "/admin/./",
        "/admin/login/",
        "/admin/login",
        "/admin/login/?next=/admin/",
        "https://example.com/admin/",
        "//example.com/admin/",
        "/\\example.com/admin/",
    ],
)
def test_safe_admin_destination_rejects_ambiguous_or_invalid_paths(ambiguous_or_invalid):
    rf = RequestFactory()
    request = rf.get("/admin/login/")
    assert safe_admin_destination(request, ambiguous_or_invalid) == "/admin/"


@pytest.mark.parametrize(
    ("valid_path", "expected"),
    [
        ("/admin/", "/admin/"),
        ("/admin/accounts/user/", "/admin/accounts/user/"),
        ("/admin/accounts/user/?q=alice", "/admin/accounts/user/?q=alice"),
        ("/admin/vault/document/?q=%2e%2e", "/admin/vault/document/?q=%2e%2e"),
        (
            "/admin/vault/document/?filter=1&name=test%20name",
            "/admin/vault/document/?filter=1&name=test%20name",
        ),
    ],
)
def test_safe_admin_destination_preserves_valid_paths_and_queries(valid_path, expected):
    rf = RequestFactory()
    request = rf.get("/admin/login/")
    assert safe_admin_destination(request, valid_path) == expected


@pytest.mark.django_db
def test_reauthentication_preserves_valid_query_string(client, users, settings):
    settings.MFA_ENABLED = False
    authenticate_client(client, users["manager"])
    destination = "/manage/?page=2&sort=name"
    response = client.post(
        "/accounts/confirm/?next=%2Fmanage%2F%3Fpage%3D2%26sort%3Dname",
        {"password": "Strong-Manager-Password-42"},
    )
    assert response.url == destination


@pytest.mark.django_db
def test_get_and_form_views_keep_safe_return_destinations(client, users, document, folder):
    authenticate_client(client, users["manager"])
    expire_identity(client)

    manage = f"/documents/{document.pk}/manage/?tab=versions&order=oldest"
    assert reauthentication_destination(client.get(manage)) == manage

    create = f"/folders/{folder.pk}/new/?from=library"
    response = client.post(create, {"name": "Must not be created"})
    assert reauthentication_destination(response) == create
    assert not Folder.objects.filter(name="Must not be created").exists()


@pytest.mark.django_db
def test_post_only_actions_return_to_get_page_without_replaying(client, users, document, settings):
    settings.MFA_ENABLED = False
    authenticate_client(client, users["manager"])
    expire_identity(client)
    action = f"/documents/{document.pk}/actions/archive/?source=manage"
    response = client.post(action)
    manage = f"/documents/{document.pk}/manage/"
    assert reauthentication_destination(response) == manage
    document.refresh_from_db()
    assert not document.archived

    response = client.post(response.url, {"password": "Strong-Manager-Password-42"})
    assert response.url == manage
    assert client.get(response.url).status_code == 200
    document.refresh_from_db()
    assert not document.archived

    expire_identity(client)
    version = document.active_version
    response = client.post(f"/documents/{document.pk}/versions/{version.pk}/restore/")
    assert reauthentication_destination(response) == manage


@pytest.mark.django_db
def test_plain_import_returns_to_get_form_without_retaining_upload(client, users, folder):
    authenticate_client(client, users["manager"])
    expire_identity(client)
    destination = "/documents/import/?source=batch"
    response = client.post(
        destination,
        {"folder": folder.pk, "title": "Not uploaded", "file": pdf_upload()},
    )
    assert reauthentication_destination(response) == destination
    assert not Document.objects.exists()


@pytest.mark.django_db
def test_admin_reauthentication_validates_next_and_avoids_login_loops(client, users, settings):
    settings.MFA_ENABLED = False
    authenticate_client(client, users["admin"], mfa=False)
    expire_identity(client)

    destination = "/admin/accounts/user/?q=alice"
    response = client.get("/admin/login/?next=" + quote(destination))
    assert reauthentication_destination(response) == destination
    response = client.post(response.url, {"password": "Strong-Admin-Password-42"})
    assert response.url == destination

    expire_identity(client)
    # Valid destination with preserved query string containing encoded dots
    query_dest = "/admin/vault/document/?q=%2e%2e"
    response = client.get("/admin/login/?next=" + quote(query_dest))
    assert reauthentication_destination(response) == query_dest

    # Ambiguous paths and path traversal attempts must fall back to /admin/
    for ambiguous in (
        "https://example.com/",
        "/",
        "/admin/login/?next=/admin/",
        "/admin/login",
        "/admin/../admin/login/",
        "/admin/%2e%2e/admin/login/",
        "/admin/%2E%2E/admin/login/",
        "/admin/../accounts/password/",
        "/admin/%2e%2e/accounts/password/",
        "/admin/%2e/login/",
    ):
        response = client.get("/admin/login/?next=" + quote(ambiguous))
        assert reauthentication_destination(response) == "/admin/"


@pytest.mark.django_db
def test_non_admin_is_not_sent_through_admin_reauthentication_loop(client, users):
    authenticate_client(client, users["alice"])
    response = client.get("/admin/login/?next=/admin/")
    assert response.url == "/"
