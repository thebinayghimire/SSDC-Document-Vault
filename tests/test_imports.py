import time
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

import pytest
from django.core.exceptions import PermissionDenied
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import Client

from vault.models import Document, Folder, FolderGrant, Version

from .conftest import authenticate_client, pdf_upload

pytestmark = pytest.mark.django_db
URL = "/documents/import/"
JSON = {"HTTP_ACCEPT": "application/json"}


def test_library_exposes_import_and_only_manageable_destinations(client, users, folder):
    hidden = Folder.objects.create(name="Private destination")
    authenticate_client(client, users["manager"])
    response = client.get("/")
    assert b"Bring files into your vault" in response.content
    assert list(response.context["import_folders"]) == [folder]
    assert str(hidden.pk).encode() not in response.content
    response = client.get(f"/folders/{folder.pk}/")
    assert b"data-import-form" in response.content
    assert b"selected" in response.content
    authenticate_client(client, users["alice"])
    assert b"data-import-form" not in client.get("/").content
    assert client.get(URL).status_code == 200
    assert (
        client.post(
            URL, {"folder": folder.pk, "title": "Denied", "file": pdf_upload()}, **JSON
        ).status_code
        == 404
    )


def test_import_uses_existing_validation_and_publishing(client, users, folder):
    authenticate_client(client, users["manager"])
    response = client.post(
        URL, {"folder": folder.pk, "title": "Imported report", "file": pdf_upload()}, **JSON
    )
    assert response.status_code == 201
    assert response.json()["status"] == Version.Status.READY
    doc = Document.objects.get(title="Imported report")
    assert doc.folder == folder
    assert doc.active_version.status == Version.Status.READY
    assert response.json()["manage_url"] == f"/documents/{doc.pk}/manage/"
    response = client.post(
        URL,
        {"folder": folder.pk, "title": "Fake", "file": SimpleUploadedFile("fake.pdf", b"fake")},
        **JSON,
    )
    assert response.status_code == 400
    assert "file" in response.json()["errors"]
    assert Document.objects.count() == 1


def test_forged_destination_and_revoked_access_cannot_upload(client, users, folder):
    authenticate_client(client, users["manager"])
    hidden = Folder.objects.create(name="Hidden")
    response = client.post(
        URL, {"folder": hidden.pk, "title": "Denied", "file": pdf_upload()}, **JSON
    )
    assert response.status_code == 400
    assert "folder" in response.json()["errors"]
    with patch("vault.views.upload_document", side_effect=PermissionDenied):
        response = client.post(
            URL, {"folder": folder.pk, "title": "Revoked", "file": pdf_upload()}, **JSON
        )
    assert response.status_code == 403
    FolderGrant.objects.filter(user=users["manager"]).delete()
    response = client.post(
        URL, {"folder": folder.pk, "title": "Revoked", "file": pdf_upload()}, **JSON
    )
    assert response.status_code == 400
    assert not Document.objects.exists()


def test_expired_identity_returns_actionable_json_without_upload(client, users, folder):
    authenticate_client(client, users["manager"])
    session = client.session
    session["reauth_at"] = time.time() - 601
    session.save()
    response = client.post(
        URL, {"folder": folder.pk, "title": "Wait", "file": pdf_upload()}, **JSON
    )
    assert response.status_code == 401
    payload = response.json()
    assert set(payload) == {"error", "reauth_url"}
    assert payload["error"] == "Verify your identity, then continue your upload."
    redirect = urlsplit(payload["reauth_url"])
    assert redirect.path == "/accounts/confirm/"
    assert parse_qs(redirect.query) == {"next": [URL]}
    assert not Document.objects.exists()


def test_import_requires_csrf_and_supports_plain_form(users, folder):
    client = authenticate_client(Client(enforce_csrf_checks=True), users["manager"])
    response = client.post(
        URL, {"folder": folder.pk, "title": "Denied", "file": pdf_upload()}, **JSON
    )
    assert response.status_code == 403
    client.get(URL)
    response = client.post(
        URL,
        {
            "folder": folder.pk,
            "title": "Plain form",
            "file": pdf_upload(),
            "csrfmiddlewaretoken": client.cookies["csrftoken"].value,
        },
    )
    assert response.status_code == 302
    assert Document.objects.get().title == "Plain form"


def test_manager_without_destinations_sees_access_guidance(client, users):
    authenticate_client(client, users["manager"])
    assert b"You need a folder with upload access" in client.get(URL).content
    authenticate_client(client, users["admin"])
    assert b"Create your first folder" in client.get(URL).content


def test_destination_labels_do_not_leak_hidden_parent(client, users):
    parent = Folder.objects.create(name="Secret parent")
    child = Folder.objects.create(name="Shared child", parent=parent)
    FolderGrant.objects.create(folder=child, user=users["manager"], manage=True)
    authenticate_client(client, users["manager"])
    for url in ("/", URL):
        response = client.get(url)
        assert b"Shared child" in response.content
        assert b"Secret parent" not in response.content


@pytest.mark.parametrize("role", ["staff", "restricted"])
def test_read_only_dashboards_hide_import_without_upload_access(client, users, folder, role):
    user = users["alice"]
    user.role = role
    user.save()
    authenticate_client(client, user)
    for url in ("/", f"/folders/{folder.pk}/"):
        response = client.get(url)
        assert response.status_code == 200
        assert b'href="#import-documents"' not in response.content
        assert b"Bring files into your vault" not in response.content
        assert b"Your account has viewing access" not in response.content
        assert b"data-import-form" not in response.content
    response = client.get(URL)
    assert response.status_code == 200
    assert b"Your account has viewing access" in response.content
    assert (
        client.post(
            URL, {"folder": folder.pk, "title": "Denied", "file": pdf_upload()}, **JSON
        ).status_code
        == 404
    )
    assert not Document.objects.exists()
