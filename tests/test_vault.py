import uuid
from unittest.mock import patch

import pytest
from django.core.exceptions import SuspiciousFileOperation, ValidationError
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import Client

from audit.models import Event
from vault.models import DocumentGrant, Folder, FolderGrant, Version
from vault.policy import folder_permissions, permitted_documents
from vault.scanner import ScanUnavailable
from vault.services import process_version, upload_document
from vault.storage import path_for
from vault.validation import InvalidUpload

from .conftest import authenticate_client, image_upload, pdf_upload

pytestmark = pytest.mark.django_db


@pytest.mark.parametrize("endpoint", ["", "content/", "thumbnail/", "manage/", "replace/"])
def test_other_user_denied(client, users, document, endpoint):
    authenticate_client(client, users["bob"])
    assert client.get(f"/documents/{document.pk}/{endpoint}").status_code == 404


@pytest.mark.parametrize("method", ["get", "head"])
def test_range_and_head_authorization(client, users, document, method):
    url = f"/documents/{document.pk}/content/"
    authenticate_client(client, users["bob"])
    assert getattr(client, method)(url, HTTP_RANGE="bytes=0-9").status_code == 404
    authenticate_client(client, users["alice"])
    response = getattr(client, method)(url, HTTP_RANGE="bytes=0-9")
    assert response.status_code == (206 if method == "get" else 200)
    assert response["Content-Length"] == (
        "10" if method == "get" else str(document.active_version.size)
    )
    assert response["Cache-Control"].startswith("no-store")
    if method == "get":
        assert b"".join(response.streaming_content).startswith(b"%PDF-")


@pytest.mark.parametrize(
    "range_header", ["bytes=9999999-", "bytes=10-1", "bytes=-0", "bytes=0-1,4-5", "bad"]
)
def test_invalid_ranges(client, users, document, range_header):
    authenticate_client(client, users["alice"])
    assert (
        client.get(f"/documents/{document.pk}/content/", HTTP_RANGE=range_header).status_code == 416
    )


def test_suffix_range(client, users, document):
    authenticate_client(client, users["alice"])
    response = client.get(f"/documents/{document.pk}/content/", HTTP_RANGE="bytes=-12")
    assert response.status_code == 206
    assert len(b"".join(response.streaming_content)) == 12


def test_unauthenticated_endpoints(client, document):
    for suffix in ("", "content/", "thumbnail/", "manage/"):
        assert client.get(f"/documents/{document.pk}/{suffix}").status_code == 302
    assert client.get("/private-media/anything").status_code == 404


def test_revocation_applies_to_next_range(client, users, document, folder):
    authenticate_client(client, users["alice"])
    assert (
        client.get(f"/documents/{document.pk}/content/", HTTP_RANGE="bytes=0-9").status_code == 206
    )
    FolderGrant.objects.filter(folder=folder, user=users["alice"]).delete()
    assert (
        client.get(f"/documents/{document.pk}/content/", HTTP_RANGE="bytes=10-19").status_code
        == 404
    )


def test_folder_inheritance_and_empty_override(users, folder):
    child = Folder.objects.create(name="Child", parent=folder, restricted=False)
    hidden = Folder.objects.create(name="Restricted", parent=child, restricted=True)
    visible, manageable = folder_permissions(users["alice"])
    assert child.pk in visible and hidden.pk not in visible
    assert not manageable
    assert hidden.pk in folder_permissions(users["admin"])[0]


def test_document_override_and_move(users, document, folder):
    document.restricted = True
    document.save()
    assert not permitted_documents(users["alice"]).filter(pk=document.pk).exists()
    DocumentGrant.objects.create(document=document, user=users["bob"])
    assert permitted_documents(users["bob"]).filter(pk=document.pk).exists()
    document.restricted = False
    document.folder = Folder.objects.create(name="Confidential")
    document.save()
    assert not permitted_documents(users["alice"]).filter(pk=document.pk).exists()


def test_staff_manage_grant_does_not_elevate_role(client, users, folder, document):
    FolderGrant.objects.filter(folder=folder, user=users["alice"]).update(manage=True)
    authenticate_client(client, users["alice"])
    assert client.get(f"/folders/{folder.pk}/upload/").status_code == 404
    assert client.post(f"/documents/{document.pk}/actions/delete/").status_code == 404


def test_search_does_not_leak(client, users, document):
    authenticate_client(client, users["bob"])
    response = client.get("/?q=Project")
    assert b"Project report" not in response.content
    assert response.context["total"] == 0


@pytest.mark.parametrize("user_key", ["alice", "admin"])
def test_xss_title_and_unwatermarked_preview(client, users, document, user_key):
    document.title = '<script>alert("x")</script>'
    document.save()
    authenticate_client(client, users[user_key])
    response = client.get("/")
    assert b"<script>alert" not in response.content
    assert b"&lt;script&gt;" in response.content
    response = client.get(f"/documents/{document.pk}/")
    assert b'class="watermark"' not in response.content
    assert b"data-watermark" not in response.content
    assert b"Your staff ID appears on this preview" not in response.content
    assert b'data-url="/documents/' in response.content
    assert b"Content-Security-Policy" not in response.content
    assert "object-src 'none'" in response["Content-Security-Policy"]


def test_upload_publish_and_safe_thumbnail(folder, users):
    version = upload_document(users["manager"], folder, image_upload(), "Photo")
    assert version.status == Version.Status.READY
    assert version.sha256 and version.thumbnail_key
    assert path_for(version.thumbnail_key).is_file()
    assert version.document.active_version_id == version.pk


@pytest.mark.parametrize(
    "name,data",
    [
        ("fake.pdf", b"not PDF"),
        ("payload.svg", b"<svg/>"),
        ("bad.png", b"%PDF-1.4 fake"),
        ("bad.pdf", b"%PDF-1.4 malformed"),
    ],
)
def test_malformed_and_mismatched_uploads(folder, users, name, data):
    with pytest.raises(InvalidUpload):
        upload_document(users["manager"], folder, SimpleUploadedFile(name, data), "Bad")
    assert not Version.objects.exists()


def test_limits(folder, users, settings):
    settings.MAX_UPLOAD_BYTES = 2
    with pytest.raises(InvalidUpload):
        upload_document(users["manager"], folder, pdf_upload(), "Too big")


def test_global_quota(folder, users, settings):
    settings.MAX_STORAGE_BYTES = 10
    with pytest.raises(InvalidUpload):
        upload_document(users["manager"], folder, pdf_upload(), "Quota")
    assert not Version.objects.exists()


def test_quota_reserves_generated_preview_bytes(folder, users, settings):
    settings.MAX_STORAGE_BYTES = 1024
    with pytest.raises(InvalidUpload):
        upload_document(users["manager"], folder, image_upload(), "Preview exceeds quota")
    assert not Version.objects.exists()


def test_pixel_limit(folder, users, settings):
    settings.MAX_IMAGE_PIXELS = 10
    with pytest.raises(InvalidUpload):
        upload_document(users["manager"], folder, image_upload(), "Big image")


def test_pdf_page_limit(folder, users, settings):
    settings.MAX_PDF_PAGES = 1
    with pytest.raises(InvalidUpload):
        upload_document(users["manager"], folder, pdf_upload(), "Long PDF")


def test_scan_failure_quarantines_and_retry_publishes(folder, users):
    with patch("vault.services.scan", side_effect=ScanUnavailable):
        version = upload_document(users["manager"], folder, pdf_upload(), "Pending")
    assert version.status == Version.Status.QUARANTINED
    version.document.refresh_from_db()
    assert version.document.active_version_id is None
    version = process_version(version)
    assert version.status == Version.Status.READY


@pytest.mark.django_db(transaction=True)
def test_malware_rejected(folder, users):
    with patch("vault.services.scan", return_value="infected"):
        version = upload_document(users["manager"], folder, pdf_upload(), "Infected")
    assert version.status == Version.Status.REJECTED
    assert not path_for(version.storage_key).exists()
    assert version.document.active_version_id is None


def test_failed_replacement_preserves_old_version(document, users):
    old = document.active_version_id
    with patch("vault.services.scan", side_effect=ScanUnavailable):
        upload_document(users["manager"], document.folder, pdf_upload(), document.title, document)
    document.refresh_from_db()
    assert document.active_version_id == old


def test_same_filename_unique_storage(folder, users):
    first = upload_document(users["manager"], folder, pdf_upload(), "First")
    second = upload_document(users["manager"], folder, pdf_upload(), "Second")
    assert first.storage_key != second.storage_key


@pytest.mark.parametrize("key", ["../secret", "/etc/passwd", "originals/../../secret"])
def test_storage_traversal(key):
    with pytest.raises(SuspiciousFileOperation):
        path_for(key)


def test_storage_rejects_symlink(settings, tmp_path):
    root = settings.PRIVATE_STORAGE_ROOT
    root.mkdir()
    target = tmp_path / "outside"
    target.mkdir()
    try:
        (root / "link").symlink_to(target, target_is_directory=True)
    except OSError:
        pytest.skip("Windows symlink creation requires Developer Mode or elevated privileges")
    with pytest.raises(SuspiciousFileOperation):
        path_for("link/secret")


def test_folder_cycle(folder):
    child = Folder.objects.create(name="Child", parent=folder)
    folder.parent = child
    with pytest.raises(ValidationError):
        folder.full_clean()


def test_lifecycle(client, users, document):
    authenticate_client(client, users["manager"])
    url = f"/documents/{document.pk}/"
    assert client.post(url + "actions/archive/").status_code == 302
    authenticate_client(client, users["alice"])
    assert client.get(url).status_code == 404
    authenticate_client(client, users["manager"])
    assert client.post(url + "actions/unarchive/").status_code == 302
    assert client.post(url + "actions/delete/").status_code == 302
    authenticate_client(client, users["alice"])
    assert client.get(url + "content/").status_code == 404
    authenticate_client(client, users["manager"])
    assert client.post(url + "actions/restore/").status_code == 302
    assert Event.objects.filter(kind="document_restore").exists()


def test_metadata_cannot_move_to_ungranted_folder(client, users, document):
    authenticate_client(client, users["manager"])
    other = Folder.objects.create(name="Other")
    response = client.post(
        f"/documents/{document.pk}/manage/",
        {"title": "Moved", "folder": str(other.pk), "role": "admin"},
    )
    assert response.status_code == 200
    document.refresh_from_db()
    assert document.folder_id != other.pk
    users["manager"].refresh_from_db()
    assert users["manager"].role == "manager"


def test_upload_requires_recent_identity(client, users, folder):
    authenticate_client(client, users["manager"])
    session = client.session
    session["reauth_at"] = 0
    session.save()
    assert client.get(f"/folders/{folder.pk}/upload/").url == "/accounts/confirm/"


def test_explicit_document_manager_can_edit_title_without_folder_grant(
    client, users, document, folder
):
    document.restricted = True
    document.save()
    FolderGrant.objects.filter(folder=folder, user=users["manager"]).delete()
    DocumentGrant.objects.create(document=document, user=users["manager"], manage=True)
    authenticate_client(client, users["manager"])
    response = client.post(
        f"/documents/{document.pk}/manage/",
        {"title": "Updated within document grant", "folder": str(folder.pk)},
    )
    assert response.status_code == 302
    document.refresh_from_db()
    assert document.title == "Updated within document grant" and document.folder_id == folder.pk


def test_write_csrf(users, document):
    client = Client(enforce_csrf_checks=True)
    authenticate_client(client, users["manager"])
    assert client.post(f"/documents/{document.pk}/actions/delete/").status_code == 403


def test_guessed_uuid(client, users):
    authenticate_client(client, users["alice"])
    assert client.get(f"/documents/{uuid.uuid4()}/").status_code == 404


def test_production_scanner_cannot_skip(settings, tmp_path):
    from vault.scanner import scan

    settings.PRODUCTION = True
    settings.SCAN_MODE = "skip-development"
    with patch("vault.scanner.socket.create_connection", side_effect=OSError):
        with pytest.raises(ScanUnavailable):
            scan(tmp_path / "sample")
