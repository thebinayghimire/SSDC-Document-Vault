"""Synthetic documents and mocked HTTPS only; these tests never access a Google account."""

import hashlib
import io
import json
import logging
import tarfile
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import PropertyMock, patch
from urllib.parse import parse_qs, urlsplit

import pytest
import requests
from cryptography.fernet import Fernet
from django.core.exceptions import PermissionDenied
from django.core.management import call_command
from django.core.management.base import CommandError
from django.db import DatabaseError
from django.test import Client
from google.auth.exceptions import RefreshError
from google.oauth2.credentials import Credentials

from audit.models import Event
from config.logging import SafeJSONFormatter
from vault import drive_auth, drive_storage
from vault.drive_auth import SCOPE, StorageError, access_token, cipher, decrypt
from vault.models import (
    Document,
    DriveConnection,
    DriveOAuthAttempt,
    DriveObject,
    FolderGrant,
    Version,
)
from vault.scanner import ScanUnavailable
from vault.services import process_version, upload_document
from vault.storage import path_for

from .conftest import authenticate_client, image_upload, pdf_upload

pytestmark = pytest.mark.django_db


class Reply:
    def __init__(self, status=200, data=None, headers=None, body=b""):
        self.status_code, self.data, self.headers, self.body = (
            status,
            data or {},
            headers or {},
            body,
        )
        self.closed = False

    def json(self):
        return self.data

    def close(self):
        self.closed = True

    def iter_content(self, size):
        for offset in range(0, len(self.body), size):
            yield self.body[offset : offset + size]


class MockDrive:
    def __init__(self):
        self.files, self.sessions, self.calls = {}, {}, []
        self.counter, self.failures = 0, []
        self.ignore_range = False
        self.lose_completed_reply = False

    def request(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        assert kwargs["allow_redirects"] is False
        assert kwargs["timeout"][0] > 0 and kwargs["timeout"][1] > 0
        assert kwargs["headers"]["Authorization"] == "Bearer synthetic-access"
        assert "permissions" not in url  # The app never creates sharing permissions.
        if self.failures:
            failure = self.failures.pop(0)
            if isinstance(failure, Exception):
                raise failure
            return failure
        params = kwargs.get("params", {})
        if url.endswith("generateIds"):
            self.counter += 1
            return Reply(data={"ids": [f"mock-{self.counter}"]})
        if method == "POST":
            data = dict(kwargs["json"])
            identifier = data["id"]
            if identifier in self.files:
                return Reply(409)
            if params.get("uploadType") == "resumable":
                session = f"{drive_storage.UPLOAD}?upload_id={identifier}"
                self.sessions[session] = (data, bytearray())
                return Reply(headers={"Location": session})
            self.files[identifier] = {
                **data,
                "ownedByMe": True,
                "trashed": False,
                "permissions": [{"type": "user", "role": "owner"}],
            }
            return Reply(data=self.files[identifier])
        if method == "PUT":
            if url not in self.sessions:
                return Reply(404)
            data, body = self.sessions[url]
            total = int(kwargs["headers"]["Content-Range"].split("/")[-1])
            if kwargs.get("data"):
                begin = int(kwargs["headers"]["Content-Range"].split(" ")[1].split("-")[0])
                assert begin == len(body)
                body.extend(kwargs["data"])
            if len(body) == total:
                self.files[data["id"]] = {
                    **data,
                    "body": bytes(body),
                    "size": str(total),
                    "md5Checksum": hashlib.md5(body).hexdigest(),
                    "ownedByMe": True,
                    "trashed": False,
                    "permissions": [{"type": "user", "role": "owner"}],
                }
                if self.lose_completed_reply:
                    self.lose_completed_reply = False
                    raise requests.Timeout("synthetic secret must not leak")
                return Reply(data={"id": data["id"]})
            return Reply(308, headers={"Range": f"bytes=0-{len(body) - 1}"} if body else {})
        identifier = url.split("/")[-1]
        if identifier not in self.files:
            return Reply(404)
        if method == "DELETE":
            del self.files[identifier]
            return Reply(204)
        data = self.files[identifier]
        if params.get("alt") != "media":
            return Reply(data=data)
        body = data["body"]
        header = kwargs["headers"].get("Range")
        if header and not self.ignore_range:
            start, end = map(int, header[6:].split("-"))
            return Reply(
                206,
                headers={
                    "Content-Range": f"bytes {start}-{end}/{len(body)}",
                    "Content-Length": str(end - start + 1),
                },
                body=body[start : end + 1],
            )
        return Reply(headers={"Content-Length": str(len(body))}, body=body)


@pytest.fixture
def google_settings(settings):
    settings.DOCUMENT_STORAGE_PROVIDER = "gdrive"
    settings.GOOGLE_DRIVE_CLIENT_ID = "synthetic-client"
    settings.GOOGLE_DRIVE_CLIENT_SECRET = "synthetic-client-secret"
    settings.GOOGLE_DRIVE_CREDENTIAL_KEY = Fernet.generate_key().decode()
    settings.GOOGLE_DRIVE_REDIRECT_URI = "http://localhost:8080/storage/google/callback/"


@pytest.fixture
def drive(google_settings, monkeypatch):
    backend = MockDrive()
    monkeypatch.setattr(drive_storage, "access_token", lambda **kw: "synthetic-access")
    monkeypatch.setattr(drive_storage.requests, "request", backend.request)
    monkeypatch.setattr(drive_storage.time, "sleep", lambda delay: None)
    drive_storage.forget_metadata()
    return backend


def store_credentials(expired=False, refresh="synthetic-refresh"):
    credentials = Credentials(
        "synthetic-access",
        refresh_token=refresh,
        token_uri="https://oauth2.googleapis.com/token",
        client_id="synthetic-client",
        client_secret="synthetic-client-secret",
        scopes=[SCOPE],
        expiry=datetime.now(timezone.utc).replace(tzinfo=None)
        + timedelta(hours=-1 if expired else 1),
    )
    connection, _ = DriveConnection.objects.get_or_create(pk=1)
    connection.encrypted_credentials = cipher().encrypt(credentials.to_json().encode()).decode()
    connection.owner_id = "owner-one"
    connection.save()
    return credentials


def oauth_state(client, users):
    authenticate_client(client, users["admin"])
    response = client.post("/storage/google/", {"action": "connect"})
    assert response.status_code == 302
    parsed = parse_qs(urlsplit(response.url).query)
    assert parsed["scope"] == [SCOPE]
    assert parsed["access_type"] == ["offline"]
    assert parsed["redirect_uri"] == ["http://localhost:8080/storage/google/callback/"]
    assert parsed["code_challenge_method"] == ["S256"]
    assert "synthetic-client-secret" not in response.url
    return parsed["state"][0]


@pytest.mark.parametrize("user", ["alice", "manager"])
@pytest.mark.parametrize("method", ["get", "post"])
def test_oauth_admin_only(client, users, google_settings, user, method):
    authenticate_client(client, users[user])
    assert getattr(client, method)("/storage/google/").status_code == 403
    assert client.get("/storage/google/callback/?state=x&code=y").status_code == 403


def test_oauth_csrf_and_recent_identity(users, google_settings):
    client = authenticate_client(Client(enforce_csrf_checks=True), users["admin"])
    assert client.post("/storage/google/", {"action": "connect"}).status_code == 403
    session = client.session
    session["reauth_at"] = 0
    session.save()
    response = client.get("/storage/google/")
    assert response.status_code == 302
    assert response["Location"] == "/accounts/confirm/?next=/storage/google/"


def test_oauth_state_session_binding_expiry_and_replay(client, users, google_settings):
    state = oauth_state(client, users)
    assert (
        client.get("/storage/google/callback/", {"state": "wrong", "code": "x"}).status_code == 403
    )
    other = authenticate_client(Client(), users["admin"])
    assert other.get("/storage/google/callback/", {"state": state, "code": "x"}).status_code == 403
    response = client.get("/storage/google/callback/", {"state": state, "error": "access_denied"})
    assert response.status_code == 302
    assert response["Referrer-Policy"] == "no-referrer"
    assert client.get("/storage/google/callback/", {"state": state, "code": "x"}).status_code == 403
    state = oauth_state(client, users)
    DriveOAuthAttempt.objects.update(expires_at=datetime.now(timezone.utc) - timedelta(seconds=1))
    assert client.get("/storage/google/callback/", {"state": state, "code": "x"}).status_code == 403


def test_oauth_preserves_refresh_and_rejects_different_owner(client, users, google_settings):
    store_credentials()
    fresh = Credentials(
        "new-access",
        token_uri="https://oauth2.googleapis.com/token",
        client_id="synthetic-client",
        client_secret="synthetic-client-secret",
        scopes=[SCOPE],
    )
    state = oauth_state(client, users)
    with (
        patch.object(drive_auth.Flow, "fetch_token") as exchange,
        patch.object(
            drive_auth.Flow,
            "credentials",
            new_callable=PropertyMock,
            return_value=fresh,
        ),
        patch.object(
            drive_auth.requests,
            "get",
            return_value=Reply(data={"user": {"permissionId": "owner-one"}}),
        ),
    ):
        assert (
            client.get(
                "/storage/google/callback/", {"state": state, "code": "one-use-code"}
            ).status_code
            == 302
        )
        assert exchange.call_args.kwargs["code"] == "one-use-code"
    connection = DriveConnection.objects.get(pk=1)
    assert decrypt(connection.encrypted_credentials)["refresh_token"] == "synthetic-refresh"
    assert "new-access" not in connection.encrypted_credentials
    state = oauth_state(client, users)
    with (
        patch.object(drive_auth.Flow, "fetch_token"),
        patch.object(
            drive_auth.Flow,
            "credentials",
            new_callable=PropertyMock,
            return_value=fresh,
        ),
        patch.object(
            drive_auth.requests,
            "get",
            return_value=Reply(data={"user": {"permissionId": "different-owner"}}),
        ),
    ):
        client.get("/storage/google/callback/", {"state": state, "code": "x"})
    assert (
        DriveConnection.objects.get(pk=1).encrypted_credentials == connection.encrypted_credentials
    )


def test_refresh_encrypted_and_revoked(google_settings):
    store_credentials(expired=True)

    def refreshed(credentials, transport):
        credentials.token = "refreshed-access"
        credentials.expiry = datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(hours=1)

    with patch.object(Credentials, "refresh", refreshed):
        assert access_token() == "refreshed-access"
    assert "refreshed-access" not in DriveConnection.objects.get(pk=1).encrypted_credentials
    store_credentials(expired=True)
    with patch.object(
        Credentials, "refresh", side_effect=RefreshError("sensitive", {"error": "invalid_grant"})
    ):
        with pytest.raises(StorageError, match="reconnection"):
            access_token()
    assert DriveConnection.objects.get(pk=1).reconnect_required
    with pytest.raises(StorageError):
        access_token()


def test_refresh_outage_keeps_connection(google_settings):
    store_credentials(expired=True)
    with patch.object(
        Credentials,
        "refresh",
        side_effect=RefreshError("secret", {"error": "temporarily_unavailable"}),
    ):
        with pytest.raises(StorageError, match="temporarily"):
            access_token()
    assert not DriveConnection.objects.get(pk=1).reconnect_required


def test_upload_preview_range_and_thumbnail(drive, users, folder, client):
    version = upload_document(users["manager"], folder, pdf_upload(), "Synthetic")
    assert version.status == Version.Status.READY and version.storage_provider == "gdrive"
    obj = DriveObject.objects.get(key=version.storage_key)
    assert obj.complete and obj.sha256 == version.sha256
    authenticate_client(client, users["alice"])
    url = f"/documents/{version.document_id}/content/"
    response = client.get(url, HTTP_RANGE="bytes=0-9")
    assert response.status_code == 206 and response["Content-Range"] == f"bytes 0-9/{version.size}"
    assert len(b"".join(response.streaming_content)) == 10
    assert response["Cache-Control"].startswith("no-store")
    response = client.head(url)
    assert response.status_code == 200 and response["Content-Length"] == str(version.size)
    response = client.get(url, HTTP_RANGE="bytes=-12")
    assert len(b"".join(response.streaming_content)) == 12
    response = client.get(url, HTTP_RANGE="bytes=999999-")
    assert response.status_code == 416 and response["Content-Range"] == f"bytes */{version.size}"
    image = upload_document(users["manager"], folder, image_upload(), "Synthetic image")
    response = client.get(f"/documents/{image.document_id}/thumbnail/")
    assert response.status_code == 200 and response["Content-Type"] == "image/jpeg"
    assert b"".join(response.streaming_content).startswith(b"\xff\xd8")
    # No upstream locations, credentials or Drive IDs are passed to staff.
    html = client.get(f"/documents/{version.document_id}/").content
    assert b"googleapis.com" not in html and obj.file_id.encode() not in html
    assert b"synthetic-access" not in html and b"synthetic-client-secret" not in html


def test_drive_range_requests_reuse_metadata_without_caching_bytes(drive, users, folder, client):
    version = upload_document(users["manager"], folder, pdf_upload(), "Synthetic")
    authenticate_client(client, users["alice"])
    url = f"/documents/{version.document_id}/content/"
    drive.calls.clear()

    response = client.get(url, HTTP_RANGE="bytes=0-9")
    assert response.status_code == 206
    assert len(b"".join(response.streaming_content)) == 10
    first_metadata = [
        call for call in drive.calls if call[0] == "GET" and call[2]["params"] != {"alt": "media"}
    ]
    assert len(first_metadata) == 2  # Private folder plus document metadata.

    calls_after_first = len(drive.calls)
    response = client.get(url, HTTP_RANGE="bytes=10-19")
    assert response.status_code == 206
    assert len(b"".join(response.streaming_content)) == 10
    later_calls = drive.calls[calls_after_first:]
    assert [(method, kwargs["params"]) for method, _, kwargs in later_calls] == [
        ("GET", {"alt": "media"})
    ]


@pytest.mark.parametrize("endpoint", ["", "content/", "thumbnail/", "manage/"])
def test_drive_permission_revocation_and_disabled(drive, users, folder, client, endpoint):
    version = upload_document(users["manager"], folder, image_upload(), "Synthetic")
    authenticate_client(client, users["alice"])
    FolderGrant.objects.filter(user=users["alice"]).delete()
    calls = len(drive.calls)
    url = f"/documents/{version.document_id}/{endpoint}"
    assert client.get(url, HTTP_RANGE="bytes=0-9").status_code == 404
    assert client.head(url).status_code == (405 if endpoint == "manage/" else 404)
    assert len(drive.calls) == calls
    authenticate_client(client, users["manager"])
    users["manager"].is_active = False
    users["manager"].save()
    assert client.get(url).status_code == 302
    assert len(drive.calls) == calls


def test_unauthorized_upload_never_stages_or_contacts_drive(drive, users, folder, client):
    with pytest.raises(PermissionDenied):
        upload_document(users["alice"], folder, pdf_upload(), "Denied")
    authenticate_client(client, users["bob"])
    assert (
        client.post(
            f"/folders/{folder.pk}/upload/", {"title": "Denied", "file": pdf_upload()}
        ).status_code
        == 404
    )
    assert drive.calls == []
    assert not path_for("originals").exists()


def test_rate_limits_outages_bounded_retries_and_quota(drive):
    drive.failures = [Reply(429), Reply(503), requests.Timeout("sensitive")]
    response = drive_storage.request("GET", f"{drive_storage.API}/files/generateIds")
    assert response.json()["ids"] and len(drive.calls) == 4
    drive.failures = [Reply(503)] * 4
    with pytest.raises(StorageError) as error:
        drive_storage.request("GET", f"{drive_storage.API}/files/generateIds")
    assert "sensitive" not in str(error.value)
    drive.failures = [Reply(403, {"error": {"errors": [{"reason": "storageQuotaExceeded"}]}})]
    with pytest.raises(StorageError) as error:
        drive_storage.request("GET", f"{drive_storage.API}/files/generateIds")
    assert error.value.code == "quota"


def test_missing_files_and_upstream_full_range_response(drive, users, folder, client):
    version = upload_document(users["manager"], folder, pdf_upload(), "Synthetic")
    authenticate_client(client, users["alice"])
    drive.ignore_range = True
    url = f"/documents/{version.document_id}/content/"
    assert client.get(url, HTTP_RANGE="bytes=0-9").status_code == 503
    del drive.files[DriveObject.objects.get(key=version.storage_key).file_id]
    assert client.get(url).status_code == 404


def test_resumable_uncertain_completion_does_not_duplicate(drive, users, folder):
    drive.lose_completed_reply = True
    version = upload_document(users["manager"], folder, pdf_upload(), "Synthetic")
    assert version.status == Version.Status.READY
    assert len(drive.files) == 2  # One folder and one document.
    assert any(method == "PUT" and kw["data"] == b"" for method, _, kw in drive.calls)


def test_metadata_failure_keeps_quarantine_and_reuses_remote_id(drive, users, folder):
    original = Version.save

    def fail_publication(self, *args, **kwargs):
        if self.status == Version.Status.READY:
            raise DatabaseError("synthetic metadata recording failure")
        return original(self, *args, **kwargs)

    with patch.object(Version, "save", fail_publication), pytest.raises(DatabaseError):
        upload_document(users["manager"], folder, pdf_upload(), "Synthetic")
    version = Version.objects.get()
    assert version.status == Version.Status.QUARANTINED
    assert version.document.active_version_id is None
    obj = DriveObject.objects.get(key=version.storage_key)
    assert obj.complete and path_for(version.storage_key).is_file()
    assert process_version(version).status == Version.Status.READY
    assert DriveObject.objects.get(key=version.storage_key).file_id == obj.file_id
    assert len(drive.files) == 2


def test_scan_and_storage_failure_leave_unpublished(drive, users, folder):
    with patch("vault.services.scan", return_value="infected"):
        version = upload_document(users["manager"], folder, pdf_upload(), "Rejected")
    assert version.status == Version.Status.REJECTED and drive.calls == []
    with patch.object(drive_storage.GoogleDriveStorage, "put", side_effect=StorageError("quota")):
        version = upload_document(users["manager"], folder, pdf_upload(), "Pending")
    assert version.status == Version.Status.QUARANTINED
    assert "full" in version.processing_note and version.document.active_version_id is None


def test_external_sharing_fails_closed(drive, users, folder, client):
    version = upload_document(users["manager"], folder, pdf_upload(), "Synthetic")
    authenticate_client(client, users["alice"])
    root = drive.files[DriveConnection.objects.get(pk=1).folder_id]
    root["permissions"].append({"type": "anyone", "role": "reader"})
    assert client.get(f"/documents/{version.document_id}/content/").status_code == 503


def test_orphan_cleanup_requires_ownership_and_no_reference(drive, users, folder):
    version = upload_document(users["manager"], folder, pdf_upload(), "Synthetic")
    storage = drive_storage.GoogleDriveStorage()
    with pytest.raises(StorageError):
        storage.delete_orphan(version.storage_key)
    obj = DriveObject.objects.get(key=version.storage_key)
    version.document.delete()
    drive.files[obj.file_id]["appProperties"] = {"ssdc_installation": "other"}
    with pytest.raises(StorageError):
        storage.delete_orphan(obj.key)
    DriveObject.objects.filter(pk=obj.pk).update(complete=False, encrypted_session="synthetic")
    with pytest.raises(StorageError):
        storage.delete_orphan(obj.key, allow_incomplete=True)
    assert obj.file_id in drive.files


def test_restore_to_filesystem_verifies_hashes(drive, users, folder):
    version = upload_document(users["manager"], folder, pdf_upload(), "Synthetic")
    call_command("restore_storage_to_filesystem", stdout=io.StringIO())
    version.refresh_from_db()
    assert version.storage_provider == "gdrive"
    call_command("restore_storage_to_filesystem", execute=True, stdout=io.StringIO())
    version.refresh_from_db()
    assert version.storage_provider == "filesystem"


def test_credentials_redacted_from_logging(google_settings):
    record = logging.LogRecord(
        "google",
        logging.ERROR,
        "test",
        1,
        "synthetic-access synthetic-client-secret synthetic-refresh",
        (),
        None,
    )
    rendered = SafeJSONFormatter().format(record)
    assert "synthetic" not in rendered
    assert json.loads(rendered)["event"] == "application_error"


def test_multichunk_upload(drive):
    path = path_for("originals/multichunk")
    path.parent.mkdir(parents=True)
    body = b"synthetic bytes" * 180000
    path.write_bytes(body)
    storage = drive_storage.GoogleDriveStorage()
    storage.put("originals/multichunk", path, "application/pdf", "synthetic.pdf")
    obj = DriveObject.objects.get(key="originals/multichunk")
    assert drive.files[obj.file_id]["body"] == body
    chunks = [kw for method, _, kw in drive.calls if method == "PUT"]
    assert len(chunks) == 3
    assert len(chunks[0]["data"]) == drive_storage.CHUNK


def test_backoff_jitter_and_deadline(drive):
    with (
        patch.object(drive_storage.time, "sleep") as sleep,
        patch.object(drive_storage.random, "uniform", return_value=0.5),
    ):
        for attempt in range(4):
            drive_storage.backoff(attempt)
        assert [c.args[0] for c in sleep.call_args_list] == [1.5, 2.5, 4.5, 8.5]
    calls = len(drive.calls)
    with patch.object(drive_storage, "access_token", return_value="synthetic-access"):
        with drive_storage.network_budget(-1), pytest.raises(StorageError):
            drive_storage.request("GET", f"{drive_storage.API}/files/generateIds")
    assert len(drive.calls) == calls


def test_drive_401_refresh(drive):
    drive.failures = [Reply(401)]
    with patch.object(drive_storage, "access_token", return_value="synthetic-access") as refresh:
        drive_storage.request("GET", f"{drive_storage.API}/files/generateIds")
        assert refresh.call_args_list[-1].kwargs == {"force": True}


def test_state_rejects_role_change_and_token_exchange_errors(client, users, google_settings):
    state = oauth_state(client, users)
    users["admin"].is_active = False
    users["admin"].save()
    assert client.get("/storage/google/callback/", {"state": state, "code": "x"}).status_code == 302
    assert not DriveConnection.objects.exists()
    users["admin"].is_active = True
    users["admin"].save()
    state = oauth_state(client, users)
    with patch.object(
        drive_auth.Flow, "fetch_token", side_effect=RuntimeError("synthetic-client-secret")
    ):
        response = client.get("/storage/google/callback/", {"state": state, "code": "secret-code"})
    assert response.status_code == 302
    page = client.get("/storage/google/").content
    assert b"synthetic-client-secret" not in page and b"secret-code" not in page


def test_key_loss_and_initial_missing_refresh(client, users, google_settings, settings):
    credentials = store_credentials()
    settings.GOOGLE_DRIVE_CREDENTIAL_KEY = Fernet.generate_key().decode()
    with pytest.raises(StorageError) as error:
        access_token()
    assert error.value.code == "configuration"
    DriveConnection.objects.all().delete()
    credentials = Credentials(
        "synthetic-access",
        token_uri="https://oauth2.googleapis.com/token",
        client_id="synthetic-client",
        client_secret="synthetic-client-secret",
        scopes=[SCOPE],
    )
    state = oauth_state(client, users)
    with (
        patch.object(drive_auth.Flow, "fetch_token"),
        patch.object(
            drive_auth.Flow, "credentials", new_callable=PropertyMock, return_value=credentials
        ),
        patch.object(
            drive_auth.requests,
            "get",
            return_value=Reply(data={"user": {"permissionId": "owner-one"}}),
        ),
    ):
        client.get("/storage/google/callback/", {"state": state, "code": "x"})
    assert not DriveConnection.objects.exists()


def test_drive_export_and_filesystem_migration(drive, users, folder, settings):
    settings.DOCUMENT_STORAGE_PROVIDER = "filesystem"
    version = upload_document(users["manager"], folder, pdf_upload(), "Synthetic")
    call_command("migrate_storage_to_drive", stdout=io.StringIO())
    assert drive.calls == []
    with patch("vault.management.commands.migrate_storage_to_drive.path_for", wraps=path_for):
        call_command("migrate_storage_to_drive", execute=True, stdout=io.StringIO())
    version.refresh_from_db()
    assert version.storage_provider == "gdrive"
    # Simulate the local cleanup normally performed at the outer commit.
    path_for(version.storage_key).unlink()
    output = io.BytesIO()
    with patch(
        "vault.management.commands.export_storage.sys.stdout", SimpleNamespace(buffer=output)
    ):
        call_command("export_storage", "--stdout", stdout=io.StringIO(), stderr=io.StringIO())
    output.seek(0)
    with tarfile.open(fileobj=output) as archive:
        restored = archive.extractfile(f"private/{version.storage_key}").read()
        assert hashlib.sha256(restored).hexdigest() == version.sha256
    call_command("verify_storage", stdout=io.StringIO())
    with pytest.raises(CommandError):
        call_command("restore_storage_to_filesystem", execute=True, stdout=io.StringIO())


def test_remote_orphan_deletion_and_quarantined_preview_protection(drive, users, folder):
    version = upload_document(users["manager"], folder, image_upload(), "Synthetic")
    obj = DriveObject.objects.get(key=version.thumbnail_key)
    Version.objects.filter(pk=version.pk).update(
        status=Version.Status.QUARANTINED, thumbnail_key=""
    )
    storage = drive_storage.GoogleDriveStorage()
    with pytest.raises(StorageError):
        storage.delete_orphan(obj.key)
    version.document.delete()
    storage.delete_orphan(obj.key)
    assert obj.file_id not in drive.files
    assert not DriveObject.objects.filter(pk=obj.pk).exists()


@pytest.mark.parametrize("complete", [True, False])
@pytest.mark.django_db(transaction=True)
def test_cleanup_orphans_discards_unrecoverable_quarantine_and_remote_intent(
    drive, users, folder, complete
):
    with patch("vault.services.scan", side_effect=ScanUnavailable):
        version = upload_document(users["manager"], folder, pdf_upload(), "Pending")
    assert version.status == Version.Status.QUARANTINED
    path = path_for(version.storage_key)
    drive_storage.GoogleDriveStorage().put(
        version.storage_key, path, version.mime_type, version.original_name
    )
    obj = DriveObject.objects.get(key=version.storage_key)
    if not complete:
        # Simulate an interrupted resumable upload: partial bytes, no digest,
        # and a pre-allocated Drive intent that was never marked complete.
        drive.files[obj.file_id]["size"] = str(version.size // 2)
        drive.files[obj.file_id].pop("md5Checksum")
        DriveObject.objects.filter(pk=obj.pk).update(complete=False, encrypted_session="synthetic")
    document_id = version.document_id
    Version.objects.filter(pk=version.pk).update(
        uploaded_at=datetime.now(timezone.utc) - timedelta(days=2)
    )
    path.unlink()

    output = io.StringIO()
    call_command("cleanup_orphans", before="2099-01-01T00:00:00Z", stdout=output)
    assert "Unrecoverable quarantined versions eligible: 1" in output.getvalue()
    assert Version.objects.filter(pk=version.pk).exists()
    assert path_for(version.storage_key).exists() is False

    call_command(
        "cleanup_orphans",
        before="2099-01-01T00:00:00Z",
        execute=True,
        stdout=io.StringIO(),
    )
    assert not Version.objects.filter(pk=version.pk).exists()
    assert not Document.objects.filter(pk=document_id).exists()
    assert not DriveObject.objects.filter(pk=obj.pk).exists()
    assert obj.file_id not in drive.files
    assert Event.objects.filter(kind="quarantine_discarded", target=str(version.pk)).exists()


@pytest.mark.django_db(transaction=True)
def test_cleanup_orphans_keeps_quarantine_with_staging_bytes(drive, users, folder):
    with patch("vault.services.scan", side_effect=ScanUnavailable):
        version = upload_document(users["manager"], folder, pdf_upload(), "Pending")
    Version.objects.filter(pk=version.pk).update(
        uploaded_at=datetime.now(timezone.utc) - timedelta(days=2)
    )
    call_command(
        "cleanup_orphans",
        before="2099-01-01T00:00:00Z",
        execute=True,
        stdout=io.StringIO(),
    )
    assert Version.objects.filter(pk=version.pk).exists()
    assert path_for(version.storage_key).is_file()


@pytest.mark.django_db(transaction=True)
def test_interrupted_staging_cleanup_only_removes_verified_drive_copy(drive, users, folder):
    version = upload_document(users["manager"], folder, pdf_upload(), "Synthetic")
    obj = DriveObject.objects.get(key=version.storage_key)
    path = path_for(version.storage_key)
    assert not path.exists()
    path.write_bytes(drive.files[obj.file_id]["body"])
    call_command("cleanup_orphans", before="2099-01-01T00:00:00Z", stdout=io.StringIO())
    assert path.exists()
    call_command(
        "cleanup_orphans", before="2099-01-01T00:00:00Z", execute=True, stdout=io.StringIO()
    )
    assert not path.exists() and obj.file_id in drive.files
    path.write_bytes(drive.files[obj.file_id]["body"])
    drive.files[obj.file_id]["md5Checksum"] = "corrupted"
    with pytest.raises(StorageError):
        call_command(
            "cleanup_orphans", before="2099-01-01T00:00:00Z", execute=True, stdout=io.StringIO()
        )
    assert path.exists() and obj.file_id in drive.files


def test_changed_staging_bytes_cannot_publish(drive, users, folder):
    with patch("vault.services.scan", side_effect=StorageError()):
        version = upload_document(users["manager"], folder, pdf_upload(), "Synthetic")
    path = path_for(version.storage_key)
    path.write_bytes(path.read_bytes() + b"\nsynthetic append")
    result = process_version(version)
    assert result.status == Version.Status.REJECTED and drive.calls == []


@pytest.mark.parametrize("expired", [False, True])
def test_persistent_resumable_session_retry(drive, expired):
    key = "originals/persistent-synthetic"
    path = path_for(key)
    path.parent.mkdir(parents=True)
    body = b"synthetic resumable blob" * 100000
    path.write_bytes(body)
    storage = drive_storage.GoogleDriveStorage()

    def first_chunk_only(storage, obj, path, session, offset, deadline):
        response = drive_storage.request(
            "PUT",
            session,
            accepted=(308,),
            data=body[: drive_storage.CHUNK],
            headers={"Content-Range": f"bytes 0-{drive_storage.CHUNK - 1}/{len(body)}"},
        )
        response.close()
        raise StorageError()

    with (
        patch.object(drive_storage.GoogleDriveStorage, "send_chunks", first_chunk_only),
        pytest.raises(StorageError),
    ):
        storage.put(key, path, "application/pdf", "synthetic.pdf")
    obj = DriveObject.objects.get(key=key)
    assert not obj.complete and obj.encrypted_session and "googleapis" not in obj.encrypted_session
    session = cipher().decrypt(obj.encrypted_session.encode()).decode()
    if expired:
        del drive.sessions[session]
    storage.put(key, path, "application/pdf", "synthetic.pdf")
    obj.refresh_from_db()
    assert obj.complete and not obj.encrypted_session
    assert drive.files[obj.file_id]["body"] == body
    assert len(drive.files) == 2
    creates = [
        kw["json"]["id"]
        for method, url, kw in drive.calls
        if method == "POST" and url == drive_storage.UPLOAD
    ]
    assert creates == [obj.file_id] * (2 if expired else 1)
