import io
import json
import os
import subprocess
import sys
from unittest.mock import patch

import pytest
from cryptography.fernet import Fernet
from django.core.exceptions import ImproperlyConfigured
from django.core.files.uploadedfile import SimpleUploadedFile
from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import Client, RequestFactory

from accounts.models import User
from audit.models import Event
from config.database import database_from_url
from config.middleware import UploadLimitMiddleware
from config.readiness import readiness_failures
from vault.models import Document, DriveConnection, Version
from vault.upload_handlers import UploadBudgetHandler

from .conftest import authenticate_client, pdf_upload


def test_hosted_database_url_verifies_hostname_and_bounds_connections():
    database = database_from_url(
        "postgresql://user:password@database.example.test/vault", {}, production=True
    )
    assert database["OPTIONS"]["sslmode"] == "verify-full"
    assert database["OPTIONS"]["sslrootcert"]
    assert database["OPTIONS"]["connect_timeout"] == 5
    assert database["CONN_MAX_AGE"] == 60
    assert database["CONN_HEALTH_CHECKS"]


@pytest.mark.parametrize(
    "url",
    [
        "postgresql://user:canary@database.example.test/vault?sslmode=disable",
        "postgresql://user:canary@database.example.test/vault?sslmode=require",
        "postgresql://user:canary@database.example.test:6543/vault",
        "postgresql://user:canary@database-pooler.example.test/vault",
        "sqlite:///canary",
        "invalid://canary",
    ],
)
def test_unsafe_hosted_database_urls_fail_without_credentials(url):
    with pytest.raises(ImproperlyConfigured) as error:
        database_from_url(url, {}, production=True)
    assert "canary" not in str(error.value)


def test_url_can_use_explicit_database_ca(tmp_path):
    certificate = tmp_path / "database-ca.crt"
    certificate.write_text("Synthetic CA configuration only")
    database = database_from_url(
        "postgresql://user:password@database.example.test/vault?sslmode=verify-full",
        {"POSTGRES_SSLROOTCERT": str(certificate)},
        production=True,
    )
    assert database["OPTIONS"]["sslrootcert"] == str(certificate)


def production_settings(**overrides):
    environment = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith(
            ("GOOGLE_", "DRIVE_", "RENDER", "POSTGRES_", "SECRET_KEY", "MFA_ENCRYPTION_KEY")
        )
    }
    environment.update(
        APP_ENV="production",
        DATABASE_URL="postgresql://user:password@database.example.test/vault",
        DATABASE_URL_UNPOOLED="",
        SECRET_KEY="Synthetic-Production-Settings-Key-For-Tests-Only-123456789",
        MFA_ENCRYPTION_KEY=Fernet.generate_key().decode(),
        DOCUMENT_STORAGE_PROVIDER="filesystem",
        SCAN_MODE="clamav",
        ALLOWED_HOSTS="vault.example.test",
    )
    environment.update(overrides)
    return subprocess.run(
        [
            sys.executable,
            "-c",
            "import json; from config import settings; print(json.dumps(settings.ALLOWED_HOSTS))",
        ],
        env=environment,
        capture_output=True,
        text=True,
    )


def test_render_host_is_exact_and_custom_host_is_retained():
    result = production_settings(RENDER_EXTERNAL_HOSTNAME="synthetic-vault.onrender.com")
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == ["vault.example.test", "synthetic-vault.onrender.com"]


@pytest.mark.parametrize("hosts", ["", "*", ".onrender.com", ".example.test"])
def test_production_rejects_missing_or_broad_host_settings(hosts):
    result = production_settings(ALLOWED_HOSTS=hosts)
    assert result.returncode != 0
    assert "explicit hosts" in result.stderr


@pytest.mark.django_db
@pytest.mark.parametrize("active,role", [(False, User.Role.ADMIN), (True, User.Role.STAFF)])
def test_bootstrap_cannot_reactivate_or_promote_existing_accounts(monkeypatch, active, role):
    user = User.objects.create_user(
        "bootstrap", password="Existing-Account-Password-42", is_active=active, role=role
    )
    monkeypatch.setenv("DJANGO_SUPERUSER_USERNAME", "bootstrap")
    monkeypatch.setenv("DJANGO_SUPERUSER_PASSWORD", "New-Bootstrap-Password-42")
    with pytest.raises(CommandError, match="will not reactivate or promote"):
        call_command("ensure_admin", stdout=io.StringIO())
    user.refresh_from_db()
    assert user.is_active == active
    assert user.role == role
    assert not user.is_superuser
    assert user.check_password("Existing-Account-Password-42")


@pytest.mark.django_db
def test_bootstrap_account_and_event_roll_back_together(monkeypatch):
    monkeypatch.setenv("DJANGO_SUPERUSER_USERNAME", "bootstrap")
    monkeypatch.setenv("DJANGO_SUPERUSER_PASSWORD", "New-Bootstrap-Password-42")
    with patch(
        "accounts.management.commands.ensure_admin.record", side_effect=RuntimeError("event failed")
    ):
        with pytest.raises(RuntimeError, match="event failed"):
            call_command("ensure_admin", stdout=io.StringIO())
    assert not User.objects.filter(username="bootstrap").exists()
    call_command("ensure_admin", stdout=io.StringIO())
    assert Event.objects.filter(kind="deployment_admin_created").count() == 1


@pytest.mark.django_db
def test_large_request_is_rejected_before_upload_processing(client, users, folder, settings):
    settings.DATA_UPLOAD_MAX_MEMORY_SIZE = 100
    authenticate_client(client, users["manager"])
    with patch("vault.views.upload_document") as upload:
        response = client.post(
            "/documents/import/",
            {"folder": folder.pk, "title": "Too large", "file": pdf_upload()},
            HTTP_ACCEPT="application/json",
        )
    assert response.status_code == 413
    assert "error" in response.json()
    upload.assert_not_called()
    assert not Document.objects.exists()


@pytest.mark.django_db
def test_file_budget_rejects_payload_before_temporary_file_write(
    client, users, folder, settings, tmp_path
):
    settings.MAX_UPLOAD_BYTES = 100
    settings.FILE_UPLOAD_MAX_MEMORY_SIZE = 0
    settings.FILE_UPLOAD_TEMP_DIR = str(tmp_path)
    authenticate_client(client, users["manager"])
    response = client.post(
        "/documents/import/",
        {
            "folder": folder.pk,
            "title": "Too large",
            "file": SimpleUploadedFile("sample.pdf", b"x" * 101),
        },
        HTTP_ACCEPT="application/json",
    )
    assert response.status_code == 413
    assert not list(tmp_path.glob("*.upload*"))
    assert not Document.objects.exists()


@pytest.mark.django_db
def test_multiple_files_do_not_publish_first_file(client, users, folder):
    authenticate_client(client, users["manager"])
    response = client.post(
        "/documents/import/",
        {
            "folder": folder.pk,
            "title": "Ambiguous",
            "file": [pdf_upload(), pdf_upload("second.pdf")],
        },
        HTTP_ACCEPT="application/json",
    )
    assert response.status_code == 413
    assert not Document.objects.exists()


def test_budget_counts_across_chunks(settings):
    from django.core.files.uploadhandler import StopUpload

    settings.MAX_UPLOAD_BYTES = 8
    request = RequestFactory().post("/")
    handler = UploadBudgetHandler(request)
    assert handler.receive_data_chunk(b"12345", 0) == b"12345"
    with pytest.raises(StopUpload):
        handler.receive_data_chunk(b"6789", 5)
    assert request.upload_limit_exceeded


def test_malformed_request_length_returns_controlled_error():
    request = RequestFactory().get("/")
    request.META["CONTENT_LENGTH"] = "invalid"
    middleware = UploadLimitMiddleware(lambda request: pytest.fail("view should not run"))
    assert middleware(request).status_code == 400


@pytest.mark.django_db
@pytest.mark.parametrize("reconnect", [False, True])
def test_readiness_includes_drive_setup_without_network(settings, reconnect):
    settings.DOCUMENT_STORAGE_PROVIDER = "gdrive"
    if reconnect:
        DriveConnection.objects.create(
            pk=1,
            folder_id="synthetic-folder",
            encrypted_credentials="synthetic",
            reconnect_required=True,
        )
    failures = readiness_failures()
    assert ("drive_reconnect_required" if reconnect else "drive_setup_incomplete") in failures


@pytest.mark.django_db
def test_matching_if_range_uses_current_etag_and_stale_if_range_returns_full(
    client, users, document
):
    authenticate_client(client, users["alice"])
    url = f"/documents/{document.pk}/content/"
    etag = client.head(url)["ETag"]
    response = client.get(url, HTTP_RANGE="bytes=0-9", HTTP_IF_RANGE=etag)
    assert response.status_code == 206
    assert len(b"".join(response.streaming_content)) == 10
    response = client.get(url, HTTP_RANGE="bytes=0-9", HTTP_IF_RANGE='"stale"')
    assert response.status_code == 200
    assert len(b"".join(response.streaming_content)) == document.active_version.size


@pytest.mark.django_db
def test_retry_checks_requires_current_scope_and_csrf(users, folder):
    from vault.scanner import ScanUnavailable
    from vault.services import upload_document

    with patch("vault.services.scan", side_effect=ScanUnavailable):
        version = upload_document(users["manager"], folder, pdf_upload(), "Pending report")
    url = f"/documents/{version.document_id}/versions/{version.pk}/retry/"
    client = authenticate_client(Client(enforce_csrf_checks=True), users["manager"])
    assert client.get(url).status_code == 405
    assert client.post(url).status_code == 403
    client.get(f"/documents/{version.document_id}/manage/")
    csrf = client.cookies["csrftoken"].value
    response = client.post(url, {"csrfmiddlewaretoken": csrf})
    assert response.status_code == 302
    version.refresh_from_db()
    assert version.status == Version.Status.READY
    assert client.post(url, {"csrfmiddlewaretoken": csrf}).status_code == 404
    authenticate_client(client, users["bob"])
    assert client.post(url, {"csrfmiddlewaretoken": csrf}).status_code == 404
