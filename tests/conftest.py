import io
import os
import time

import pytest
from django.conf import settings as django_settings
from django.core.files.uploadedfile import SimpleUploadedFile
from PIL import Image
from pypdf import PdfWriter

from accounts.models import User
from vault.models import Folder, FolderGrant
from vault.services import upload_document

LOCAL_TEST_DATABASE_HOSTS = frozenset({"", "localhost", "127.0.0.1", "::1", "db"})


def require_local_test_database(database=None, environment=None):
    """Refuse to create/drop a test database on a remote host without explicit consent."""
    database = database or django_settings.DATABASES["default"]
    if "sqlite" in str(database.get("ENGINE", "")):
        return
    host = str(database.get("HOST") or "").strip()
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    # An empty host or an absolute path uses a local PostgreSQL Unix socket.
    if host in LOCAL_TEST_DATABASE_HOSTS or host.startswith("/"):
        return
    if (environment or os.environ).get("ALLOW_REMOTE_TEST_DB") == "1":
        return
    raise RuntimeError(
        f"Refusing to run database tests against non-local host {host!r}. "
        "Set ALLOW_REMOTE_TEST_DB=1 only when the target test database is disposable."
    )


def _test_uses_database(item):
    database_fixtures = {
        "db",
        "transactional_db",
        "django_db_setup",
        "django_db_reset_sequences",
    }
    return bool(item.get_closest_marker("django_db")) or bool(
        database_fixtures.intersection(item.fixturenames)
    )


def pytest_runtest_setup(item):
    # Runs before fixture setup, including the session-scoped test database creation.
    if _test_uses_database(item):
        require_local_test_database()


@pytest.fixture(autouse=True)
def isolated_storage(settings, tmp_path):
    settings.PRIVATE_STORAGE_ROOT = tmp_path / "private"
    settings.SCAN_MODE = "skip-development"
    settings.PRODUCTION = False
    settings.DOCUMENT_STORAGE_PROVIDER = "filesystem"
    settings.STORAGES = {
        "default": {"BACKEND": "django.core.files.storage.FileSystemStorage"},
        "staticfiles": {"BACKEND": "django.contrib.staticfiles.storage.StaticFilesStorage"},
    }


@pytest.fixture
def users(db):
    return {
        "alice": User.objects.create_user("alice", password="Strong-Staff-Password-42"),
        "bob": User.objects.create_user("bob", password="Strong-Staff-Password-43"),
        "manager": User.objects.create_user(
            "manager", password="Strong-Manager-Password-42", role=User.Role.MANAGER
        ),
        "admin": User.objects.create_superuser("admin", password="Strong-Admin-Password-42"),
    }


@pytest.fixture
def folder(users):
    folder = Folder.objects.create(name="Programmes")
    FolderGrant.objects.create(folder=folder, user=users["alice"])
    FolderGrant.objects.create(folder=folder, user=users["manager"], manage=True)
    return folder


def pdf_upload(name="sample.pdf", pages=2):
    buffer = io.BytesIO()
    writer = PdfWriter()
    for _ in range(pages):
        writer.add_blank_page(width=612, height=792)
    writer.write(buffer)
    return SimpleUploadedFile(name, buffer.getvalue(), content_type="application/pdf")


def image_upload(name="sample.png", format="PNG"):
    buffer = io.BytesIO()
    Image.new("RGB", (100, 80), "#48725b").save(buffer, format=format)
    return SimpleUploadedFile(name, buffer.getvalue(), content_type="application/octet-stream")


@pytest.fixture
def document(folder, users):
    return upload_document(users["manager"], folder, pdf_upload(), "Project report").document


def authenticate_client(client, user, mfa=True):
    client.force_login(user)
    session = client.session
    now = time.time()
    session.update(
        {
            "auth_version": user.auth_version,
            "auth_started": now,
            "last_seen": now,
            "reauth_at": now,
            "mfa_verified": mfa,
        }
    )
    session.save()
    return client
