import io
import time

import pytest
from django.core.files.uploadedfile import SimpleUploadedFile
from PIL import Image
from pypdf import PdfWriter

from accounts.models import User
from vault.models import Folder, FolderGrant
from vault.services import upload_document


@pytest.fixture(autouse=True)
def isolated_storage(settings, tmp_path):
    settings.PRIVATE_STORAGE_ROOT = tmp_path / "private"
    settings.SCAN_MODE = "skip-development"
    settings.PRODUCTION = False
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
