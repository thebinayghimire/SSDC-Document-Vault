import hashlib
import io
import json
import logging
from unittest.mock import patch

import pytest
from django.core.exceptions import ValidationError
from django.core.management import call_command
from django.core.management.base import CommandError

from audit.models import Event
from audit.services import record
from config.logging import SafeJSONFormatter
from vault.models import DocumentGrant, Folder, Version
from vault.scanner import ScanUnavailable
from vault.services import process_version, restore_document_version, upload_document
from vault.storage import path_for

from .conftest import authenticate_client, image_upload, pdf_upload


@pytest.mark.django_db
def test_selected_preview_requires_refresh_after_replacement(client, users, document):
    authenticate_client(client, users["alice"])
    old = document.active_version
    response = client.get(
        f"/documents/{document.pk}/content/?version={old.pk}", HTTP_RANGE="bytes=0-9"
    )
    assert response.status_code == 206
    assert len(b"".join(response.streaming_content)) == 10
    upload_document(users["manager"], document.folder, pdf_upload(pages=3), "Ignored", document)
    assert (
        client.get(
            f"/documents/{document.pk}/content/?version={old.pk}", HTTP_RANGE="bytes=10-19"
        ).status_code
        == 409
    )
    document.refresh_from_db()
    assert (
        client.get(
            f"/documents/{document.pk}/content/?version={document.active_version_id}"
        ).status_code
        == 200
    )


@pytest.mark.django_db
def test_delayed_scan_preserves_explicit_restore(users, document):
    first = document.active_version
    upload_document(users["manager"], document.folder, pdf_upload(pages=3), "Ignored", document)
    with patch("vault.services.scan", side_effect=ScanUnavailable):
        pending = upload_document(
            users["manager"], document.folder, pdf_upload(pages=4), "Ignored", document
        )
    restore_document_version(users["manager"], document, first.pk)
    assert process_version(pending).status == Version.Status.READY
    document.refresh_from_db()
    assert document.active_version_id == first.pk
    # A replacement intentionally uploaded after restore can become current.
    latest = upload_document(users["manager"], document.folder, pdf_upload(), "Ignored", document)
    document.refresh_from_db()
    assert document.active_version_id == latest.pk


@pytest.mark.django_db
def test_thumbnail_hash_detects_same_size_corruption(users, folder):
    version = upload_document(users["manager"], folder, image_upload(), "Synthetic")
    thumbnail = path_for(version.thumbnail_key)
    assert hashlib.sha256(thumbnail.read_bytes()).hexdigest() == version.thumbnail_sha256
    contents = bytearray(thumbnail.read_bytes())
    contents[30] ^= 1
    thumbnail.write_bytes(contents)
    with pytest.raises(CommandError, match="integrity"):
        call_command("verify_storage", stdout=io.StringIO(), stderr=io.StringIO())


@pytest.mark.django_db
def test_folder_validation_uses_current_ancestry_and_subtree(folder):
    other = Folder.objects.create(name="Other")
    stale = Folder.objects.get(pk=folder.pk)
    stale.parent = other
    other.parent = folder
    other.save()
    with pytest.raises(ValidationError, match="cycles"):
        stale.save()
    branch = other
    for depth in range(19):
        branch = Folder.objects.create(name=str(depth), parent=branch)
    with pytest.raises(ValidationError, match="descendants"):
        Folder.objects.create(name="Too deep", parent=branch)


@pytest.mark.django_db
def test_document_only_preview_does_not_link_denied_folder(client, users, document):
    document.restricted = True
    document.save(update_fields=["restricted"])
    DocumentGrant.objects.create(document=document, user=users["bob"])
    authenticate_client(client, users["bob"])
    response = client.get(f"/documents/{document.pk}/")
    assert response.status_code == 200
    assert f"/folders/{document.folder_id}/".encode() not in response.content
    assert document.folder.name.encode() not in response.content


@pytest.mark.django_db
def test_audit_details_reject_secrets(users):
    with pytest.raises(ValueError, match="Unsupported"):
        record(users["admin"], "synthetic", details={"password": "private"})
    assert not Event.objects.filter(kind="synthetic").exists()


def test_logs_distinguish_failures_without_message_or_locals():
    formatter = SafeJSONFormatter()
    first = logging.LogRecord("vault", logging.ERROR, "storage.py", 12, "password=secret", (), None)
    second = logging.LogRecord(
        "vault", logging.ERROR, "validation.py", 99, "token=private", (), None
    )
    assert (
        json.loads(formatter.format(first))["location"]
        != json.loads(formatter.format(second))["location"]
    )
    assert "secret" not in formatter.format(first)
    assert "private" not in formatter.format(second)
