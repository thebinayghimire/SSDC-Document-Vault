import io

import pytest
from django.core.files.uploadedfile import SimpleUploadedFile
from django.core.management import call_command
from pypdf import PdfWriter
from pypdf.generic import DictionaryObject, NameObject, TextStringObject

from accounts.admin import ChangeForm
from accounts.models import User
from audit.models import Event
from vault.models import Folder
from vault.services import upload_document
from vault.validation import InvalidUpload

from .conftest import authenticate_client, pdf_upload

pytestmark = pytest.mark.django_db


def test_admin_can_create_staff(client, users):
    authenticate_client(client, users["admin"])
    response = client.post(
        "/admin/accounts/user/add/",
        {
            "username": "new.staff",
            "role": "staff",
            "password1": "Unique-New-Staff-Password-49",
            "password2": "Unique-New-Staff-Password-49",
            "_save": "Save",
        },
    )
    assert response.status_code == 302
    assert User.objects.filter(username="new.staff", role="staff", is_superuser=False).exists()
    assert Event.objects.filter(kind="account_created").exists()


def test_last_admin_protected(users):
    user = users["admin"]
    form = ChangeForm(
        data={"username": user.username, "role": "staff", "is_active": ""}, instance=user
    )
    assert not form.is_valid()
    assert "last active administrator" in str(form.errors)


def test_admin_permission_changes_audited(client, users, folder):
    authenticate_client(client, users["admin"])
    response = client.post(
        "/admin/vault/foldergrant/add/",
        {"folder": str(folder.pk), "user": str(users["bob"].pk), "manage": "", "_save": "Save"},
    )
    assert response.status_code == 302
    assert Event.objects.filter(kind="permission_changed").exists()


def test_audit_cannot_be_mutated_via_admin(client, users):
    authenticate_client(client, users["admin"])
    event = Event.objects.create(actor=users["admin"], kind="test")
    assert (
        client.post(f"/admin/audit/event/{event.pk}/change/", {"kind": "forged"}).status_code == 403
    )
    assert client.post(f"/admin/audit/event/{event.pk}/delete/", {"post": "yes"}).status_code == 403


def test_restore_version_matches_document(client, users, folder, document):
    old = document.active_version_id
    new = upload_document(users["manager"], folder, pdf_upload(), "Replacement", document)
    authenticate_client(client, users["manager"])
    url = f"/documents/{document.pk}/versions/{old}/restore/"
    assert client.post(url).status_code == 302
    document.refresh_from_db()
    assert document.active_version_id == old
    other = upload_document(users["manager"], folder, pdf_upload(), "Different")
    assert client.post(f"/documents/{document.pk}/versions/{other.pk}/restore/").status_code == 404
    authenticate_client(client, users["alice"])
    assert client.post(f"/documents/{document.pk}/versions/{new.pk}/restore/").status_code == 404


def test_pdf_active_content_rejected(users, folder):
    writer = PdfWriter()
    writer.add_blank_page(width=100, height=100)
    writer._root_object[NameObject("/OpenAction")] = DictionaryObject(
        {
            NameObject("/S"): NameObject("/JavaScript"),
            NameObject("/JS"): TextStringObject("alert('unsafe')"),
        }
    )
    stream = io.BytesIO()
    writer.write(stream)
    with pytest.raises(InvalidUpload):
        upload_document(
            users["manager"], folder, SimpleUploadedFile("active.pdf", stream.getvalue()), "Active"
        )


def test_encrypted_pdf_rejected(users, folder):
    writer = PdfWriter()
    writer.add_blank_page(width=100, height=100)
    writer.encrypt("fixture-password")
    stream = io.BytesIO()
    writer.write(stream)
    with pytest.raises(InvalidUpload):
        upload_document(
            users["manager"],
            folder,
            SimpleUploadedFile("encrypted.pdf", stream.getvalue()),
            "Encrypted",
        )


@pytest.mark.django_db(transaction=True)
def test_cleanup_orphans_dry_run(document):
    from vault.storage import path_for, write_exclusive

    orphan = write_exclusive("originals/orphan-test", [b"orphan"])
    call_command("cleanup_orphans", before="2099-01-01T00:00:00Z", stdout=io.StringIO())
    assert orphan.exists()
    call_command(
        "cleanup_orphans", before="2099-01-01T00:00:00Z", execute=True, stdout=io.StringIO()
    )
    assert not orphan.exists()
    assert path_for(document.active_version.storage_key).is_file()


def test_folder_count_limit(client, users, folder, settings):
    settings.MAX_FOLDERS = 1
    authenticate_client(client, users["manager"])
    response = client.post(f"/folders/{folder.pk}/new/", {"name": "Too many"})
    assert response.status_code == 200
    assert b"folder limit has been reached" in response.content
    assert Folder.objects.count() == 1
