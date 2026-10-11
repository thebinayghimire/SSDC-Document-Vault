"""Document detail edits must preserve changes from overlapping requests."""

import threading
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch

import pytest
from django.db import connections
from django.test import Client
from django.utils import timezone

from vault.admin import DocumentAdmin
from vault.forms import MetadataForm
from vault.models import Document, DocumentGrant, Folder, FolderGrant
from vault.services import upload_document

from .conftest import authenticate_client, pdf_upload


@pytest.mark.django_db
def test_stale_metadata_form_preserves_newer_document_state(document, users):
    stale = Document.objects.get(pk=document.pk)
    form = MetadataForm(
        {"title": "Edited title", "folder": str(stale.folder_id)},
        instance=stale,
        allowed_folders=Folder.objects.all(),
        actor=users["admin"],
    )
    assert form.is_valid()
    latest = upload_document(users["manager"], document.folder, pdf_upload(), "New", document)
    deleted_at = timezone.now()
    Document.objects.filter(pk=document.pk).update(
        restricted=True, archived=True, deleted_at=deleted_at
    )

    saved = form.save()

    document.refresh_from_db()
    assert document.title == "Edited title"
    assert document.restricted and document.archived
    assert document.deleted_at == deleted_at
    assert document.active_version_id == latest.pk
    assert saved.active_version_id == latest.pk


@pytest.mark.django_db(transaction=True)
def test_manager_title_edit_overlaps_admin_restriction_and_lifecycle(
    users, folder, document, monkeypatch
):
    from vault import views

    manager = authenticate_client(Client(), users["manager"])
    administrator = authenticate_client(Client(), users["admin"])
    DocumentGrant.objects.create(document=document, user=users["manager"], manage=True)
    loaded, resume = threading.Event(), threading.Event()
    original = views.authorized_document

    def pause_after_initial_load(request, identifier, manage=False):
        result = original(request, identifier, manage=manage)
        if request.user.pk == users["manager"].pk and not loaded.is_set():
            loaded.set()
            assert resume.wait(20), "Concurrent edit did not finish"
        return result

    def edit_title():
        try:
            return manager.post(
                f"/documents/{document.pk}/manage/",
                {"title": "Manager's new title", "folder": str(folder.pk)},
            )
        finally:
            connections.close_all()

    monkeypatch.setattr(views, "authorized_document", pause_after_initial_load)
    with ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(edit_title)
        try:
            assert loaded.wait(20), "Manager did not load the document"
            latest = upload_document(users["admin"], folder, pdf_upload(), "New", document)
            response = administrator.post(
                f"/admin/vault/document/{document.pk}/change/",
                {
                    "title": document.title,
                    "folder": str(folder.pk),
                    "restricted": "on",
                    "archived": "on",
                    "_save": "Save",
                },
            )
            assert response.status_code == 302
            assert (
                administrator.post(f"/documents/{document.pk}/actions/delete/").status_code == 302
            )
            document.refresh_from_db()
            deleted_at = document.deleted_at
        finally:
            resume.set()
        assert future.result(timeout=20).status_code == 302

    document.refresh_from_db()
    assert document.title == "Manager's new title"
    assert document.restricted and document.archived
    assert document.deleted_at == deleted_at
    assert document.active_version_id == latest.pk


@pytest.mark.django_db(transaction=True)
def test_admin_title_edit_overlaps_manager_version_and_lifecycle(
    users, folder, document, monkeypatch
):
    administrator = authenticate_client(Client(), users["admin"])
    manager = authenticate_client(Client(), users["manager"])
    validated, resume = threading.Event(), threading.Event()
    original = DocumentAdmin.save_model

    def pause_before_admin_save(admin, request, obj, form, change):
        validated.set()
        assert resume.wait(20), "Concurrent manager action did not finish"
        return original(admin, request, obj, form, change)

    def edit_title():
        try:
            return administrator.post(
                f"/admin/vault/document/{document.pk}/change/",
                {"title": "Administrator's new title", "folder": str(folder.pk), "_save": "Save"},
            )
        finally:
            connections.close_all()

    monkeypatch.setattr(DocumentAdmin, "save_model", pause_before_admin_save)
    with ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(edit_title)
        try:
            assert validated.wait(20), "Admin did not validate the document form"
            latest = upload_document(users["manager"], folder, pdf_upload(), "New", document)
            assert manager.post(f"/documents/{document.pk}/actions/archive/").status_code == 302
            assert manager.post(f"/documents/{document.pk}/actions/delete/").status_code == 302
            Document.objects.filter(pk=document.pk).update(restricted=True)
            document.refresh_from_db()
            deleted_at = document.deleted_at
        finally:
            resume.set()
        assert future.result(timeout=20).status_code == 302

    document.refresh_from_db()
    assert document.title == "Administrator's new title"
    assert document.restricted and document.archived
    assert document.deleted_at == deleted_at
    assert document.active_version_id == latest.pk


@pytest.mark.django_db
def test_metadata_does_not_revert_an_unchanged_folder(document, users):
    form = MetadataForm(
        {"title": "Title only", "folder": str(document.folder_id)},
        instance=document,
        allowed_folders=Folder.objects.all(),
        actor=users["admin"],
    )
    assert form.is_valid()
    destination = Folder.objects.create(name="New location")
    Document.objects.filter(pk=document.pk).update(folder=destination)

    form.save()

    document.refresh_from_db()
    assert document.title == "Title only"
    assert document.folder_id == destination.pk


@pytest.mark.django_db
def test_metadata_rechecks_destination_grant_before_save(client, users, folder, document):
    destination = Folder.objects.create(name="Destination")
    grant = FolderGrant.objects.create(folder=destination, user=users["manager"], manage=True)
    authenticate_client(client, users["manager"])
    original = MetadataForm.save

    def revoke_before_save(form, *args, **kwargs):
        grant.delete()
        return original(form, *args, **kwargs)

    with patch.object(MetadataForm, "save", revoke_before_save):
        response = client.post(
            f"/documents/{document.pk}/manage/",
            {"title": "Move attempt", "folder": str(destination.pk)},
        )

    document.refresh_from_db()
    assert response.status_code == 200
    assert document.folder_id == folder.pk
    assert document.title == "Project report"
    assert b"permission" in response.content


@pytest.mark.django_db
def test_admin_can_intentionally_change_document_policy(client, users, folder, document):
    authenticate_client(client, users["admin"])
    response = client.post(
        f"/admin/vault/document/{document.pk}/change/",
        {
            "title": "Approved admin edit",
            "folder": str(folder.pk),
            "restricted": "on",
            "archived": "on",
            "_save": "Save",
        },
    )
    document.refresh_from_db()
    assert response.status_code == 302
    assert document.title == "Approved admin edit"
    assert document.restricted and document.archived


@pytest.mark.django_db
def test_metadata_can_move_to_a_currently_managed_folder(client, users, document):
    destination = Folder.objects.create(name="Approved destination")
    FolderGrant.objects.create(folder=destination, user=users["manager"], manage=True)
    authenticate_client(client, users["manager"])

    response = client.post(
        f"/documents/{document.pk}/manage/",
        {"title": "Moved document", "folder": str(destination.pk)},
    )

    document.refresh_from_db()
    assert response.status_code == 302
    assert document.title == "Moved document"
    assert document.folder_id == destination.pk


@pytest.mark.django_db
def test_metadata_rechecks_document_access_before_save(client, users, folder, document):
    authenticate_client(client, users["manager"])
    original = MetadataForm.save

    def revoke_before_save(form, *args, **kwargs):
        FolderGrant.objects.filter(folder=folder, user=users["manager"]).delete()
        return original(form, *args, **kwargs)

    with patch.object(MetadataForm, "save", revoke_before_save):
        response = client.post(
            f"/documents/{document.pk}/manage/",
            {"title": "Revoked edit", "folder": str(folder.pk)},
        )

    document.refresh_from_db()
    assert response.status_code == 404
    assert document.title == "Project report"
