"""Writes must coordinate with current account and inherited/document permissions."""

import threading
import time
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace

import pytest
from django.core.exceptions import PermissionDenied
from django.db import OperationalError, connection, connections, transaction
from django.db.models import F
from django.utils import timezone

from accounts.models import User
from audit.models import Event
from config.admin import site
from vault import services, views
from vault.admin import FolderGrantAdmin
from vault.models import Document, DocumentGrant, Folder, FolderGrant, Version

from .conftest import authenticate_client, pdf_upload


def change_access(action, user, folder, document=None):
    if action in {"grant", "inherit_grant"}:
        FolderGrant.objects.filter(user=user, folder=folder).delete()
    elif action == "grant_downgrade":
        FolderGrant.objects.filter(user=user, folder=folder).update(manage=False)
    elif action in {"restrict_folder", "folder"}:
        Folder.objects.filter(pk=folder.pk).update(restricted=True)
    elif action == "reparent_folder":
        hidden = Folder.objects.create(name="Private parent")
        Folder.objects.filter(pk=folder.pk).update(parent=hidden)
    elif action == "role":
        User.objects.filter(pk=user.pk).update(role=User.Role.STAFF)
    elif action == "disable":
        User.objects.filter(pk=user.pk).update(is_active=False)
    elif action == "revoke":
        User.objects.filter(pk=user.pk).update(auth_version=F("auth_version") + 1)
    elif action == "admin_demote":
        User.objects.filter(pk=user.pk).update(
            is_superuser=False, is_staff=False, role=User.Role.STAFF
        )
    elif action == "move":
        hidden = Folder.objects.create(name="Private destination")
        Document.objects.filter(pk=document.pk).update(folder=hidden)
    elif action == "restrict_document":
        Document.objects.filter(pk=document.pk).update(restricted=True)
    elif action == "delete_document":
        Document.objects.filter(pk=document.pk).update(deleted_at=timezone.now())
    elif action == "document_grant":
        DocumentGrant.objects.filter(user=user, document=document).delete()
    else:
        raise AssertionError(f"Unknown change: {action}")


def document_only_grant(user, folder, document):
    Document.objects.filter(pk=document.pk).update(restricted=True)
    FolderGrant.objects.filter(user=user, folder=folder).delete()
    DocumentGrant.objects.create(user=user, document=document, manage=True)
    document.refresh_from_db()


@pytest.mark.django_db
@pytest.mark.parametrize(
    "action",
    ["grant", "inherit_grant", "restrict_folder", "reparent_folder", "role", "disable", "revoke"],
)
def test_upload_rechecks_access_after_file_validation(users, folder, settings, monkeypatch, action):
    actor = users["manager"]
    target = folder
    if action in {"inherit_grant", "restrict_folder", "reparent_folder"}:
        target = Folder.objects.create(name="Inherited child", parent=folder, restricted=False)
    original = services.inspect_file

    def change_after_inspection(*args, **kwargs):
        result = original(*args, **kwargs)
        change_access(action, actor, folder if action == "inherit_grant" else target)
        return result

    monkeypatch.setattr(services, "inspect_file", change_after_inspection)
    with pytest.raises(PermissionDenied):
        services.upload_document(actor, target, pdf_upload(), "Must not be stored")

    assert not Document.objects.exists()
    assert not Version.objects.exists()
    assert not list((settings.PRIVATE_STORAGE_ROOT / "originals").glob("*"))
    assert not Event.objects.filter(kind="upload", outcome="success").exists()


@pytest.mark.django_db
@pytest.mark.parametrize(
    "action", ["move", "restrict_document", "delete_document", "document_grant"]
)
def test_replacement_rechecks_current_document_after_validation(
    users, folder, document, monkeypatch, action
):
    actor = users["manager"]
    if action == "document_grant":
        document_only_grant(actor, folder, document)
    previous = document.active_version_id
    original = services.inspect_file

    def change_after_inspection(*args, **kwargs):
        result = original(*args, **kwargs)
        change_access(action, actor, folder, document)
        return result

    monkeypatch.setattr(services, "inspect_file", change_after_inspection)
    with pytest.raises(PermissionDenied):
        services.upload_document(actor, folder, pdf_upload(), "Replacement", document)

    document.refresh_from_db()
    assert document.active_version_id == previous
    assert document.versions.count() == 1
    assert services.path_for(document.active_version.storage_key).is_file()


@pytest.mark.django_db
@pytest.mark.parametrize("action", ["grant", "disable", "revoke"])
def test_access_removed_during_scan_prevents_publication(users, folder, monkeypatch, action):
    original = services.scan

    def change_during_scan(path):
        result = original(path)
        change_access(action, users["manager"], folder)
        return result

    monkeypatch.setattr(services, "scan", change_during_scan)
    version = services.upload_document(users["manager"], folder, pdf_upload(), "Pending review")

    version.refresh_from_db()
    version.document.refresh_from_db()
    assert version.status == Version.Status.QUARANTINED
    assert version.document.active_version_id is None
    assert services.path_for(version.storage_key).is_file()
    assert not Event.objects.filter(
        kind="version_published", target=str(version.pk), outcome="success"
    ).exists()


@pytest.mark.django_db
@pytest.mark.parametrize("action", ["archive", "unarchive", "delete", "restore"])
def test_lifecycle_rechecks_access_after_initial_lookup(
    users, folder, document, client, monkeypatch, action
):
    if action == "unarchive":
        document.archived = True
    if action == "restore":
        document.deleted_at = timezone.now()
    document.save(update_fields=["archived", "deleted_at"])
    expected = (document.archived, document.deleted_at)
    authenticate_client(client, users["manager"])
    original = views.authorized_document

    def revoke_after_lookup(*args, **kwargs):
        result = original(*args, **kwargs)
        change_access("grant", users["manager"], folder)
        return result

    monkeypatch.setattr(views, "authorized_document", revoke_after_lookup)
    response = client.post(f"/documents/{document.pk}/actions/{action}/")

    assert response.status_code == 404
    document.refresh_from_db()
    assert (document.archived, document.deleted_at) == expected
    assert not Event.objects.filter(kind=f"document_{action}", outcome="success").exists()


@pytest.mark.django_db
@pytest.mark.parametrize("action", ["grant", "reparent_folder", "role", "admin_demote"])
def test_folder_creation_rechecks_actor_and_parent_at_save(
    users, folder, client, monkeypatch, action
):
    actor = users["admin"] if action == "admin_demote" else users["manager"]
    parent = folder
    if action == "reparent_folder":
        parent = Folder.objects.create(name="Inherited parent", parent=folder, restricted=False)
    authenticate_client(client, actor)
    original = views.request_limit

    def change_before_write(request, scope="content", limit=240):
        result = original(request, scope, limit)
        if scope == "folder-create":
            change_access(action, actor, parent)
        return result

    monkeypatch.setattr(views, "request_limit", change_before_write)
    url = "/folders/new/" if action == "admin_demote" else f"/folders/{parent.pk}/new/"
    response = client.post(url, {"name": "Must not be created"})

    assert response.status_code == 404
    assert not Folder.objects.filter(name="Must not be created").exists()
    assert not Event.objects.filter(kind="folder_created", outcome="success").exists()


@pytest.mark.django_db
@pytest.mark.parametrize("action", ["grant", "move", "document_grant"])
def test_version_restoration_rechecks_current_scope(
    users, folder, document, client, monkeypatch, action
):
    previous = document.active_version_id
    latest = services.upload_document(
        users["manager"], folder, pdf_upload(), "Replacement", document
    )
    if action == "document_grant":
        document_only_grant(users["manager"], folder, document)
    authenticate_client(client, users["manager"])
    original = views.authorized_document

    def change_after_lookup(*args, **kwargs):
        result = original(*args, **kwargs)
        change_access(action, users["manager"], folder, document)
        return result

    monkeypatch.setattr(views, "authorized_document", change_after_lookup)
    response = client.post(f"/documents/{document.pk}/versions/{previous}/restore/")

    assert response.status_code == 404
    document.refresh_from_db()
    assert document.active_version_id == latest.pk
    assert not Event.objects.filter(kind="version_restored", outcome="success").exists()


@pytest.mark.django_db(transaction=True)
@pytest.mark.parametrize(
    "action", ["grant", "grant_downgrade", "folder", "role", "document_grant", "admin_delete"]
)
def test_policy_change_waits_for_checked_metadata_write(
    users, folder, document, monkeypatch, action
):
    actor = users["manager"]
    if action == "document_grant":
        document_only_grant(actor, folder, document)
    if action == "folder":
        child = Folder.objects.create(name="Inherited child", parent=folder, restricted=False)
        Document.objects.filter(pk=document.pk).update(folder=child)
        document.refresh_from_db()
    checked, resume = threading.Event(), threading.Event()
    original = services.can_manage_document

    def pause_after_check(*args, **kwargs):
        result = original(*args, **kwargs)
        assert result
        checked.set()
        assert resume.wait(20), "Concurrent revocation check did not finish"
        return result

    def edit():
        try:
            current = Document.objects.get(pk=document.pk)
            current.title = "Authorized edit"
            return services.save_document_fields(current, ["title"], actor=actor)
        finally:
            connections.close_all()

    monkeypatch.setattr(services, "can_manage_document", pause_after_check)
    with ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(edit)
        try:
            assert checked.wait(20), "Metadata did not check access"
            with pytest.raises(OperationalError) as failure:
                with transaction.atomic():
                    with connection.cursor() as cursor:
                        cursor.execute("SET LOCAL lock_timeout = '500ms'")
                    if action == "admin_delete":
                        admin = FolderGrantAdmin(FolderGrant, site)
                        admin.delete_queryset(
                            SimpleNamespace(user=users["admin"]),
                            FolderGrant.objects.filter(user=actor, folder=folder),
                        )
                    elif action == "folder":
                        change_access("folder", actor, document.folder)
                    else:
                        change_access(action, actor, folder, document)
            assert failure.value.__cause__.sqlstate == "55P03"
        finally:
            resume.set()
        assert future.result(timeout=20).title == "Authorized edit"

    monkeypatch.setattr(services, "can_manage_document", original)
    if action == "admin_delete":
        change_access("grant", actor, folder)
    elif action == "folder":
        change_access("folder", actor, document.folder)
    else:
        change_access(action, actor, folder, document)
    current = Document.objects.get(pk=document.pk)
    current.title = "No longer authorized"
    with pytest.raises(PermissionDenied):
        services.save_document_fields(current, ["title"], actor=actor)
    document.refresh_from_db()
    assert document.title == "Authorized edit"


@pytest.mark.django_db(transaction=True)
@pytest.mark.parametrize("action", ["grant", "document_grant"])
def test_waiting_metadata_write_sees_committed_revocation(users, folder, document, action):
    actor = users["manager"]
    if action == "document_grant":
        document_only_grant(actor, folder, document)
    started = threading.Event()
    worker = {}

    def edit():
        try:
            current = Document.objects.get(pk=document.pk)
            current.title = "Queued edit"
            with connection.cursor() as cursor:
                cursor.execute("SELECT pg_backend_pid()")
                worker["pid"] = cursor.fetchone()[0]
            started.set()
            return services.save_document_fields(current, ["title"], actor=actor)
        finally:
            connections.close_all()

    with ThreadPoolExecutor(max_workers=1) as executor:
        with transaction.atomic():
            # An uncommitted policy change owns the guard. The waiting write must
            # load permissions after that change commits, even with a stale object.
            change_access(action, actor, folder, document)
            future = executor.submit(edit)
            assert started.wait(20), "Queued edit did not start"
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                with connection.cursor() as cursor:
                    cursor.execute("SELECT pg_stat_clear_snapshot()")
                    cursor.execute(
                        "SELECT wait_event FROM pg_stat_activity WHERE pid = %s",
                        [worker["pid"]],
                    )
                    if cursor.fetchone() == ("advisory",):
                        break
                threading.Event().wait(0.05)
            else:
                pytest.fail("Write did not wait for the concurrent permission change")
        with pytest.raises(PermissionDenied):
            future.result(timeout=20)
    document.refresh_from_db()
    assert document.title != "Queued edit"


@pytest.mark.django_db
def test_document_only_manager_can_replace_and_restore_with_current_grant(
    users, folder, document, client
):
    document_only_grant(users["manager"], folder, document)
    old = document.active_version_id
    authenticate_client(client, users["manager"])
    response = client.post(
        f"/documents/{document.pk}/replace/", {"title": "Replacement", "file": pdf_upload()}
    )
    assert response.status_code == 302
    document.refresh_from_db()
    assert document.active_version_id != old
    assert client.post(f"/documents/{document.pk}/versions/{old}/restore/").status_code == 302
    document.refresh_from_db()
    assert document.active_version_id == old


@pytest.mark.django_db
def test_metadata_service_requires_an_actor(users, document):
    document.title = "Unauthorized edit"
    with pytest.raises(PermissionDenied):
        services.save_document_fields(document, ["title"])
