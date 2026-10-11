"""An event-store failure must not leave an unaudited security mutation."""

import io
from pathlib import Path
from unittest.mock import patch

import pyotp
import pytest
from django.contrib.admin.models import DELETION, LogEntry
from django.contrib.auth.hashers import make_password
from django.core.management import call_command
from django.core.management.base import CommandError
from django.db import IntegrityError, transaction
from django.utils import timezone

from accounts.mfa import decrypt, encrypt, verify
from accounts.models import User
from audit.models import Event
from vault import services
from vault.models import Document, DocumentGrant, Folder, FolderGrant, Version
from vault.scanner import ScanUnavailable
from vault.storage import path_for, write_exclusive

from .conftest import authenticate_client, image_upload, pdf_upload

pytestmark = pytest.mark.django_db(transaction=True)


def fail_event(monkeypatch, kind, *, number=1):
    original = Event.objects.create
    seen = 0

    def create(**kwargs):
        nonlocal seen
        if kwargs.get("kind") == kind:
            seen += 1
            if seen == number:
                raise IntegrityError("Synthetic event-store failure")
        return original(**kwargs)

    monkeypatch.setattr(Event.objects, "create", create)


def account_state(user):
    user.refresh_from_db()
    return (
        user.password,
        user.auth_version,
        user.mfa_secret,
        user.mfa_confirmed,
        user.mfa_last_step,
        list(user.recovery_hashes),
    )


@pytest.mark.parametrize(
    "action,kind", [("revoke_sessions", "sessions_revoked"), ("reset_mfa", "mfa_reset")]
)
@pytest.mark.parametrize("number", [1, 2])
def test_account_action_rolls_back_entire_selection_on_audit_failure(
    client, users, monkeypatch, action, kind, number
):
    selected = [users["alice"], users["bob"]]
    for user in selected:
        user.mfa_secret = encrypt(pyotp.random_base32())
        user.mfa_confirmed = True
        user.mfa_last_step = 12
        user.recovery_hashes = ["retained-recovery-hash"]
        user.save()
    before = [account_state(user) for user in selected]
    authenticate_client(client, users["admin"])
    fail_event(monkeypatch, kind, number=number)

    with pytest.raises(IntegrityError, match="event-store failure"):
        client.post(
            "/admin/accounts/user/",
            {"action": action, "_selected_action": [str(user.pk) for user in selected]},
        )

    assert [account_state(user) for user in selected] == before
    assert not Event.objects.filter(kind=kind).exists()


def test_admin_password_reset_rolls_back_password_version_and_admin_history(
    client, users, monkeypatch
):
    user = users["alice"]
    before = account_state(user)
    authenticate_client(client, users["admin"])
    fail_event(monkeypatch, "admin_password_reset")
    with pytest.raises(IntegrityError, match="event-store failure"):
        client.post(
            f"/admin/accounts/user/{user.pk}/password/",
            {
                "password1": "Changed-By-Admin-Password-57",
                "password2": "Changed-By-Admin-Password-57",
                "usable_password": "true",
            },
        )
    assert account_state(user) == before
    assert not LogEntry.objects.filter(object_id=str(user.pk)).exists()
    assert not Event.objects.filter(kind="admin_password_reset").exists()


def test_cancelled_admin_password_disable_does_not_record_success(client, users):
    user = users["alice"]
    before = account_state(user)
    authenticate_client(client, users["admin"])
    response = client.post(
        f"/admin/accounts/user/{user.pk}/password/", {"usable_password": "false"}
    )
    assert response.status_code == 302
    assert account_state(user) == before
    assert not Event.objects.filter(kind="admin_password_reset").exists()


def test_bulk_grant_deletion_rolls_back_both_histories(client, users, folder, monkeypatch):
    ids = list(FolderGrant.objects.filter(folder=folder).values_list("pk", flat=True))
    authenticate_client(client, users["admin"])
    fail_event(monkeypatch, "admin_deleted", number=2)
    with pytest.raises(IntegrityError, match="event-store failure"):
        client.post(
            "/admin/vault/foldergrant/",
            {
                "action": "delete_selected",
                "_selected_action": [str(pk) for pk in ids],
                "post": "yes",
            },
        )
    assert FolderGrant.objects.filter(pk__in=ids).count() == len(ids)
    assert not Event.objects.filter(kind="admin_deleted").exists()
    assert not LogEntry.objects.filter(action_flag=DELETION).exists()


def test_orphan_cleanup_records_intent_before_deleting_files(monkeypatch):
    orphan = write_exclusive("originals/orphan-f09", [b"Synthetic orphan"])
    fail_event(monkeypatch, "operator_orphan_cleanup")
    with pytest.raises(IntegrityError, match="event-store failure"):
        call_command(
            "cleanup_orphans", before="2099-01-01T00:00:00Z", execute=True, stdout=io.StringIO()
        )
    assert orphan.is_file()


def test_orphan_cleanup_completion_audit_failure_keeps_durable_intent(monkeypatch):
    orphan = write_exclusive("originals/orphan-f09", [b"Synthetic orphan"])
    fail_event(monkeypatch, "operator_orphan_cleanup", number=2)
    with pytest.raises(IntegrityError, match="event-store failure"):
        call_command(
            "cleanup_orphans", before="2099-01-01T00:00:00Z", execute=True, stdout=io.StringIO()
        )
    assert not orphan.exists()
    assert Event.objects.filter(kind="operator_orphan_cleanup", outcome="started").count() == 1
    assert not Event.objects.filter(kind="operator_orphan_cleanup", outcome="success").exists()


@pytest.mark.parametrize(
    "action,kind", [("revoke_sessions", "sessions_revoked"), ("reset_mfa", "mfa_reset")]
)
def test_account_batch_success_records_each_changed_user(client, users, action, kind):
    selected = [users["alice"], users["bob"]]
    versions = {user.pk: user.auth_version for user in selected}
    authenticate_client(client, users["admin"])
    response = client.post(
        "/admin/accounts/user/",
        {"action": action, "_selected_action": [str(user.pk) for user in selected]},
    )
    assert response.status_code == 302
    for user in selected:
        user.refresh_from_db()
        assert user.auth_version == versions[user.pk] + 1
    assert set(Event.objects.filter(kind=kind).values_list("target", flat=True)) == {
        str(user.pk) for user in selected
    }


@pytest.mark.parametrize("creation", [False, True])
def test_account_admin_form_rolls_back_on_audit_failure(client, users, monkeypatch, creation):
    authenticate_client(client, users["admin"])
    user = users["alice"]
    before = account_state(user)
    data = {"username": user.username, "role": "manager", "is_active": "on", "_save": "Save"}
    if creation:
        url = "/admin/accounts/user/add/"
        data.update(
            username="audit.new",
            password1="New-Audit-Staff-Password-87",
            password2="New-Audit-Staff-Password-87",
        )
    else:
        url = f"/admin/accounts/user/{user.pk}/change/"
    kind = "account_created" if creation else "account_changed"
    fail_event(monkeypatch, kind)
    with pytest.raises(IntegrityError, match="event-store failure"):
        client.post(url, data)
    assert not User.objects.filter(username="audit.new").exists()
    assert account_state(user) == before
    user.refresh_from_db()
    assert user.role == User.Role.STAFF
    assert not Event.objects.filter(kind=kind).exists()
    assert not LogEntry.objects.exists()


def test_self_password_change_rolls_back_account_and_session(client, users, monkeypatch):
    user = users["alice"]
    authenticate_client(client, user)
    before = account_state(user)
    fail_event(monkeypatch, "password_changed")
    with pytest.raises(IntegrityError, match="event-store failure"):
        client.post(
            "/accounts/password/",
            {
                "old_password": "Strong-Staff-Password-42",
                "new_password1": "Updated-Audit-Password-87",
                "new_password2": "Updated-Audit-Password-87",
            },
        )
    assert account_state(user) == before
    assert client.session["auth_version"] == before[1]
    assert client.get("/").status_code == 200


def test_automatic_password_hash_upgrade_rolls_back_if_its_event_fails(client, users, monkeypatch):
    user = users["alice"]
    User.objects.filter(pk=user.pk).update(
        password=make_password("Strong-Staff-Password-42", hasher="pbkdf2_sha256")
    )
    before = account_state(user)
    fail_event(monkeypatch, "password_hash_upgraded")
    with pytest.raises(IntegrityError, match="event-store failure"):
        client.post(
            "/accounts/login/", {"staff_id": user.username, "password": "Strong-Staff-Password-42"}
        )
    assert account_state(user) == before
    assert "_auth_user_id" not in client.session


def test_login_event_failure_does_not_persist_login_state(client, users, monkeypatch):
    user = users["alice"]
    assert user.last_login is None
    fail_event(monkeypatch, "login")
    with pytest.raises(IntegrityError, match="event-store failure"):
        client.post(
            "/accounts/login/", {"staff_id": user.username, "password": "Strong-Staff-Password-42"}
        )
    user.refresh_from_db()
    assert user.last_login is None
    assert "_auth_user_id" not in client.session


@pytest.mark.parametrize("event", ["login", "mfa_enrolled"])
def test_mfa_enrollment_rolls_back_when_an_event_fails(client, users, monkeypatch, event):
    user = users["manager"]
    before = account_state(user)
    client.post(
        "/accounts/login/", {"staff_id": user.username, "password": "Strong-Manager-Password-42"}
    )
    client.get("/accounts/mfa/enroll/")
    secret = decrypt(client.session["enrollment_secret"])
    fail_event(monkeypatch, event)
    with pytest.raises(IntegrityError, match="event-store failure"):
        client.post("/accounts/mfa/enroll/", {"code": pyotp.TOTP(secret).now()})
    assert account_state(user) == before
    assert "_auth_user_id" not in client.session
    assert not Event.objects.filter(kind__in=["login", "mfa_enrolled"]).exists()


@pytest.mark.parametrize("challenge", [True, False])
@pytest.mark.parametrize("recovery", [True, False])
def test_mfa_consumption_rolls_back_if_completion_event_fails(
    client, users, monkeypatch, challenge, recovery
):
    user = users["manager"]
    secret = pyotp.random_base32()
    user.mfa_secret, user.mfa_confirmed = encrypt(secret), True
    user.recovery_hashes = [make_password("single-recovery-code")]
    user.save()
    before = account_state(user)
    if challenge:
        client.post(
            "/accounts/login/",
            {"staff_id": user.username, "password": "Strong-Manager-Password-42"},
        )
        url, kind = "/accounts/mfa/", "login"
        data = {}
    else:
        authenticate_client(client, user)
        url, kind = "/accounts/confirm/", "reauthentication"
        session = client.session
        session["reauth_at"] = 0
        session.save()
        data = {"password": "Strong-Manager-Password-42"}
    data["code"] = "single-recovery-code" if recovery else pyotp.TOTP(secret).now()
    fail_event(monkeypatch, kind)
    with pytest.raises(IntegrityError, match="event-store failure"):
        client.post(url, data)
    assert account_state(user) == before
    assert not Event.objects.filter(kind="mfa_recovery_used").exists()
    if challenge:
        assert "_auth_user_id" not in client.session
    else:
        assert client.session["reauth_at"] == 0


def test_recovery_code_consumption_rolls_back_if_its_own_event_fails(users, monkeypatch):
    user = users["manager"]
    user.mfa_secret, user.mfa_confirmed = encrypt(pyotp.random_base32()), True
    user.recovery_hashes = [make_password("single-recovery-code")]
    user.save()
    before = account_state(user)
    fail_event(monkeypatch, "mfa_recovery_used")
    with pytest.raises(IntegrityError, match="event-store failure"):
        verify(user, "single-recovery-code")
    assert account_state(user) == before


@pytest.mark.parametrize("action", ["archive", "unarchive", "delete", "restore"])
def test_lifecycle_change_rolls_back_if_its_event_fails(
    client, users, document, monkeypatch, action
):
    if action == "unarchive":
        document.archived = True
    if action == "restore":
        document.deleted_at = timezone.now()
    document.save(update_fields=["archived", "deleted_at"])
    before = (document.archived, document.deleted_at, document.active_version_id)
    authenticate_client(client, users["manager"])
    fail_event(monkeypatch, f"document_{action}")
    with pytest.raises(IntegrityError, match="event-store failure"):
        client.post(f"/documents/{document.pk}/actions/{action}/")
    document.refresh_from_db()
    assert (document.archived, document.deleted_at, document.active_version_id) == before


@pytest.mark.parametrize("admin", [True, False])
def test_document_metadata_rolls_back_if_its_event_fails(
    client, users, folder, document, monkeypatch, admin
):
    authenticate_client(client, users["admin"] if admin else users["manager"])
    fail_event(monkeypatch, "admin_changed" if admin else "metadata_changed")
    url = (
        f"/admin/vault/document/{document.pk}/change/"
        if admin
        else f"/documents/{document.pk}/manage/"
    )
    with pytest.raises(IntegrityError, match="event-store failure"):
        client.post(url, {"title": "Unrecorded title", "folder": str(folder.pk), "_save": "Save"})
    document.refresh_from_db()
    assert document.title == "Project report"


def test_folder_creation_rolls_back_if_its_event_fails(client, users, folder, monkeypatch):
    authenticate_client(client, users["manager"])
    fail_event(monkeypatch, "folder_created")
    with pytest.raises(IntegrityError, match="event-store failure"):
        client.post(f"/folders/{folder.pk}/new/", {"name": "Unrecorded child"})
    assert not Folder.objects.filter(name="Unrecorded child").exists()


@pytest.mark.parametrize("model", ["folder", "foldergrant", "documentgrant"])
def test_admin_policy_form_rolls_back_if_its_event_fails(
    client, users, folder, document, monkeypatch, model
):
    authenticate_client(client, users["admin"])
    if model == "folder":
        data = {"name": "Unrecorded folder", "restricted": "on", "_save": "Save"}
    else:
        data = {
            "folder" if model == "foldergrant" else "document": str(
                folder.pk if model == "foldergrant" else document.pk
            ),
            "user": str(users["bob"].pk),
            "manage": "on",
            "_save": "Save",
        }
    fail_event(monkeypatch, "admin_changed" if model == "folder" else "permission_changed")
    with pytest.raises(IntegrityError, match="event-store failure"):
        client.post(f"/admin/vault/{model}/add/", data)
    assert not Folder.objects.filter(name="Unrecorded folder").exists()
    assert not FolderGrant.objects.filter(user=users["bob"]).exists()
    assert not DocumentGrant.objects.filter(user=users["bob"]).exists()


@pytest.mark.parametrize("replacement", [True, False])
def test_upload_reservation_rolls_back_and_removes_prepared_file_on_event_failure(
    users, folder, document, settings, monkeypatch, replacement
):
    originals = set((settings.PRIVATE_STORAGE_ROOT / "originals").iterdir())
    fail_event(monkeypatch, "upload")
    with pytest.raises(IntegrityError, match="event-store failure"):
        services.upload_document(
            users["manager"],
            folder,
            pdf_upload(),
            "Unrecorded upload",
            document if replacement else None,
        )
    assert Document.objects.count() == 1
    assert Version.objects.count() == 1
    assert set((settings.PRIVATE_STORAGE_ROOT / "originals").iterdir()) == originals


@pytest.mark.parametrize("kind", ["version_published", "scan", "upload"])
def test_processing_outcome_rolls_back_if_its_event_fails(users, folder, monkeypatch, kind):
    with patch("vault.services.scan", side_effect=ScanUnavailable):
        version = services.upload_document(users["manager"], folder, image_upload(), "Pending")
    note = version.processing_note
    fail_event(monkeypatch, kind)
    scan_effect = ScanUnavailable() if kind == "scan" else None
    with patch(
        "vault.services.scan",
        return_value="infected" if kind == "upload" else "clean",
        side_effect=scan_effect,
    ):
        with pytest.raises(IntegrityError, match="event-store failure"):
            services.process_version(version)
    version.refresh_from_db()
    assert version.status == Version.Status.QUARANTINED
    assert version.processing_note == note
    assert version.document.active_version_id is None
    assert path_for(version.storage_key).is_file()


def test_version_restoration_rolls_back_if_its_event_fails(
    client, users, folder, document, monkeypatch
):
    old = document.active_version_id
    current = services.upload_document(
        users["manager"], folder, pdf_upload(), "New version", document
    )
    authenticate_client(client, users["manager"])
    fail_event(monkeypatch, "version_restored")
    with pytest.raises(IntegrityError, match="event-store failure"):
        client.post(f"/documents/{document.pk}/versions/{old}/restore/")
    document.refresh_from_db()
    assert document.active_version_id == current.pk


def test_purge_scheduling_audit_failure_keeps_document_versions_and_files(document, monkeypatch):
    document.deleted_at = timezone.now()
    document.save(update_fields=["deleted_at"])
    key = document.active_version.storage_key
    fail_event(monkeypatch, "operator_purge")
    with pytest.raises(IntegrityError, match="event-store failure"):
        call_command(
            "purge_deleted",
            before="2099-01-01T00:00:00Z",
            execute=True,
            policy_reference="F09-TEST",
            stdout=io.StringIO(),
        )
    assert Document.objects.filter(pk=document.pk).exists()
    assert Version.objects.filter(document=document).exists()
    assert path_for(key).is_file()


def test_purge_completion_audit_failure_keeps_committed_schedule(document, monkeypatch):
    document.deleted_at = timezone.now()
    document.save(update_fields=["deleted_at"])
    identifier = str(document.pk)
    key = document.active_version.storage_key
    fail_event(monkeypatch, "operator_purge", number=2)
    with pytest.raises(IntegrityError, match="event-store failure"):
        call_command(
            "purge_deleted",
            before="2099-01-01T00:00:00Z",
            execute=True,
            policy_reference="F09-TEST",
            stdout=io.StringIO(),
        )
    assert not Document.objects.filter(pk=document.pk).exists()
    assert not path_for(key).exists()
    assert Event.objects.filter(
        kind="operator_purge", target=identifier, outcome="scheduled"
    ).exists()
    assert not Event.objects.filter(kind="operator_purge", outcome="success").exists()


@pytest.mark.parametrize("command", ["cleanup_orphans", "purge_deleted"])
def test_operator_file_failure_records_failed_outcome(document, monkeypatch, command):
    if command == "purge_deleted":
        document.deleted_at = timezone.now()
        document.save(update_fields=["deleted_at"])
        target = path_for(document.active_version.storage_key)
        arguments = {"policy_reference": "F09-TEST"}
        kind, initial = "operator_purge", "scheduled"
    else:
        target = write_exclusive("originals/orphan-f09", [b"Synthetic orphan"])
        arguments = {}
        kind, initial = "operator_orphan_cleanup", "started"
    original_unlink = Path.unlink

    def fail_unlink(path, *args, **kwargs):
        if path == target:
            raise OSError("Synthetic file failure")
        return original_unlink(path, *args, **kwargs)

    monkeypatch.setattr(Path, "unlink", fail_unlink)
    with pytest.raises(OSError, match="file failure"):
        call_command(
            command, before="2099-01-01T00:00:00Z", execute=True, stdout=io.StringIO(), **arguments
        )
    outcomes = set(Event.objects.filter(kind=kind).values_list("outcome", flat=True))
    assert outcomes == {initial, "failed"}
    assert target.is_file()


def test_file_cleanup_refuses_a_transaction_that_cannot_commit_intent():
    orphan = write_exclusive("originals/orphan-f09", [b"Synthetic orphan"])
    with transaction.atomic():
        with pytest.raises(CommandError, match="existing database transaction"):
            call_command(
                "cleanup_orphans", before="2099-01-01T00:00:00Z", execute=True, stdout=io.StringIO()
            )
    assert orphan.is_file()
    assert not Event.objects.filter(kind="operator_orphan_cleanup").exists()


def test_purge_batch_retains_audited_earlier_results_when_a_later_document_fails(
    users, folder, document, monkeypatch
):
    other = services.upload_document(
        users["manager"], folder, pdf_upload(), "Other document"
    ).document
    paths = {item.pk: path_for(item.active_version.storage_key) for item in [document, other]}
    Document.objects.filter(pk__in=paths).update(deleted_at=timezone.now())
    first, second = list(
        Document.objects.filter(deleted_at__isnull=False).values_list("pk", flat=True)
    )
    # First schedule and completion succeed; the next document's schedule fails.
    fail_event(monkeypatch, "operator_purge", number=3)
    with pytest.raises(IntegrityError, match="event-store failure"):
        call_command(
            "purge_deleted",
            before="2099-01-01T00:00:00Z",
            execute=True,
            policy_reference="F09-TEST",
            stdout=io.StringIO(),
        )
    assert not Document.objects.filter(pk=first).exists() and not paths[first].exists()
    assert Document.objects.filter(pk=second).exists() and paths[second].is_file()
    assert set(
        Event.objects.filter(kind="operator_purge", target=str(first)).values_list(
            "outcome", flat=True
        )
    ) == {"scheduled", "success"}
    assert not Event.objects.filter(kind="operator_purge", target=str(second)).exists()


@pytest.mark.parametrize("model", ["folder", "foldergrant", "documentgrant"])
def test_single_admin_deletion_preserves_object_and_both_histories_on_event_failure(
    client, users, folder, document, monkeypatch, model
):
    if model == "folder":
        obj = Folder.objects.create(name="Empty folder")
    elif model == "foldergrant":
        obj = FolderGrant.objects.get(user=users["alice"], folder=folder)
    else:
        obj = DocumentGrant.objects.create(user=users["alice"], document=document)
    identifier = obj.pk
    authenticate_client(client, users["admin"])
    fail_event(monkeypatch, "admin_deleted")
    with pytest.raises(IntegrityError, match="event-store failure"):
        client.post(f"/admin/vault/{model}/{identifier}/delete/", {"post": "yes"})
    assert type(obj).objects.filter(pk=identifier).exists()
    assert not LogEntry.objects.filter(action_flag=DELETION).exists()
    assert not Event.objects.filter(kind="admin_deleted").exists()


def test_bulk_deletion_success_records_each_deleted_object_in_both_histories(client, users, folder):
    ids = list(FolderGrant.objects.filter(folder=folder).values_list("pk", flat=True))
    authenticate_client(client, users["admin"])
    response = client.post(
        "/admin/vault/foldergrant/",
        {"action": "delete_selected", "_selected_action": [str(pk) for pk in ids], "post": "yes"},
    )
    assert response.status_code == 302
    assert not FolderGrant.objects.filter(pk__in=ids).exists()
    expected = {str(identifier) for identifier in ids}
    assert (
        set(Event.objects.filter(kind="admin_deleted").values_list("target", flat=True)) == expected
    )
    assert (
        set(LogEntry.objects.filter(action_flag=DELETION).values_list("object_id", flat=True))
        == expected
    )


def test_admin_password_reset_success_has_one_event_and_revokes_existing_sessions(client, users):
    user = users["alice"]
    before = user.auth_version
    authenticate_client(client, users["admin"])
    response = client.post(
        f"/admin/accounts/user/{user.pk}/password/",
        {
            "password1": "Changed-By-Admin-Password-57",
            "password2": "Changed-By-Admin-Password-57",
            "usable_password": "true",
        },
    )
    assert response.status_code == 302
    user.refresh_from_db()
    assert user.check_password("Changed-By-Admin-Password-57")
    assert user.auth_version == before + 1
    assert Event.objects.filter(kind="admin_password_reset", target=str(user.pk)).count() == 1
    assert LogEntry.objects.filter(object_id=str(user.pk)).count() == 1


@pytest.mark.parametrize("document_grant", [True, False])
def test_permission_change_rolls_back_on_event_failure(
    client, users, folder, document, monkeypatch, document_grant
):
    if document_grant:
        grant = DocumentGrant.objects.create(user=users["alice"], document=document, manage=False)
        name, field, identifier = "documentgrant", "document", document.pk
    else:
        grant = FolderGrant.objects.get(user=users["alice"], folder=folder)
        name, field, identifier = "foldergrant", "folder", folder.pk
    authenticate_client(client, users["admin"])
    fail_event(monkeypatch, "permission_changed")
    with pytest.raises(IntegrityError, match="event-store failure"):
        client.post(
            f"/admin/vault/{name}/{grant.pk}/change/",
            {
                field: str(identifier),
                "user": str(users["alice"].pk),
                "manage": "on",
                "_save": "Save",
            },
        )
    grant.refresh_from_db()
    assert not grant.manage
    assert not Event.objects.filter(kind="permission_changed").exists()
