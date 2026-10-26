import hashlib
import uuid
from pathlib import Path

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.exceptions import PermissionDenied, ValidationError
from django.db import connection, transaction
from django.db.models import Sum
from django.utils import timezone

from audit.services import record

from .drive_storage import network_budget
from .models import Document, Folder, Version
from .mutations import lock_policy_writes, mutation_access
from .policy import can_manage_document, folder_permissions
from .processing import processing_claim
from .scanner import ScanUnavailable, scan
from .storage import StorageError, path_for, provider, write_atomic, write_exclusive
from .validation import InvalidUpload, ProcessingBusy, inspect_file, isolated_inspection

THUMBNAIL_RESERVE = 1024 * 1024
DOCUMENT_EDIT_FIELDS = frozenset({"title", "folder", "restricted", "archived"})


def save_document_fields(document, fields, actor=None):
    """Apply intended edits to the locked current row, preserving unrelated state."""
    fields = set(fields)
    if not fields <= DOCUMENT_EDIT_FIELDS:
        raise ValueError("Unsupported document edit fields")
    with mutation_access(actor) as user:
        current = Document.objects.select_for_update().get(pk=document.pk)
        if not can_manage_document(user, current):
            raise PermissionDenied
        if fields - {"title", "folder"} and not user.is_portal_admin:
            raise PermissionDenied
        if "folder" in fields and document.folder_id != current.folder_id:
            _, manageable = folder_permissions(user)
            if document.folder_id not in manageable:
                raise ValidationError(
                    {"folder": "You no longer have permission to move documents to this folder."}
                )
        for name in fields:
            attribute = Document._meta.get_field(name).attname
            setattr(current, attribute, getattr(document, attribute))
        if fields:
            current.save(update_fields=fields | {"modified_at"})
        return current


def change_document_lifecycle(actor, document, action):
    if action not in {"archive", "unarchive", "delete", "restore"}:
        raise ValueError("Unknown document action")
    with mutation_access(actor) as user:
        current = Document.objects.select_for_update().get(pk=document.pk)
        if not can_manage_document(user, current):
            raise PermissionDenied
        field = "archived" if action in {"archive", "unarchive"} else "deleted_at"
        if field == "archived":
            current.archived = action == "archive"
        else:
            current.deleted_at = timezone.now() if action == "delete" else None
        current.save(update_fields=[field, "modified_at"])
        record(user, f"document_{action}", current.pk)
        return current


def create_folder(actor, folder):
    with mutation_access(actor) as user:
        if folder.parent_id:
            parent = Folder.objects.filter(pk=folder.parent_id).first()
            _, manageable = folder_permissions(user)
            if parent is None or parent.pk not in manageable:
                raise PermissionDenied
            folder.parent = parent
        elif not user.is_portal_admin:
            raise PermissionDenied
        if not user.is_portal_admin and folder.restricted:
            raise PermissionDenied
        folder.full_clean()
        folder.save()
        record(user, "folder_created", folder.pk)
        return folder


def restore_document_version(actor, document, version_id):
    # Keep remote I/O outside the global permission-write guard.
    with mutation_access(actor) as user:
        current = Document.objects.select_for_update().get(pk=document.pk)
        if not can_manage_document(user, current) or current.deleted_at:
            raise PermissionDenied
        candidate = Version.objects.filter(
            pk=version_id,
            document=current,
            status=Version.Status.READY,
        ).first()
        if candidate is None:
            raise PermissionDenied
    if not provider(candidate.storage_provider).exists(candidate.storage_key):
        raise PermissionDenied
    with mutation_access(actor) as user:
        current = Document.objects.select_for_update().get(pk=document.pk)
        if not can_manage_document(user, current) or current.deleted_at:
            raise PermissionDenied
        version = (
            Version.objects.select_for_update()
            .filter(pk=version_id, document=current, status=Version.Status.READY)
            .first()
        )
        if version is None or (version.storage_provider, version.storage_key) != (
            candidate.storage_provider,
            candidate.storage_key,
        ):
            raise PermissionDenied
        current.active_version = version
        current.selection_revision += 1
        current.save(update_fields=["active_version", "modified_at", "selection_revision"])
        record(user, "version_restored", version.pk)
        return current


def process_version(version, actor=None):
    with processing_claim(version.pk) as claimed:
        version.refresh_from_db()
        if not claimed or version.status != Version.Status.QUARANTINED:
            return version
        return _process_claimed_version(version, actor=actor)


def _remove_rejected_files(keys):
    for key in set(keys) - {""}:
        path_for(key).unlink(missing_ok=True)


def _record_scan_failure(version, note, *, rejected=False, denied=False):
    with transaction.atomic():
        lock_policy_writes()
        Document.objects.select_for_update().get(pk=version.document_id)
        current = Version.objects.select_for_update().get(pk=version.pk)
        if current.status != Version.Status.QUARANTINED:
            return current
        fields = ["processing_note"]
        current.processing_note = note
        if rejected:
            keys = (current.storage_key, current.thumbnail_key, f"thumbnails/{current.pk}.jpg")
            current.status = Version.Status.REJECTED
            current.thumbnail_key, current.thumbnail_size = "", 0
            fields += ["status", "thumbnail_key", "thumbnail_size"]
        current.save(update_fields=fields)
        if rejected:
            record(current.uploader, "upload", current.pk, "rejected")
            transaction.on_commit(lambda keys=keys: _remove_rejected_files(keys))
        elif denied:
            record(None, "version_published", current.pk, "denied")
        else:
            record(current.uploader, "scan", current.pk, "unavailable")
        return current


def _process_claimed_version(version, actor=None):
    if version.status != Version.Status.QUARANTINED:
        return version
    path = path_for(version.storage_key)
    try:
        mime, pages, thumbnail = isolated_inspection(path, version.original_name, thumbnail=True)
        result = scan(path)
        if result == "infected":
            raise InvalidUpload("Malware detected. This file cannot be published.")
        with path.open("rb") as stream:
            digest = hashlib.file_digest(stream, "sha256").hexdigest()
        if digest != version.sha256 or path.stat().st_size != version.size:
            raise InvalidUpload("File integrity check failed; this version cannot be published.")
        thumbnail_key = ""
        if len(thumbnail) > THUMBNAIL_RESERVE:
            raise InvalidUpload("Generated preview exceeds the processing limit.")
        actor = actor or get_user_model().objects.filter(pk=version.uploader_id).first()
        with mutation_access(actor) as user:
            current_document = Document.objects.select_for_update().get(pk=version.document_id)
            if not can_manage_document(user, current_document) or current_document.deleted_at:
                raise PermissionDenied
        storage = provider(version.storage_provider)
        if mime.startswith("image/"):
            thumbnail_key = f"thumbnails/{version.pk}.jpg"
            write_atomic(thumbnail_key, [thumbnail])
        # Remote writes and durable intents are outside the publication transaction.
        # A rollback leaves quarantined metadata and the same retryable Drive IDs.
        with network_budget():
            storage.put(version.storage_key, path, mime, version.original_name)
            if thumbnail_key:
                storage.put(thumbnail_key, path_for(thumbnail_key), "image/jpeg", "preview.jpg")
        # Synchronous uploads retain their password-authenticated account version.
        # Operator retries check the uploader's current role and document grants.
        with mutation_access(actor) as user:
            document = Document.objects.select_for_update().get(pk=version.document_id)
            version = Version.objects.select_for_update().get(pk=version.pk)
            if version.status != Version.Status.QUARANTINED:
                return version
            if not can_manage_document(user, document) or document.deleted_at:
                raise PermissionDenied
            version.status = Version.Status.READY
            version.mime_type, version.page_count = mime, pages
            version.scan_result, version.thumbnail_key = result, thumbnail_key
            version.thumbnail_size = len(thumbnail)
            version.thumbnail_sha256 = (
                hashlib.sha256(thumbnail).hexdigest() if thumbnail_key else ""
            )
            version.processing_note = {
                "clean": "Validated and scanned",
                "disabled": "Validated; malware scanning disabled",
            }.get(result, "Development-only scan bypass")
            version.save(
                update_fields=[
                    "status",
                    "mime_type",
                    "page_count",
                    "scan_result",
                    "thumbnail_key",
                    "thumbnail_size",
                    "thumbnail_sha256",
                    "processing_note",
                ]
            )
            if version.selection_revision == document.selection_revision and (
                not document.active_version
                or document.active_version.uploaded_at < version.uploaded_at
            ):
                document.active_version = version
                document.save(update_fields=["active_version", "modified_at"])
            record(version.uploader, "version_published", version.pk)
        if version.storage_provider == "gdrive":

            def remove_staging():
                _remove_rejected_files((version.storage_key, thumbnail_key))

            transaction.on_commit(remove_staging)
    except PermissionDenied:
        return _record_scan_failure(
            version, "Access changed; administrator review required", denied=True
        )
    except ScanUnavailable:
        return _record_scan_failure(version, "Scanner unavailable; retry required")
    except ProcessingBusy:
        return _record_scan_failure(version, "Parser busy; retry required")
    except OSError:
        return _record_scan_failure(version, "Storage unavailable; retry required")
    except StorageError as exc:
        return _record_scan_failure(version, str(exc))
    except InvalidUpload as exc:
        return _record_scan_failure(version, str(exc), rejected=True)
    return version


def upload_document(actor, folder, upload, title, document=None):
    # Check current authorization before accepting/staging untrusted bytes.
    with mutation_access(actor) as user:
        if document is None:
            _, manageable = folder_permissions(user)
            if folder.pk not in manageable:
                raise PermissionDenied
        else:
            current = Document.objects.select_for_update().get(pk=document.pk)
            if not can_manage_document(user, current) or current.deleted_at:
                raise PermissionDenied
    if not upload.size or upload.size > settings.MAX_UPLOAD_BYTES:
        raise InvalidUpload("File is empty or exceeds the upload limit.")
    original_name = Path(upload.name.replace("\\", "/")).name[:255]
    if not original_name or any(ord(char) < 32 for char in original_name):
        raise InvalidUpload("Unsupported filename.")
    key = f"originals/{uuid.uuid4().hex}"
    digest = hashlib.sha256()
    size = 0

    def chunks():
        nonlocal size
        for chunk in upload.chunks():
            size += len(chunk)
            if size > settings.MAX_UPLOAD_BYTES:
                raise InvalidUpload("File exceeds the upload limit.")
            digest.update(chunk)
            yield chunk

    try:
        write_exclusive(key, chunks())
        mime, pages = inspect_file(path_for(key), original_name)
        with mutation_access(actor) as user:
            if document is None:
                current_folder = Folder.objects.filter(pk=folder.pk).first()
                _, manageable = folder_permissions(user)
                if current_folder is None or current_folder.pk not in manageable:
                    raise PermissionDenied
            else:
                document = Document.objects.select_for_update().get(pk=document.pk)
                if not can_manage_document(user, document) or document.deleted_at:
                    raise PermissionDenied
            # Serialize global quota reservation across all application workers.
            # This short transaction ends before process_version() streams bytes
            # to ClamAV or Google Drive; no network I/O holds the quota lock.
            with connection.cursor() as cursor:
                cursor.execute("SELECT pg_advisory_xact_lock(731009)")
            totals = Version.objects.exclude(status=Version.Status.REJECTED).aggregate(
                originals=Sum("size"), previews=Sum("thumbnail_size")
            )
            used = (totals["originals"] or 0) + (totals["previews"] or 0)
            reserve = THUMBNAIL_RESERVE if mime.startswith("image/") else 0
            if used + size + reserve > settings.MAX_STORAGE_BYTES:
                raise InvalidUpload("The storage quota has been reached.")
            if document is None:
                document = Document.objects.create(
                    title=title, folder=current_folder, created_by=user
                )
            version = Version.objects.create(
                document=document,
                original_name=original_name,
                storage_key=key,
                storage_provider=settings.DOCUMENT_STORAGE_PROVIDER,
                size=size,
                sha256=digest.hexdigest(),
                mime_type=mime,
                thumbnail_size=reserve,
                page_count=pages,
                uploader=user,
                selection_revision=document.selection_revision,
            )
            record(user, "upload", version.pk)
    except Exception as exc:
        try:
            path_for(key).unlink(missing_ok=True)
        except OSError:
            pass
        if isinstance(exc, OSError):
            raise InvalidUpload(
                "Storage is temporarily unavailable or full. Please retry shortly."
            ) from exc
        raise
    return process_version(version, actor=actor)
