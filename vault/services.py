import hashlib
import uuid
from pathlib import Path

from django.conf import settings
from django.db import connection, transaction
from django.db.models import Sum

from audit.services import record

from .models import Document, Version
from .scanner import ScanUnavailable, scan
from .storage import path_for, write_exclusive
from .validation import InvalidUpload, inspect_file, isolated_inspection

THUMBNAIL_RESERVE = 1024 * 1024


def process_version(version):
    if version.status != Version.Status.QUARANTINED:
        return version
    path = path_for(version.storage_key)
    try:
        mime, pages, thumbnail = isolated_inspection(path, version.original_name, thumbnail=True)
        result = scan(path)
        if result == "infected":
            raise InvalidUpload("Malware detected. This file cannot be published.")
        thumbnail_key = ""
        if len(thumbnail) > THUMBNAIL_RESERVE:
            raise InvalidUpload("Generated preview exceeds the processing limit.")
        if mime.startswith("image/"):
            thumbnail_key = f"thumbnails/{version.pk}.jpg"
            if not path_for(thumbnail_key).exists():
                write_exclusive(thumbnail_key, [thumbnail])
        with transaction.atomic():
            document = Document.objects.select_for_update().get(pk=version.document_id)
            version = Version.objects.select_for_update().get(pk=version.pk)
            if version.status != Version.Status.QUARANTINED:
                return version
            version.status = Version.Status.READY
            version.mime_type, version.page_count = mime, pages
            version.scan_result, version.thumbnail_key = result, thumbnail_key
            version.thumbnail_size = len(thumbnail)
            version.processing_note = (
                "Validated and scanned" if result == "clean" else "Development-only scan bypass"
            )
            version.save()
            if (
                not document.active_version
                or document.active_version.uploaded_at < version.uploaded_at
            ):
                document.active_version = version
                document.save()
            record(version.uploader, "version_published", version.pk)
    except ScanUnavailable:
        version.processing_note = "Scanner unavailable; retry required"
        version.save(update_fields=["processing_note"])
        record(version.uploader, "scan", version.pk, "unavailable")
    except InvalidUpload as exc:
        version.status = Version.Status.REJECTED
        version.processing_note = str(exc)
        version.save(update_fields=["status", "processing_note"])
        path.unlink(missing_ok=True)
        record(version.uploader, "upload", version.pk, "rejected")
    return version


def upload_document(actor, folder, upload, title, document=None):
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
        with transaction.atomic():
            # Serialize global quota reservation across all application workers.
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
                document = Document.objects.create(title=title, folder=folder, created_by=actor)
            version = Version.objects.create(
                document=document,
                original_name=original_name,
                storage_key=key,
                size=size,
                sha256=digest.hexdigest(),
                mime_type=mime,
                thumbnail_size=reserve,
                page_count=pages,
                uploader=actor,
            )
            record(actor, "upload", version.pk)
    except Exception:
        path_for(key).unlink(missing_ok=True)
        raise
    return process_version(version)
