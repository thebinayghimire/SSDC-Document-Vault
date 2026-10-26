"""Scan attempts must preserve committed outcomes and publish complete previews."""

import io
import threading
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch

import pytest
from django.core.management import call_command
from django.db import connection, connections, transaction
from PIL import Image

from accounts.models import User
from audit.models import Event
from vault import services
from vault.models import Document, Folder, Version
from vault.scanner import ScanUnavailable
from vault.storage import path_for, write_atomic
from vault.validation import InvalidUpload

from .conftest import image_upload, pdf_upload

pytestmark = pytest.mark.django_db(transaction=True)


def pending_version(users, folder, *, image=False):
    with patch("vault.services.scan", side_effect=ScanUnavailable):
        return services.upload_document(
            users["manager"], folder, image_upload() if image else pdf_upload(), "Pending scan"
        )


@pytest.mark.parametrize("failure", ["invalid", "infected", "unavailable"])
def test_stale_retry_preserves_published_version(users, folder, failure):
    pending = pending_version(users, folder, image=True)
    stale = Version.objects.get(pk=pending.pk)
    ready = services.process_version(pending)
    original = path_for(ready.storage_key).read_bytes()
    thumbnail = path_for(ready.thumbnail_key).read_bytes()
    note = ready.processing_note
    audit_count = Event.objects.count()

    with patch("vault.services.isolated_inspection", wraps=services.isolated_inspection) as inspect:
        if failure == "invalid":
            inspect.side_effect = InvalidUpload("An older worker failed")
        effect = ScanUnavailable() if failure == "unavailable" else None
        with patch("vault.services.scan", return_value="infected", side_effect=effect):
            result = services.process_version(stale)

    ready.refresh_from_db()
    ready.document.refresh_from_db()
    assert result.status == ready.status == Version.Status.READY
    assert ready.processing_note == note
    assert ready.document.active_version_id == ready.pk
    assert path_for(ready.storage_key).read_bytes() == original
    assert path_for(ready.thumbnail_key).read_bytes() == thumbnail
    assert Event.objects.count() == audit_count
    inspect.assert_not_called()


@pytest.mark.parametrize("failure", ["infected", "unavailable", "denied"])
def test_late_failure_rechecks_terminal_state_before_writing(users, folder, monkeypatch, failure):
    version = pending_version(users, folder)
    audit_count = Event.objects.count()

    def newer_outcome(path):
        # A terminal result committed after this attempt's initial lookup must
        # still win, including when an older worker or operator wrote it.
        Version.objects.filter(pk=version.pk).update(
            status=Version.Status.READY, processing_note="Already published"
        )
        Document.objects.filter(pk=version.document_id).update(active_version=version)
        if failure == "unavailable":
            raise ScanUnavailable
        if failure == "denied":
            User.objects.filter(pk=users["manager"].pk).update(role=User.Role.STAFF)
            return "clean"
        return "infected"

    monkeypatch.setattr(services, "scan", newer_outcome)
    result = services.process_version(version)

    version.refresh_from_db()
    assert result.status == version.status == Version.Status.READY
    assert version.processing_note == "Already published"
    assert path_for(version.storage_key).is_file()
    assert Event.objects.count() == audit_count


def test_rejection_deletes_files_only_after_commit(users, folder):
    version = pending_version(users, folder)
    original = path_for(version.storage_key)
    with transaction.atomic():
        with patch("vault.services.scan", return_value="infected"):
            result = services.process_version(version)
        assert result.status == Version.Status.REJECTED
        assert original.is_file(), "An uncommitted rejection must not delete the original"
    assert not original.exists()
    assert result.document.active_version_id is None


def test_failed_rejection_audit_rolls_back_and_preserves_files(users, folder):
    version = pending_version(users, folder)
    with patch("vault.services.scan", return_value="infected"):
        with patch("vault.services.record", side_effect=RuntimeError("Audit failed")):
            with pytest.raises(RuntimeError, match="Audit failed"):
                services.process_version(version)
    version.refresh_from_db()
    assert version.status == Version.Status.QUARANTINED
    assert path_for(version.storage_key).is_file()
    assert services.process_version(version).status == Version.Status.READY


def test_retry_repairs_incomplete_preview_before_publication(users, folder):
    version = pending_version(users, folder, image=True)
    thumbnail = path_for(f"thumbnails/{version.pk}.jpg")
    thumbnail.parent.mkdir(parents=True, exist_ok=True)
    thumbnail.write_bytes(b"interrupted preview")

    result = services.process_version(version)

    assert result.status == Version.Status.READY
    with Image.open(path_for(result.thumbnail_key)) as preview:
        preview.verify()
    assert not list(thumbnail.parent.glob("*.tmp"))


def test_processing_reloads_status_instead_of_trusting_input(users, folder):
    version = pending_version(users, folder)
    version.status = Version.Status.READY
    services.process_version(version)
    version.refresh_from_db()
    assert version.status == Version.Status.READY
    assert version.document.active_version_id == version.pk


def test_upload_and_two_retry_commands_share_one_processing_attempt(users, folder, monkeypatch):
    scanning, resume = threading.Event(), threading.Event()
    counts = {"scan": 0, "inspect": 0}
    count_lock = threading.Lock()
    inspect = services.isolated_inspection

    def count_inspection(*args, **kwargs):
        with count_lock:
            counts["inspect"] += 1
        return inspect(*args, **kwargs)

    def pause_scan(path):
        with count_lock:
            counts["scan"] += 1
            attempt = counts["scan"]
        if attempt == 1:
            scanning.set()
            assert resume.wait(20), "Concurrent retries did not finish"
            return "clean"
        return "infected"

    def upload():
        try:
            return services.upload_document(
                User.objects.get(pk=users["manager"].pk),
                Folder.objects.get(pk=folder.pk),
                image_upload(),
                "Concurrent upload",
            )
        finally:
            connections.close_all()

    def retry():
        try:
            output = io.StringIO()
            call_command("retry_scans", limit=20, stdout=output)
            return output.getvalue()
        finally:
            connections.close_all()

    monkeypatch.setattr(services, "scan", pause_scan)
    monkeypatch.setattr(services, "isolated_inspection", count_inspection)
    with ThreadPoolExecutor(max_workers=3) as executor:
        future = executor.submit(upload)
        try:
            assert scanning.wait(20), "Upload did not reach the scanner"
            version = Version.objects.get(status=Version.Status.QUARANTINED)
            retries = [executor.submit(retry) for _ in range(2)]
            for retry_future in retries:
                assert str(version.pk) in retry_future.result(timeout=10)
            version.refresh_from_db()
            assert version.status == Version.Status.QUARANTINED
            assert path_for(version.storage_key).is_file()
            assert counts == {"scan": 1, "inspect": 1}
        finally:
            resume.set()
        result = future.result(timeout=20)

    assert result.status == Version.Status.READY
    assert result.document.active_version_id == result.pk
    assert path_for(result.storage_key).is_file()
    with Image.open(path_for(result.thumbnail_key)) as preview:
        preview.verify()
    assert Event.objects.filter(kind="version_published", outcome="success").count() == 1
    assert not Event.objects.filter(outcome="rejected").exists()


def test_unexpected_error_releases_processing_for_another_worker(users, folder):
    version = pending_version(users, folder)
    with patch("vault.services.scan", side_effect=RuntimeError("Interrupted scan")):
        with pytest.raises(RuntimeError, match="Interrupted scan"):
            services.process_version(version)

    def retry():
        try:
            return services.process_version(Version.objects.get(pk=version.pk))
        finally:
            connections.close_all()

    with ThreadPoolExecutor(max_workers=1) as executor:
        result = executor.submit(retry).result(timeout=20)
    assert result.status == Version.Status.READY


def test_disconnected_owner_does_not_leave_a_stuck_processing_claim(users, folder):
    version = pending_version(users, folder)

    def disconnect(path):
        connection.close()
        raise RuntimeError("Worker lost its database connection")

    with patch("vault.services.scan", side_effect=disconnect):
        with pytest.raises(RuntimeError, match="Worker lost"):
            services.process_version(version)
    assert services.process_version(version).status == Version.Status.READY


def test_different_versions_can_be_scanned_at_the_same_time(users, folder, monkeypatch, settings):
    settings.PARSER_CONCURRENCY = 2
    versions = [pending_version(users, folder) for _ in range(2)]
    both_scanning, resume = threading.Event(), threading.Event()
    count_lock = threading.Lock()
    count = 0

    def scan(path):
        nonlocal count
        with count_lock:
            count += 1
            if count == 2:
                both_scanning.set()
        assert resume.wait(20), "Other version did not reach scanning"
        return "clean"

    def process(identifier):
        try:
            return services.process_version(Version.objects.get(pk=identifier))
        finally:
            connections.close_all()

    monkeypatch.setattr(services, "scan", scan)
    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [executor.submit(process, version.pk) for version in versions]
        try:
            assert both_scanning.wait(20), "Scanning locked unrelated versions"
        finally:
            resume.set()
        assert all(future.result(timeout=20).status == Version.Status.READY for future in futures)


def test_nested_attempt_cannot_reenter_the_same_processing_claim(users, folder, monkeypatch):
    version = pending_version(users, folder)
    calls = 0

    def scan(path):
        nonlocal calls
        calls += 1
        assert calls == 1, "Nested retry started another scan"
        nested = services.process_version(Version.objects.get(pk=version.pk))
        assert nested.status == Version.Status.QUARANTINED
        return "clean"

    monkeypatch.setattr(services, "scan", scan)
    assert services.process_version(version).status == Version.Status.READY
    assert calls == 1


def test_stale_retry_does_not_reprocess_a_rejected_file(users, folder):
    version = pending_version(users, folder)
    stale = Version.objects.get(pk=version.pk)
    with patch("vault.services.scan", return_value="infected"):
        assert services.process_version(version).status == Version.Status.REJECTED
    audit_count = Event.objects.count()
    with patch("vault.services.isolated_inspection") as inspect:
        assert services.process_version(stale).status == Version.Status.REJECTED
    inspect.assert_not_called()
    assert Event.objects.count() == audit_count


def test_rolled_back_rejection_keeps_original_and_preview(users, folder):
    version = pending_version(users, folder, image=True)
    original = path_for(version.storage_key)
    preview = path_for(f"thumbnails/{version.pk}.jpg")
    preview.parent.mkdir(parents=True, exist_ok=True)
    preview.write_bytes(b"Pending preview")
    with pytest.raises(RuntimeError, match="Rollback"):
        with transaction.atomic():
            with patch("vault.services.scan", return_value="infected"):
                assert services.process_version(version).status == Version.Status.REJECTED
            raise RuntimeError("Rollback")
    version.refresh_from_db()
    assert version.status == Version.Status.QUARANTINED
    assert version.thumbnail_size == services.THUMBNAIL_RESERVE
    assert original.is_file()
    assert preview.read_bytes() == b"Pending preview"
    assert services.process_version(version).status == Version.Status.READY


def test_publication_rollback_can_retry_without_preview_collision(users, folder):
    version = pending_version(users, folder, image=True)
    with patch("vault.services.record", side_effect=RuntimeError("Publication audit failed")):
        with pytest.raises(RuntimeError, match="Publication audit failed"):
            services.process_version(version)
    version.refresh_from_db()
    version.document.refresh_from_db()
    assert version.status == Version.Status.QUARANTINED
    assert version.document.active_version_id is None
    assert path_for(version.storage_key).is_file()
    result = services.process_version(version)
    assert result.status == Version.Status.READY
    with Image.open(path_for(result.thumbnail_key)) as preview:
        preview.verify()


def test_rejection_cleans_interrupted_preview_and_releases_reservation(users, folder):
    version = pending_version(users, folder, image=True)
    preview = path_for(f"thumbnails/{version.pk}.jpg")
    preview.parent.mkdir(parents=True, exist_ok=True)
    preview.write_bytes(b"Interrupted preview")
    with patch("vault.services.scan", return_value="infected"):
        result = services.process_version(version)
    assert result.status == Version.Status.REJECTED
    assert result.thumbnail_size == 0 and result.thumbnail_key == ""
    assert not preview.exists()
    assert not path_for(result.storage_key).exists()


def test_interrupted_preview_write_preserves_previous_file_and_removes_staging_file():
    key = "thumbnails/atomic-fixture.jpg"
    preview = path_for(key)
    preview.parent.mkdir(parents=True, exist_ok=True)
    preview.write_bytes(b"Previous complete preview")

    def chunks():
        yield b"Incomplete replacement"
        raise OSError("Storage full")

    with pytest.raises(OSError, match="Storage full"):
        write_atomic(key, chunks())
    assert preview.read_bytes() == b"Previous complete preview"
    assert not list(preview.parent.glob("*.tmp"))


def test_retry_command_skips_a_version_removed_after_its_initial_query(users, folder):
    version = pending_version(users, folder)
    process = services.process_version

    def remove_before_processing(candidate):
        Version.objects.filter(pk=candidate.pk).delete()
        return process(candidate)

    output = io.StringIO()
    with patch(
        "vault.management.commands.retry_scans.process_version",
        side_effect=remove_before_processing,
    ):
        call_command("retry_scans", stdout=output)
    assert "removed; skipped" in output.getvalue()
    assert not Version.objects.filter(pk=version.pk).exists()


def test_retry_command_skips_missing_staging_without_retrying(users, folder):
    version = pending_version(users, folder)
    note = version.processing_note
    path_for(version.storage_key).unlink()

    output = io.StringIO()
    with patch("vault.management.commands.retry_scans.process_version") as process:
        call_command("retry_scans", stdout=output)

    process.assert_not_called()
    assert "staging missing; run cleanup_orphans" in output.getvalue()
    version.refresh_from_db()
    assert version.status == Version.Status.QUARANTINED
    assert version.processing_note == note


def test_quota_transaction_ends_before_scanning_or_drive_io(users, folder, monkeypatch):
    original = services.process_version
    observed = {}

    def process(version, actor=None):
        observed["in_atomic_block"] = connection.in_atomic_block
        observed["autocommit"] = connection.get_autocommit()
        return original(version, actor=actor)

    monkeypatch.setattr(services, "process_version", process)
    result = services.upload_document(users["manager"], folder, pdf_upload(), "Scope check")
    assert result.status == Version.Status.READY
    assert observed == {"in_atomic_block": False, "autocommit": True}


def test_disabled_scanning_publishes_without_contacting_the_scanner(users, folder, settings):
    """SSDC accepted the risk of no malware scanning; uploads must still publish."""
    settings.SCAN_MODE = "disabled"
    with patch("vault.scanner.socket.create_connection", side_effect=AssertionError("no scanner")):
        version = services.upload_document(users["manager"], folder, pdf_upload(), "Unscanned")
        published = services.process_version(version)
    assert published.status == Version.Status.READY
    assert published.scan_result == "disabled"
    assert published.processing_note == "Validated; malware scanning disabled"
