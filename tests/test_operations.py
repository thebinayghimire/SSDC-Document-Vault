import io
import os
import subprocess
import sys
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidTag
from django.core.management import call_command
from django.core.management.base import CommandError
from django.utils import timezone

from scripts.backup import decrypt_file, encrypt_file
from vault.models import Document
from vault.storage import path_for


@pytest.mark.django_db
def test_restored_storage_integrity(document):
    output = io.StringIO()
    call_command("verify_storage", stdout=output)
    assert "Verified 1 versions" in output.getvalue()
    path_for(document.active_version.storage_key).write_bytes(b"corrupt")
    with pytest.raises(CommandError):
        call_command("verify_storage", stdout=io.StringIO(), stderr=io.StringIO())


@pytest.mark.django_db(transaction=True)
def test_purge_dry_run_requires_policy(document):
    document.deleted_at = timezone.now()
    document.save()
    cutoff = "2099-01-01T00:00:00Z"
    call_command("purge_deleted", before=cutoff, stdout=io.StringIO())
    assert Document.objects.filter(pk=document.pk).exists()
    with pytest.raises(CommandError):
        call_command("purge_deleted", before=cutoff, execute=True, stdout=io.StringIO())
    path = path_for(document.active_version.storage_key)
    call_command(
        "purge_deleted",
        before=cutoff,
        execute=True,
        policy_reference="TEST-ONLY",
        stdout=io.StringIO(),
    )
    assert not Document.objects.filter(pk=document.pk).exists()
    assert not path.exists()


def test_backup_encryption_and_tamper_detection(tmp_path):
    key = os.urandom(32)
    original, encrypted, restored = [
        tmp_path / name for name in ("source", "encrypted", "restored")
    ]
    original.write_bytes(b"private synthetic data" * 10000)
    encrypt_file(original, encrypted, key)
    assert b"private synthetic data" not in encrypted.read_bytes()
    decrypt_file(encrypted, restored, key)
    assert restored.read_bytes() == original.read_bytes()
    data = bytearray(encrypted.read_bytes())
    data[40] ^= 1
    encrypted.write_bytes(data)
    with pytest.raises(InvalidTag):
        decrypt_file(encrypted, tmp_path / "tampered", key)


def test_production_missing_secrets_fails():
    environment = {
        k: v for k, v in os.environ.items() if k not in {"SECRET_KEY", "SECRET_KEY_FILE"}
    }
    environment["APP_ENV"] = "production"
    result = subprocess.run(
        [sys.executable, "manage.py", "check"],
        cwd=Path(__file__).resolve().parent.parent,
        env=environment,
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0
    assert "SECRET_KEY must be explicitly configured" in result.stderr


def test_private_storage_cannot_overlap_static():
    root = Path(__file__).resolve().parent.parent
    environment = dict(
        os.environ, APP_ENV="development", PRIVATE_STORAGE_ROOT=str(root / "static" / "documents")
    )
    result = subprocess.run(
        [sys.executable, "manage.py", "check"],
        cwd=root,
        env=environment,
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0
    assert "Private storage must be outside" in result.stderr
