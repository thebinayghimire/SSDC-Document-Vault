import os
import subprocess
from unittest.mock import patch

import pytest

from scripts.backup import encrypt_file, stopped_services


def test_partial_stop_failure_restarts_only_previously_running_services():
    calls = []

    def run(command, **kwargs):
        calls.append(command)
        if command[0] == "ps":
            return subprocess.CompletedProcess(command, 0, stdout="app\ndb\n")
        if command[0] == "stop":
            raise subprocess.CalledProcessError(1, command)
        return subprocess.CompletedProcess(command, 0)

    with pytest.raises(subprocess.CalledProcessError):
        with stopped_services(run):
            pytest.fail("Snapshot should not run after stop failure")
    assert ["start", "app"] in calls
    assert ["start", "proxy"] not in calls


def test_restart_failure_still_attempts_both_services():
    calls = []

    def run(command, **kwargs):
        calls.append(command)
        if command[0] == "ps":
            return subprocess.CompletedProcess(command, 0, stdout="app\nproxy\n")
        if command == ["start", "app"]:
            raise subprocess.CalledProcessError(1, command)
        return subprocess.CompletedProcess(command, 0)

    with pytest.raises(RuntimeError, match="app"):
        with stopped_services(run):
            pass
    assert ["start", "proxy"] in calls


def test_encryption_failure_never_publishes_archive(tmp_path):
    source, destination = tmp_path / "source", tmp_path / "backup"
    source.write_bytes(b"Synthetic" * 2000)
    with patch("scripts.backup.os.fsync", side_effect=OSError("Synthetic disk failure")):
        with pytest.raises(OSError):
            encrypt_file(source, destination, os.urandom(32))
    assert not destination.exists()
    assert not list(tmp_path.glob(".ssdc-backup-*"))


def test_backup_atomic_publication_does_not_overwrite(tmp_path):
    source, destination = tmp_path / "source", tmp_path / "backup"
    source.write_bytes(b"Synthetic")
    destination.write_bytes(b"Existing backup")
    with pytest.raises(FileExistsError):
        encrypt_file(source, destination, os.urandom(32))
    assert destination.read_bytes() == b"Existing backup"


def test_unauthenticated_plaintext_is_never_published(tmp_path):
    from cryptography.exceptions import InvalidTag

    from scripts.backup import decrypt_file

    source, archive, destination = tmp_path / "source", tmp_path / "archive", tmp_path / "restored"
    source.write_bytes(b"Synthetic confidential text")
    encrypt_file(source, archive, os.urandom(32))
    with pytest.raises(InvalidTag):
        decrypt_file(archive, destination, os.urandom(32))
    assert not destination.exists()
    assert not list(tmp_path.glob(".ssdc-restore-*"))
