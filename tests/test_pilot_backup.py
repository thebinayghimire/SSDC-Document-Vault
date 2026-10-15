import io
import os
import subprocess
import tarfile
from contextlib import nullcontext

import pytest

from scripts.backup import decrypt_file
from scripts.backup_pilot import backup


@pytest.mark.parametrize("dump_fails", [False, True])
def test_pilot_snapshot_encrypts_paired_data_and_restarts_services(
    tmp_path, monkeypatch, dump_fails
):
    commands = []
    monkeypatch.setattr("scripts.backup_pilot.snapshot_lock", lambda compose: nullcontext())

    def run(command, **kwargs):
        commands.append(command)
        assert kwargs["stderr"] == subprocess.PIPE
        if command == ["ps", "--services", "--filter", "status=running"]:
            return subprocess.CompletedProcess(command, 0, stdout="app\nproxy\n")
        if "dbtools" in command:
            if dump_fails:
                raise subprocess.CalledProcessError(1, command, stderr=b"secret-canary")
            kwargs["stdout"].write(b"synthetic postgres dump")
        if "export_storage" in command:
            kwargs["stdout"].write(b"synthetic private tar including Drive bytes")
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr("scripts.backup_pilot.subprocess.run", run)
    archive = tmp_path / "snapshot.ssdcbackup"
    key = os.urandom(32)
    if dump_fails:
        with pytest.raises(subprocess.CalledProcessError):
            backup([], archive, key, "host", "database", "user")
        assert not archive.exists()
    else:
        backup([], archive, key, "host", "database", "user")
        assert b"synthetic" not in archive.read_bytes()
        restored = tmp_path / "restored.tar"
        decrypt_file(archive, restored, key)
        with tarfile.open(fileobj=io.BytesIO(restored.read_bytes())) as bundle:
            assert set(bundle.getnames()) == {"postgres.dump", "private.tar"}
            assert bundle.extractfile("postgres.dump").read() == b"synthetic postgres dump"
    assert "check_pilot_database" in commands[0]
    assert ["start", "app"] in commands and ["start", "proxy"] in commands


def test_existing_backup_is_preserved_before_any_network(tmp_path, monkeypatch):
    archive = tmp_path / "existing"
    archive.write_bytes(b"previous backup")
    monkeypatch.setattr("scripts.backup_pilot.subprocess.run", lambda *a, **k: pytest.fail())
    with pytest.raises(ValueError, match="already exists"):
        backup([], archive, os.urandom(32), "host", "database", "user")
    assert archive.read_bytes() == b"previous backup"
