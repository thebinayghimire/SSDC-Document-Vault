"""Encrypted paired backup and non-destructive restore drill. Requires Docker CLI."""

import argparse
import base64
import hashlib
import json
import os
import queue
import secrets
import signal
import subprocess
import sys
import tarfile
import tempfile
import threading
from contextlib import contextmanager
from pathlib import Path

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

MAGIC = b"SSDCBACKUP1"
CHUNK = 1024 * 1024


def encrypt_file(source, destination, key):
    nonce = secrets.token_bytes(12)
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce)).encryptor()
    cipher.authenticate_additional_data(MAGIC)
    descriptor, name = tempfile.mkstemp(prefix=".ssdc-backup-", dir=destination.parent)
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, "wb") as outgoing, source.open("rb") as incoming:
            outgoing.write(MAGIC + nonce)
            while block := incoming.read(CHUNK):
                outgoing.write(cipher.update(block))
            outgoing.write(cipher.finalize() + cipher.tag)
            outgoing.flush()
            os.fsync(outgoing.fileno())
        # Atomic publication without overwriting a competing/existing backup.
        os.link(temporary, destination)
    finally:
        temporary.unlink(missing_ok=True)


def decrypt_file(source, destination, key):
    size = source.stat().st_size
    if size < len(MAGIC) + 12 + 16:
        raise ValueError("Truncated backup")
    with source.open("rb") as incoming:
        if incoming.read(len(MAGIC)) != MAGIC:
            raise ValueError("Unsupported backup format")
        nonce = incoming.read(12)
        incoming.seek(-16, 2)
        tag = incoming.read(16)
        incoming.seek(len(MAGIC) + 12)
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag)).decryptor()
        cipher.authenticate_additional_data(MAGIC)
        remaining = size - len(MAGIC) - 12 - 16
        descriptor, name = tempfile.mkstemp(prefix=".ssdc-restore-", dir=destination.parent)
        temporary = Path(name)
        try:
            with os.fdopen(descriptor, "wb") as outgoing:
                while remaining:
                    block = incoming.read(min(CHUNK, remaining))
                    if not block:
                        raise ValueError("Truncated backup")
                    remaining -= len(block)
                    outgoing.write(cipher.update(block))
                outgoing.write(cipher.finalize())
                outgoing.flush()
                os.fsync(outgoing.fileno())
            os.link(temporary, destination)
        finally:
            temporary.unlink(missing_ok=True)


@contextmanager
def snapshot_lock(compose):
    name = "ssdc-maintenance-" + secrets.token_hex(6)
    command = compose + [
        "run",
        "--name",
        name,
        "--rm",
        "--no-deps",
        "-T",
        "app",
        "python",
        "manage.py",
        "hold_maintenance",
    ]
    process = subprocess.Popen(
        command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    try:
        ready = queue.Queue(maxsize=1)
        threading.Thread(target=lambda: ready.put(process.stdout.readline()), daemon=True).start()
        try:
            line = ready.get(timeout=30)
        except queue.Empty as exc:
            raise RuntimeError("Timed out acquiring the snapshot maintenance lock") from exc
        if line.strip() != b"SSDC_MAINTENANCE_READY":
            raise RuntimeError(
                "Snapshot lock helper failed. Confirm the rebuilt release, secret permissions and an idle maintenance window."
            )
        yield
        if process.poll() is not None:
            raise RuntimeError("Snapshot maintenance lock was lost")
    finally:
        process.stdin.close()
        try:
            process.wait(timeout=20)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
        process.stdout.close()
        process.stderr.close()
        subprocess.run(["docker", "rm", "--force", name], check=False, capture_output=True)


@contextmanager
def stopped_services(run):
    result = run(["ps", "--services", "--filter", "status=running"], capture_output=True, text=True)
    running = set(result.stdout.splitlines()) & {"app", "proxy"}
    try:
        if running:
            run(["stop", *sorted(running)], stdout=subprocess.DEVNULL)
        yield
    finally:
        failures = []
        for service in ("app", "proxy"):
            if service in running:
                try:
                    run(["start", service], stdout=subprocess.DEVNULL)
                except subprocess.CalledProcessError:
                    failures.append(service)
        if failures:
            raise RuntimeError("Failed to restore prior service state: " + ", ".join(failures))


def main():
    signal.signal(signal.SIGTERM, lambda signum, frame: sys.exit(128 + signum))
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["backup", "drill", "restore"])
    parser.add_argument("--compose", action="append", help="Repeat for Compose overlays")
    parser.add_argument("--env-file")
    parser.add_argument("--project-name")
    parser.add_argument("--key-file", type=Path, required=True)
    parser.add_argument("--archive", type=Path, required=True)
    args = parser.parse_args()
    if args.action == "restore" and (
        not args.project_name or not args.project_name.startswith("ssdc-restore-")
    ):
        parser.error(
            "Restore requires an explicit isolated --project-name ssdc-restore-<reference>"
        )
    key = base64.urlsafe_b64decode(args.key_file.read_bytes().strip())
    if len(key) != 32:
        parser.error("Backup key must be base64-encoded 32 bytes")
    compose = ["docker", "compose"]
    if args.project_name:
        compose += ["--project-name", args.project_name]
    if args.env_file:
        compose += ["--env-file", args.env_file]
    for filename in args.compose or ["compose.yaml"]:
        compose += ["-f", filename]

    def run(command, **kwargs):
        return subprocess.run(compose + command, check=True, **kwargs)

    if args.action == "restore":
        config = json.loads(run(["config", "--format", "json"], capture_output=True).stdout)
        if config["name"] != args.project_name or any(
            value.get("external") or not value["name"].startswith(args.project_name + "_")
            for value in config.get("volumes", {}).values()
        ):
            parser.error("Restore refuses external/shared volumes or mismatched projects")
        if (
            config["services"]["app"]["environment"].get("DOCUMENT_STORAGE_PROVIDER")
            != "filesystem"
        ):
            parser.error("Isolated recovery must explicitly use filesystem storage")
        running = run(
            ["ps", "--services", "--filter", "status=running"], capture_output=True, text=True
        ).stdout.splitlines()
        if {"app", "proxy"} & set(running):
            parser.error("Restore requires app/proxy stopped in the isolated project")
        empty = run(
            [
                "exec",
                "-T",
                "db",
                "sh",
                "-c",
                'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Atc "SELECT count(*) FROM pg_tables WHERE schemaname=\'public\'"',
            ],
            capture_output=True,
            text=True,
        )
        if empty.stdout.strip() != "0":
            parser.error("Restore requires an empty destination database")
        run(
            [
                "run",
                "--rm",
                "--no-deps",
                "-T",
                "app",
                "python",
                "manage.py",
                "restore_files",
                "--check-empty",
            ],
            stdout=subprocess.DEVNULL,
        )

    with snapshot_lock(compose), tempfile.TemporaryDirectory(prefix="ssdc-backup-") as temporary:
        root = Path(temporary)
        bundle = root / "bundle.tar"
        if args.action == "backup":
            if args.archive.exists():
                parser.error("Archive already exists; backups are never overwritten")
            args.archive.parent.mkdir(parents=True, exist_ok=True)
            with stopped_services(run):
                with (root / "postgres.dump").open("wb") as stream:
                    run(
                        [
                            "exec",
                            "-T",
                            "db",
                            "sh",
                            "-c",
                            'pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Fc --no-owner',
                        ],
                        stdout=stream,
                    )
                with (root / "private.tar").open("wb") as stream:
                    run(
                        [
                            "run",
                            "--rm",
                            "--no-deps",
                            "-T",
                            "app",
                            "python",
                            "manage.py",
                            "export_storage",
                            "--stdout",
                        ],
                        stdout=stream,
                    )
                with tarfile.open(bundle, "w") as archive:
                    archive.add(root / "postgres.dump", arcname="postgres.dump")
                    archive.add(root / "private.tar", arcname="private.tar")
                encrypt_file(bundle, args.archive, key)
                with args.archive.open("rb") as archive_stream:
                    reference = hashlib.file_digest(archive_stream, "sha256").hexdigest()
                run(
                    [
                        "run",
                        "--rm",
                        "--no-deps",
                        "-T",
                        "app",
                        "python",
                        "manage.py",
                        "record_operation",
                        "backup",
                        "--reference",
                        reference,
                    ],
                    stdout=subprocess.DEVNULL,
                )
                print("Encrypted database and private-storage backup created.")
        else:
            decrypt_file(args.archive, bundle, key)
            with args.archive.open("rb") as archive_stream:
                reference = hashlib.file_digest(archive_stream, "sha256").hexdigest()
            with tarfile.open(bundle) as archive:
                if {m.name for m in archive.getmembers()} != {"postgres.dump", "private.tar"}:
                    raise ValueError("Unexpected backup members")
                archive.extractall(root, filter="data")
            restored = root / "restored"
            restored.mkdir()
            with tarfile.open(root / "private.tar") as archive:
                archive.extractall(restored, filter="data")
            if args.action == "restore":
                with (root / "postgres.dump").open("rb") as stream:
                    run(
                        [
                            "exec",
                            "-T",
                            "db",
                            "sh",
                            "-c",
                            'pg_restore --exit-on-error --no-owner --no-acl --role=ssdc_migrator -U "$POSTGRES_USER" -d "$POSTGRES_DB"',
                        ],
                        stdin=stream,
                    )
                run(["run", "--rm", "--no-deps", "-T", "migrate"], stdout=subprocess.DEVNULL)
                run(
                    [
                        "run",
                        "--rm",
                        "--no-deps",
                        "-T",
                        "migrate",
                        "python",
                        "manage.py",
                        "configure_runtime_role",
                    ],
                    stdout=subprocess.DEVNULL,
                )
                with (root / "private.tar").open("rb") as stream:
                    run(
                        [
                            "run",
                            "--rm",
                            "--no-deps",
                            "-T",
                            "app",
                            "python",
                            "manage.py",
                            "restore_files",
                        ],
                        stdin=stream,
                    )
                for command in (
                    ["restore_storage_to_filesystem", "--execute"],
                    ["verify_storage"],
                    ["verify_mfa_seeds"],
                    ["revoke_all_sessions", "--policy-reference", "isolated-host-restore"],
                ):
                    run(["run", "--rm", "--no-deps", "-T", "app", "python", "manage.py", *command])
                run(
                    [
                        "run",
                        "--rm",
                        "--no-deps",
                        "-T",
                        "app",
                        "python",
                        "manage.py",
                        "record_operation",
                        "restore",
                        "--reference",
                        reference,
                    ]
                )
                print(
                    "Isolated restore completed. App/proxy remain stopped pending MFA, ACL and HTTPS acceptance."
                )
                return
            name = "ssdc_restore_" + secrets.token_hex(6)
            run(
                ["exec", "-T", "db", "sh", "-c", 'createdb -U "$POSTGRES_USER" "$1"', "sh", name],
                stdout=subprocess.DEVNULL,
            )
            try:
                with (root / "postgres.dump").open("rb") as stream:
                    run(
                        [
                            "exec",
                            "-T",
                            "db",
                            "sh",
                            "-c",
                            'pg_restore --exit-on-error --no-owner -U "$POSTGRES_USER" -d "$1"',
                            "sh",
                            name,
                        ],
                        stdin=stream,
                        stdout=subprocess.DEVNULL,
                    )
                query = "SELECT COALESCE(json_agg(t),'[]'::json) FROM (SELECT storage_key,size,sha256,thumbnail_key,thumbnail_size,thumbnail_sha256 FROM vault_version WHERE status <> 'rejected') t"
                result = run(
                    [
                        "exec",
                        "-T",
                        "db",
                        "sh",
                        "-c",
                        'psql -U "$POSTGRES_USER" -d "$1" -Atc "$2"',
                        "sh",
                        name,
                        query,
                    ],
                    capture_output=True,
                )
                rows = json.loads(result.stdout)
                for row in rows:
                    path = (restored / "private" / row["storage_key"]).resolve()
                    if not path.is_relative_to((restored / "private").resolve()):
                        raise ValueError("Invalid restored storage path")
                    with path.open("rb") as stream:
                        digest = hashlib.file_digest(stream, "sha256").hexdigest()
                    if digest != row["sha256"] or path.stat().st_size != row["size"]:
                        raise ValueError("Restored document integrity mismatch")
                    if row["thumbnail_key"]:
                        thumbnail = (restored / "private" / row["thumbnail_key"]).resolve()
                        if (
                            not thumbnail.is_relative_to((restored / "private").resolve())
                            or not thumbnail.is_file()
                        ):
                            raise ValueError("Restored thumbnail missing")
                        with thumbnail.open("rb") as stream:
                            digest = hashlib.file_digest(stream, "sha256").hexdigest()
                        if (
                            thumbnail.stat().st_size != row["thumbnail_size"]
                            or digest != row["thumbnail_sha256"]
                        ):
                            raise ValueError("Restored thumbnail integrity mismatch")
                print(
                    f"Restore drill passed: restored PostgreSQL schema/data and verified {len(rows)} document hashes. Live documents unchanged."
                )
            finally:
                run(
                    ["exec", "-T", "db", "sh", "-c", 'dropdb -U "$POSTGRES_USER" "$1"', "sh", name],
                    stdout=subprocess.DEVNULL,
                )
            run(
                [
                    "run",
                    "--rm",
                    "--no-deps",
                    "-T",
                    "app",
                    "python",
                    "manage.py",
                    "record_operation",
                    "restore_drill",
                    "--reference",
                    reference,
                ],
                stdout=subprocess.DEVNULL,
            )


if __name__ == "__main__":
    main()
