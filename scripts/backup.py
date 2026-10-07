"""Encrypted paired backup and non-destructive restore drill. Requires Docker CLI."""

import argparse
import base64
import hashlib
import json
import os
import secrets
import subprocess
import tarfile
import tempfile
from pathlib import Path

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

MAGIC = b"SSDCBACKUP1"
CHUNK = 1024 * 1024


def encrypt_file(source, destination, key):
    nonce = secrets.token_bytes(12)
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce)).encryptor()
    cipher.authenticate_additional_data(MAGIC)
    with source.open("rb") as incoming, destination.open("xb") as outgoing:
        os.chmod(destination, 0o600)
        outgoing.write(MAGIC + nonce)
        while block := incoming.read(CHUNK):
            outgoing.write(cipher.update(block))
        outgoing.write(cipher.finalize() + cipher.tag)


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
        with destination.open("xb") as outgoing:
            os.chmod(destination, 0o600)
            while remaining:
                block = incoming.read(min(CHUNK, remaining))
                if not block:
                    raise ValueError("Truncated backup")
                remaining -= len(block)
                outgoing.write(cipher.update(block))
            outgoing.write(cipher.finalize())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["backup", "drill"])
    parser.add_argument("--compose", default="compose.yaml")
    parser.add_argument("--env-file")
    parser.add_argument("--key-file", type=Path, required=True)
    parser.add_argument("--archive", type=Path, required=True)
    args = parser.parse_args()
    key = base64.urlsafe_b64decode(args.key_file.read_bytes().strip())
    if len(key) != 32:
        parser.error("Backup key must be base64-encoded 32 bytes")
    compose = ["docker", "compose"]
    if args.env_file:
        compose += ["--env-file", args.env_file]
    compose += ["-f", args.compose]

    def run(command, **kwargs):
        return subprocess.run(compose + command, check=True, **kwargs)

    with tempfile.TemporaryDirectory(prefix="ssdc-backup-") as temporary:
        root = Path(temporary)
        bundle = root / "bundle.tar"
        if args.action == "backup":
            if args.archive.exists():
                parser.error("Archive already exists; backups are never overwritten")
            args.archive.parent.mkdir(parents=True, exist_ok=True)
            run(["stop", "proxy", "app"], stdout=subprocess.DEVNULL)
            try:
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
                code = "import sys,tarfile; t=tarfile.open(fileobj=sys.stdout.buffer,mode='w|'); t.add('/data/private',arcname='private'); t.close()"
                with (root / "private.tar").open("wb") as stream:
                    run(
                        ["run", "--rm", "--no-deps", "-T", "app", "python", "-c", code],
                        stdout=stream,
                    )
                with tarfile.open(bundle, "w") as archive:
                    archive.add(root / "postgres.dump", arcname="postgres.dump")
                    archive.add(root / "private.tar", arcname="private.tar")
                encrypt_file(bundle, args.archive, key)
                reference = hashlib.sha256(str(args.archive.resolve()).encode()).hexdigest()
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
            finally:
                run(["start", "app", "proxy"], stdout=subprocess.DEVNULL)
        else:
            decrypt_file(args.archive, bundle, key)
            with tarfile.open(bundle) as archive:
                if {m.name for m in archive.getmembers()} != {"postgres.dump", "private.tar"}:
                    raise ValueError("Unexpected backup members")
                archive.extractall(root, filter="data")
            restored = root / "restored"
            restored.mkdir()
            with tarfile.open(root / "private.tar") as archive:
                archive.extractall(restored, filter="data")
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
                query = "SELECT COALESCE(json_agg(t),'[]'::json) FROM (SELECT storage_key,size,sha256,thumbnail_key FROM vault_version WHERE status <> 'rejected') t"
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
                print(
                    f"Restore drill passed: restored PostgreSQL schema/data and verified {len(rows)} document hashes. Live documents unchanged."
                )
            finally:
                run(
                    ["exec", "-T", "db", "sh", "-c", 'dropdb -U "$POSTGRES_USER" "$1"', "sh", name],
                    stdout=subprocess.DEVNULL,
                )
            reference = hashlib.sha256(str(args.archive.resolve()).encode()).hexdigest()
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
