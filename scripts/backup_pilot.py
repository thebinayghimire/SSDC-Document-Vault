"""Encrypted Supabase/public-schema + private/Drive snapshot; never restores a hosted DB."""

import argparse
import base64
import hashlib
import signal
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

from scripts.backup import encrypt_file, snapshot_lock, stopped_services


def backup(compose, archive, key, expected_host, expected_database, expected_user):
    if archive.exists():
        raise ValueError("Archive already exists; backups are never overwritten")

    def run(arguments, **kwargs):
        # Do not expose libpq/Docker diagnostics or credentials to console logs.
        return subprocess.run(compose + arguments, check=True, stderr=subprocess.PIPE, **kwargs)

    run(
        [
            "run",
            "--rm",
            "--no-deps",
            "-T",
            "migrate",
            "python",
            "manage.py",
            "check_pilot_database",
            "--expected-host",
            expected_host,
            "--expected-database",
            expected_database,
            "--expected-user",
            expected_user,
        ],
        stdout=subprocess.DEVNULL,
    )
    archive.parent.mkdir(parents=True, exist_ok=True)
    with snapshot_lock(compose), tempfile.TemporaryDirectory(prefix="ssdc-pilot-backup-") as temp:
        root = Path(temp)
        with stopped_services(run):
            with (root / "postgres.dump").open("wb") as stream:
                run(["run", "--rm", "--no-deps", "-T", "dbtools"], stdout=stream)
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
            bundle = root / "bundle.tar"
            with tarfile.open(bundle, "w") as output:
                for name in ("postgres.dump", "private.tar"):
                    output.add(root / name, arcname=name)
            encrypt_file(bundle, archive, key)
            with archive.open("rb") as stream:
                reference = hashlib.file_digest(stream, "sha256").hexdigest()
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


def main():
    signal.signal(signal.SIGTERM, lambda signum, frame: sys.exit(128 + signum))
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--env-file", type=Path, required=True)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--key-file", type=Path, required=True)
    for field in ("host", "database", "user"):
        parser.add_argument(f"--expected-{field}", required=True)
    args = parser.parse_args()
    compose = ["docker", "compose", "--env-file", str(args.env_file), "-f", "compose.pilot.yaml"]
    try:
        key = base64.urlsafe_b64decode(args.key_file.read_bytes().strip())
        if len(key) != 32:
            raise ValueError("Invalid backup key")
        backup(
            compose,
            args.archive,
            key,
            args.expected_host,
            args.expected_database,
            args.expected_user,
        )
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError):
        parser.exit(
            1, "Pilot backup failed; check private configuration and prior service state.\n"
        )
    print("Encrypted paired pilot backup created. Store offsite; run an isolated restore drill.")


if __name__ == "__main__":
    main()
