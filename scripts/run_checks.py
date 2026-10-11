"""Run checks against an automatically cleaned disposable database, without saved credentials."""

import argparse
import os
import secrets
import subprocess
import sys
import time
from pathlib import Path

import psycopg

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--junit", default="artifacts/deployment-fixes.xml")
    parser.add_argument("tests", nargs="*")
    args = parser.parse_args()
    name = "ssdc-checks-" + secrets.token_hex(6)
    password = secrets.token_urlsafe(32)
    try:
        subprocess.run(
            [
                "docker",
                "run",
                "--detach",
                "--name",
                name,
                "--cap-drop",
                "ALL",
                "--security-opt",
                "no-new-privileges:true",
                "-e",
                "POSTGRES_DB=ssdc_checks",
                "-e",
                "POSTGRES_USER=ssdc_checks",
                "-e",
                "POSTGRES_PASSWORD=" + password,
                "-p",
                "127.0.0.1::5432",
                "ssdc-postgres",
            ],
            check=True,
            capture_output=True,
        )
        port = (
            subprocess.run(
                ["docker", "port", name, "5432"], check=True, capture_output=True, text=True
            )
            .stdout.strip()
            .rsplit(":", 1)[1]
        )
        for attempt in range(60):
            try:
                with psycopg.connect(
                    host="127.0.0.1",
                    port=port,
                    dbname="ssdc_checks",
                    user="ssdc_checks",
                    password=password,
                    connect_timeout=1,
                ):
                    break
            except psycopg.OperationalError:
                if attempt == 59:
                    raise RuntimeError("Disposable test database unavailable") from None
                time.sleep(1)
        environment = dict(
            os.environ,
            APP_ENV="test",
            POSTGRES_DB="ssdc_checks",
            POSTGRES_USER="ssdc_checks",
            POSTGRES_PASSWORD=password,
            POSTGRES_HOST="127.0.0.1",
            POSTGRES_PORT=port,
            DOCUMENT_STORAGE_PROVIDER="filesystem",
            SCAN_MODE="skip-development",
        )
        for key in ("POSTGRES_PASSWORD_FILE", "SECRET_KEY_FILE", "MFA_ENCRYPTION_KEY_FILE"):
            environment.pop(key, None)
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "pytest",
                *(args.tests or ["tests"]),
                "-q",
                "--junitxml=" + args.junit,
            ],
            cwd=ROOT,
            env=environment,
        )
        return result.returncode
    finally:
        subprocess.run(
            ["docker", "rm", "--force", "--volumes", name], check=False, capture_output=True
        )


if __name__ == "__main__":
    sys.exit(main())
