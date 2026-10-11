"""Check smoke/production coexistence using only disposable Compose projects."""

import json
import os
import secrets
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main():
    prefix = "ssdc-isolation-check-" + secrets.token_hex(6)
    projects = [prefix + "-production", prefix + "-smoke"]
    environment = dict(os.environ)
    commands = []

    def run(command):
        return subprocess.run(
            command, cwd=ROOT, env=environment, check=True, capture_output=True, text=True
        ).stdout.strip()

    with tempfile.TemporaryDirectory(prefix=prefix) as temporary:
        directory = Path(temporary)
        password = directory / "synthetic-password"
        password.write_text(secrets.token_urlsafe(32), encoding="utf-8")
        # No app/proxy/scanner is started; these values only allow full config
        # resolution. Never load a deployment env file or use its credentials.
        environment.update(
            APP_IMAGE="ssdc-vault-app",
            DB_IMAGE="ssdc-postgres",
            SCANNER_IMAGE="ssdc-clamav",
            PROXY_IMAGE="ssdc-proxy",
            POSTGRES_DB="ssdc_isolation",
            POSTGRES_USER="ssdc_isolation",
            ALLOWED_HOSTS="localhost",
            HEALTHCHECK_HOST="localhost",
            PORTAL_HOST="localhost",
            TLS_DIRECTORY=str(directory),
            CSRF_TRUSTED_ORIGINS="https://localhost",
            GOOGLE_DRIVE_REDIRECT_URI="https://localhost/storage/google/callback/",
        )
        for key in (
            "DB_PASSWORD",
            "DB_BOOTSTRAP_PASSWORD",
            "DB_MIGRATION_PASSWORD",
            "DJANGO_KEY",
            "MFA_KEY",
            "GOOGLE_DRIVE_CLIENT_ID",
            "GOOGLE_DRIVE_CLIENT_SECRET",
            "GOOGLE_DRIVE_CREDENTIAL_KEY",
        ):
            environment[key + "_FILE"] = str(password)
        try:
            configs = []
            for project, smoke in zip(projects, (False, True), strict=True):
                command = [
                    "docker",
                    "compose",
                    "--project-name",
                    project,
                    "-f",
                    "compose.prod.yaml",
                ]
                if smoke:
                    command += ["-f", "deploy/compose.smoke.yaml"]
                config = json.loads(run(command + ["config", "--format", "json"]))
                assert config["name"] == project
                for section in ("volumes", "networks"):
                    assert all(
                        item["name"].startswith(project + "_") and not item.get("external")
                        for item in config[section].values()
                    )
                configs.append(config)
                commands.append(command)
            for section in ("volumes", "networks"):
                assert {item["name"] for item in configs[0][section].values()}.isdisjoint(
                    {item["name"] for item in configs[1][section].values()}
                )
            production, smoke = commands
            run(production + ["up", "-d", "--no-build", "--wait", "--wait-timeout", "90", "db"])
            sql = [
                "exec",
                "-T",
                "db",
                "psql",
                "-U",
                "ssdc_isolation",
                "-d",
                "ssdc_isolation",
                "-Atc",
            ]
            run(
                production
                + sql
                + [
                    "CREATE TABLE isolation_marker(value text); INSERT INTO isolation_marker VALUES ('production-preserved')"
                ]
            )
            run(
                production
                + [
                    "exec",
                    "-T",
                    "db",
                    "sh",
                    "-ec",
                    "printf production-preserved > /var/lib/postgresql/data/isolation-marker",
                ]
            )
            container = run(production + ["ps", "-q", "db"])
            before = json.loads(run(["docker", "inspect", container]))[0]["State"]["StartedAt"]
            run(smoke + ["up", "-d", "--no-build", "--wait", "--wait-timeout", "90", "db"])
            assert (
                run(smoke + sql + ["SELECT to_regclass('public.isolation_marker') IS NULL"]) == "t"
            )
            run(
                smoke
                + sql
                + [
                    "CREATE TABLE isolation_marker(value text); INSERT INTO isolation_marker VALUES ('smoke-only')"
                ]
            )
            run(smoke + ["down", "--volumes"])
            assert run(production + ["ps", "-q", "db"]) == container
            assert (
                json.loads(run(["docker", "inspect", container]))[0]["State"]["StartedAt"] == before
            )
            assert (
                run(production + sql + ["SELECT value FROM isolation_marker"])
                == "production-preserved"
            )
            assert (
                run(
                    production
                    + ["exec", "-T", "db", "cat", "/var/lib/postgresql/data/isolation-marker"]
                )
                == "production-preserved"
            )
            print(
                "Compose isolation passed: distinct volume/network names; concurrent databases; smoke creation, writes and teardown preserved the other container, start time, SQL and files."
            )
        finally:
            for command in reversed(commands):
                subprocess.run(
                    command + ["down", "--volumes"],
                    cwd=ROOT,
                    env=environment,
                    check=False,
                    capture_output=True,
                )


if __name__ == "__main__":
    main()
