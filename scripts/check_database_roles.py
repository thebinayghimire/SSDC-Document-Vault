"""Verify migrations and runtime SQL privileges in a fresh disposable PostgreSQL container."""

import os
import secrets
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import psycopg

ROOT = Path(__file__).resolve().parents[1]


def main():
    name = "ssdc-role-check-" + secrets.token_hex(6)
    bootstrap, runtime, migrator = [secrets.token_urlsafe(32) for _ in range(3)]
    with tempfile.TemporaryDirectory(prefix="ssdc-role-check-") as temporary:
        directory = Path(temporary)
        for filename, value in (("db-password", runtime), ("db-migration-password", migrator)):
            (directory / filename).write_text(value)
        arguments = [
            "docker",
            "run",
            "--detach",
            "--name",
            name,
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges:true",
            "--user",
            "999:999",
            "-e",
            "POSTGRES_DB=ssdc_check",
            "-e",
            "POSTGRES_USER=ssdc_bootstrap",
            "-e",
            "POSTGRES_PASSWORD=" + bootstrap,
            "-p",
            "127.0.0.1::5432",
            "-v",
            str(directory / "db-password") + ":/run/secrets/db_password:ro",
            "-v",
            str(directory / "db-migration-password") + ":/run/secrets/db_migration_password:ro",
            "-v",
            str(ROOT / "deploy" / "init-db.sh") + ":/docker-entrypoint-initdb.d/10-roles.sh:ro",
            "ssdc-postgres",
        ]
        try:
            subprocess.run(arguments, check=True, capture_output=True)
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
                        dbname="ssdc_check",
                        user="ssdc_migrator",
                        password=migrator,
                        connect_timeout=1,
                    ):
                        break
                except psycopg.OperationalError:
                    if attempt == 59:
                        raise RuntimeError("Disposable database did not initialize") from None
                    time.sleep(1)
            environment = dict(
                os.environ,
                APP_ENV="test",
                POSTGRES_DB="ssdc_check",
                POSTGRES_USER="ssdc_migrator",
                POSTGRES_PASSWORD=migrator,
                POSTGRES_HOST="127.0.0.1",
                POSTGRES_PORT=port,
                DOCUMENT_STORAGE_PROVIDER="filesystem",
                SCAN_MODE="skip-development",
                MFA_ENABLED="1",
                MFA_ALL_STAFF="0",
                PRIVATE_STORAGE_ROOT=str(directory / "private"),
            )
            for key in ("POSTGRES_PASSWORD_FILE", "SECRET_KEY_FILE", "MFA_ENCRYPTION_KEY_FILE"):
                environment.pop(key, None)
            for command in (["migrate", "--noinput"], ["configure_runtime_role"]):
                result = subprocess.run(
                    [sys.executable, "manage.py", *command],
                    cwd=ROOT,
                    env=environment,
                    capture_output=True,
                    text=True,
                )
                if result.returncode:
                    raise RuntimeError("Migration/grant check failed: " + result.stderr)
            # Reapplying grants must reject inherited owner privileges and object
            # ownership too: REVOKE cannot take rights away from an object's owner.
            with psycopg.connect(
                host="127.0.0.1",
                port=port,
                dbname="ssdc_check",
                user="ssdc_bootstrap",
                password=bootstrap,
                autocommit=True,
            ) as operator:
                for setup, cleanup in (
                    (
                        "GRANT ssdc_migrator TO ssdc_runtime",
                        "REVOKE ssdc_migrator FROM ssdc_runtime",
                    ),
                    (
                        "ALTER TABLE audit_event OWNER TO ssdc_runtime",
                        "ALTER TABLE audit_event OWNER TO ssdc_migrator",
                    ),
                ):
                    operator.execute(setup)
                    try:
                        result = subprocess.run(
                            [sys.executable, "manage.py", "configure_runtime_role"],
                            cwd=ROOT,
                            env=environment,
                            capture_output=True,
                            text=True,
                        )
                        assert result.returncode != 0, "Unsafe runtime role was accepted"
                        assert "Runtime role must not" in result.stderr
                    finally:
                        operator.execute(cleanup)
            # Transferring ownership can remove the prior owner's explicit ACL.
            # Restore grants after the deliberate unsafe-ownership fixture.
            subprocess.run(
                [sys.executable, "manage.py", "configure_runtime_role"],
                cwd=ROOT,
                env=environment,
                check=True,
                capture_output=True,
            )
            environment.update(POSTGRES_USER="ssdc_runtime", POSTGRES_PASSWORD=runtime)
            code = (
                "from accounts.models import User; from audit.services import record; "
                "from vault.models import Folder,FolderGrant; from vault.services import upload_document; "
                "from tests.conftest import pdf_upload; from django.test import Client,override_settings; "
                "from accounts.mfa import encrypt; import pyotp; "
                "u=User.objects.create_superuser('synthetic',password='Synthetic-Password-42'); "
                "f=Folder.objects.create(name='Synthetic'); "
                "d=upload_document(u,f,pdf_upload(),'Synthetic').document; assert d.active_version_id; "
                "record(u,'runtime_check',d.pk); "
                "staff=User.objects.create_user('synthetic.staff',password='Synthetic-Password-42'); "
                "FolderGrant.objects.create(folder=f,user=staff); "
                "seed=pyotp.random_base32(); u.mfa_secret=encrypt(seed); u.mfa_confirmed=True; "
                "u.save(update_fields=['mfa_secret','mfa_confirmed']); "
                "\nwith override_settings(ALLOWED_HOSTS=['testserver'],STORAGES={"
                "'default':{'BACKEND':'django.core.files.storage.FileSystemStorage'},"
                "'staticfiles':{'BACKEND':'django.contrib.staticfiles.storage.StaticFilesStorage'}}):\n"
                " c=Client(); r=c.post('/accounts/login/',{'staff_id':staff.username,'password':'Synthetic-Password-42'}); "
                "assert r.status_code==302; assert c.get('/').status_code==200; "
                "assert c.get(f'/documents/{d.pk}/').status_code==200; "
                "assert c.get(f'/documents/{d.pk}/content/?version={d.active_version_id}',HTTP_RANGE='bytes=0-15').status_code==206; "
                "assert c.post('/accounts/logout/').status_code==302; "
                "assert c.get('/').status_code==302; "
                "admin=Client(); r=admin.post('/accounts/login/',{'staff_id':u.username,'password':'Synthetic-Password-42'}); "
                "assert r.url=='/accounts/mfa/'; "
                "assert admin.post('/accounts/mfa/',{'code':pyotp.TOTP(seed).now()}).status_code==302; "
                "assert admin.session['mfa_verified']; assert admin.get('/admin/').status_code==200\n"
            )
            result = subprocess.run(
                [sys.executable, "manage.py", "shell", "-c", code],
                cwd=ROOT,
                env=environment,
                capture_output=True,
                text=True,
            )
            if result.returncode:
                raise RuntimeError("Runtime workflow failed: " + result.stderr)
            with psycopg.connect(
                host="127.0.0.1",
                port=port,
                dbname="ssdc_check",
                user="ssdc_runtime",
                password=runtime,
                autocommit=True,
            ) as connection:
                row = connection.execute(
                    "SELECT rolsuper,rolcreatedb,rolcreaterole,rolreplication,rolbypassrls FROM pg_roles WHERE rolname=current_user"
                ).fetchone()
                assert not any(row)
                assert not connection.execute(
                    "SELECT EXISTS (SELECT 1 FROM pg_auth_members WHERE member=current_user::regrole)"
                ).fetchone()[0]
                assert not connection.execute(
                    "SELECT EXISTS (SELECT 1 FROM pg_class WHERE relowner=current_user::regrole) "
                    "OR EXISTS (SELECT 1 FROM pg_namespace WHERE nspowner=current_user::regrole) "
                    "OR EXISTS (SELECT 1 FROM pg_database WHERE datdba=current_user::regrole)"
                ).fetchone()[0]
                assert connection.execute("SELECT count(*) FROM audit_event").fetchone()[0] > 0
                for sql in (
                    "UPDATE audit_event SET outcome='tampered'",
                    "DELETE FROM audit_event",
                    "TRUNCATE audit_event",
                    "CREATE TABLE public.forbidden(id int)",
                    "CREATE ROLE forbidden SUPERUSER",
                    "UPDATE django_migrations SET name='tampered'",
                ):
                    try:
                        connection.execute(sql)
                    except psycopg.errors.InsufficientPrivilege:
                        continue
                    raise AssertionError("Runtime privilege unexpectedly allowed: " + sql)
            print(
                "Fresh PostgreSQL checks passed: schema-owner migrations; unsafe memberships/ownership refused; runtime upload/audit, staff login/library/view/versioned range/logout and administrator MFA; audit tampering, schema writes and privileged roles denied."
            )
        finally:
            subprocess.run(
                ["docker", "rm", "--force", "--volumes", name], check=False, capture_output=True
            )


if __name__ == "__main__":
    main()
