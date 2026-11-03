import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from cryptography.fernet import Fernet
from django.core.management import call_command

from accounts.models import User
from config import settings as project_settings

ROOT = Path(__file__).resolve().parents[1]


def test_public_oauth_pages_are_available_without_a_session(client):
    home = client.get("/")
    assert home.status_code == 200
    assert b"SSDC Document Vault" in home.content
    assert b"Siddhartha Social Development Centre" in home.content
    assert b'href="/privacy/"' in home.content
    assert b'href="/terms/"' in home.content

    login = client.get("/accounts/login/")
    assert b"internal document library" in login.content
    assert b'href="/privacy/"' in login.content

    privacy = client.get("/privacy/")
    assert privacy.status_code == 200
    assert b"drive.file" in privacy.content
    assert b"environment secret" in privacy.content
    assert client.get("/terms/").status_code == 200


@pytest.mark.django_db
def test_ensure_admin_is_idempotent_and_does_not_reset_password(monkeypatch):
    monkeypatch.setenv("DJANGO_SUPERUSER_USERNAME", "render-admin")
    monkeypatch.setenv("DJANGO_SUPERUSER_EMAIL", "admin@example.test")
    monkeypatch.setenv("DJANGO_SUPERUSER_PASSWORD", "Initial-Render-Password-42")
    call_command("ensure_admin")
    user = User.objects.get(username="render-admin")
    assert user.is_active and user.is_staff and user.is_superuser
    assert user.role == User.Role.ADMIN
    assert user.check_password("Initial-Render-Password-42")

    monkeypatch.setenv("DJANGO_SUPERUSER_PASSWORD", "Must-Not-Replace-Password-43")
    call_command("ensure_admin")
    user.refresh_from_db()
    assert user.check_password("Initial-Render-Password-42")
    assert not user.check_password("Must-Not-Replace-Password-43")


def test_drive_environment_secret_precedes_file_fallback(monkeypatch, tmp_path):
    key_file = tmp_path / "drive-key"
    file_key = Fernet.generate_key().decode()
    environment_key = Fernet.generate_key().decode()
    key_file.write_text(file_key)
    monkeypatch.setenv("DRIVE_TOKEN_ENCRYPTION_KEY_FILE", str(key_file))
    monkeypatch.setenv("DRIVE_TOKEN_ENCRYPTION_KEY", environment_key)
    assert (
        project_settings.drive_secret("GOOGLE_DRIVE_CREDENTIAL_KEY", "DRIVE_TOKEN_ENCRYPTION_KEY")
        == environment_key
    )


def test_database_url_uses_ssl_and_persistent_connections():
    environment = dict(os.environ)
    environment.update(
        {
            "APP_ENV": "development",
            "DEBUG": "0",
            "DATABASE_URL": "postgresql://render:password@db.example.test:5432/vault",
        }
    )
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            (
                "import json; from config import settings; "
                "print(json.dumps(settings.DATABASES['default']))"
            ),
        ],
        cwd=ROOT,
        env=environment,
        check=True,
        capture_output=True,
        text=True,
    )
    database = json.loads(result.stdout)
    assert database["ENGINE"] == "django.db.backends.postgresql"
    assert database["CONN_MAX_AGE"] == 600
    assert database["CONN_HEALTH_CHECKS"] is True
    assert database["OPTIONS"]["sslmode"] == "require"


def test_neon_unpooled_url_is_preferred_for_session_advisory_locks():
    environment = dict(os.environ)
    environment.update(
        {
            "APP_ENV": "development",
            "DEBUG": "0",
            "DATABASE_URL": "postgresql://pooled:password@pooled.example.test:5432/vault",
            "DATABASE_URL_UNPOOLED": (
                "postgresql://direct:password@direct.example.test:5432/vault"
            ),
        }
    )
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            "from config import settings; print(settings.DATABASES['default']['HOST'])",
        ],
        cwd=ROOT,
        env=environment,
        check=True,
        capture_output=True,
        text=True,
    )
    assert result.stdout.strip() == "direct.example.test"


def test_render_rejects_ephemeral_filesystem_storage():
    environment = dict(os.environ)
    environment.update(
        {
            "APP_ENV": "production",
            "RENDER": "true",
            "DOCUMENT_STORAGE_PROVIDER": "filesystem",
            "SECRET_KEY": "s" * 64,
            "MFA_ENCRYPTION_KEY": Fernet.generate_key().decode(),
            "ALLOWED_HOSTS": "vault.example.test",
            "POSTGRES_DB": "vault",
            "POSTGRES_USER": "vault",
            "POSTGRES_PASSWORD": "synthetic-password",
            "POSTGRES_HOST": "db.example.test",
            "POSTGRES_SSLMODE": "verify-full",
            "SCAN_MODE": "clamav",
            "DATABASE_URL": "",
            "DATABASE_URL_UNPOOLED": "",
        }
    )
    result = subprocess.run(
        [sys.executable, "-c", "import config.settings"],
        cwd=ROOT,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0
    assert "ephemeral" in result.stderr


def test_render_blueprint_and_build_script_cover_free_tier_requirements():
    blueprint = (ROOT / "render.yaml").read_text()
    script = (ROOT / "build.sh").read_text()
    for expected in (
        "runtime: python",
        "region: singapore",
        "plan: free",
        "DATABASE_URL",
        "DRIVE_TOKEN_ENCRYPTION_KEY",
        "ENABLE_CLAMAV",
        "gunicorn config.wsgi:application --workers 2 --threads 2 --timeout 120",
    ):
        assert expected in blueprint
    assert script.startswith("#!/usr/bin/env bash\nset -o errexit")
    assert "collectstatic --no-input" in script
    assert "migrate --no-input" in script
    assert "python manage.py ensure_admin" in script
    assert "--require-hashes" in script
    assert script.index("npm run vendor") < script.index("collectstatic")
    assert "- key: MFA_ENCRYPTION_KEY\n        sync: false" in blueprint
    assert "ACCEPT_NO_MALWARE_SCANNING" in blueprint
