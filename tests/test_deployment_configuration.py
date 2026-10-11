import json
import os
import subprocess
from pathlib import Path

import pytest

from scripts.generate_secrets import generate
from scripts.smoke_safety import require_isolated_smoke

ROOT = Path(__file__).resolve().parents[1]


def compose_config(smoke=False):
    environment = dict(os.environ)
    environment.update(
        {
            "APP_IMAGE": "ssdc-app:synthetic",
            "DB_IMAGE": "ssdc-db:synthetic",
            "SCANNER_IMAGE": "ssdc-scanner:synthetic",
            "PROXY_IMAGE": "ssdc-proxy:synthetic",
            "POSTGRES_DB": "synthetic",
            "POSTGRES_USER": "synthetic_bootstrap",
            "ALLOWED_HOSTS": "localhost",
            "HEALTHCHECK_HOST": "localhost",
            "PORTAL_HOST": "localhost",
            "TLS_DIRECTORY": str(ROOT / "artifacts" / "synthetic"),
            "CSRF_TRUSTED_ORIGINS": "https://localhost",
            "GOOGLE_DRIVE_REDIRECT_URI": "https://localhost/storage/google/callback/",
        }
    )
    for name in (
        "DB_PASSWORD",
        "DB_BOOTSTRAP_PASSWORD",
        "DB_MIGRATION_PASSWORD",
        "DJANGO_KEY",
        "MFA_KEY",
        "TLS_CERT",
        "TLS_KEY",
        "GOOGLE_DRIVE_CLIENT_ID",
        "GOOGLE_DRIVE_CLIENT_SECRET",
        "GOOGLE_DRIVE_CREDENTIAL_KEY",
    ):
        environment[name + "_FILE"] = str(ROOT / "artifacts" / "synthetic" / name.lower())
    command = ["docker", "compose", "--profile", "operations", "-f", "compose.prod.yaml"]
    if smoke:
        command += ["-f", "deploy/compose.smoke.yaml"]
    result = subprocess.run(
        command + ["config", "--format", "json"],
        cwd=ROOT,
        env=environment,
        check=True,
        capture_output=True,
        text=True,
    )
    return json.loads(result.stdout)


def test_smoke_has_no_production_resources():
    production, smoke = compose_config(), compose_config(True)
    require_isolated_smoke(smoke)
    assert production["name"] != smoke["name"] == "ssdc-vault-smoke"
    for section in ("volumes", "networks"):
        production_names = {item["name"] for item in production[section].values()}
        smoke_names = {item["name"] for item in smoke[section].values()}
        assert production_names.isdisjoint(smoke_names)
        assert all(name.startswith("ssdc-vault-smoke_") for name in smoke_names)
    assert smoke["services"]["proxy"]["ports"][0]["host_ip"] == "127.0.0.1"


@pytest.mark.parametrize("section", ["volumes", "networks"])
@pytest.mark.parametrize("unsafe", ["production-name", "external", "missing-name"])
def test_smoke_refuses_shared_resources(section, unsafe):
    config = {
        "name": "ssdc-vault-smoke",
        section: {"fixture": {"name": "ssdc-vault-smoke_fixture"}},
    }
    resource = config[section]["fixture"]
    if unsafe == "production-name":
        resource["name"] = "ssdc-vault-production_fixture"
    elif unsafe == "external":
        resource["external"] = True
    else:
        resource.pop("name")
    with pytest.raises(RuntimeError, match="refuses shared"):
        require_isolated_smoke(config)


def test_smoke_refuses_production_project():
    with pytest.raises(RuntimeError, match="refuses shared"):
        require_isolated_smoke({"name": "ssdc-vault-production"})


def test_services_use_separate_credentials_and_reader_groups():
    services = compose_config()["services"]
    assert services["app"]["environment"]["POSTGRES_USER"] == "ssdc_runtime"
    assert services["migrate"]["environment"]["POSTGRES_USER"] == "ssdc_migrator"
    assert services["db"]["environment"]["POSTGRES_USER"] == "synthetic_bootstrap"
    assert services["app"]["group_add"] == ["11001"]
    app_secrets = {item["source"] for item in services["app"]["secrets"]}
    assert not {"db_bootstrap_password", "db_migration_password", "backup_key"} & app_secrets
    assert services["app"]["read_only"]
    assert services["app"]["cap_drop"] == ["ALL"]


def test_only_proxy_publishes_ports_in_production():
    services = compose_config()["services"]
    for name in ("app", "migrate", "db", "clamav"):
        assert not services[name].get("ports"), name
    assert {port["published"] for port in services["proxy"]["ports"]} == {"80", "443"}


def test_generation_keeps_backup_key_separate_and_refuses_overwrite(tmp_path):
    directory, recovery = tmp_path / "service", tmp_path / "recovery"
    generate(directory, recovery)
    assert not (directory / "backup-key").exists()
    assert (recovery / "backup-key").is_file()
    original = (directory / "db-password").read_bytes()
    assert b"\r" not in original
    with pytest.raises(ValueError, match="already exists"):
        generate(directory, recovery)
    assert (directory / "db-password").read_bytes() == original


def test_generator_rejects_shared_recovery_directory(tmp_path):
    with pytest.raises(ValueError, match="separate directory"):
        generate(tmp_path, tmp_path)
