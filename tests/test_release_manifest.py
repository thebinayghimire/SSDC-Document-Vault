import hashlib
import json
import subprocess
from pathlib import Path

import pytest

from scripts import release_manifest

ROOT = Path(__file__).resolve().parents[1]


def target_config(target, missing=None, extra_services=None, overridden_images=None):
    overridden_images = overridden_images or {}
    services = {
        service: {
            "image": overridden_images.get(
                service, f"registry.example/{target}-{service}@sha256:synthetic-{service}"
            )
        }
        for service in release_manifest.TARGET_IMAGE_POLICIES[target]["required_services"]
        if service != missing
    }
    if extra_services:
        services.update(extra_services)
    return {"services": services}


_real_subprocess_run = subprocess.run


def subprocess_runner(
    config,
    *,
    inspect_failure=False,
    scan_exit_code=0,
    scanner_launch_failure=False,
    calls=None,
    use_actual_compose=False,
):
    calls = calls if calls is not None else []

    def run(command, **kwargs):
        calls.append(command)
        if command[:2] == ["docker", "compose"]:
            if use_actual_compose:
                return _real_subprocess_run(command, **kwargs)
            return subprocess.CompletedProcess(command, 0, stdout=json.dumps(config).encode())
        if command[:3] == ["git", "rev-parse", "HEAD"]:
            return subprocess.CompletedProcess(command, 0, stdout="a" * 40 + "\n")
        if command[:3] == ["git", "status", "--porcelain"]:
            return subprocess.CompletedProcess(command, 0, stdout=b"")
        if command[:3] == ["docker", "image", "inspect"]:
            if inspect_failure:
                raise subprocess.CalledProcessError(1, command)
            reference = command[-1]
            image_id = "sha256:" + hashlib.sha256(reference.encode()).hexdigest()[:16]
            result = [{"Id": image_id, "RepoDigests": [reference]}]
            return subprocess.CompletedProcess(command, 0, stdout=json.dumps(result).encode())
        if command[:3] == ["docker", "scout", "cves"]:
            if scanner_launch_failure:
                raise OSError("Scanner binary not found")
            kwargs["stdout"].write(b"synthetic scan output for " + command[-1].encode() + b"\n")
            return subprocess.CompletedProcess(command, scan_exit_code)
        raise AssertionError(f"Unexpected subprocess: {command}")

    return run


@pytest.mark.parametrize(
    ("target", "expected_services"),
    [
        ("prod", {"app", "migrate", "db", "proxy", "clamav"}),
        ("pilot", {"app", "migrate", "proxy", "clamav", "dbtools"}),
        ("oracle", {"app", "migrate", "db", "proxy"}),
    ],
)
def test_release_manifest_applies_explicit_target_image_policy(
    tmp_path, monkeypatch, target, expected_services
):
    calls = []
    cfg = target_config(target)
    monkeypatch.setattr(
        release_manifest.subprocess,
        "run",
        subprocess_runner(cfg, calls=calls),
    )
    output = tmp_path / target / "manifest.json"

    result = release_manifest.generate_manifest(
        target=target,
        compose_filenames=None,
        env_file="synthetic.env",
        project_name=None,
        output=output,
    )

    assert result == 0
    manifest = json.loads(output.read_text())
    assert manifest["target"] == target
    assert set(manifest["images"]) == expected_services
    assert set(manifest["image_policy"]) == expected_services
    assert manifest["container_scan_gate_passed"] is True
    assert manifest["release_approved"] is False
    inspected = {command[-1] for command in calls if command[:3] == ["docker", "image", "inspect"]}
    assert inspected == {cfg["services"][service]["image"] for service in expected_services}


def test_release_manifest_hashes_every_selected_compose_input(tmp_path, monkeypatch):
    first = tmp_path / "compose.base.yaml"
    second = tmp_path / "compose.overlay.yaml"
    first.write_text("services: {}\n")
    second.write_text("services: {}\n")
    calls = []
    monkeypatch.setattr(
        release_manifest.subprocess,
        "run",
        subprocess_runner(target_config("prod"), calls=calls),
    )
    output = tmp_path / "release" / "manifest.json"

    assert (
        release_manifest.generate_manifest(
            target="prod",
            compose_filenames=[str(first), str(second)],
            env_file="synthetic.env",
            project_name="synthetic",
            output=output,
        )
        == 0
    )

    manifest = json.loads(output.read_text())
    assert manifest["compose_inputs"] == [
        {"path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
        for path in (first, second)
    ]
    compose_call = next(command for command in calls if command[:2] == ["docker", "compose"])
    assert compose_call.count("-f") == 2
    assert str(first.resolve()) in compose_call and str(second.resolve()) in compose_call


@pytest.mark.parametrize("reference", [None, ""])
def test_release_manifest_rejects_missing_required_image_reference(reference):
    config = target_config("pilot")
    if reference is None:
        config["services"].pop("dbtools")
    else:
        config["services"]["dbtools"]["image"] = reference
    with pytest.raises(release_manifest.ReleaseManifestError, match="requires service dbtools"):
        release_manifest.release_references(config, "pilot")


def test_release_manifest_fails_closed_when_image_inspection_fails(tmp_path, monkeypatch):
    monkeypatch.setattr(
        release_manifest.subprocess,
        "run",
        subprocess_runner(target_config("oracle"), inspect_failure=True),
    )
    output = tmp_path / "manifest.json"
    with pytest.raises(subprocess.CalledProcessError):
        release_manifest.generate_manifest(
            target="oracle",
            compose_filenames=None,
            env_file="synthetic.env",
            project_name=None,
            output=output,
        )
    assert not output.exists()


def test_release_manifest_records_and_blocks_scan_failure(tmp_path, monkeypatch):
    monkeypatch.setattr(
        release_manifest.subprocess,
        "run",
        subprocess_runner(target_config("prod"), scan_exit_code=2),
    )
    output = tmp_path / "manifest.json"
    result = release_manifest.generate_manifest(
        target="prod",
        compose_filenames=None,
        env_file="synthetic.env",
        project_name=None,
        output=output,
    )

    assert result == 1
    manifest = json.loads(output.read_text())
    assert manifest["container_scan_gate_passed"] is False
    assert {image["scan_exit_code"] for image in manifest["images"].values()} == {2}


def test_release_manifest_overridden_migrate_image(tmp_path, monkeypatch):
    calls = []
    config = target_config(
        "prod",
        overridden_images={
            "app": "registry.example/app:v1",
            "migrate": "registry.example/custom-migrator:v2",
        },
    )
    monkeypatch.setattr(
        release_manifest.subprocess,
        "run",
        subprocess_runner(config, calls=calls),
    )
    output = tmp_path / "manifest.json"
    result = release_manifest.generate_manifest(
        target="prod",
        compose_filenames=None,
        env_file="synthetic.env",
        project_name=None,
        output=output,
    )

    assert result == 0
    manifest = json.loads(output.read_text())
    assert manifest["images"]["app"]["reference"] == "registry.example/app:v1"
    assert manifest["images"]["migrate"]["reference"] == "registry.example/custom-migrator:v2"
    assert manifest["images"]["app"]["id"] != manifest["images"]["migrate"]["id"]
    inspected = [command[-1] for command in calls if command[:3] == ["docker", "image", "inspect"]]
    assert "registry.example/app:v1" in inspected
    assert "registry.example/custom-migrator:v2" in inspected
    scanned = [command[-1] for command in calls if command[:3] == ["docker", "scout", "cves"]]
    assert "local://" + manifest["images"]["app"]["id"] in scanned
    assert "local://" + manifest["images"]["migrate"]["id"] in scanned


def test_release_manifest_overlay_added_sidecar(tmp_path, monkeypatch):
    calls = []
    config = target_config(
        "prod",
        extra_services={
            "metrics-sidecar": {"image": "registry.example/sidecar:latest"},
        },
    )
    monkeypatch.setattr(
        release_manifest.subprocess,
        "run",
        subprocess_runner(config, calls=calls),
    )
    output = tmp_path / "manifest.json"
    result = release_manifest.generate_manifest(
        target="prod",
        compose_filenames=None,
        env_file="synthetic.env",
        project_name=None,
        output=output,
    )

    assert result == 0
    manifest = json.loads(output.read_text())
    assert "metrics-sidecar" in manifest["images"]
    assert manifest["images"]["metrics-sidecar"]["reference"] == "registry.example/sidecar:latest"
    assert (tmp_path / "metrics-sidecar-cves.txt").exists()


def test_release_manifest_deduplicates_identical_images(tmp_path, monkeypatch):
    calls = []
    shared_image = "registry.example/shared-app-and-migrate@sha256:1111"
    config = target_config(
        "prod",
        overridden_images={
            "app": shared_image,
            "migrate": shared_image,
        },
    )
    monkeypatch.setattr(
        release_manifest.subprocess,
        "run",
        subprocess_runner(config, calls=calls),
    )
    output = tmp_path / "manifest.json"
    result = release_manifest.generate_manifest(
        target="prod",
        compose_filenames=None,
        env_file="synthetic.env",
        project_name=None,
        output=output,
    )

    assert result == 0
    manifest = json.loads(output.read_text())
    # Both services are recorded in the manifest mapping
    assert "app" in manifest["images"]
    assert "migrate" in manifest["images"]
    assert manifest["images"]["app"]["id"] == manifest["images"]["migrate"]["id"]
    # Inspection and scan were executed only once for the shared image
    inspect_calls = [
        command[-1]
        for command in calls
        if command[:3] == ["docker", "image", "inspect"] and command[-1] == shared_image
    ]
    assert len(inspect_calls) == 1
    shared_id = manifest["images"]["app"]["id"]
    scan_calls = [
        command[-1]
        for command in calls
        if command[:3] == ["docker", "scout", "cves"] and command[-1] == "local://" + shared_id
    ]
    assert len(scan_calls) == 1
    # Both service reports exist
    assert (tmp_path / "app-cves.txt").exists()
    assert (tmp_path / "migrate-cves.txt").exists()


def test_release_manifest_resolves_all_declared_profiles(tmp_path, monkeypatch):
    calls = []
    config = target_config("pilot")
    monkeypatch.setattr(
        release_manifest.subprocess,
        "run",
        subprocess_runner(config, calls=calls),
    )
    output = tmp_path / "manifest.json"
    release_manifest.generate_manifest(
        target="pilot",
        compose_filenames=None,
        env_file="synthetic.env",
        project_name=None,
        output=output,
    )
    compose_call = next(command for command in calls if command[:2] == ["docker", "compose"])
    assert "--profile" in compose_call
    profile_idx = compose_call.index("--profile")
    assert compose_call[profile_idx + 1] == "*"


def test_release_manifest_stale_artifacts_lifecycle(tmp_path, monkeypatch):
    output = tmp_path / "manifest.json"
    stale_report = tmp_path / "app-cves.txt"

    # Helper to set up preexisting successful state
    def setup_preexisting():
        output.write_text(json.dumps({"stale": True, "container_scan_gate_passed": True}))
        stale_report.write_bytes(b"stale scan report from previous run")

    # 1. Configuration failure: preexisting manifest and scan files must be invalidated
    setup_preexisting()
    bad_config = target_config("prod")
    bad_config["services"].pop("app")  # missing required service
    monkeypatch.setattr(
        release_manifest.subprocess,
        "run",
        subprocess_runner(bad_config),
    )
    with pytest.raises(release_manifest.ReleaseManifestError):
        release_manifest.generate_manifest(
            target="prod",
            compose_filenames=None,
            env_file="synthetic.env",
            project_name=None,
            output=output,
        )
    assert not output.exists()
    assert not stale_report.exists()

    # 2. Inspection failure: preexisting manifest must be invalidated
    setup_preexisting()
    monkeypatch.setattr(
        release_manifest.subprocess,
        "run",
        subprocess_runner(target_config("prod"), inspect_failure=True),
    )
    with pytest.raises(subprocess.CalledProcessError):
        release_manifest.generate_manifest(
            target="prod",
            compose_filenames=None,
            env_file="synthetic.env",
            project_name=None,
            output=output,
        )
    assert not output.exists()
    assert not stale_report.exists()

    # 3. Scanner-launch failure: preexisting manifest must be invalidated
    setup_preexisting()
    monkeypatch.setattr(
        release_manifest.subprocess,
        "run",
        subprocess_runner(target_config("prod"), scanner_launch_failure=True),
    )
    with pytest.raises(OSError, match="Scanner binary not found"):
        release_manifest.generate_manifest(
            target="prod",
            compose_filenames=None,
            env_file="synthetic.env",
            project_name=None,
            output=output,
        )
    assert not output.exists()
    assert not stale_report.exists()

    # 4. Completed scan with blocked gate preserves evidence and updates manifest
    setup_preexisting()
    monkeypatch.setattr(
        release_manifest.subprocess,
        "run",
        subprocess_runner(target_config("prod"), scan_exit_code=1),
    )
    result = release_manifest.generate_manifest(
        target="prod",
        compose_filenames=None,
        env_file="synthetic.env",
        project_name=None,
        output=output,
    )
    assert result == 1
    assert output.exists()
    manifest = json.loads(output.read_text())
    assert manifest["container_scan_gate_passed"] is False
    assert (tmp_path / "app-cves.txt").exists()
    assert (tmp_path / "app-cves.txt").read_bytes() != b"stale scan report from previous run"


@pytest.mark.parametrize("target", ["prod", "pilot", "oracle"])
def test_release_manifest_actual_compose_resolution_with_synthetic_env(
    tmp_path, monkeypatch, target
):
    env_file = tmp_path / "synthetic.env"
    env_file.write_text(
        """APP_IMAGE=ssdc-app:synthetic
DB_IMAGE=ssdc-db:synthetic
SCANNER_IMAGE=ssdc-scanner:synthetic
PROXY_IMAGE=ssdc-proxy:synthetic
POSTGRES_DB=synthetic
POSTGRES_USER=synthetic_bootstrap
ALLOWED_HOSTS=localhost
HEALTHCHECK_HOST=localhost
PORTAL_HOST=localhost
TLS_DIRECTORY=.
CSRF_TRUSTED_ORIGINS=https://localhost
GOOGLE_DRIVE_REDIRECT_URI=https://localhost/storage/google/callback/
POSTGRES_HOST=synthetic.pooler.supabase.com
POSTGRES_MIGRATION_USER=ssdc_migrator.synthetic
POSTGRES_SSLROOTCERT_FILE=./root.crt
DB_PASSWORD_FILE=./db_pass
DB_BOOTSTRAP_PASSWORD_FILE=./db_boot
DB_MIGRATION_PASSWORD_FILE=./db_mig
DJANGO_KEY_FILE=./dj_key
MFA_KEY_FILE=./mfa_key
GOOGLE_DRIVE_CLIENT_ID_FILE=./g_id
GOOGLE_DRIVE_CLIENT_SECRET_FILE=./g_sec
GOOGLE_DRIVE_CREDENTIAL_KEY_FILE=./g_key
"""
    )
    calls = []
    monkeypatch.setattr(
        release_manifest.subprocess,
        "run",
        subprocess_runner(None, calls=calls, use_actual_compose=True),
    )
    output = tmp_path / f"manifest-{target}.json"
    result = release_manifest.generate_manifest(
        target=target,
        compose_filenames=None,
        env_file=str(env_file),
        project_name=None,
        output=output,
    )
    assert result == 0
    manifest = json.loads(output.read_text())
    expected_required = set(release_manifest.TARGET_IMAGE_POLICIES[target]["required_services"])
    assert expected_required.issubset(set(manifest["images"].keys()))
    # Verify profile-gated migrate is resolved in actual compose
    assert "migrate" in manifest["images"]
    if target == "pilot":
        assert "dbtools" in manifest["images"]
