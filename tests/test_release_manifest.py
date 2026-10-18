import concurrent.futures
import hashlib
import json
import subprocess
import threading
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
    fail_scan_on_call=None,
    calls=None,
    use_actual_compose=False,
):
    calls = calls if calls is not None else []
    scan_count = [0]

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
            scan_count[0] += 1
            if scanner_launch_failure:
                raise OSError("Scanner binary not found")
            if fail_scan_on_call is not None and scan_count[0] == fail_scan_on_call:
                raise OSError(f"Scanner binary failed on scan call #{scan_count[0]}")
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
    assert manifest["invocation_completed"] is True
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
    assert manifest["invocation_completed"] is True
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
    assert (output.parent / manifest["images"]["metrics-sidecar"]["report_path"]).exists()


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
    assert (output.parent / manifest["images"]["app"]["report_path"]).exists()
    assert (output.parent / manifest["images"]["migrate"]["report_path"]).exists()


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


def test_release_manifest_invocation_specific_artifact_ownership(tmp_path, monkeypatch):
    foreign_report = tmp_path / "unrelated-tool-cves.txt"
    foreign_report.write_bytes(b"foreign report that must not be deleted")
    monkeypatch.setattr(
        release_manifest.subprocess,
        "run",
        subprocess_runner(target_config("prod")),
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
    assert foreign_report.exists()
    assert foreign_report.read_bytes() == b"foreign report that must not be deleted"


def test_release_manifest_rejects_concurrent_runs_on_same_output(tmp_path, monkeypatch):
    output = tmp_path / "manifest.json"
    lock_file = tmp_path / ".manifest.json.lock"
    lock_file.write_text("99999\n")
    monkeypatch.setattr(
        release_manifest.subprocess,
        "run",
        subprocess_runner(target_config("prod")),
    )
    with pytest.raises(
        release_manifest.ReleaseManifestError, match="Concurrent run detected"
    ) as exc_info:
        release_manifest.generate_manifest(
            target="prod",
            compose_filenames=None,
            env_file="synthetic.env",
            project_name=None,
            output=output,
        )
    err_msg = str(exc_info.value)
    assert str(lock_file) in err_msg
    assert "99999" in err_msg
    assert "stale lock" in err_msg
    assert "delete the lock file" in err_msg
    # Ensure rejected invocation cannot remove the existing lock
    assert lock_file.exists()
    assert lock_file.read_text().strip() == "99999"


def test_release_manifest_preserves_completed_evidence_when_later_scanner_launch_fails(
    tmp_path, monkeypatch
):
    calls = []
    config = target_config(
        "prod",
        overridden_images={
            "app": "registry.example/app:v1",
            "migrate": "registry.example/migrate:v2",
        },
    )
    monkeypatch.setattr(
        release_manifest.subprocess,
        "run",
        subprocess_runner(config, fail_scan_on_call=2, calls=calls),
    )
    output = tmp_path / "manifest.json"
    with pytest.raises(OSError, match="Scanner binary failed on scan call #2"):
        release_manifest.generate_manifest(
            target="prod",
            compose_filenames=None,
            env_file="synthetic.env",
            project_name=None,
            output=output,
        )

    # 1. Output exists and is clearly marked incomplete
    assert output.exists()
    manifest = json.loads(output.read_text())
    assert manifest["invocation_completed"] is False
    assert manifest["container_scan_gate_passed"] is False
    assert "Scanner failed on service" in manifest.get("failure_reason", "")

    # 2. Completed scan evidence from the first successful scan is preserved in evidence directory
    first_service = next(
        service
        for service, info in manifest["images"].items()
        if info.get("scan_exit_code") is not None
    )
    first_report = output.parent / manifest["images"][first_service]["report_path"]
    assert first_report.exists()
    assert b"synthetic scan output" in first_report.read_bytes()


def test_release_manifest_stale_artifacts_lifecycle(tmp_path, monkeypatch):
    output = tmp_path / "manifest.json"
    stale_report = tmp_path / "app-cves.txt"

    # Helper to set up preexisting successful state
    def setup_preexisting():
        output.write_text(
            json.dumps(
                {
                    "stale": True,
                    "container_scan_gate_passed": True,
                    "invocation_completed": True,
                }
            )
        )
        stale_report.write_bytes(b"stale scan report from previous run")

    # 1. Configuration failure: preexisting manifest must be invalidated
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

    # 3. Scanner-launch failure on first service: preexisting manifest must be invalidated
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
    assert manifest["invocation_completed"] is True
    app_report = output.parent / manifest["images"]["app"]["report_path"]
    assert app_report.exists()
    assert b"synthetic scan output" in app_report.read_bytes()


def test_release_manifest_two_outputs_same_directory_sequential(tmp_path, monkeypatch):
    monkeypatch.setattr(
        release_manifest.subprocess,
        "run",
        subprocess_runner(target_config("prod")),
    )
    output1 = tmp_path / "manifest-1.json"
    output2 = tmp_path / "manifest-2.json"

    res1 = release_manifest.generate_manifest(
        target="prod",
        compose_filenames=None,
        env_file="synthetic.env",
        project_name=None,
        output=output1,
    )
    res2 = release_manifest.generate_manifest(
        target="prod",
        compose_filenames=None,
        env_file="synthetic.env",
        project_name=None,
        output=output2,
    )

    assert res1 == 0
    assert res2 == 0
    assert output1.exists()
    assert output2.exists()

    manifest1 = json.loads(output1.read_text())
    manifest2 = json.loads(output2.read_text())

    assert manifest1["evidence_directory"] != manifest2["evidence_directory"]

    for service, info in manifest1["images"].items():
        report_path = output1.parent / info["report_path"]
        assert report_path.exists()
        assert hashlib.sha256(report_path.read_bytes()).hexdigest() == info["scan_sha256"]

    for service, info in manifest2["images"].items():
        report_path = output2.parent / info["report_path"]
        assert report_path.exists()
        assert hashlib.sha256(report_path.read_bytes()).hexdigest() == info["scan_sha256"]


def test_release_manifest_two_outputs_same_directory_overlapping(tmp_path, monkeypatch):
    output_a = tmp_path / "manifest-a.json"
    output_b = tmp_path / "manifest-b.json"

    barrier = threading.Barrier(2)
    base_runner = subprocess_runner(target_config("prod"))

    def overlapping_runner(command, **kwargs):
        if command[:3] == ["docker", "scout", "cves"]:
            try:
                barrier.wait(timeout=5)
            except threading.BrokenBarrierError:
                pass
        return base_runner(command, **kwargs)

    monkeypatch.setattr(release_manifest.subprocess, "run", overlapping_runner)

    def run_gen(out):
        return release_manifest.generate_manifest(
            target="prod",
            compose_filenames=None,
            env_file="synthetic.env",
            project_name=None,
            output=out,
        )

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        f_a = executor.submit(run_gen, output_a)
        f_b = executor.submit(run_gen, output_b)
        assert f_a.result() == 0
        assert f_b.result() == 0

    assert output_a.exists()
    assert output_b.exists()

    manifest_a = json.loads(output_a.read_text())
    manifest_b = json.loads(output_b.read_text())

    assert manifest_a["evidence_directory"] != manifest_b["evidence_directory"]

    for service, info in manifest_a["images"].items():
        report_path = output_a.parent / info["report_path"]
        assert report_path.exists()
        assert hashlib.sha256(report_path.read_bytes()).hexdigest() == info["scan_sha256"]

    for service, info in manifest_b["images"].items():
        report_path = output_b.parent / info["report_path"]
        assert report_path.exists()
        assert hashlib.sha256(report_path.read_bytes()).hexdigest() == info["scan_sha256"]


def test_release_manifest_failed_second_run_preserves_first_run_manifest_and_evidence(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(
        release_manifest.subprocess,
        "run",
        subprocess_runner(target_config("prod")),
    )
    output1 = tmp_path / "manifest-first.json"
    result1 = release_manifest.generate_manifest(
        target="prod",
        compose_filenames=None,
        env_file="synthetic.env",
        project_name=None,
        output=output1,
    )
    assert result1 == 0
    manifest1_bytes = output1.read_bytes()
    manifest1 = json.loads(manifest1_bytes)
    evidence_reports = {
        service: (tmp_path / info["report_path"]).read_bytes()
        for service, info in manifest1["images"].items()
    }

    # Second run targeting a different manifest in the same directory fails during scanner launch
    monkeypatch.setattr(
        release_manifest.subprocess,
        "run",
        subprocess_runner(target_config("prod"), scanner_launch_failure=True),
    )
    output2 = tmp_path / "manifest-second.json"
    with pytest.raises(OSError, match="Scanner binary not found"):
        release_manifest.generate_manifest(
            target="prod",
            compose_filenames=None,
            env_file="synthetic.env",
            project_name=None,
            output=output2,
        )

    # First run's manifest and all its evidence reports are preserved intact
    assert output1.exists()
    assert output1.read_bytes() == manifest1_bytes
    for service, original_bytes in evidence_reports.items():
        report_file = tmp_path / manifest1["images"][service]["report_path"]
        assert report_file.exists()
        assert report_file.read_bytes() == original_bytes
    assert not output2.exists()


def test_release_manifest_rerun_preserves_previously_generated_evidence(tmp_path, monkeypatch):
    monkeypatch.setattr(
        release_manifest.subprocess,
        "run",
        subprocess_runner(target_config("prod")),
    )
    output = tmp_path / "manifest.json"
    result1 = release_manifest.generate_manifest(
        target="prod",
        compose_filenames=None,
        env_file="synthetic.env",
        project_name=None,
        output=output,
    )
    assert result1 == 0
    manifest1 = json.loads(output.read_text())
    ev_dir1 = tmp_path / manifest1["evidence_directory"]
    reports1 = {
        service: (tmp_path / info["report_path"]).read_bytes()
        for service, info in manifest1["images"].items()
    }
    assert ev_dir1.exists()

    # Rerun the exact same output filename
    result2 = release_manifest.generate_manifest(
        target="prod",
        compose_filenames=None,
        env_file="synthetic.env",
        project_name=None,
        output=output,
    )
    assert result2 == 0
    manifest2 = json.loads(output.read_text())
    ev_dir2 = tmp_path / manifest2["evidence_directory"]
    assert ev_dir1 != ev_dir2
    assert ev_dir2.exists()

    # Previously generated evidence in ev_dir1 is preserved
    assert ev_dir1.exists()
    for service, original_bytes in reports1.items():
        report_file = tmp_path / manifest1["images"][service]["report_path"]
        assert report_file.exists()
        assert report_file.read_bytes() == original_bytes


def test_release_manifest_report_hash_verification_fails_closed(tmp_path, monkeypatch):
    monkeypatch.setattr(
        release_manifest.subprocess,
        "run",
        subprocess_runner(target_config("prod")),
    )
    real_write_bytes = Path.write_bytes
    corrupted = [False]

    def fake_write_bytes(self, data):
        # Tamper with the report file written into evidence_dir
        if self.name.endswith("-cves.txt") and not corrupted[0]:
            corrupted[0] = True
            return real_write_bytes(self, b"corrupted payload")
        return real_write_bytes(self, data)

    monkeypatch.setattr(Path, "write_bytes", fake_write_bytes)

    output = tmp_path / "manifest.json"
    with pytest.raises(
        release_manifest.ReleaseManifestError, match="Evidence report hash mismatch"
    ):
        release_manifest.generate_manifest(
            target="prod",
            compose_filenames=None,
            env_file="synthetic.env",
            project_name=None,
            output=output,
        )

    # Manifest must fail closed and NOT be published
    assert not output.exists()


def test_release_manifest_rejects_compose_input_change_during_resolution(tmp_path, monkeypatch):
    compose_file = tmp_path / "docker-compose.yml"
    compose_file.write_text("services: {}\n")

    def run_with_mutation(command, **kwargs):
        if command[:2] == ["docker", "compose"]:
            compose_file.write_text("services: {tampered: true}\n")
            cfg = target_config("prod")
            return subprocess.CompletedProcess(command, 0, stdout=json.dumps(cfg).encode())
        if command[:3] == ["docker", "image", "inspect"]:
            return subprocess.CompletedProcess(
                command, 0, stdout=json.dumps([{"Id": "sha256:1", "RepoDigests": []}]).encode()
            )
        if command[:3] == ["docker", "scout", "cves"]:
            kwargs["stdout"].write(b"scan")
            return subprocess.CompletedProcess(command, 0)
        raise AssertionError(f"Unexpected: {command}")

    monkeypatch.setattr(release_manifest.subprocess, "run", run_with_mutation)
    output = tmp_path / "manifest.json"
    with pytest.raises(
        release_manifest.ReleaseManifestError,
        match="A Compose input changed while the configuration was resolved",
    ):
        release_manifest.generate_manifest(
            target="prod",
            compose_filenames=[str(compose_file)],
            env_file="synthetic.env",
            project_name=None,
            output=output,
        )
    assert not output.exists()


def test_release_manifest_reuses_verified_digest_snapshot_for_source_and_compose_inputs(
    tmp_path, monkeypatch
):
    compose_file = tmp_path / "docker-compose.yml"
    compose_file.write_text("services: {}\n")
    monkeypatch.setattr(
        release_manifest.subprocess,
        "run",
        subprocess_runner(target_config("prod")),
    )
    output = tmp_path / "manifest.json"
    result = release_manifest.generate_manifest(
        target="prod",
        compose_filenames=[str(compose_file)],
        env_file="synthetic.env",
        project_name=None,
        output=output,
    )
    assert result == 0
    manifest = json.loads(output.read_text())
    compose_entry = next(
        item for item in manifest["compose_inputs"] if item["path"] == str(compose_file)
    )
    source_label = release_manifest.source_label(compose_file.resolve())
    assert manifest["source_sha256"][source_label] == compose_entry["sha256"]


def test_release_manifest_rejects_output_or_evidence_within_source_directories(
    tmp_path, monkeypatch
):
    output_in_source = release_manifest.ROOT / "accounts" / "manifest.json"
    with pytest.raises(
        release_manifest.ReleaseManifestError,
        match="Output path cannot be within source directory 'accounts'",
    ):
        release_manifest.generate_manifest(
            target="prod",
            compose_filenames=None,
            env_file="synthetic.env",
            project_name=None,
            output=output_in_source,
        )

    evidence_in_source = release_manifest.ROOT / "vault" / "evidence-dir"
    with pytest.raises(
        release_manifest.ReleaseManifestError,
        match="Evidence directory cannot be within source directory 'vault'",
    ):
        release_manifest.generate_manifest(
            target="prod",
            compose_filenames=None,
            env_file="synthetic.env",
            project_name=None,
            output=tmp_path / "manifest.json",
            evidence_dir=evidence_in_source,
        )


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
