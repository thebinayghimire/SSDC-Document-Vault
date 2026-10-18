"""Record exact source/images/scans and fail the release gate on unresolved high CVEs."""

import argparse
import hashlib
import json
import os
import subprocess
import tempfile
import uuid
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# Every target lists each required release service that must have an image reference.
# Operational services (such as migrate and dbtools) are gated by Compose profiles
# and must be resolved and scanned alongside primary runtime services.
TARGET_IMAGE_POLICIES = {
    "prod": {
        "default_compose": ("compose.prod.yaml",),
        "required_services": {
            "app": "application runtime",
            "migrate": "database migrations",
            "db": "self-hosted database",
            "proxy": "TLS reverse proxy",
            "clamav": "malware scanner",
        },
    },
    "pilot": {
        "default_compose": ("compose.pilot.yaml",),
        "required_services": {
            "app": "application runtime",
            "migrate": "database migrations",
            "proxy": "TLS reverse proxy",
            "clamav": "malware scanner",
            "dbtools": "database backup and recovery operations",
        },
    },
    "oracle": {
        "default_compose": ("compose.oracle.yaml",),
        "required_services": {
            "app": "application runtime",
            "migrate": "database migrations",
            "db": "self-hosted database",
            "proxy": "TLS reverse proxy",
        },
    },
}
for policy in TARGET_IMAGE_POLICIES.values():
    policy["services"] = policy["required_services"]


SOURCE_DIRECTORIES = ("accounts", "audit", "config", "vault", "templates", "static", "deploy")


class ReleaseManifestError(RuntimeError):
    pass


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def resolve_compose_inputs(filenames):
    inputs = []
    for filename in filenames:
        path = Path(filename)
        if not path.is_absolute():
            path = ROOT / path
        path = path.resolve()
        if not path.is_file():
            raise ReleaseManifestError(f"Compose input does not exist: {filename}")
        inputs.append((filename, path))
    return inputs


def source_label(path):
    try:
        return path.relative_to(ROOT).as_posix()
    except ValueError:
        return path.as_posix()


def release_references(config, target):
    services = config.get("services")
    if not isinstance(services, dict):
        raise ReleaseManifestError("Resolved Compose configuration has no services mapping")
    policy = TARGET_IMAGE_POLICIES[target]
    required_services = policy.get("required_services", policy.get("services", {}))
    for service in required_services:
        definition = services.get(service)
        reference = definition.get("image") if isinstance(definition, dict) else None
        if not isinstance(reference, str) or not reference.strip():
            raise ReleaseManifestError(
                f"Target {target} requires service {service} with a resolved image reference"
            )
    references = {}
    for service, definition in services.items():
        if isinstance(definition, dict):
            reference = definition.get("image")
            if isinstance(reference, str) and reference.strip():
                references[service] = reference.strip()
    return references


def _verify_and_publish_manifest(*, manifest, output, output_dir):
    """Verify that every referenced report exists and matches its recorded hash, then publish manifest atomically."""
    for service, image_info in manifest.get("images", {}).items():
        report_rel = image_info.get("report_path") or image_info.get("scan_report_path")
        expected_hash = image_info.get("scan_sha256")
        if not report_rel or not expected_hash:
            continue
        report_path = (output_dir / report_rel).resolve()
        if not report_path.is_file():
            raise ReleaseManifestError(
                f"Evidence report missing for service '{service}' at: {report_path}"
            )
        actual_hash = hashlib.sha256(report_path.read_bytes()).hexdigest()
        if actual_hash != expected_hash:
            raise ReleaseManifestError(
                f"Evidence report hash mismatch for service '{service}': expected {expected_hash}, got {actual_hash}"
            )

    temp_manifest = output_dir / f".{output.name}.tmp-{uuid.uuid4().hex}"
    temp_manifest.write_text(json.dumps(manifest, indent=2) + "\n")
    temp_manifest.replace(output)


def generate_manifest(
    *,
    target,
    compose_filenames,
    env_file,
    project_name,
    output,
    evidence_dir=None,
):
    output = Path(output).resolve()
    output_dir = output.parent
    output_dir.mkdir(parents=True, exist_ok=True)

    if evidence_dir is not None:
        evidence_dir = Path(evidence_dir).resolve()
    else:
        invocation_id = uuid.uuid4().hex
        evidence_dir = output_dir / f"{output.stem}-evidence-{invocation_id}"

    # Reject output and evidence locations within directories included in source hashing
    for check_path, label in [(output, "Output path"), (evidence_dir, "Evidence directory")]:
        for folder in SOURCE_DIRECTORIES:
            source_folder = (ROOT / folder).resolve()
            try:
                check_path.relative_to(source_folder)
                raise ReleaseManifestError(
                    f"{label} cannot be within source directory '{folder}': {check_path}"
                )
            except ValueError:
                pass

    # Prevent concurrent runs from mixing manifests and scan reports
    lock_path = output_dir / f".{output.name}.lock"
    lock_fd = None
    acquired_lock = False
    try:
        lock_fd = os.open(str(lock_path), os.O_CREAT | os.O_EXCL | os.O_RDWR)
        acquired_lock = True
        try:
            os.write(lock_fd, f"{os.getpid()}\n".encode())
        except OSError:
            pass
    except FileExistsError:
        recorded_pid = "unknown"
        try:
            if lock_path.exists():
                content = lock_path.read_text().strip()
                if content:
                    recorded_pid = content
        except Exception:
            pass
        raise ReleaseManifestError(
            f"Concurrent run detected: output '{output}' is locked by lockfile '{lock_path}' "
            f"(recorded PID: {recorded_pid}). "
            f"An interrupted or crashed process may have left a stale lock file. "
            f"To recover manually, first verify and confirm that no process with PID {recorded_pid} "
            f"(or any other active release manifest generator) is currently running, "
            f"and then delete the lock file at '{lock_path}'."
        )

    try:
        # Invalidate preexisting output manifest before processing
        if output.exists():
            output.unlink()

        evidence_dir.mkdir(parents=True, exist_ok=True)

        policy = TARGET_IMAGE_POLICIES[target]
        selected_inputs = resolve_compose_inputs(compose_filenames or policy["default_compose"])
        selected_input_hashes = {path: digest(path) for _, path in selected_inputs}
        compose = ["docker", "compose", "--profile", "*"]
        if env_file:
            compose += ["--env-file", env_file]
        if project_name:
            compose += ["--project-name", project_name]
        for _, path in selected_inputs:
            compose += ["-f", str(path)]
        config_result = subprocess.run(
            compose + ["config", "--format", "json"],
            check=True,
            capture_output=True,
            cwd=ROOT,
        )
        config = json.loads(config_result.stdout)
        if any(digest(path) != selected_input_hashes[path] for _, path in selected_inputs):
            raise ReleaseManifestError(
                "A Compose input changed while the configuration was resolved"
            )
        references = release_references(config, target)

        files = []
        for folder in SOURCE_DIRECTORIES:
            files.extend(
                path
                for path in (ROOT / folder).rglob("*")
                if path.is_file()
                and "__pycache__" not in path.parts
                and "vendor" not in path.parts
                and not path.name.endswith(".lock")
                and not path.name.endswith("-cves.txt")
                and not path.name.startswith(".tmp-")
            )
        files.extend(
            ROOT / name
            for name in (
                "Dockerfile",
                ".dockerignore",
                "requirements.txt",
                "package-lock.json",
                "package.json",
                "manage.py",
                "pyproject.toml",
            )
        )
        files.extend(path for _, path in selected_inputs)
        commit = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
            cwd=ROOT,
        ).stdout.strip()
        dirty = subprocess.run(
            ["git", "status", "--porcelain"],
            check=True,
            capture_output=True,
            cwd=ROOT,
        ).stdout
        try:
            evidence_dir_rel = evidence_dir.relative_to(output_dir).as_posix()
        except ValueError:
            evidence_dir_rel = str(evidence_dir)

        manifest = {
            "generated_utc": datetime.now(UTC).isoformat(),
            "source_commit": commit,
            "source_dirty": bool(dirty),
            "target": target,
            "compose_inputs": [
                {"path": filename, "sha256": selected_input_hashes[path]}
                for filename, path in selected_inputs
            ],
            "source_sha256": {
                source_label(path): selected_input_hashes.get(path) or digest(path)
                for path in sorted(set(files))
            },
            "image_policy": policy.get("required_services", policy["services"]),
            "evidence_directory": evidence_dir_rel,
            "images": {},
            "invocation_completed": False,
            "container_scan_gate_passed": False,
            "release_approved": False,
        }

        blocked = False
        inspections_by_ref = {}
        scans_by_image_id = {}
        completed_service_reports = {}

        with tempfile.TemporaryDirectory() as temp_dir:
            temp_dir_path = Path(temp_dir)
            # Deduplicate inspection by reference
            for service, reference in references.items():
                if reference not in inspections_by_ref:
                    inspection_result = subprocess.run(
                        ["docker", "image", "inspect", reference],
                        check=True,
                        capture_output=True,
                    )
                    inspection_output = json.loads(inspection_result.stdout)
                    if (
                        not isinstance(inspection_output, list)
                        or not inspection_output
                        or not isinstance(inspection_output[0].get("Id"), str)
                        or not inspection_output[0]["Id"]
                    ):
                        raise ReleaseManifestError(f"Docker returned no image ID for {service}")
                    inspections_by_ref[reference] = inspection_output[0]

            # Run scans and deduplicate by image ID using isolated temp files
            try:
                for service, reference in references.items():
                    inspection = inspections_by_ref[reference]
                    image_id = inspection["Id"]
                    if image_id not in scans_by_image_id:
                        safe_scan_name = image_id.replace(":", "_").replace("/", "_")
                        temp_scan_file = temp_dir_path / f"scan-{safe_scan_name}.txt"
                        with temp_scan_file.open("wb") as scan_output:
                            scan = subprocess.run(
                                [
                                    "docker",
                                    "scout",
                                    "cves",
                                    "--only-severity",
                                    "critical,high",
                                    "--exit-code",
                                    "local://" + image_id,
                                ],
                                stdout=scan_output,
                                stderr=subprocess.STDOUT,
                            )
                        scan_bytes = temp_scan_file.read_bytes()
                        scan_hash = hashlib.sha256(scan_bytes).hexdigest()
                        scans_by_image_id[image_id] = (scan.returncode, scan_bytes, scan_hash)

                    scan_returncode, scan_bytes, scan_hash = scans_by_image_id[image_id]
                    # Publish completed report to unique evidence directory before manifest publication
                    report_file = evidence_dir / f"{service}-cves.txt"
                    report_file.write_bytes(scan_bytes)
                    try:
                        report_rel = report_file.relative_to(output_dir).as_posix()
                    except ValueError:
                        report_rel = str(report_file)

                    completed_service_reports[service] = {
                        "reference": reference,
                        "id": image_id,
                        "repo_digests": inspection.get("RepoDigests", []),
                        "scan_exit_code": scan_returncode,
                        "scan_sha256": scan_hash,
                        "report_path": report_rel,
                        "scan_report_path": report_rel,
                    }

                    blocked |= scan_returncode != 0
                    manifest["images"][service] = completed_service_reports[service]
            except Exception as scan_exc:
                # Preserve completed scan evidence if a later scanner launch fails,
                # while clearly marking the invocation incomplete.
                if completed_service_reports:
                    manifest["invocation_completed"] = False
                    manifest["container_scan_gate_passed"] = False
                    manifest["failure_reason"] = f"Scanner failed on service {service}: {scan_exc}"
                    _verify_and_publish_manifest(
                        manifest=manifest,
                        output=output,
                        output_dir=output_dir,
                    )
                raise scan_exc

            manifest["invocation_completed"] = True
            manifest["container_scan_gate_passed"] = not blocked

            for service in references:
                scan_returncode = manifest["images"][service]["scan_exit_code"]
                print(
                    f"{service}: "
                    + (
                        "scan passed"
                        if scan_returncode == 0
                        else "release gate blocked; see scan report"
                    )
                )

            # Verify that every referenced report exists and matches its recorded hash,
            # then publish the completed manifest atomically.
            _verify_and_publish_manifest(
                manifest=manifest,
                output=output,
                output_dir=output_dir,
            )

        print("Release manifest recorded; organizational sign-off remains separate.")
        return 1 if blocked else 0
    finally:
        if lock_fd is not None:
            try:
                os.close(lock_fd)
            except OSError:
                pass
        if acquired_lock:
            try:
                if lock_path.exists():
                    lock_path.unlink()
            except OSError:
                pass


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", choices=TARGET_IMAGE_POLICIES, default="prod")
    parser.add_argument("--compose", action="append", default=None)
    parser.add_argument("--env-file", required=True)
    parser.add_argument("--project-name")
    parser.add_argument("--output", type=Path, default=Path("artifacts/release/manifest.json"))
    parser.add_argument("--evidence-dir", type=Path, default=None)
    args = parser.parse_args(argv)
    return generate_manifest(
        target=args.target,
        compose_filenames=args.compose,
        env_file=args.env_file,
        project_name=args.project_name,
        output=args.output,
        evidence_dir=args.evidence_dir,
    )


if __name__ == "__main__":
    raise SystemExit(main())
