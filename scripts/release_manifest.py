"""Record exact source/images/scans and fail the release gate on unresolved high CVEs."""

import argparse
import hashlib
import json
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


def generate_manifest(*, target, compose_filenames, env_file, project_name, output):
    output = Path(output)
    output_dir = output.parent
    output_dir.mkdir(parents=True, exist_ok=True)

    # Invalidate preexisting output and scan reports before processing
    if output.exists():
        output.unlink()
    for existing_report in output_dir.glob("*-cves.txt"):
        existing_report.unlink()

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
        raise ReleaseManifestError("A Compose input changed while the configuration was resolved")
    references = release_references(config, target)

    files = []
    for folder in ("accounts", "audit", "config", "vault", "templates", "static", "deploy"):
        files.extend(
            path
            for path in (ROOT / folder).rglob("*")
            if path.is_file() and "__pycache__" not in path.parts and "vendor" not in path.parts
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
        "images": {},
        "release_approved": False,
    }

    blocked = False
    inspections_by_ref = {}
    scans_by_image_id = {}

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

        # Deduplicate scans by image ID using invocation-specific temporary scan files
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

        # Record every service-to-image mapping and preserve completed scan evidence
        for service, reference in references.items():
            inspection = inspections_by_ref[reference]
            image_id = inspection["Id"]
            scan_returncode, scan_bytes, scan_hash = scans_by_image_id[image_id]
            report = output_dir / f"{service}-cves.txt"
            report.write_bytes(scan_bytes)

            blocked |= scan_returncode != 0
            manifest["images"][service] = {
                "reference": reference,
                "id": image_id,
                "repo_digests": inspection.get("RepoDigests", []),
                "scan_exit_code": scan_returncode,
                "scan_sha256": scan_hash,
            }
            print(
                f"{service}: "
                + (
                    "scan passed"
                    if scan_returncode == 0
                    else "release gate blocked; see scan report"
                )
            )

        manifest["container_scan_gate_passed"] = not blocked

        # Publish the completed result atomically
        temp_manifest = output_dir / f".{output.name}.tmp-{uuid.uuid4().hex}"
        temp_manifest.write_text(json.dumps(manifest, indent=2) + "\n")
        temp_manifest.replace(output)

    print("Release manifest recorded; organizational sign-off remains separate.")
    return 1 if blocked else 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", choices=TARGET_IMAGE_POLICIES, default="prod")
    parser.add_argument("--compose", action="append", default=None)
    parser.add_argument("--env-file", required=True)
    parser.add_argument("--project-name")
    parser.add_argument("--output", type=Path, default=Path("artifacts/release/manifest.json"))
    args = parser.parse_args(argv)
    return generate_manifest(
        target=args.target,
        compose_filenames=args.compose,
        env_file=args.env_file,
        project_name=args.project_name,
        output=args.output,
    )


if __name__ == "__main__":
    raise SystemExit(main())
