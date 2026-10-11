"""Record exact source/images/scans and fail the release gate on unresolved high CVEs."""

import argparse
import hashlib
import json
import subprocess
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--compose", action="append", default=None)
    parser.add_argument("--env-file", required=True)
    parser.add_argument("--project-name")
    parser.add_argument("--output", type=Path, default=Path("artifacts/release/manifest.json"))
    args = parser.parse_args()
    compose = ["docker", "compose", "--env-file", args.env_file]
    if args.project_name:
        compose += ["--project-name", args.project_name]
    for filename in args.compose or ["compose.prod.yaml"]:
        compose += ["-f", filename]
    config = json.loads(
        subprocess.run(
            compose + ["config", "--format", "json"], check=True, capture_output=True
        ).stdout
    )
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
            "compose.prod.yaml",
        )
    )
    manifest = {
        "generated_utc": datetime.now(UTC).isoformat(),
        "source_commit": subprocess.run(
            ["git", "rev-parse", "HEAD"], check=True, capture_output=True, text=True
        ).stdout.strip(),
        "source_dirty": bool(
            subprocess.run(["git", "status", "--porcelain"], check=True, capture_output=True).stdout
        ),
        "source_sha256": {
            path.relative_to(ROOT).as_posix(): digest(path) for path in sorted(set(files))
        },
        "images": {},
        "release_approved": False,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    blocked = False
    for service in ("app", "db", "proxy", "clamav"):
        reference = config["services"][service]["image"]
        inspection = json.loads(
            subprocess.run(
                ["docker", "image", "inspect", reference], check=True, capture_output=True
            ).stdout
        )[0]
        report = args.output.parent / (service + "-cves.txt")
        with report.open("wb") as output:
            scan = subprocess.run(
                [
                    "docker",
                    "scout",
                    "cves",
                    "--only-severity",
                    "critical,high",
                    "--exit-code",
                    "local://" + inspection["Id"],
                ],
                stdout=output,
                stderr=subprocess.STDOUT,
            )
        blocked |= scan.returncode != 0
        manifest["images"][service] = {
            "reference": reference,
            "id": inspection["Id"],
            "repo_digests": inspection.get("RepoDigests", []),
            "scan_exit_code": scan.returncode,
            "scan_sha256": digest(report),
        }
        print(
            service
            + ": "
            + ("scan passed" if scan.returncode == 0 else "release gate blocked; see scan report")
        )
    manifest["container_scan_gate_passed"] = not blocked
    args.output.write_text(json.dumps(manifest, indent=2) + "\n")
    print("Release manifest recorded; organizational sign-off remains separate.")
    return 1 if blocked else 0


if __name__ == "__main__":
    raise SystemExit(main())
