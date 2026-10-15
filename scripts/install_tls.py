"""Install a verified Certbot certificate pair and optionally reload the production proxy."""

import argparse
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path


def openssl(*args):
    return subprocess.run(["openssl", *args], check=True, capture_output=True, timeout=30).stdout


def switch(directory, target):
    candidate = directory / ".current-next"
    if candidate.exists() or candidate.is_symlink():
        candidate.unlink()
    candidate.symlink_to(target, target_is_directory=True)
    os.replace(candidate, directory / "current")


def install(
    lineage,
    directory,
    hostname,
    reload_proxy=False,
    release=None,
    environment=None,
    compose_file="compose.prod.yaml",
):
    if not hostname or not re.fullmatch(r"[A-Za-z0-9.-]+", hostname):
        raise ValueError("Provide the canonical DNS hostname")
    lineage, directory = Path(lineage).resolve(), Path(directory).resolve()
    certificate, key = lineage / "fullchain.pem", lineage / "privkey.pem"
    # Reject an invalid, nearly expired, wrong-host, or mismatched pair before installation.
    openssl("x509", "-in", str(certificate), "-noout", "-checkhost", hostname)
    openssl("x509", "-in", str(certificate), "-noout", "-checkend", "86400")
    if openssl("x509", "-in", str(certificate), "-pubkey", "-noout") != openssl(
        "pkey", "-in", str(key), "-pubout"
    ):
        raise ValueError("Certificate and private key do not match")

    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    for name in ("cert.pem", "key.pem"):
        link = directory / name
        expected = f"current/{name}"
        if link.exists() or link.is_symlink():
            if not link.is_symlink() or os.readlink(link) != expected:
                raise ValueError("TLS directory must use the managed current/ certificate links")
        else:
            link.symlink_to(expected)
    current = directory / "current"
    if current.exists() and not current.is_symlink():
        raise ValueError("TLS current pointer must be a symbolic link")
    previous = os.readlink(current) if current.is_symlink() else None
    if reload_proxy and previous is None:
        raise ValueError("Install the initial pair without --reload-proxy before starting Nginx")

    versions = directory / "versions"
    versions.mkdir(mode=0o700, exist_ok=True)
    staged = Path(tempfile.mkdtemp(prefix="certificate-", dir=versions))
    shutil.copyfile(certificate, staged / "cert.pem")
    shutil.copyfile(key, staged / "key.pem")
    (staged / "cert.pem").chmod(0o644)
    (staged / "key.pem").chmod(0o600)
    switch(directory, f"versions/{staged.name}")

    if reload_proxy:
        release = Path(release).resolve()
        command = [
            "docker",
            "compose",
            "--project-directory",
            str(release),
            "--env-file",
            str(Path(environment).resolve()),
            "-f",
            str(release / compose_file),
            "-f",
            str(release / "deploy/compose.acme.yaml"),
            "exec",
            "-T",
            "proxy",
            "nginx",
        ]
        try:
            subprocess.run([*command, "-t"], check=True, timeout=60)
            subprocess.run([*command, "-s", "reload"], check=True, timeout=60)
        except (OSError, subprocess.SubprocessError):
            switch(directory, previous)
            # Keep the prior pair available; the operator must investigate/recheck live TLS.
            raise RuntimeError(
                "Proxy reload failed; restored the previous certificate pair"
            ) from None
    print("Certificate pair installed" + ("; proxy reload requested" if reload_proxy else ""))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lineage", default=os.environ.get("RENEWED_LINEAGE"))
    parser.add_argument("--hostname", default=os.environ.get("SSDC_PORTAL_HOST"))
    parser.add_argument("--tls-directory", default="/srv/ssdc/tls")
    parser.add_argument("--release-directory", default="/srv/ssdc/app")
    parser.add_argument("--env-file", default="/srv/ssdc/.env.production")
    parser.add_argument(
        "--compose",
        choices=["compose.prod.yaml", "compose.pilot.yaml"],
        default="compose.prod.yaml",
    )
    parser.add_argument("--reload-proxy", action="store_true")
    args = parser.parse_args()
    if not args.lineage or not args.hostname:
        parser.error("A Certbot lineage and canonical hostname are required")
    try:
        install(
            args.lineage,
            args.tls_directory,
            args.hostname,
            args.reload_proxy,
            args.release_directory,
            args.env_file,
            args.compose,
        )
    except (OSError, ValueError, subprocess.SubprocessError, RuntimeError) as exc:
        parser.exit(1, f"TLS installation failed: {exc}\n")


if __name__ == "__main__":
    main()
