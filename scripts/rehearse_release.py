"""Rehearse production HTTPS, scanning and encrypted recovery using disposable resources."""

import argparse
import json
import os
import secrets
import socket
import subprocess
import sys
import time
from pathlib import Path

from smoke_safety import require_isolated_smoke

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--app-image", default="ssdc-vault-app")
    parser.add_argument("--db-image", default="ssdc-postgres")
    parser.add_argument(
        "--restore-db-image", help="Optional different image for a logical database migration drill"
    )
    parser.add_argument("--scanner-image", default="ssdc-clamav")
    parser.add_argument("--proxy-image", default="ssdc-proxy")
    parser.add_argument(
        "--signature-source-volume",
        help="Optional read-only source of public ClamAV signatures; never a document volume",
    )
    args = parser.parse_args()
    # Existing workloads remain untouched. Refuse occupied fixture ports.
    for port in (8081, 8443):
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", port))
    suffix = secrets.token_hex(6)
    project = "ssdc-vault-smoke-" + suffix
    restore_project = "ssdc-restore-" + suffix
    secret_volume = project + "-secrets"
    output = ROOT / "artifacts" / ("rehearsal-" + suffix)
    output.mkdir(parents=True, mode=0o700)
    log = (output / "rehearsal.log").open("w")
    report = {
        "project": project,
        "restore_project": restore_project,
        "passed": False,
        "source_db_image": args.db_image,
        "restored_db_image": args.restore_db_image or args.db_image,
    }
    stacks = []
    owned_volumes = []

    def run(command, *, capture=False, **kwargs):
        return subprocess.run(
            command,
            cwd=ROOT,
            check=True,
            stdout=subprocess.PIPE if capture else log,
            stderr=log,
            **kwargs,
        )

    def compose(name, env_file):
        return [
            "docker",
            "compose",
            "--project-name",
            name,
            "--env-file",
            str(env_file),
            "-f",
            str(ROOT / "compose.prod.yaml"),
            "-f",
            str(ROOT / "deploy" / "compose.smoke.yaml"),
        ]

    try:
        run(["docker", "volume", "create", secret_volume])
        owned_volumes.append(secret_volume)
        setup = """import datetime,ipaddress,runpy
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
tools=runpy.run_path('/fixture-code/generate_secrets.py')
root=Path('/fixture'); service=root/'service'; recovery=root/'recovery'
tools['generate'](service,recovery,linux=True)
for name in ('google-client-id','google-client-secret'):
 path=service/name; path.write_text('synthetic-not-a-google-credential')
 tools['set_permissions'](path,11001)
tls=root/'tls'; tls.mkdir(mode=0o700)
key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'localhost')])
now=datetime.datetime.now(datetime.UTC)
cert=(x509.CertificateBuilder().subject_name(name).issuer_name(name)
 .public_key(key.public_key()).serial_number(x509.random_serial_number())
 .not_valid_before(now-datetime.timedelta(minutes=5))
 .not_valid_after(now+datetime.timedelta(days=2))
 .add_extension(x509.SubjectAlternativeName([x509.DNSName('localhost'),
 x509.IPAddress(ipaddress.ip_address('127.0.0.1'))]),critical=False)
 .sign(key,hashes.SHA256()))
(tls/'cert.pem').write_bytes(cert.public_bytes(serialization.Encoding.PEM))
path=tls/'key.pem'
path.write_bytes(key.private_bytes(serialization.Encoding.PEM,
 serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
path.chmod(0o600)
"""
        helper = [
            "docker",
            "run",
            "--rm",
            "--network",
            "none",
            "--user",
            "0:0",
            "--mount",
            f"type=volume,source={secret_volume},target=/fixture",
        ]
        run(
            [
                *helper,
                "--mount",
                f"type=bind,source={ROOT / 'scripts'},target=/fixture-code,readonly",
                args.app_image,
                "python",
                "-c",
                setup,
            ]
        )
        mountpoint = json.loads(
            run(["docker", "volume", "inspect", secret_volume], capture=True).stdout
        )[0]["Mountpoint"]
        key_file = output / "synthetic-backup-key"
        key = run(
            [
                *helper,
                args.app_image,
                "python",
                "-c",
                "import sys; from pathlib import Path; sys.stdout.buffer.write(Path('/fixture/recovery/backup-key').read_bytes())",
            ],
            capture=True,
        ).stdout
        with os.fdopen(
            os.open(key_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb"
        ) as stream:
            stream.write(key)
        values = {
            "APP_IMAGE": args.app_image,
            "DB_IMAGE": args.db_image,
            "SCANNER_IMAGE": args.scanner_image,
            "PROXY_IMAGE": args.proxy_image,
            "SMOKE_APP_IMAGE": args.app_image,
            "SMOKE_DB_IMAGE": args.db_image,
            "SMOKE_SCANNER_IMAGE": args.scanner_image,
            "SMOKE_PROXY_IMAGE": args.proxy_image,
            "PORTAL_HOST": "localhost",
            "HTTPS_PORT": "8443",
            "TLS_DIRECTORY": mountpoint + "/tls",
            "POSTGRES_DB": "ssdc_rehearsal",
            "POSTGRES_USER": "ssdc_bootstrap",
            "ALLOWED_HOSTS": "localhost,127.0.0.1",
            "HEALTHCHECK_HOST": "localhost",
            "CSRF_TRUSTED_ORIGINS": "https://localhost:8443,https://127.0.0.1:8443",
            "GOOGLE_DRIVE_REDIRECT_URI": "https://localhost:8443/storage/google/callback/",
        }
        for name, filename in {
            "DB_PASSWORD": "db-password",
            "DB_BOOTSTRAP_PASSWORD": "db-bootstrap-password",
            "DB_MIGRATION_PASSWORD": "db-migration-password",
            "DJANGO_KEY": "django-key",
            "MFA_KEY": "mfa-key",
            "GOOGLE_DRIVE_CLIENT_ID": "google-client-id",
            "GOOGLE_DRIVE_CLIENT_SECRET": "google-client-secret",
            "GOOGLE_DRIVE_CREDENTIAL_KEY": "google-credential-key",
        }.items():
            values[name + "_FILE"] = mountpoint + "/service/" + filename
        env_file = output / "fixture.env"
        with os.fdopen(
            os.open(env_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w"
        ) as stream:
            stream.write(
                "\n".join(f"{name}={json.dumps(value)}" for name, value in values.items()) + "\n"
            )
        stack = compose(project, env_file)
        config = json.loads(run([*stack, "config", "--format", "json"], capture=True).stdout)
        require_isolated_smoke(config, project)
        stacks.append(stack)
        if args.signature_source_volume:
            destination = config["volumes"]["clam-data"]["name"]
            run(
                [
                    "docker",
                    "volume",
                    "create",
                    "--label",
                    f"com.docker.compose.project={project}",
                    "--label",
                    "com.docker.compose.volume=clam-data",
                    destination,
                ]
            )
            owned_volumes.append(destination)
            run(
                [
                    "docker",
                    "run",
                    "--rm",
                    "--network",
                    "none",
                    "--user",
                    "0:0",
                    "--mount",
                    f"type=volume,source={args.signature_source_volume},target=/source,readonly",
                    "--mount",
                    f"type=volume,source={destination},target=/destination",
                    args.app_image,
                    "sh",
                    "-ec",
                    "cp -a /source/. /destination/; chown -R 100:101 /destination",
                ]
            )
        print("Starting isolated production database and scanner", flush=True)
        run([*stack, "up", "-d", "--wait", "--wait-timeout", "600", "db", "clamav"])
        run([*stack, "run", "--rm", "--no-deps", "-T", "migrate"])
        run(
            [
                *stack,
                "run",
                "--rm",
                "--no-deps",
                "-T",
                "migrate",
                "python",
                "manage.py",
                "configure_runtime_role",
            ]
        )
        run([*stack, "up", "-d", "--wait", "--wait-timeout", "120", "app", "proxy"])
        fixture = output / "synthetic-account.json"
        print("Checking real HTTPS, MFA, scanning, PDF rendering and ranges", flush=True)
        run(
            [
                sys.executable,
                "scripts/production_smoke.py",
                "--env-file",
                str(env_file),
                "--project-name",
                project,
                "--retain-fixture",
                str(fixture),
            ]
        )
        archive = output / "paired.ssdcbackup"
        backup_args = [
            "--project-name",
            project,
            "--env-file",
            str(env_file),
            "--compose",
            "compose.prod.yaml",
            "--compose",
            "deploy/compose.smoke.yaml",
            "--key-file",
            str(key_file),
            "--archive",
            str(archive),
        ]
        print("Creating encrypted paired backup and performing restore drill", flush=True)
        run([sys.executable, "scripts/backup.py", "backup", *backup_args])
        run([sys.executable, "scripts/backup.py", "drill", *backup_args])
        # Stop only this disposable stack so the recovered stack can use the fixture ports.
        run([*stack, "stop", "proxy", "app", "clamav"])
        recovery_values = {
            **values,
            "DB_IMAGE": args.restore_db_image or args.db_image,
            "SMOKE_DB_IMAGE": args.restore_db_image or args.db_image,
        }
        recovery_env = output / "recovery.env"
        with os.fdopen(
            os.open(recovery_env, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w"
        ) as stream:
            stream.write(
                "\n".join(f"{name}={json.dumps(value)}" for name, value in recovery_values.items())
                + "\n"
            )
        recovered = compose(restore_project, recovery_env)
        recovery_config = json.loads(
            run([*recovered, "config", "--format", "json"], capture=True).stdout
        )
        if recovery_config["name"] != restore_project or any(
            resource.get("external")
            or not resource.get("name", "").startswith(restore_project + "_")
            for section in ("volumes", "networks")
            for resource in recovery_config.get(section, {}).values()
        ):
            raise RuntimeError("Recovered fixture refuses shared resources")
        stacks.append(recovered)
        # The second stack needs the same public signatures, not another
        # concurrent engine or a duplicate download during the recovery drill.
        destination = recovery_config["volumes"]["clam-data"]["name"]
        run(
            [
                "docker",
                "volume",
                "create",
                "--label",
                f"com.docker.compose.project={restore_project}",
                "--label",
                "com.docker.compose.volume=clam-data",
                destination,
            ]
        )
        owned_volumes.append(destination)
        run(
            [
                "docker",
                "run",
                "--rm",
                "--network",
                "none",
                "--user",
                "0:0",
                "--mount",
                f"type=volume,source={config['volumes']['clam-data']['name']},target=/source,readonly",
                "--mount",
                f"type=volume,source={destination},target=/destination",
                args.app_image,
                "sh",
                "-ec",
                "cp -a /source/. /destination/; chown -R 100:101 /destination",
            ]
        )
        run([*recovered, "up", "-d", "--wait", "db"])
        restore_args = ["--project-name", restore_project, *backup_args[2:]]
        restore_args[3] = str(recovery_env)
        print("Restoring into a second empty database and storage volume", flush=True)
        run([sys.executable, "scripts/backup.py", "restore", *restore_args])
        # Readiness needs a real scanner. Only the synthetic fixture uses a provider switch.
        run([*recovered, "up", "-d", "--wait", "--wait-timeout", "600", "clamav", "app", "proxy"])
        time.sleep(31 - time.time() % 30)
        run([sys.executable, "scripts/check_restored_portal.py", "--fixture", str(fixture)])
        report["passed"] = True
        print("Production rehearsal passed, including restored MFA and document access", flush=True)
    finally:
        for stack in reversed(stacks):
            subprocess.run([*stack, "logs", "--no-color"], stdout=log, stderr=log, cwd=ROOT)
            subprocess.run(
                [*stack, "down", "--volumes", "--remove-orphans"], stdout=log, stderr=log, cwd=ROOT
            )
        for volume in reversed(owned_volumes):
            subprocess.run(["docker", "volume", "rm", volume], stdout=log, stderr=log)
        (output / "result.json").write_text(json.dumps(report, indent=2) + "\n")
        log.close()
        print(f"Evidence: {output}", flush=True)


if __name__ == "__main__":
    main()
