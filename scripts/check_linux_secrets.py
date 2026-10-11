"""Check production secret permissions in disposable Linux volumes, never host secrets."""

import argparse
import io
import json
import secrets
import subprocess
import tarfile
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", default="ssdc-vault-app", help="App release image to verify")
    parser.add_argument(
        "--db-image", default="ssdc-postgres", help="Database release image to verify"
    )
    options = parser.parse_args()
    prefix = "ssdc-secret-check-" + secrets.token_hex(6)
    volumes = [prefix + "-service", prefix + "-recovery"]
    image = options.image

    def run(arguments, **options):
        return subprocess.run(["docker", *arguments], check=True, capture_output=True, **options)

    try:
        for volume in volumes:
            run(["volume", "create", volume])
        script = Path(__file__).with_name("generate_secrets.py")
        archive = io.BytesIO()
        with tarfile.open(fileobj=archive, mode="w") as tar:
            tar.add(script, arcname="generate_secrets.py")
        code = (
            "import sys,tarfile; from pathlib import Path; "
            "tarfile.open(fileobj=sys.stdin.buffer,mode='r|').extractall('/tmp',filter='data'); "
            "source=compile(open('/tmp/generate_secrets.py').read(),'/tmp/generate_secrets.py','exec'); "
            "exec(source); "
            "Path('/fixture/service/google-client-id').write_text('synthetic-client'); "
            "Path('/fixture/service/google-client-secret').write_text('synthetic-secret'); "
            "sys.argv=['generate_secrets.py','--linux','--permissions-only',"
            "'--directory','/fixture/service']; exec(source)"
        )
        run(
            [
                "run",
                "--rm",
                "-i",
                "--user",
                "0:0",
                "-v",
                volumes[0] + ":/fixture/service",
                "-v",
                volumes[1] + ":/fixture/recovery",
                image,
                "python",
                "-c",
                code,
                "--linux",
                "--directory",
                "/fixture/service",
                "--recovery-directory",
                "/fixture/recovery",
            ],
            input=archive.getvalue(),
        )
        # Docker resolves bind sources on its Linux host, even when this script
        # runs on Windows. Keep the generated directory at 0700 and mount each
        # file separately, exactly as file-backed Compose secrets are mounted.
        mountpoint = json.loads(run(["volume", "inspect", volumes[0]]).stdout)[0]["Mountpoint"]
        filenames = {
            "django-key",
            "mfa-key",
            "db-password",
            "db-bootstrap-password",
            "db-migration-password",
            "google-credential-key",
            "google-client-id",
            "google-client-secret",
        }
        metadata = (
            "import os,stat; from pathlib import Path; "
            "assert stat.S_IMODE(os.stat('/fixture/service').st_mode)==0o700; "
            "assert stat.S_IMODE(os.stat('/fixture/recovery').st_mode)==0o700; "
            "groups={'db-bootstrap-password':11002,'db-migration-password':11003}; "
            "\nfor p in Path('/fixture/service').iterdir():\n"
            " s=p.stat(); assert s.st_uid==0 and s.st_gid==groups.get(p.name,11001); "
            "assert stat.S_IMODE(s.st_mode)==0o640\n"
            "s=Path('/fixture/recovery/backup-key').stat(); "
            "assert s.st_uid==0 and stat.S_IMODE(s.st_mode)==0o600"
        )
        run(
            [
                "run",
                "--rm",
                "--user",
                "0:0",
                "--network",
                "none",
                "-v",
                volumes[0] + ":/fixture/service:ro",
                "-v",
                volumes[1] + ":/fixture/recovery:ro",
                image,
                "python",
                "-c",
                metadata,
            ]
        )
        for user, groups, expected in (
            (
                "10001:10001",
                ["11001"],
                {
                    "django-key",
                    "mfa-key",
                    "db-password",
                    "google-credential-key",
                    "google-client-id",
                    "google-client-secret",
                },
            ),
            (
                "999:999",
                ["11001", "11002", "11003"],
                {
                    "django-key",
                    "mfa-key",
                    "db-password",
                    "db-bootstrap-password",
                    "db-migration-password",
                    "google-credential-key",
                    "google-client-id",
                    "google-client-secret",
                },
            ),
            (
                "10001:10001",
                ["11001", "11003"],
                {
                    "django-key",
                    "mfa-key",
                    "db-password",
                    "db-migration-password",
                    "google-credential-key",
                    "google-client-id",
                    "google-client-secret",
                },
            ),
            ("12000:12000", [], set()),
        ):
            reads = (
                "import os; from pathlib import Path; expected="
                + repr(expected)
                + "; actual=set();\nfor path in Path('/run/secrets').iterdir():\n try: path.read_bytes(); actual.add(path.name)\n except PermissionError: pass\nassert actual == expected, (actual,expected)\nassert not Path('/run/secrets/backup-key').exists()"
            )
            args = [
                "run",
                "--rm",
                "--read-only",
                "--cap-drop",
                "ALL",
                "--security-opt",
                "no-new-privileges:true",
                "--network",
                "none",
                "--user",
                user,
            ]
            for group in groups:
                args += ["--group-add", group]
            for filename in sorted(filenames):
                args += [
                    "--mount",
                    f"type=bind,source={mountpoint}/{filename},target=/run/secrets/{filename},readonly",
                ]
            args += [image, "python", "-c", reads]
            run(args)
        # Also use the database image's actual configured user, rather than only
        # approximating that identity with Python in the app image.
        db_args = [
            "run",
            "--rm",
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges:true",
            "--network",
            "none",
            "--entrypoint",
            "/bin/sh",
        ]
        for group in ("11001", "11002", "11003"):
            db_args += ["--group-add", group]
        for filename in ("db-password", "db-bootstrap-password", "db-migration-password"):
            db_args += [
                "--mount",
                f"type=bind,source={mountpoint}/{filename},target=/run/secrets/{filename},readonly",
            ]
        db_args += [
            options.db_image,
            "-ec",
            'test "$(id -u)" = 999; for f in /run/secrets/*; do cat "$f" >/dev/null; done',
        ]
        run(db_args)
        print(
            "Linux secret checks passed: app, DB, migration reader groups; unrelated UID denied; recovery key excluded."
        )
    finally:
        for volume in volumes:
            subprocess.run(["docker", "volume", "rm", volume], check=False, capture_output=True)


if __name__ == "__main__":
    main()
