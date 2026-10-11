"""Generate private secrets with explicit Linux service reader groups."""

import argparse
import os
import secrets
from pathlib import Path

from cryptography.fernet import Fernet

SECRET_GROUPS = {
    "django-key": 11001,
    "db-password": 11001,
    "db-bootstrap-password": 11002,
    "db-migration-password": 11003,
    "mfa-key": 11001,
    "google-client-id": 11001,
    "google-client-secret": 11001,
    "google-credential-key": 11001,
}


def set_permissions(path, gid=None):
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"Secret must be a regular, non-symlink file: {path.name}")
    if gid is not None:
        os.chown(path, -1, gid)
    os.chmod(path, 0o640 if gid is not None else 0o600)


def generate(directory, recovery_directory, linux=False):
    if linux and (os.name != "posix" or os.geteuid() != 0):
        raise ValueError("--linux requires root on the deployment host to set numeric groups")
    if directory.resolve() == recovery_directory.resolve():
        raise ValueError("Recovery keys require a separate directory outside service mounts")
    for folder in (directory, recovery_directory):
        folder.mkdir(parents=True, exist_ok=True, mode=0o700)
    values = {
        "django-key": secrets.token_urlsafe(64),
        "db-password": secrets.token_urlsafe(32),
        "db-bootstrap-password": secrets.token_urlsafe(32),
        "db-migration-password": secrets.token_urlsafe(32),
        "mfa-key": Fernet.generate_key().decode(),
        "google-credential-key": Fernet.generate_key().decode(),
        "backup-key": Fernet.generate_key().decode(),
    }
    paths = [(recovery_directory if name == "backup-key" else directory) / name for name in values]
    if any(path.exists() or path.is_symlink() for path in paths):
        raise ValueError("A generated secret already exists; no files were changed")
    # mkdir's mode only applies to new directories. Operators may have already
    # created these paths (and Docker volumes start at 0755).
    for folder in (directory, recovery_directory):
        os.chmod(folder, 0o700)
    for (name, value), path in zip(values.items(), paths, strict=True):
        with os.fdopen(
            os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w", newline="\n"
        ) as stream:
            stream.write(value + "\n")
        set_permissions(path, SECRET_GROUPS.get(name) if linux else None)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, default=Path("secrets"))
    parser.add_argument("--recovery-directory", type=Path, default=Path("recovery-secrets"))
    parser.add_argument("--linux", action="store_true")
    parser.add_argument("--permissions-only", action="store_true")
    args = parser.parse_args()
    try:
        if args.permissions_only:
            if not args.linux or os.name != "posix" or os.geteuid() != 0:
                raise ValueError("--permissions-only requires --linux and root")
            for name, gid in SECRET_GROUPS.items():
                path = args.directory / name
                if path.exists():
                    set_permissions(path, gid)
        else:
            generate(args.directory, args.recovery_directory, args.linux)
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    print("Secret files prepared. Keep recovery keys separately; no secret values printed.")


if __name__ == "__main__":
    main()
