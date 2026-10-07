"""Generate secrets into an ignored directory without printing their values."""

import argparse
import os
import secrets
from pathlib import Path

from cryptography.fernet import Fernet

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--directory", type=Path, default=Path("secrets"))
args = parser.parse_args()
args.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
values = {
    "django-key": secrets.token_urlsafe(64),
    "db-password": secrets.token_urlsafe(32),
    "mfa-key": Fernet.generate_key().decode(),
    "backup-key": Fernet.generate_key().decode(),
}
for name, value in values.items():
    with os.fdopen(
        os.open(args.directory / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w"
    ) as stream:
        stream.write(value + "\n")
print("Generated secret files. Protect this directory and keep backup-key separately from backups.")
