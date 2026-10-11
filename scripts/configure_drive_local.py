"""Prepare local Drive secret files from a downloaded Google web OAuth client JSON."""

import argparse
import json
import os
from pathlib import Path

from cryptography.fernet import Fernet

CALLBACK = "http://127.0.0.1:8080/storage/google/callback/"
LOCAL_CALLBACKS = {CALLBACK, "http://localhost:8080/storage/google/callback/"}


def prepare(client_json, private_directory, env_file, callback=CALLBACK):
    if callback not in LOCAL_CALLBACKS:
        raise ValueError("Use a local vault callback on port 8080.")
    data = json.loads(Path(client_json).read_text(encoding="utf-8-sig"))
    client = data.get("web") if isinstance(data, dict) else None
    if not isinstance(client, dict):
        raise ValueError("Download credentials for a Web application OAuth client.")
    client_id, client_secret = client.get("client_id"), client.get("client_secret")
    if (
        not isinstance(client_id, str)
        or not client_id.endswith(".apps.googleusercontent.com")
        or not isinstance(client_secret, str)
        or not client_secret
        or any(ord(char) < 32 for char in client_id + client_secret)
    ):
        raise ValueError("The downloaded file is missing valid OAuth client credentials.")
    if callback not in client.get("redirect_uris", []):
        raise ValueError(f"Register this exact authorized redirect URI first: {callback}")
    directory = Path(private_directory).resolve()
    values = {
        "google-client-id": client_id.encode(),
        "google-client-secret": client_secret.encode(),
    }
    for name, value in values.items():
        target = directory / name
        if target.exists() and target.read_bytes() != value:
            raise ValueError(
                "Existing OAuth client differs. Replacing an installation requires review."
            )
    key_file = directory / "google-credential-key"
    if key_file.exists():
        Fernet(key_file.read_bytes())
    else:
        values[key_file.name] = Fernet.generate_key()
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    for name, value in values.items():
        target = directory / name
        if not target.exists():
            with os.fdopen(
                os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb"
            ) as stream:
                stream.write(value)
    paths = {
        "GOOGLE_DRIVE_CLIENT_ID_FILE": directory / "google-client-id",
        "GOOGLE_DRIVE_CLIENT_SECRET_FILE": directory / "google-client-secret",
        "GOOGLE_DRIVE_CREDENTIAL_KEY_FILE": key_file,
    }
    # Single-quoted dotenv values preserve spaces and prevent variable interpolation.
    lines = ["# Local Drive file paths only; credentials remain outside the repository."]
    for name, path in paths.items():
        value = path.as_posix()
        if "'" in value or "\n" in value or "\r" in value:
            raise ValueError("Choose a private directory whose path has no quotes or line breaks.")
        lines.append(f"{name}='{value}'")
    lines.append(f"GOOGLE_DRIVE_REDIRECT_URI={callback}")
    Path(env_file).write_text("\n".join(lines) + "\n", encoding="utf-8")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--client-json", type=Path, required=True)
    parser.add_argument("--redirect-uri", choices=sorted(LOCAL_CALLBACKS), default=CALLBACK)
    args = parser.parse_args()
    repository = Path(__file__).resolve().parent.parent
    try:
        prepare(
            args.client_json,
            Path.home() / ".ssdc-vault" / "google-drive",
            repository / ".env.drive.local",
            args.redirect_uri,
        )
    except (OSError, ValueError) as exc:
        # File contents and credential values never appear in diagnostics.
        parser.exit(1, f"Setup not completed: {exc}\n")
    print("Prepared .env.drive.local and private OAuth files. No credentials were printed.")
    print("The vault still needs the storage owner's Google authorization.")


if __name__ == "__main__":
    main()
