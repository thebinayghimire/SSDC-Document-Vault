import json

import pytest

from scripts.configure_drive_local import CALLBACK, prepare


def client_file(tmp_path, **changes):
    client = {
        "client_id": "synthetic.apps.googleusercontent.com",
        "client_secret": "synthetic-secret",
        "redirect_uris": [CALLBACK],
    }
    client.update(changes)
    path = tmp_path / "client.json"
    path.write_text(json.dumps({"web": client}))
    return path


def test_local_setup_preserves_key_and_keeps_secrets_out_of_env(tmp_path):
    source = client_file(tmp_path)
    private = tmp_path / "Private files"
    env = tmp_path / ".env.drive.local"
    prepare(source, private, env)
    key = (private / "google-credential-key").read_bytes()
    prepare(source, private, env)
    assert (private / "google-credential-key").read_bytes() == key
    assert (private / "google-client-secret").read_text() == "synthetic-secret"
    content = env.read_text()
    assert "synthetic-secret" not in content
    assert "synthetic.apps.googleusercontent.com" not in content
    assert CALLBACK in content
    client_file(tmp_path, client_secret="different-secret")
    with pytest.raises(ValueError, match="Existing OAuth client differs"):
        prepare(source, private, env)
    assert (private / "google-client-secret").read_text() == "synthetic-secret"
    assert env.read_text() == content


@pytest.mark.parametrize(
    "changes", [{"redirect_uris": []}, {"client_id": "invalid"}, {"client_secret": "line\nbreak"}]
)
def test_invalid_client_does_not_write_credentials(tmp_path, changes):
    private = tmp_path / "Private"
    env = tmp_path / ".env.drive.local"
    with pytest.raises(ValueError):
        prepare(client_file(tmp_path, **changes), private, env)
    assert not private.exists()
    assert not env.exists()
