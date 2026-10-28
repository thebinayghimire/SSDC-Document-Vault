import os
import shutil
import subprocess
from pathlib import Path

import pytest

from tests.test_production_hardening import production_settings


def test_render_cannot_start_with_development_security_settings():
    result = production_settings(RENDER="true", APP_ENV="development")
    assert result.returncode != 0
    assert "Render requires APP_ENV=production" in result.stderr


@pytest.mark.parametrize("environment", ["test", "invalid"])
def test_render_cannot_hide_an_unsafe_environment(environment):
    result = production_settings(RENDER="true", APP_ENV=environment)
    assert result.returncode != 0


def test_unique_smoke_projects_are_explicit_and_cannot_share_volumes():
    from scripts.smoke_safety import require_isolated_smoke

    project = "ssdc-vault-smoke-abcdef123456"
    config = {"name": project, "volumes": {"db": {"name": project + "_db"}}}
    require_isolated_smoke(config, project)
    with pytest.raises(RuntimeError):
        require_isolated_smoke(config)
    config["volumes"]["db"]["name"] = "ssdc-vault_db-data"
    with pytest.raises(RuntimeError):
        require_isolated_smoke(config, project)


@pytest.mark.skipif(not shutil.which("sh"), reason="POSIX shell required")
def test_database_image_refuses_unverified_existing_volume_without_changing_it(tmp_path):
    (tmp_path / "PG_VERSION").write_text("17\n")
    sentinel = tmp_path / "existing-data"
    sentinel.write_bytes(b"preserve this database")
    script = Path(__file__).resolve().parents[1] / "deploy" / "database-entrypoint.sh"
    result = subprocess.run(
        ["sh", str(script), "postgres"],
        env={**os.environ, "PGDATA": str(tmp_path)},
        capture_output=True,
        text=True,
    )
    assert result.returncode == 1
    assert "logical dump/restore" in result.stderr
    assert sentinel.read_bytes() == b"preserve this database"
    assert not (tmp_path / ".ssdc-runtime-family").exists()
