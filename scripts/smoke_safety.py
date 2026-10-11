"""Validate resolved Compose resources before creating synthetic smoke data."""


def require_isolated_smoke(config):
    if config.get("name") != "ssdc-vault-smoke" or any(
        not item.get("name", "").startswith("ssdc-vault-smoke_") or item.get("external")
        for section in ("volumes", "networks")
        for item in config.get(section, {}).values()
    ):
        raise RuntimeError("Synthetic smoke refuses shared or production projects/volumes/networks")
