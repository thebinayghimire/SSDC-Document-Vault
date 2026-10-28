"""Validate resolved Compose resources before creating synthetic smoke data."""

import re


def require_isolated_smoke(config, expected_project="ssdc-vault-smoke"):
    if (
        not re.fullmatch(r"ssdc-vault-smoke(?:-[a-f0-9]{12})?", expected_project)
        or config.get("name") != expected_project
        or any(
            not item.get("name", "").startswith(expected_project + "_") or item.get("external")
            for section in ("volumes", "networks")
            for item in config.get(section, {}).values()
        )
    ):
        raise RuntimeError("Synthetic smoke refuses shared or production projects/volumes/networks")
