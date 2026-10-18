# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import json
from typing import Any

from tests.conftest import REPO_ROOT


def _load(name: str) -> dict[str, Any]:
    return json.loads((REPO_ROOT / ".claude-plugin" / name).read_text())


def test_marketplace_top_level_fields() -> None:
    data = _load("marketplace.json")
    assert data["name"] == "daedalus"
    assert data["owner"] == {"name": "Brad Duhon"}
    assert data["description"]
    assert len(data["plugins"]) == 1


def test_plugin_entry_points_at_the_repo_root() -> None:
    entry = _load("marketplace.json")["plugins"][0]
    assert entry["name"] == "daedalus"
    assert entry["source"] == "."
    assert entry["description"]
    # 0021: strict stays at its default; the entry declares no components.
    assert set(entry) == {"name", "source", "version", "description"}


def test_entry_version_mirrors_plugin_json() -> None:
    entry = _load("marketplace.json")["plugins"][0]
    assert entry["version"] == _load("plugin.json")["version"] == "3.2.0"
