# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import json

from tests.conftest import REPO_ROOT


def test_manifest_has_required_keys() -> None:
    data = json.loads((REPO_ROOT / ".claude-plugin" / "plugin.json").read_text())
    assert data["name"] == "daedalus"
    assert data["version"] == "1.2.0"
    assert data["description"]
    assert data["author"]["name"] == "Brad Duhon"


def test_only_manifest_lives_in_dot_claude_plugin() -> None:
    entries = sorted(p.name for p in (REPO_ROOT / ".claude-plugin").iterdir())
    assert entries == ["plugin.json"]


def test_howto_exists_and_starts_with_header() -> None:
    text = (REPO_ROOT / "docs" / "howto" / "README.md").read_text()
    assert text.splitlines()[0] == (
        "<!-- Copyright (c) 2026 Brad Duhon. SPDX-License-Identifier: GPL-3.0-or-later -->"
    )
    assert "--plugin-dir" in text
