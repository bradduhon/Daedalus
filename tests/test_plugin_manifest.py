# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import json

from tests.conftest import REPO_ROOT


def test_manifest_has_required_keys() -> None:
    data = json.loads((REPO_ROOT / ".claude-plugin" / "plugin.json").read_text())
    assert data["name"] == "daedalus"
    assert data["version"] == "4.0.0"
    assert data["description"]
    assert data["author"]["name"] == "Brad Duhon"


def test_only_the_two_manifests_live_in_dot_claude_plugin() -> None:
    entries = sorted(p.name for p in (REPO_ROOT / ".claude-plugin").iterdir())
    assert entries == ["marketplace.json", "plugin.json"]


def test_howto_exists_and_starts_with_header() -> None:
    text = (REPO_ROOT / "docs" / "howto" / "README.md").read_text()
    assert text.splitlines()[0] == (
        "<!-- Copyright (c) 2026 Brad Duhon. SPDX-License-Identifier: GPL-3.0-or-later -->"
    )


def test_howto_keeps_plugin_dir_in_the_developer_section() -> None:
    # 0020: --plugin-dir is a developer path; the user path is the marketplace.
    text = (REPO_ROOT / "docs" / "howto" / "README.md").read_text()
    head, found, rest = text.partition("\n## Developing Daedalus\n")
    assert found, "howto has no Developing Daedalus section"
    assert "--plugin-dir" in rest.split("\n## ", 1)[0]
    assert "--plugin-dir" not in head
    assert "/plugin install daedalus --marketplace bradduhon/Daedalus" in head


def test_readme_installs_from_the_marketplace() -> None:
    # 0020: one command from the self-hosted marketplace.
    text = (REPO_ROOT / "README.md").read_text()
    assert "/plugin install daedalus --marketplace bradduhon/Daedalus" in text
    assert "claude plugin marketplace add bradduhon/Daedalus" in text
    assert "claude plugin install daedalus@daedalus" in text
    assert "--plugin-dir" not in text
    assert "worktree.baseRef" not in text
    assert "spawn depth" not in text


def test_requirements_carry_the_reviewer_rule() -> None:
    # 0024: git and file state findings close in scripts, not skill prose.
    text = (REPO_ROOT / "docs" / "project-requirements.md").read_text()
    section = text.split("\n## Reviewing changes to Daedalus\n", 1)[1]
    assert "\n## " not in section
    assert (
        "A finding about git or file state is closed by a script change and a script test, "
        "never by a skill sentence."
    ) in section
