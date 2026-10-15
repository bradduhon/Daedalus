# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import json
from typing import Any

from tests.conftest import REPO_ROOT


def _load() -> dict[str, Any]:
    return json.loads((REPO_ROOT / "settings.recommended.json").read_text())


def test_spawn_depth_is_one() -> None:
    assert _load()["env"]["CLAUDE_CODE_MAX_SUBAGENT_SPAWN_DEPTH"] == "1"


def test_sandbox_enabled_with_no_escape_hatches() -> None:
    sandbox = _load()["sandbox"]
    assert sandbox["enabled"] is True
    assert sandbox.get("excludedCommands", []) == []


def test_plugin_data_is_write_denied() -> None:
    sandbox = _load()["sandbox"]
    assert "~/.claude/plugins/data" in sandbox["filesystem"]["denyWrite"]


def test_sandbox_fails_closed_when_unavailable() -> None:
    assert _load()["sandbox"]["failIfUnavailable"] is True


def test_permission_denies_are_read_rules() -> None:
    deny = _load()["permissions"]["deny"]
    assert all(entry.startswith("Read(") for entry in deny)
    assert deny == [
        "Read(~/.ssh/**)",
        "Read(~/.aws/credentials)",
        "Read(~/.gnupg/**)",
        "Read(~/.config/gh/**)",
        "Read(~/.claude/.credentials.json)",
    ]


def test_deny_read_covers_credential_stores() -> None:
    # I2: gh token store and Claude Code's own credentials join the key material paths.
    assert _load()["sandbox"]["filesystem"]["denyRead"] == [
        "~/.ssh",
        "~/.aws/credentials",
        "~/.gnupg",
        "~/.config/gh",
        "~/.claude/.credentials.json",
    ]


def test_worktrees_branch_from_head() -> None:
    # C1: coders must branch from the integration branch the main session sits on.
    assert _load()["worktree"] == {"baseRef": "head"}
