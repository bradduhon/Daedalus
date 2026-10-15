# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import json
import re
from typing import Any

from lib.jail import WEB_TOOLS, WORKER_DENIED_TOOLS, WRITE_TOOLS

from tests.conftest import REPO_ROOT

JAIL_SCRIPT = "scripts/enforce_agent_jail.py"
BLOCKING_EVENTS = (
    "SessionStart",
    "UserPromptSubmit",
    "SubagentStart",
    "SubagentStop",
    "Stop",
    "SessionEnd",
)

EXPECTED_EVENTS = {
    "SessionStart",
    "UserPromptSubmit",
    "PreToolUse",
    "PostToolUse",
    "PostToolUseFailure",
    "SubagentStart",
    "SubagentStop",
    "Stop",
    "SessionEnd",
}


def _load() -> dict[str, Any]:
    return json.loads((REPO_ROOT / "hooks" / "hooks.json").read_text())


def _commands(event: str) -> list[dict[str, Any]]:
    return [hook for entry in _load()["hooks"][event] for hook in entry["hooks"]]


def test_every_event_is_bound() -> None:
    assert set(_load()["hooks"]) == EXPECTED_EVENTS


def test_every_command_points_at_an_existing_python_script() -> None:
    for event in EXPECTED_EVENTS:
        for hook in _commands(event):
            assert hook["type"] == "command"
            prefix = "python3 ${CLAUDE_PLUGIN_ROOT}/"
            assert hook["command"].startswith(prefix), hook["command"]
            rel = hook["command"][len(prefix) :]
            assert (REPO_ROOT / rel).exists(), rel
            assert rel.endswith(".py")


def _jail_entries() -> list[dict[str, Any]]:
    entries = _load()["hooks"]["PreToolUse"]
    return [e for e in entries if e["hooks"][0]["command"].endswith(JAIL_SCRIPT)]


def test_pretooluse_mutating_matcher_runs_the_jail_synchronously() -> None:
    jail = _jail_entries()
    assert len(jail) == 1
    hook = jail[0]["hooks"][0]
    assert not hook.get("async", False)
    assert hook["timeout"] == 10
    reads = [e for e in _load()["hooks"]["PreToolUse"] if e.get("matcher") == "Read|Glob|Grep"]
    assert len(reads) == 1
    read_hook = reads[0]["hooks"][0]
    assert read_hook["command"].endswith("scripts/audit_log.py")
    assert read_hook["timeout"] == 10
    assert not read_hook.get("async", False)


def test_jail_matcher_covers_every_jail_policed_tool() -> None:
    matcher = _jail_entries()[0]["matcher"]
    policed = (
        WRITE_TOOLS
        | WEB_TOOLS
        | WORKER_DENIED_TOOLS
        | {"Bash", "mcp__drive__create_file", "mcp__x__y"}
    )
    for name in policed:
        assert re.fullmatch(matcher, name), name
    for name in ("TaskCreate", "Read"):
        assert not re.fullmatch(matcher, name), name


def test_jail_is_bound_under_pretooluse_only() -> None:
    for event in EXPECTED_EVENTS:
        jailed = [h for h in _commands(event) if h["command"].endswith(JAIL_SCRIPT)]
        assert bool(jailed) == (event == "PreToolUse"), event


def test_blocking_hooks_carry_a_numeric_timeout() -> None:
    for event in (*BLOCKING_EVENTS, "PreToolUse"):
        for hook in _commands(event):
            timeout = hook.get("timeout")
            assert isinstance(timeout, int | float) and not isinstance(timeout, bool), (event, hook)


def test_post_events_are_async() -> None:
    for event in ("PostToolUse", "PostToolUseFailure"):
        assert all(hook.get("async") is True for hook in _commands(event))


def test_blocking_events_are_not_async() -> None:
    for event in BLOCKING_EVENTS:
        assert all(not hook.get("async", False) for hook in _commands(event))
