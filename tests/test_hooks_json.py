# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from lib import agent_files
from lib.jail import CREDENTIAL_TOOLS, WEB_TOOLS, WORKER_DENIED_TOOLS, WRITE_TOOLS

from tests.conftest import REPO_ROOT

JAIL_SCRIPT = "scripts/enforce_agent_jail.py"
HANDBACK_SCRIPT = "scripts/handback_check.py"
# RCP, train 20261026-002310 pick 4: the hand-back tool's message gets the receipts check too.
HANDBACK_ENTRY = {
    "matcher": "^SubagentHandback$",
    "hooks": [
        {
            "type": "command",
            "command": "python3 ${CLAUDE_PLUGIN_ROOT}/" + HANDBACK_SCRIPT,
            "timeout": 10,
        }
    ],
}
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
    # spec 8, 0023: Read, Glob and Grep left the audit-only binding; the jail audits them.
    assert _load()["hooks"]["PreToolUse"] == [*jail, HANDBACK_ENTRY]


def test_a_failed_jail_hook_blocks_the_call() -> None:
    # pin U2 -> D9, 0122: documented minimum 2.1.295 (code.claude.com/docs/en/hooks, Command
    # hook fields, fetched 2026-10-20); this branch closes the FIFO plant side only (issue 75).
    hook = _jail_entries()[0]["hooks"][0]
    assert hook["onFailure"] == "block"
    others = [h for e in EXPECTED_EVENTS - {"PreToolUse"} for h in _commands(e)]
    assert all("onFailure" not in h for h in others)


def test_jail_matcher_covers_every_jail_policed_tool() -> None:
    matcher = _jail_entries()[0]["matcher"]
    policed = (
        WRITE_TOOLS
        | WEB_TOOLS
        | WORKER_DENIED_TOOLS
        | CREDENTIAL_TOOLS
        | {"Bash", "mcp__drive__create_file", "mcp__x__y"}
    )
    for name in policed:
        assert re.fullmatch(matcher, name), name
    for name in ("TaskCreate", "ReadX", "LS"):
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


def _frontmatter_lines(path: Path) -> list[str]:
    lines = path.read_text(encoding="utf-8").splitlines()
    if not lines or lines[0] != "---" or "---" not in lines[1:]:
        return []
    return lines[1 : lines.index("---", 1)]


def test_hooks_register_only_in_hooks_json() -> None:
    # issue 39: Claude Code runs the router alone; no other plugin file registers a hook.
    assert sorted(p.name for p in (REPO_ROOT / "hooks").iterdir()) == ["hooks.json"]
    for name in ("plugin.json", "marketplace.json"):
        doc = json.loads((REPO_ROOT / ".claude-plugin" / name).read_text(encoding="utf-8"))
        entries = [doc, *doc.get("plugins", [])]
        assert all("hooks" not in entry for entry in entries), name
    for path in sorted((REPO_ROOT / ".claude").glob("settings*.json")):
        assert "hooks" not in json.loads(path.read_text(encoding="utf-8")), path
    skills = sorted((REPO_ROOT / "skills").glob("*/SKILL.md"))
    assert skills
    for path in skills:
        assert not any(line.startswith("hooks:") for line in _frontmatter_lines(path)), path
    pre = [h["command"] for e in _load()["hooks"]["PreToolUse"] for h in e["hooks"]]
    assert pre == [
        "python3 ${CLAUDE_PLUGIN_ROOT}/" + JAIL_SCRIPT,
        "python3 ${CLAUDE_PLUGIN_ROOT}/" + HANDBACK_SCRIPT,
    ]


def test_agent_hooks_blocks_name_only_router_checks() -> None:
    # 0044, issue 39: an agent's hooks block is the router's binding of scripts/checks.
    agents = agent_files.load_all(REPO_ROOT / "agents")
    assert agents
    for agent in agents.values():
        for hook in agent.hooks:
            assert (REPO_ROOT / "scripts" / "checks" / f"{hook.script}.py").is_file(), hook


def test_subagent_stop_runs_the_audit_and_the_handback_check() -> None:
    # RCP, 0128: the hand-back receipts check binds beside the audit, synchronous with a timeout.
    assert [hook["command"] for hook in _commands("SubagentStop")] == [
        "python3 ${CLAUDE_PLUGIN_ROOT}/scripts/audit_log.py",
        "python3 ${CLAUDE_PLUGIN_ROOT}/scripts/handback_check.py",
    ]


def test_the_handback_tool_runs_the_handback_check_synchronously() -> None:
    # RCP, pick 4: the hand-back tool alone; no onFailure, so a failed check never blocks.
    entries = [e for e in _load()["hooks"]["PreToolUse"] if e["matcher"] == "^SubagentHandback$"]
    assert entries == [HANDBACK_ENTRY]
    assert re.fullmatch(HANDBACK_ENTRY["matcher"], "SubagentHandback")
    for name in ("Bash", "SubagentHandbackX", "Agent", "SubagentStop"):
        assert not re.fullmatch(HANDBACK_ENTRY["matcher"], name), name


def test_session_start_runs_only_the_audit() -> None:
    # 0037: no session start notice; the audit hook is the only SessionStart command.
    assert [hook["command"] for hook in _commands("SessionStart")] == [
        "python3 ${CLAUDE_PLUGIN_ROOT}/scripts/audit_log.py",
    ]
