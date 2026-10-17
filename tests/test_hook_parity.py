# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0044: each agent's hook chain decides as lib.jail.decide does; unit 1.4 deletes this file.
from __future__ import annotations

import pytest
from lib import agent_files, jail, shell
from lib.jail import KNOWN_AGENTS

from tests import test_jail
from tests.conftest import CFG, CWD, REPO_ROOT, WT
from tests.hook_chain import CHAINS, first_deny

pytestmark = pytest.mark.usefixtures("jail_fakes")
TOOLS = ("Read", "Glob", "Grep", "Write", "Edit", "MultiEdit", "NotebookEdit", "Bash")
TOOLS += ("WebFetch", "WebSearch", "Agent", "Task", "SendMessage", "mcp__x__y", "TodoWrite")
# 0044: arguments that name gh, git push or a network tool without running them.
PROBES = ["cat gh", "ls /usr/bin/git", "echo gh", "ls git", "rg 'gh pr' src"]
PROBES += ["git log -S aws", "cat aws", "git add docs/aws", "git add docs/push", "git log push"]
PROBES += ["timeout 5 gh pr merge 1", "find . -name gh", "jq .gh x", "git commit -m gh"]


def _harvest(argname: str) -> list[str]:
    # 0044: every value tests/test_jail.py parametrizes under argname, in any test or class.
    found: set[str] = set()
    for obj in vars(test_jail).values():
        members = [getattr(obj, n) for n in dir(obj)] if isinstance(obj, type) else [obj]
        for member in members:
            for mark in getattr(member, "pytestmark", []):
                names = mark.args[0] if mark.name == "parametrize" else ""
                names = [n.strip() for n in names.split(",")] if isinstance(names, str) else names
                if argname not in names:
                    continue
                for value in mark.args[1]:
                    item = value[names.index(argname)] if len(names) > 1 else value
                    if isinstance(item, str):
                        found.add(item)
    return sorted(found)


def _corpus() -> list[dict[str, object]]:
    payloads: list[dict[str, object]] = [
        {"tool_name": tool, "tool_input": {}, "cwd": CWD} for tool in TOOLS
    ]
    for command in _harvest("command") + PROBES:
        payloads.append({"tool_name": "Bash", "tool_input": {"command": command}, "cwd": CWD})
    paths = _harvest("path") + [f"{WT}/{rel}" for rel in _harvest("rel")]
    paths += [f"{CWD}/contracts/a.yaml", "/work/Charter/specs/x.md", f"{CWD}/docs/x.md"]
    for path in paths:
        for tool in ("Write", "Edit"):
            payloads.append({"tool_name": tool, "tool_input": {"file_path": path}, "cwd": CWD})
    return payloads


def _frontmatter_tools(agent: str) -> set[str]:
    raw = agent_files.frontmatter(REPO_ROOT / "agents" / f"{agent}.md").get("tools", "")
    return {t.strip() for t in raw.split(",") if t.strip()}


def _accepted_narrowing(agent: str, hook_input: dict[str, object], hook: str) -> bool:
    tool = str(hook_input["tool_name"])
    # 0039, open item 4: tool_bound refuses a tool the agent file does not list.
    if hook == "tool_bound":
        return tool not in _frontmatter_tools(agent)
    # open item 9: network_tools refuses an exact network word given as an argument.
    fields = hook_input.get("tool_input")
    command = str(fields.get("command") or "") if isinstance(fields, dict) else ""
    words = {shell._base(t) for s in shell.tokenize(command) or [] for t in s[1:]}
    return hook == "network_tools" and tool == "Bash" and bool(jail.NETWORK_TOOLS & words)


def test_hook_chain_matches_jail_for_every_known_agent() -> None:
    # 0044: a hook chain never allows what the jail refuses; it refuses more only by 0039.
    assert set(CHAINS) == KNOWN_AGENTS - {"main"}
    corpus = _corpus()
    widened: list[tuple[str, object]] = []
    narrowed: list[tuple[str, str, object, str]] = []
    for agent in sorted(CHAINS):
        for base in corpus:
            hook_input = {**base, "agent_type": agent}
            jail_allow = jail.decide(hook_input, CFG).allow
            denied = first_deny(hook_input, CFG)
            if denied is None and not jail_allow:
                widened.append((agent, hook_input["tool_input"]))
            elif denied is not None and jail_allow:
                if not _accepted_narrowing(agent, hook_input, denied[0]):
                    narrowed.append((agent, denied[0], hook_input["tool_input"], denied[1]))
    assert len(corpus) > 500
    assert not widened, "\n".join(map(str, widened))
    assert not narrowed, "\n".join(map(str, narrowed))
