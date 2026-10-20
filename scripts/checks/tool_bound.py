# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0044, 0039: refuses a tool the agent file's tools line omits, and every meta or MCP tool.
# 0060: the orchestrator's Agent and SendMessage are the one exception.
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from lib import agent_files, hook_io, jail  # noqa: E402

TOOLS: frozenset[str] = hook_io.EVERY_TOOL
FLAGS: dict[str, hook_io.Flag] = {}
PARSER = hook_io.build_parser(Path(__file__).stem, FLAGS)
PLUGIN_ROOT = Path(__file__).resolve().parents[2]
R_NO_AGENT_FILE = (
    "agents/{agent}.md is missing, so its tools are unknown (0044). "
    "Next: add the agent file with its tools line, or start a catalog agent."
)
# 0060: only the orchestrator starts and resumes agents, and only under its dispatch gate.
ORCHESTRATOR = "orchestrator"
ORCHESTRATOR_TOOLS = frozenset({"Agent", "SendMessage"})
DISPATCH_GATE = "dispatch_gate"
R_NO_DISPATCH_GATE = (
    "agents/orchestrator.md names no dispatch_gate hook, so its Agent and SendMessage calls "
    "would run unjudged (0060). Next: restore the agent file from git."
)


def judge(hook_input: dict[str, object], flags: argparse.Namespace) -> str | None:
    tool = hook_io.text(hook_input, "tool_name")
    agent = jail.normalize_agent(str(hook_input.get("agent_type") or "main"))
    dispatcher = agent == ORCHESTRATOR and tool in ORCHESTRATOR_TOOLS
    if (tool in jail.WORKER_DENIED_TOOLS and not dispatcher) or tool.startswith("mcp__"):
        return jail.R_TOOL
    path = PLUGIN_ROOT / "agents" / f"{agent}.md"
    if not agent_files.AGENT_NAME.fullmatch(agent) or not path.is_file():
        return R_NO_AGENT_FILE.format(agent=agent)
    if dispatcher and DISPATCH_GATE not in {hook.script for hook in agent_files.load(path).hooks}:
        return R_NO_DISPATCH_GATE
    listed = agent_files.frontmatter(path).get("tools", "")
    return None if tool in {t.strip() for t in listed.split(",")} else jail.R_TOOL


def decide(hook_input: dict[str, object], flags: list[str]) -> hook_io.HookDecision:
    return hook_io.evaluate(hook_input, flags, judge, TOOLS, PARSER)


def main() -> int:
    return hook_io.run(judge, TOOLS, PARSER)


if __name__ == "__main__":
    sys.exit(main())
