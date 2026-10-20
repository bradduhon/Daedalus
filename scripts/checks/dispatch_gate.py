# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0060: the orchestrator's Agent and SendMessage calls meet the coder dispatch and plan gates.
# A resume handing a coder another unit's Worktree: line rebinds it here (0086, spec 8).
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from lib import dispatch_binding, hook_io, jail  # noqa: E402
from lib.train_scope import KNOWN_AGENTS  # noqa: E402

TOOLS: frozenset[str] = dispatch_binding.DISPATCH_TOOLS | dispatch_binding.RESUME_TOOLS
FLAGS: dict[str, hook_io.Flag] = {}
PARSER = hook_io.build_parser(Path(__file__).stem, FLAGS)
# 0001, 0060: the train never pushes, and one train runs one orchestrator.
NEVER_STARTED = frozenset({"orchestrator", "pr-train-conductor"})
R_FOREIGN_AGENT = (
    "the orchestrator starts only Daedalus catalog agents, named daedalus:<name> (0060). "
    "Next: start an agent the catalog lists, by its daedalus: name."
)
R_NEVER_STARTED = (
    "the orchestrator starts no {agent}: a Build Train never pushes and runs one orchestrator "
    "(0001, 0060). Next: return the train to the main session; the operator runs the Push Train."
)


def _start_reason(tool_input: dict[str, object]) -> str | None:
    raw = hook_io.text(tool_input, "subagent_type")
    agent = jail.normalize_agent(raw)
    if agent == raw or agent not in KNOWN_AGENTS - {"main"}:
        return R_FOREIGN_AGENT
    return R_NEVER_STARTED.format(agent=agent) if agent in NEVER_STARTED else None


def judge(hook_input: dict[str, object], flags: argparse.Namespace) -> str | None:
    tool = hook_io.text(hook_input, "tool_name")
    tool_input = hook_io.tool_input(hook_input)
    cwd = hook_io.text(hook_input, "cwd")
    if tool in dispatch_binding.RESUME_TOOLS:
        return dispatch_binding._resume_reason(tool_input, cwd)
    return _start_reason(tool_input) or dispatch_binding._dispatch_reason(tool_input, cwd)


def decide(hook_input: dict[str, object], flags: list[str]) -> hook_io.HookDecision:
    return hook_io.evaluate(hook_input, flags, judge, TOOLS, PARSER)


def main() -> int:
    return hook_io.run(judge, TOOLS, PARSER)


if __name__ == "__main__":
    sys.exit(main())
