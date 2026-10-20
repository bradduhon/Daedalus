# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0044: refuses web tools without --web, and network commands in Bash; --gh exempts gh.
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from lib import hook_io, jail, shell  # noqa: E402

TOOLS: frozenset[str] = frozenset({"Bash"} | jail.WEB_TOOLS)
FLAGS: dict[str, hook_io.Flag] = {"--web": hook_io.Flag(), "--gh": hook_io.Flag()}
PARSER = hook_io.build_parser(Path(__file__).stem, FLAGS)


def judge(hook_input: dict[str, object], flags: argparse.Namespace) -> str | None:
    web: bool = flags.web
    gh: bool = flags.gh
    if hook_io.text(hook_input, "tool_name") in jail.WEB_TOOLS:
        if web:
            return None
        return jail.R_CONDUCTOR_WEB if gh else jail.R_WEB_RESEARCHER_ONLY
    chain = shell.worker_parse(hook_io.text(hook_io.tool_input(hook_input), "command"))
    if chain is None:
        return shell.R_UNSUPPORTED
    cwd = hook_io.text(hook_input, "cwd")
    bases = shell.chain_bases(chain, cwd, jail.DIR_CHANGE_CMDS) or [cwd] * len(chain.segments)
    banned = jail.NETWORK_TOOLS - {"gh"} if gh else jail.NETWORK_TOOLS
    for segment, base in zip(chain.segments, bases, strict=True):
        if not segment:
            continue
        exempt = shell._exempt_indices(segment)
        words = {shell._base(t) for i, t in enumerate(segment) if i not in exempt}
        if banned & words:
            return jail.R_NETWORK
        # issue 55: a link or versioned path to the claude binary, by its real file.
        if shell.runs_claude(segment, base):
            return shell.R_CLAUDE_PATH
    return None


def decide(hook_input: dict[str, object], flags: list[str]) -> hook_io.HookDecision:
    return hook_io.evaluate(hook_input, flags, judge, TOOLS, PARSER)


def main() -> int:
    return hook_io.run(judge, TOOLS, PARSER)


if __name__ == "__main__":
    sys.exit(main())
