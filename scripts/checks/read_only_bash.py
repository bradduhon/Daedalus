# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0044: every Bash segment is a read-only command or a git read from the named grant.
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from lib import hook_io, jail, shell  # noqa: E402

TOOLS: frozenset[str] = frozenset({"Bash"})
# 0051: --test-runner is reserved for unit 3.1 and is not declared here.
FLAGS: dict[str, hook_io.Flag] = {"--git": hook_io.Flag(values=frozenset(shell.GIT_SETS))}
PARSER = hook_io.build_parser(Path(__file__).stem, FLAGS)


def _reason(grant: str | None) -> str:
    if grant == "read-only":
        return jail.R_AUDITOR_BASH
    if grant == "specialist":
        return jail.R_SPECIALIST_BASH
    subs = ", ".join(sorted(shell.GIT_SETS[grant])) if grant else ""
    reads = f"read-only inspection and git {subs}" if subs else "read-only inspection"
    return f"Bash is limited to {reads}. Next: use those only."


def judge(hook_input: dict[str, object], flags: argparse.Namespace) -> str | None:
    grant: str | None = flags.git
    cwd = hook_io.text(hook_input, "cwd")
    segments = shell.worker_segments(hook_io.text(hook_io.tool_input(hook_input), "command"))
    if segments is None:
        return shell.R_UNSUPPORTED
    subs = shell.GIT_SETS[grant] if grant else frozenset()
    charter = hook_io.hook_charter(cwd)
    if all(jail._read_only_segment(s, subs, cwd, charter) for s in segments):
        return None
    return _reason(grant)


def decide(hook_input: dict[str, object], flags: list[str]) -> hook_io.HookDecision:
    return hook_io.evaluate(hook_input, flags, judge, TOOLS, PARSER)


def main() -> int:
    return hook_io.run(judge, TOOLS, PARSER)


if __name__ == "__main__":
    sys.exit(main())
