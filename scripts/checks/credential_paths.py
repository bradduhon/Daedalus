# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0044, 0023: refuses a path tool or Bash command that names a credential store.
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from lib import hook_io, jail  # noqa: E402

TOOLS: frozenset[str] = frozenset(
    {"Read", "Glob", "Grep", "Write", "Edit", "MultiEdit", "NotebookEdit", "Bash"}
)
FLAGS: dict[str, hook_io.Flag] = {}
PARSER = hook_io.build_parser(Path(__file__).stem, FLAGS)


def judge(hook_input: dict[str, object], flags: argparse.Namespace) -> str | None:
    tool = hook_io.text(hook_input, "tool_name")
    cwd = hook_io.text(hook_input, "cwd")
    return jail._credential_reason(tool, hook_io.tool_input(hook_input), cwd)


def decide(hook_input: dict[str, object], flags: list[str]) -> hook_io.HookDecision:
    return hook_io.evaluate(hook_input, flags, judge, TOOLS, PARSER)


def main() -> int:
    return hook_io.run(judge, TOOLS, PARSER)


if __name__ == "__main__":
    sys.exit(main())
