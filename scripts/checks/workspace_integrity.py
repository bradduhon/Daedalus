# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0044, 0053: refuses a write or Bash call without an absolute cwd, and writes into .git or data.
# issue 75: a Bash write into the data folder (a planted FIFO among them) is refused too.
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from lib import hook_io, jail  # noqa: E402

TOOLS: frozenset[str] = frozenset(jail.WRITE_TOOLS | {"Bash"})
FLAGS: dict[str, hook_io.Flag] = {}
PARSER = hook_io.build_parser(Path(__file__).stem, FLAGS)


def judge(hook_input: dict[str, object], flags: argparse.Namespace) -> str | None:
    tool = hook_io.text(hook_input, "tool_name")
    cwd = hook_io.text(hook_input, "cwd")
    return jail.integrity_reason(tool, hook_io.tool_input(hook_input), cwd)


decide, main = hook_io.entrypoint(judge, TOOLS, PARSER)

if __name__ == "__main__":
    sys.exit(main())
