# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0044, 0053: refuses a write or Bash call without an absolute cwd, and writes into .git or data.
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from lib import hook_io, jail, shell  # noqa: E402

TOOLS: frozenset[str] = frozenset(jail.WRITE_TOOLS | {"Bash"})
FLAGS: dict[str, hook_io.Flag] = {}
PARSER = hook_io.build_parser(Path(__file__).stem, FLAGS)


def judge(hook_input: dict[str, object], flags: argparse.Namespace) -> str | None:
    cwd = hook_io.text(hook_input, "cwd")
    if not os.path.isabs(cwd):
        return jail.R_NO_CWD
    if hook_io.text(hook_input, "tool_name") not in jail.WRITE_TOOLS:
        return None
    path = shell._abs(hook_io.write_path(hook_input), cwd)
    if ".git" in path.split(os.sep) or ".git" in os.path.normpath(path).split(os.sep):
        return jail.R_DOTGIT
    if jail._data_dir_path(path, cwd):
        return jail.R_DATA_DIR
    return None


def main() -> int:
    return hook_io.run(judge, TOOLS, PARSER)


if __name__ == "__main__":
    sys.exit(main())
