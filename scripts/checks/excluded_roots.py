# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0136, D.5: no git staging, commit, update-index or stash, gh or redirect names an excluded root.
# lib.router runs this for every routed agent after its own hooks; main meets it in lib.jail.
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from lib import hook_io, jail  # noqa: E402

TOOLS: frozenset[str] = frozenset({"Bash"})
FLAGS: dict[str, hook_io.Flag] = {}
PARSER = hook_io.build_parser(Path(__file__).stem, FLAGS)
# D.5: the two document agents write their outputs under a root, so their redirects pass here.
REDIRECT_WRITERS = frozenset({"doc-deriver", "change-logger"})


def judge(hook_input: dict[str, object], flags: argparse.Namespace) -> str | None:
    cwd = hook_io.text(hook_input, "cwd")
    if not os.path.isabs(cwd):
        return jail.R_NO_CWD
    command = hook_io.text(hook_io.tool_input(hook_input), "command")
    roots = jail.excluded_roots_for(cwd, lambda: hook_io.hook_config(cwd))
    writes = hook_io.agent(hook_input) not in REDIRECT_WRITERS
    return jail.excluded_root_reason(command, cwd, roots, writes)


decide, main = hook_io.entrypoint(judge, TOOLS, PARSER)

if __name__ == "__main__":
    sys.exit(main())
