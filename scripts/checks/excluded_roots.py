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

from lib import hook_io, jail, writer_mode  # noqa: E402

TOOLS: frozenset[str] = frozenset({"Bash"})
FLAGS: dict[str, hook_io.Flag] = {}
PARSER = hook_io.build_parser(Path(__file__).stem, FLAGS)
# D.5, 0190: the comparer and a derived writer write outputs under a root; their redirects pass.
REDIRECT_WRITERS = frozenset({"comparer"})


def _redirects_pass(hook_input: dict[str, object]) -> bool:
    agent = hook_io.agent(hook_input)
    if agent == writer_mode.WRITER:
        return writer_mode.bound_kind(hook_input) == writer_mode.DERIVED
    return agent in REDIRECT_WRITERS


def judge(hook_input: dict[str, object], flags: argparse.Namespace) -> str | None:
    cwd = hook_io.text(hook_input, "cwd")
    if not os.path.isabs(cwd):
        return jail.R_NO_CWD
    command = hook_io.text(hook_io.tool_input(hook_input), "command")
    roots = jail.excluded_roots_for(cwd, lambda: hook_io.hook_config(cwd))
    writes = not _redirects_pass(hook_input)
    return jail.excluded_root_reason(command, cwd, roots, writes)


decide, main = hook_io.entrypoint(judge, TOOLS, PARSER)

if __name__ == "__main__":
    sys.exit(main())
