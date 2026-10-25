# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0048: a coder's test command starts with the kernel wrapper whenever the doctor's probe
# finds Landlock and the seccomp filter; on any other kernel the check steps aside.
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import daedalus_confine  # noqa: E402
from lib import hook_io, jail, shell  # noqa: E402

TOOLS: frozenset[str] = frozenset({"Bash"})
FLAGS: dict[str, hook_io.Flag] = {}
PARSER = hook_io.build_parser(Path(__file__).stem, FLAGS)
R_CONFINE = (
    "a test command runs under the kernel wrapper on this machine, so its writes stay in the "
    f"unit worktree and it opens no network socket (0048). {shell.CONFINE_NEXT}"
)
R_CONFINE_UNIT = (
    "the kernel wrapper's --unit names a unit worktree of this repository, and the command runs "
    f"from inside that worktree (0048). Next: cd <your unit worktree> && {shell.CONFINE_PATH} "
    "--unit <that worktree> -- <the command>."
)


def _is_test(segment: list[str]) -> bool:
    # 0048, Plan 6 section 10.3: a test command is a segment the runner check accepts.
    tokens = shell.strip_wrappers(segment) or segment
    return shell._tester_runner_ok(shell._base(tokens[0]), tokens, lambda _: True)


def _wrapped_reason(segment: list[str], base: str, cwd: str) -> str | None:
    split = shell.confine_split(segment)
    if split is None or not shell.confine_wrapper(segment[0], base):
        return shell.R_CONFINE_FORM
    unit = split[0]
    parts = jail._unit_parts(unit, cwd) if os.path.isabs(unit) and os.path.isabs(cwd) else None
    inside = shell._under(os.path.realpath(base), os.path.realpath(unit))
    return None if parts is not None and len(parts) == 1 and inside else R_CONFINE_UNIT


def judge(hook_input: dict[str, object], flags: argparse.Namespace) -> str | None:
    if not daedalus_confine.kernel_support().ok:
        return None  # 0048: no kernel rules here; the doctor prints the OPT kernel rules line.
    chain = shell.worker_parse(hook_io.text(hook_io.tool_input(hook_input), "command"))
    if chain is None:
        return shell.R_UNSUPPORTED
    cwd = hook_io.text(hook_input, "cwd")
    bases = shell.chain_bases(chain, cwd, jail.DIR_CHANGE_CMDS) or [cwd] * len(chain.segments)
    for segment, base in zip(chain.segments, bases, strict=True):
        if not segment:
            continue
        if shell._base(segment[0]) == shell.CONFINE:
            reason = _wrapped_reason(segment, base, cwd)
        else:
            reason = R_CONFINE if _is_test(segment) else None
        if reason:
            return reason
    return None


decide, main = hook_io.entrypoint(judge, TOOLS, PARSER)

if __name__ == "__main__":
    sys.exit(main())
