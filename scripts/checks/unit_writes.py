# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0054, 0044: the coder writes anywhere in its own unit worktree except protected paths.
# The first write claims the dispatched unit (issue 29); git add and commit stay in the unit.
from __future__ import annotations

import argparse
import sys
from collections.abc import Callable
from functools import lru_cache
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from lib import dispatch_binding, hook_io, jail, shell  # noqa: E402
from lib.project_root import project_root  # noqa: E402

TOOLS: frozenset[str] = frozenset(jail.WRITE_TOOLS | {"Bash"})
FLAGS: dict[str, hook_io.Flag] = {}
PARSER = hook_io.build_parser(Path(__file__).stem, FLAGS)
Boundary = Callable[[], jail.CoderBoundary | str]


def _write_reason(hook_input: dict[str, object], cwd: str, boundary: Boundary) -> str | None:
    path = shell._abs(hook_io.write_path(hook_input), cwd)
    if not jail._in_unit_worktree(path, cwd):
        return jail.R_UNIT_OUTSIDE.format(path)
    reason = jail._coder_write_reason(path, cwd, boundary())
    if reason:
        return reason
    unit = (jail._unit_parts(shell._abs(path, cwd), cwd) or [""])[0]
    return dispatch_binding._binding_reason(hook_input, cwd, {unit})


def _followed_bases(chain: shell.WorkerChain, cwd: str) -> list[str] | None:
    # O6: a cd target is followed only inside a unit worktree of this same project.
    bases = shell.chain_bases(chain, cwd, jail.DIR_CHANGE_CMDS)
    if bases is None or bases[-1] == cwd:
        return bases
    target = bases[-1]
    same = project_root(Path(target)).resolve() == project_root(Path(cwd)).resolve()
    return bases if same and jail._unit_parts(target, cwd) is not None else None


def _bash_reason(hook_input: dict[str, object], cwd: str, boundary: Boundary) -> str | None:
    chain = shell.worker_parse(hook_io.text(hook_io.tool_input(hook_input), "command"))
    if chain is None:
        return shell.R_UNSUPPORTED
    bases = _followed_bases(chain, cwd)
    folders = bases or [cwd] * len(chain.segments)
    pairs = [(s, b) for s, b in zip(chain.segments, folders, strict=True) if s]
    moved = bases is None
    touched: set[str] = set()
    for segment, base in pairs:
        relative = jail._cd_relative_target(segment, cwd) if moved else None
        if relative is not None:
            return jail.R_CD_RELATIVE.format(relative)
        if any(t.startswith("--basetemp") for t in segment):
            return jail.R_BASETEMP
        sub = shell._git_subcommand(segment) if shell._base(segment[0]) == "git" else None
        if sub in {"add", "commit"}:
            git_dir = jail._git_dir(shell._git_split(segment)[2], base)
            if jail._unit_parts(git_dir, base) is None:
                return jail.R_CODER_UNIT_GIT
        reason = jail._coder_bash_reason(segment, base, boundary)
        if reason:
            return reason
        touched |= dispatch_binding._segment_units(segment, base)
        touched |= _script_unit(segment, base)
    return dispatch_binding._binding_reason(hook_input, cwd, touched)


def _script_unit(segment: list[str], base: str) -> set[str]:
    # B2, issue 29: a worktree script binds its unit, so a coder runs only its own unit's scripts.
    script = shell.python_script(segment)
    parts = None if script is None else jail._unit_parts(shell._abs(script, base), base)
    return {parts[0]} if parts else set()


def judge(hook_input: dict[str, object], flags: argparse.Namespace) -> str | None:
    cwd = hook_io.text(hook_input, "cwd")
    config = hook_io.hook_config(cwd)
    boundary = lru_cache(maxsize=1)(lambda: jail._coder_boundary(cwd, config))
    if hook_io.text(hook_input, "tool_name") in jail.WRITE_TOOLS:
        return _write_reason(hook_input, cwd, boundary)
    return _bash_reason(hook_input, cwd, boundary)


decide, main = hook_io.entrypoint(judge, TOOLS, PARSER)

if __name__ == "__main__":
    sys.exit(main())
