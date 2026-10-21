# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0044, 8.5: the worker shell model; unsupported constructs, tripwires, env prefix, hygiene.
from __future__ import annotations

import argparse
import os
import sys
from collections.abc import Callable
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from lib import hook_io, jail, manifest, shell  # noqa: E402
from lib.project_root import project_root  # noqa: E402

TOOLS: frozenset[str] = frozenset({"Bash"})
FLAGS: dict[str, hook_io.Flag] = {}
PARSER = hook_io.build_parser(Path(__file__).stem, FLAGS)
CODER = "repo-coder"


def _own_script(cwd: str, base: str | None) -> Callable[[str], bool]:
    # B2: the script resolves under a unit worktree; relative needs a followed working folder.
    def inside(path: str) -> bool:
        if not os.path.isabs(cwd) or (base is None and not os.path.isabs(path)):
            return False
        return jail._in_unit_worktree(shell._abs(path, base or cwd), cwd)

    return inside


def _declared(cwd: str, root: str | None = None) -> frozenset[tuple[str, ...]]:
    # B2: the manifest's stack commands; an unusable manifest declares nothing.
    if not os.path.isabs(cwd):
        return frozenset()
    root = root or os.path.realpath(str(project_root(Path(cwd))))
    loaded = jail._manifest_at(root)
    if isinstance(loaded, str):
        return frozenset()
    return shell.declared_segments(manifest.declared_commands(loaded))


def _declared_tools(cwd: str) -> frozenset[str]:
    # issue 55: the real file of each declared command's first word, anchored at the project root.
    if not os.path.isabs(cwd):
        return frozenset()
    root = os.path.realpath(str(project_root(Path(cwd))))
    return frozenset(shell.command_path(s[0], root) for s in _declared(cwd, root))


def judge(hook_input: dict[str, object], flags: argparse.Namespace) -> str | None:
    command = hook_io.text(hook_io.tool_input(hook_input), "command")
    agent = hook_io.agent(hook_input)
    chain = shell.worker_parse(command)
    if chain is None:
        return shell.R_UNSUPPORTED
    for segment in chain.tokens:
        reason = shell._segment_reason(segment, 0, main=False)
        if reason == shell._FALLBACK:
            reason = shell._regex_tripwire(command)
        if reason:
            return reason
    if not all(chain.segments):
        return shell.R_ENV
    cwd = hook_io.text(hook_input, "cwd")
    bases = shell.chain_bases(chain, cwd, jail.DIR_CHANGE_CMDS)
    tools = _declared_tools(cwd) if agent == CODER else frozenset()
    for i, segment in enumerate(chain.segments):
        words = shell._raw_words(chain.raws[i])[len(chain.tokens[i]) - len(segment) :]
        own = _own_script(cwd, bases[i] if bases else None) if agent == CODER else None
        base = bases[i] if bases else cwd
        reason = shell._worker_hygiene(segment, agent, words, own, base, tools)
        if reason and agent == CODER and tuple(segment) in _declared(cwd):
            continue
        if reason:
            return reason
    return None


decide, main = hook_io.entrypoint(judge, TOOLS, PARSER)

if __name__ == "__main__":
    sys.exit(main())
