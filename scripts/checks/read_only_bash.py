# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0044: every Bash segment is a read-only command or a git read from the named grant.
# 0109, spec 3.1: --test-runner adds one pytest form bound to the audit folder or a unit worktree.
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from typing import NamedTuple

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from lib import hook_io, jail, shell, train_state  # noqa: E402
from lib.audit import project_root  # noqa: E402
from lib.workspace import WORKTREES_DIR, worktree_path  # noqa: E402

TOOLS: frozenset[str] = frozenset({"Bash"})
RUNNERS = frozenset({"audit", "unit"})
FLAGS: dict[str, hook_io.Flag] = {
    "--git": hook_io.Flag(values=frozenset(shell.GIT_SETS)),
    "--test-runner": hook_io.Flag(values=RUNNERS),
}
PARSER = hook_io.build_parser(Path(__file__).stem, FLAGS)
PYTEST = ("python3", "-m", "pytest")
R_TEST_RUN = (
    "the {runner} test run is python3 -m pytest <absolute paths under {where}> -q "
    "[-p no:cacheprovider] [--rootdir {rootdir}] [-k <expr>] (0109). "
    "Next: send that form only, one path or node id per test file."
)
R_TEST_RUN_NO_TRAIN = (
    "the {runner} test run needs an active train in this repository, and none is marked (0109). "
    "Next: run tests only inside a train's audit or verify step."
)


class Bound(NamedTuple):
    roots: tuple[str, ...]
    rootdir: str


def _reason(grant: str | None) -> str:
    if grant == "read-only":
        return jail.R_AUDITOR_BASH
    if grant == "specialist":
        return jail.R_SPECIALIST_BASH
    subs = ", ".join(sorted(shell.GIT_SETS[grant])) if grant else ""
    reads = f"read-only inspection and git {subs}" if subs else "read-only inspection"
    return f"Bash is limited to {reads}. Next: use those only."


def _pytest_args(tokens: list[str]) -> list[str] | None:
    # issue 56: the arguments of a pytest run in any spelling the coder grammar admits.
    name = shell._base(tokens[0])
    if name in {"pytest", "py.test"}:
        return tokens[1:]
    if name.startswith("python") and tokens[1:3] == ["-m", "pytest"]:
        return tokens[3:]
    return None


def _bounds(runner: str, cwd: str) -> list[Bound] | None:
    # pin C4 -> C1: the audit worktree is <repo>/.claude/worktrees/<train-id>-audit.
    repo = project_root(cwd)
    train = train_state.active_train(repo)
    if train is None:
        return None
    if runner == "audit":
        tree = str(worktree_path(repo, f"{train}-audit"))
        scratch = str(repo / "docs" / ".tmp" / "daedalus" / train / "audit")
        return [Bound((scratch, f"{tree}/tests/adversarial"), tree)]
    try:
        units = train_state.units(train_state.load(repo, train))
    except train_state.TrainStateError:
        return []
    home = str(repo / WORKTREES_DIR)
    paths = [str(unit.get("path") or "") for unit in units]
    return [Bound((p,), p) for p in paths if os.path.isabs(p) and shell._under(p, home)]


def _path_ok(arg: str, roots: tuple[str, ...]) -> bool:
    # 0109: a path or node id; the file part is absolute, has no .., and resolves under a root.
    file = arg.split("::", 1)[0]
    if not os.path.isabs(file) or ".." in file.split("/"):
        return False
    return any(shell._under(file, root) for root in roots)


def _test_run_ok(tokens: list[str], bound: Bound) -> bool:
    if tuple(tokens[:3]) != PYTEST:
        return False
    args = tokens[3:]
    seen: set[str] = set()
    paths: list[str] = []
    i = 0
    while i < len(args):
        arg = args[i]
        if arg in {"-p", "--rootdir", "-k"} and arg not in seen and i + 1 < len(args):
            value = args[i + 1]
            if arg == "-p" and value != "no:cacheprovider":
                return False
            if arg == "--rootdir" and not (
                os.path.isabs(value) and os.path.realpath(value) == os.path.realpath(bound.rootdir)
            ):
                return False
            seen.add(arg)
            i += 2
        elif arg == "-q" and arg not in seen:
            seen.add(arg)
            i += 1
        elif arg.startswith("-"):
            return False
        else:
            paths.append(arg)
            i += 1
    return "-q" in seen and bool(paths) and all(_path_ok(p, bound.roots) for p in paths)


def _test_run_reason(tokens: list[str], runner: str, cwd: str) -> str | None:
    bounds = _bounds(runner, cwd)
    if bounds is None:
        return R_TEST_RUN_NO_TRAIN.format(runner=runner)
    if any(_test_run_ok(tokens, bound) for bound in bounds):
        return None
    if runner == "audit" and bounds:
        where, rootdir = " or ".join(bounds[0].roots), bounds[0].rootdir
    else:
        where, rootdir = "one unit worktree this train records", "<that worktree>"
    return R_TEST_RUN.format(runner=runner, where=where, rootdir=rootdir)


def _show_sed(prev: list[str], sep: str, tokens: list[str], subs: frozenset[str]) -> bool:
    # spec 6: `git show <rev>:<path> | sed -n <range>p`; this sed reads the pipe and prints only.
    return (
        "show" in subs
        and sep == "|"
        and shell._git_subcommand(prev) == "show"
        and len(tokens) == 3
        and tokens[:2] == ["sed", "-n"]
        and shell._SED_PRINT.fullmatch(tokens[2]) is not None
    )


def judge(hook_input: dict[str, object], flags: argparse.Namespace) -> str | None:
    grant: str | None = flags.git
    runner: str | None = flags.test_runner
    cwd = hook_io.text(hook_input, "cwd")
    chain = shell.worker_parse(hook_io.text(hook_io.tool_input(hook_input), "command"))
    if chain is None:
        return shell.R_UNSUPPORTED
    agent = hook_io.agent(hook_input)
    for tokens in chain.segments:
        args = _pytest_args(tokens) if tokens else None
        if args is not None and any(a.startswith("--basetemp") for a in args):
            return jail.R_BASETEMP_AGENT.format(agent=agent)
    subs = shell.GIT_SETS[grant] if grant else frozenset()
    charter = hook_io.hook_charter(cwd)
    for i, tokens in enumerate(chain.segments):
        if jail._read_only_segment(tokens, subs, cwd, charter):
            continue
        if i and _show_sed(chain.segments[i - 1], chain.seps[i - 1], tokens, subs):
            continue
        if runner is not None and tokens and _pytest_args(tokens) is not None:
            reason = _test_run_reason(tokens, runner, cwd)
            if reason is None:
                continue
            return reason
        return _reason(grant)
    return None


decide, main = hook_io.entrypoint(judge, TOOLS, PARSER)

if __name__ == "__main__":
    sys.exit(main())
