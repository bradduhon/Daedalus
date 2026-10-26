# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0054, 0044: the coder writes anywhere in its own unit worktree except protected paths.
# The first write claims the dispatched unit (issue 29); git add and commit stay in the unit.
# 0134: --docs narrows the writes to the four public docs inside the train's docs worktree.
from __future__ import annotations

import argparse
import sys
from collections.abc import Callable
from functools import lru_cache
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from lib import dispatch_binding, hook_io, jail, shell  # noqa: E402
from lib.project_root import project_root  # noqa: E402
from lib.train_state import active_train  # noqa: E402

TOOLS: frozenset[str] = frozenset(jail.WRITE_TOOLS | {"Bash"})
FLAGS: dict[str, hook_io.Flag] = {"--docs": hook_io.Flag()}
PARSER = hook_io.build_parser(Path(__file__).stem, FLAGS)
Boundary = Callable[[], jail.CoderBoundary | str]
R_DOCS_ONLY = (
    "the docs-writer writes only the four public docs ({docs}) inside the train's docs worktree "
    "{name}; {path} is not one of them (0134). Next: edit only those four files in the docs "
    "worktree."
)
R_DOCS_GIT = (
    "the docs-writer's git writes are add and commit in the docs worktree; git {sub} is refused "
    "(0134). Next: stage the edited docs with git -C <docs worktree> add, then commit."
)
R_DOCS_COMMIT = (
    "the docs-writer commits only what it staged, as git commit -m <message>; {command} is "
    "refused, since -a, --all or a pathspec commits files it never staged (0134). Next: stage "
    "each doc with git -C <docs worktree> add <path>, then run git -C <docs worktree> commit -m "
    "<message>."
)
# 0134: git forms that change files beyond the staged docs.
_DOCS_GIT_REFUSED = frozenset({"stage", "stash", "restore", "checkout"})


def _docs_unit(cwd: str) -> str:
    train = active_train(project_root(Path(cwd)))
    return (
        dispatch_binding.docs_unit(train) if train else f"<train-id>{dispatch_binding.DOCS_SUFFIX}"
    )


def _docs_reason(path: str, cwd: str) -> str | None:
    # 0134: the unit must be <train-id>-docstage and the rest of the path one of the four docs.
    name = _docs_unit(cwd)
    parts = jail._unit_parts(path, cwd) or []
    if parts[:1] == [name] and "/".join(parts[1:]) in dispatch_binding.PUBLIC_DOCS:
        return None
    return _docs_refusal(path, name)


def _docs_refusal(what: str, name: str) -> str:
    docs = ", ".join(dispatch_binding.PUBLIC_DOCS)
    return R_DOCS_ONLY.format(docs=docs, name=name, path=what)


def _write_reason(
    hook_input: dict[str, object], cwd: str, boundary: Boundary, docs: bool
) -> str | None:
    path = shell._abs(hook_io.write_path(hook_input), cwd)
    if not jail._in_unit_worktree(path, cwd):
        return jail.R_UNIT_OUTSIDE.format(path)
    reason = jail._coder_write_reason(path, cwd, boundary())
    if reason:
        return reason
    if docs and (reason := _docs_reason(path, cwd)):
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


def _docs_segment_reason(segment: list[str], base: str, cwd: str) -> str | None:
    # 0134: every write target is a public doc, and git writes stop at add and commit.
    sub = shell._git_subcommand(segment) if shell._base(segment[0]) == "git" else None
    if sub in _DOCS_GIT_REFUSED:
        return R_DOCS_GIT.format(sub=sub)
    targets = jail._coder_write_targets(segment, base)
    if sub in {"add", "commit"}:
        _, args, globals_ = shell._git_split(segment)
        git_dir = jail._git_dir(globals_, base)
        if (jail._unit_parts(git_dir, cwd) or [])[:1] != [_docs_unit(cwd)]:
            return _docs_reason(git_dir, cwd)
        # 0134: git add names each doc by path, as charter-docs does (M1); -A or . stages the rest.
        if sub == "add":
            if not jail._docs_add_ok(args, base):
                return _docs_refusal(" ".join(["git add", *args]), _docs_unit(cwd))
            targets += [shell._abs(a, git_dir) for a in args if a != "--"]
        # 0134: the commit takes the staged docs only, as charter-docs commits (_DOCS_GRAMMAR).
        if sub == "commit" and not jail._DOCS_GRAMMAR["commit"](args, base):
            return R_DOCS_COMMIT.format(command=" ".join(["git commit", *args]))
    return next((r for t in targets if (r := _docs_reason(t, cwd))), None)


def _bash_reason(
    hook_input: dict[str, object], cwd: str, boundary: Boundary, docs: bool
) -> str | None:
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
        if docs and (reason := _docs_segment_reason(segment, base, cwd)):
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
    docs = bool(flags.docs)
    if hook_io.text(hook_input, "tool_name") in jail.WRITE_TOOLS:
        return _write_reason(hook_input, cwd, boundary, docs)
    return _bash_reason(hook_input, cwd, boundary, docs)


decide, main = hook_io.entrypoint(judge, TOOLS, PARSER)

if __name__ == "__main__":
    sys.exit(main())
