# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0054, 0044: the coder writes anywhere in its own unit worktree except protected paths.
# The first write claims the dispatched unit (issue 29); git add and commit stay in the unit.
# 0134: --docs narrows the writes to the four public docs inside the train's docs worktree.
from __future__ import annotations

import argparse
import os
import sys
from collections.abc import Callable
from functools import lru_cache
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from checks.read_only_bash import basetemp  # noqa: E402
from lib import dispatch_binding, hook_io, jail, shell  # noqa: E402
from lib.admit import Admitted, AdmittedCommand  # noqa: E402
from lib.project_root import project_root  # noqa: E402
from lib.train_state import active_train  # noqa: E402

TOOLS: frozenset[str] = frozenset(jail.WRITE_TOOLS | {"Bash"})
FLAGS: dict[str, hook_io.Flag] = {"--docs": hook_io.Flag()}
PARSER = hook_io.build_parser(Path(__file__).stem, FLAGS)
Boundary = Callable[[], jail.CoderBoundary | str]
R_DOCS_ONLY = (
    "the writer writes only the four public docs ({docs}) inside the train's docs worktree "
    "{name}; {path} is not one of them (0134). Next: edit only those four files in the docs "
    "worktree."
)
R_DOCS_GIT = (
    "the writer's git writes are add and commit in the docs worktree; git {sub} is refused "
    "(0134). Next: stage the edited docs with git -C <docs worktree> add, then commit."
)
R_DOCS_COMMIT = (
    "the writer commits only what it staged, as git commit -m <message>; {command} is "
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


def _followed(call: jail.CoderCall, got: Admitted) -> tuple[str, bool]:
    # O6, 228 S3b: (base, moved); a leading cd is followed only into a unit worktree of this
    # same project and only when every join is &&; otherwise the writes judge at the hook cwd.
    cwd = call.cwd
    lead, _ = jail.lead_cd(got)
    if lead is None or lead.cd_target is None:
        return cwd, False
    target = os.path.normpath(lead.cd_target.text)
    if not set(call.script.separators) - {""} <= {"&&"}:
        return cwd, True
    if target == cwd:
        return cwd, False
    same = project_root(Path(target)).resolve() == project_root(Path(cwd)).resolve()
    return (target, False) if same and jail._unit_parts(target, cwd) is not None else (cwd, True)


def _sub(done: AdmittedCommand) -> str:
    return done.subcommand.text if done.family == "git" and done.subcommand else ""


def _git_dir(done: AdmittedCommand, base: str) -> str:
    return done.git_dir.text if done.git_dir is not None else base


def _word_after(call: jail.CoderCall, done: AdmittedCommand, span: tuple[int, int]) -> list[str]:
    # 228 S3b: the literal words of an admitted command from the word at span on.
    words = jail.admitted_words(call.script, done)
    at = next((i for i, w in enumerate(words) if w.span == span), len(words))
    return [w.literal if w.literal is not None else w.raw for w in words[at:]]


def _relative(call: jail.CoderCall, done: AdmittedCommand) -> str | None:
    # 0022, 228 S3b: after a cd the chain does not follow, a relative write or git folder.
    sub = _sub(done)
    if sub in {"add", "commit"} and done.git_dir is None:
        return f"git {sub} without -C"
    if done.git_dir is not None:
        given = _word_after(call, done, done.git_dir.span)[:1]
        return given[0] if given and not os.path.isabs(given[0]) else None
    paths = [p.text for p in done.pathspecs] if sub in {"restore", "checkout"} else []
    paths += [w.text for w in done.writes if w.text != "-"]
    return next((p for p in paths if not os.path.isabs(p)), None)


def _targets(done: AdmittedCommand, base: str) -> list[str]:
    # 0054, 228 S3b: the typed write operands, and the pathspecs git restore or checkout writes.
    found = [shell._abs(w.text, base) for w in done.writes if w.text != "-"]
    if _sub(done) in {"restore", "checkout"}:
        found += [shell._abs(p.text, _git_dir(done, base)) for p in done.pathspecs]
    return found


def _units(done: AdmittedCommand, base: str) -> set[str]:
    # issue 29, B2, 228 S3b: the units a command writes, stages or runs a script from.
    paths = _targets(done, base)
    if _sub(done) in dispatch_binding._UNIT_GIT_WRITES:
        git_dir = _git_dir(done, base)
        paths += [git_dir, *(shell._abs(p.text, git_dir) for p in done.pathspecs)]
    if done.script is not None:
        paths.append(shell._abs(done.script.text, base))
    return {parts[0] for p in paths if (parts := jail._unit_parts(p, base))}


def _coder_command_reason(
    call: jail.CoderCall, done: AdmittedCommand, base: str, boundary: Boundary
) -> str | None:
    # 0054, issue 30, 228 S3b: the typed writes stay in the unit worktree, bar protected paths.
    suffix = jail._backup_suffix(done.family, jail.admitted_tokens(call.script, done)[1:])
    if suffix is not None:
        return jail.R_BASH_OUTSIDE.format(suffix)
    for target in _targets(done, base):
        if not jail._in_unit_worktree(target, base):
            return jail.R_BASH_OUTSIDE.format(target)
        reason = jail._coder_write_reason(target, base, boundary())
        if reason:
            return reason
    return None


def _docs_command_reason(
    call: jail.CoderCall, done: AdmittedCommand, base: str, cwd: str
) -> str | None:
    # 0134: every write target is a public doc, and git writes stop at add and commit.
    sub = _sub(done)
    if sub in _DOCS_GIT_REFUSED:
        return R_DOCS_GIT.format(sub=sub)
    targets = _targets(done, base)
    if sub in {"add", "commit"} and done.subcommand is not None:
        git_dir = _git_dir(done, base)
        if (jail._unit_parts(git_dir, cwd) or [])[:1] != [_docs_unit(cwd)]:
            return _docs_reason(git_dir, cwd)
        args = _word_after(call, done, done.subcommand.span)[1:]
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
    call = jail.coder_call(hook_input)
    if basetemp(call.script, call.got):
        return jail.R_BASETEMP  # issue 56, 269: from the typed record, before any pass.
    got = call.got
    if not isinstance(got, Admitted):
        return jail.coder_refusal(call)
    base, moved = _followed(call, got)
    _, commands = jail.lead_cd(got)
    touched: set[str] = set()
    for done in commands:
        relative = _relative(call, done) if moved else None
        if relative is not None:
            return jail.R_CD_RELATIVE.format(relative)
        if _sub(done) in {"add", "commit"} and jail._unit_parts(_git_dir(done, base), base) is None:
            return jail.R_CODER_UNIT_GIT
        reason = _coder_command_reason(call, done, base, boundary)
        if reason:
            return reason
        if docs and (reason := _docs_command_reason(call, done, base, cwd)):
            return reason
        touched |= _units(done, base)
    return dispatch_binding._binding_reason(hook_input, cwd, touched)


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
