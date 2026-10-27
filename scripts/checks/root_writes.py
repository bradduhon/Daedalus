# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0044, 0053: writes land only under the named path classes, every root inside the workspace.
from __future__ import annotations

import argparse
import fnmatch
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from lib import hook_io, jail, shell  # noqa: E402
from lib.audit import project_root  # noqa: E402
from lib.config import Config  # noqa: E402
from lib.train_state import active_train, folder_output  # noqa: E402

TOOLS: frozenset[str] = frozenset(jail.WRITE_TOOLS | {"Bash"})
# open item 3: the unit-src-tests and none classes of spec 5.2 are not accepted in group 1.
CLASSES = frozenset({"contracts", "charter-specs", "charter", "docs", "scratch", "audit"})
FLAGS: dict[str, hook_io.Flag] = {
    "--touch": hook_io.Flag(values=CLASSES, many=True),
    "--ledger-guard": hook_io.Flag(),
    # spec 3.1: an exact file name or a `*` glob over one name; no path, no other glob syntax.
    "--name": hook_io.Flag(pattern=r"[A-Za-z0-9*][A-Za-z0-9._*-]*"),
    # 0152: a folder glob one level below a class root, then one exact file name.
    "--sub": hook_io.Flag(pattern=r"[A-Za-z0-9*][A-Za-z0-9._*-]*/[A-Za-z0-9][A-Za-z0-9._-]*"),
}
PARSER = hook_io.build_parser(Path(__file__).stem, FLAGS)


def _roots(classes: tuple[str, ...], cwd: str, config: Config) -> list[str]:
    # 0044: resolved per call; a class whose base is unknown has no root.
    charter = str(config.charter_root) if config.charter_root else None
    roots: list[str] = []
    for name in classes:
        if name == "contracts":
            roots.append(f"{cwd}/contracts")
        elif name == "charter-specs" and charter is not None:
            roots.append(f"{charter}/specs")
        elif name == "charter" and charter is not None:
            roots.append(charter)
        elif name == "docs":
            roots.append(f"{cwd}/docs")
        elif name == "scratch":
            # spec 3.1: the train's own folder in a train, else docs/.tmp/daedalus/ itself.
            repo = project_root(cwd)
            train = active_train(repo)
            scratch = repo / "docs" / ".tmp" / "daedalus"
            roots.append(str(scratch / train if train is not None else scratch))
        elif name == "audit":
            # 0109, spec 3.1: the train's audit folder in a train; outside a train, no root.
            repo = project_root(cwd)
            train = active_train(repo)
            if train is not None:
                roots.append(str(repo / "docs" / ".tmp" / "daedalus" / train / "audit"))
    return roots


def _reason(classes: tuple[str, ...], path: str) -> str:
    named = frozenset(classes)
    if named == {"contracts", "charter-specs"}:
        return jail.R_CONTRACT_SPEC_WRITE
    if named == {"charter", "docs"}:
        return jail.R_CHARTER_DOCS_WRITE
    listed = ", ".join(sorted(named)) or "no path class"
    return f"writes are limited to {listed}: {path}. Next: write there."


def _named(path: str, roots: list[str], name: str) -> bool:
    # 0044: --name admits a file directly in a class root, named exactly or by its glob.
    parent = os.path.realpath(os.path.dirname(path))
    return fnmatch.fnmatchcase(os.path.basename(path), name) and any(
        parent == os.path.realpath(root) for root in roots
    )


def _placed(folder: str, folder_glob: str, real_roots: list[str]) -> bool:
    return fnmatch.fnmatchcase(os.path.basename(folder), folder_glob) and (
        os.path.dirname(folder) in real_roots
    )


def _in_sub(path: str, roots: list[str], sub: str) -> bool:
    # 0152: folder glob and exact file name as two checks, never one fnmatch over the joined path.
    # Both the folder's realpath and the file's realpath must sit one level below a class root.
    folder_glob, file_name = sub.split("/", 1)
    real_roots = [os.path.realpath(root) for root in roots]
    real = os.path.realpath(path)
    return (
        os.path.basename(path) == file_name
        and os.path.basename(real) == file_name
        and _placed(os.path.realpath(os.path.dirname(path)), folder_glob, real_roots)
        and _placed(os.path.dirname(real), folder_glob, real_roots)
    )


def _allowed(path: str, roots: list[str], name: str | None, sub: str | None) -> bool:
    # W3.2: the train summary is the summary command's output, so no class admits that file.
    if name is None and sub is None:
        return any(shell._under(path, root) for root in roots)
    return (name is not None and _named(path, roots, name)) or (
        sub is not None and _in_sub(path, roots, sub)
    )


def _folder_grant(
    classes: tuple[str, ...], cwd: str, name: str | None, sub: str | None
) -> str | None:
    # issue 48: only the scratch file shapes reach a folder run's output folder; no bare grant.
    if "scratch" not in classes or (name is None and sub is None):
        return None
    return folder_output(project_root(cwd))


def _granted(path: str, out: str | None, name: str | None, sub: str | None) -> bool:
    # issue 48: the file's own realpath must sit in the output folder too, so a link cannot leave.
    if out is None:
        return False
    real = os.path.realpath(path)
    return (name is not None and _named(path, [out], name) and _named(real, [out], name)) or (
        sub is not None and _in_sub(path, [out], sub)
    )


def judge(hook_input: dict[str, object], flags: argparse.Namespace) -> str | None:
    classes: tuple[str, ...] = tuple(flags.touch or ())
    name: str | None = flags.name
    sub: str | None = flags.sub
    ledger_guard: bool = flags.ledger_guard
    cwd = hook_io.text(hook_input, "cwd")
    config = hook_io.hook_config(cwd)
    roots = _roots(classes, cwd, config)
    out = _folder_grant(classes, cwd, name, sub)
    if hook_io.text(hook_input, "tool_name") in jail.WRITE_TOOLS:
        path = shell._abs(hook_io.write_path(hook_input), cwd)
        if ledger_guard:
            reason = jail._ledger_write_reason(path, cwd, config)
            if reason:
                return reason
        if _allowed(path, roots, name, sub) or _granted(path, out, name, sub):
            return None
        return _reason(classes, path)
    segments = shell.worker_segments(hook_io.text(hook_io.tool_input(hook_input), "command"))
    if segments is None:
        return shell.R_UNSUPPORTED
    for segment in filter(None, segments):
        for target in jail._coder_write_targets(segment, cwd):
            if not (_allowed(target, roots, name, sub) or _granted(target, out, name, sub)):
                return _reason(classes, target)
    return None


decide, main = hook_io.entrypoint(judge, TOOLS, PARSER)

if __name__ == "__main__":
    sys.exit(main())
