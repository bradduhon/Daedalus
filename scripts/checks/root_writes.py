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
from lib.train_state import active_train  # noqa: E402

TOOLS: frozenset[str] = frozenset(jail.WRITE_TOOLS | {"Bash"})
# open item 3: the unit-src-tests and none classes of spec 5.2 are not accepted in group 1.
CLASSES = frozenset({"contracts", "charter-specs", "charter", "docs", "scratch"})
FLAGS: dict[str, hook_io.Flag] = {
    "--touch": hook_io.Flag(values=CLASSES, many=True),
    "--ledger-guard": hook_io.Flag(),
    # spec 3.1: an exact file name or a `*` glob over one name; no path, no other glob syntax.
    "--name": hook_io.Flag(pattern=r"[A-Za-z0-9*][A-Za-z0-9._*-]*"),
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
    return roots


def _reason(classes: tuple[str, ...], path: str) -> str:
    named = frozenset(classes)
    if named == {"contracts", "charter-specs"}:
        return jail.R_CONTRACT_SPEC_WRITE
    if named == {"charter", "docs"}:
        return jail.R_CHARTER_DOCS_WRITE
    listed = ", ".join(sorted(named)) or "no path class"
    return f"writes are limited to {listed}: {path}. Next: write there."


def _allowed(path: str, roots: list[str], name: str | None) -> bool:
    if name is None:
        return any(shell._under(path, root) for root in roots)
    # 0044: --name admits a file directly in a class root, named exactly or by its glob.
    parent = os.path.realpath(os.path.dirname(path))
    return fnmatch.fnmatchcase(os.path.basename(path), name) and any(
        parent == os.path.realpath(root) for root in roots
    )


def judge(hook_input: dict[str, object], flags: argparse.Namespace) -> str | None:
    classes: tuple[str, ...] = tuple(flags.touch or ())
    name: str | None = flags.name
    ledger_guard: bool = flags.ledger_guard
    cwd = hook_io.text(hook_input, "cwd")
    config = hook_io.hook_config(cwd)
    roots = _roots(classes, cwd, config)
    if hook_io.text(hook_input, "tool_name") in jail.WRITE_TOOLS:
        path = shell._abs(hook_io.write_path(hook_input), cwd)
        if ledger_guard:
            reason = jail._ledger_write_reason(path, cwd, config)
            if reason:
                return reason
        return None if _allowed(path, roots, name) else _reason(classes, path)
    segments = shell.worker_segments(hook_io.text(hook_io.tool_input(hook_input), "command"))
    if segments is None:
        return shell.R_UNSUPPORTED
    for segment in filter(None, segments):
        for target in jail._coder_write_targets(segment, cwd):
            if not _allowed(target, roots, name):
                return _reason(classes, target)
    return None


def decide(hook_input: dict[str, object], flags: list[str]) -> hook_io.HookDecision:
    return hook_io.evaluate(hook_input, flags, judge, TOOLS, PARSER)


def main() -> int:
    return hook_io.run(judge, TOOLS, PARSER)


if __name__ == "__main__":
    sys.exit(main())
