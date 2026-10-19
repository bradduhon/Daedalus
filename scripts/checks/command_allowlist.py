# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0044: every Bash segment runs a command the --allow list names; nothing else runs.
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from lib import hook_io, jail, shell  # noqa: E402
from lib.audit import project_root  # noqa: E402

TOOLS: frozenset[str] = frozenset({"Bash"})
NAMES = frozenset({"append_ledger", "git", "gh", "gitleaks", "read"})
FLAGS: dict[str, hook_io.Flag] = {"--allow": hook_io.Flag(values=NAMES, many=True)}
PARSER = hook_io.build_parser(Path(__file__).stem, FLAGS)


def _reason(allowed: frozenset[str]) -> str:
    if allowed == {"append_ledger", "git", "read"}:
        return jail.R_DOCS_BASH
    if allowed == {"git", "gh", "gitleaks"}:
        return jail.R_CONDUCTOR_BASH
    names = ", ".join(sorted(allowed)) or "no command"
    return f"Bash is limited to {names}. Next: use those only."


def _read_roots(cwd: str) -> tuple[list[str], str]:
    # 0084: the read class reaches the charter root and the project's docs/, scratch included.
    base = str(project_root(cwd))
    charter = hook_io.hook_config(cwd).charter_root
    roots = [f"{base}/docs"] + ([str(charter)] if charter else [])
    return roots, base


def judge(hook_input: dict[str, object], flags: argparse.Namespace) -> str | None:
    allowed: frozenset[str] = frozenset(flags.allow or ())
    command = hook_io.text(hook_io.tool_input(hook_input), "command")
    chain = shell.worker_parse(command)
    if chain is None:
        return shell.R_UNSUPPORTED
    cwd = hook_io.text(hook_input, "cwd")
    for segment, raw in zip(chain.segments, chain.raws, strict=True):
        if "append_ledger" in allowed and shell._is_append_ledger(segment):
            if not jail._ledger_args_ok(segment):
                return jail.R_LEDGER_ARGS
            continue
        name = shell._cmd_name(segment)
        if name in {"git", "gh"} and name in allowed:
            continue  # 0044: git_grammar and gh_classes judge their arguments.
        if name == "gitleaks" and name in allowed:
            if not jail._gitleaks_ok(segment):
                return jail.R_GITLEAKS
            continue
        if "read" in allowed and name in shell.DOCS_READS:
            roots, base = _read_roots(cwd)
            if shell.docs_read_ok(segment, raw, roots, cwd, base):
                continue
        return _reason(allowed)
    return None


def decide(hook_input: dict[str, object], flags: list[str]) -> hook_io.HookDecision:
    return hook_io.evaluate(hook_input, flags, judge, TOOLS, PARSER)


def main() -> int:
    return hook_io.run(judge, TOOLS, PARSER)


if __name__ == "__main__":
    sys.exit(main())
