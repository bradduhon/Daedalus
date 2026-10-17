# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0044: every Bash segment runs a command the --allow list names; nothing else runs.
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from lib import hook_io, jail, shell  # noqa: E402

TOOLS: frozenset[str] = frozenset({"Bash"})
NAMES = frozenset({"append_ledger", "git", "gh", "gitleaks"})
FLAGS: dict[str, hook_io.Flag] = {"--allow": hook_io.Flag(values=NAMES, many=True)}
PARSER = hook_io.build_parser(Path(__file__).stem, FLAGS)


def _reason(allowed: frozenset[str]) -> str:
    if allowed == {"append_ledger", "git"}:
        return jail.R_DOCS_BASH
    if allowed == {"git", "gh", "gitleaks"}:
        return jail.R_CONDUCTOR_BASH
    names = ", ".join(sorted(allowed)) or "no command"
    return f"Bash is limited to {names}. Next: use those only."


def judge(hook_input: dict[str, object], flags: argparse.Namespace) -> str | None:
    allowed: frozenset[str] = frozenset(flags.allow or ())
    segments = shell.worker_segments(hook_io.text(hook_io.tool_input(hook_input), "command"))
    if segments is None:
        return shell.R_UNSUPPORTED
    for segment in segments:
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
        return _reason(allowed)
    return None


def main() -> int:
    return hook_io.run(judge, TOOLS, PARSER)


if __name__ == "__main__":
    sys.exit(main())
