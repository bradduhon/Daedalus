# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0044: each git segment must fit the grammar of the named grant; other commands are not judged.
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from lib import hook_io, jail, shell  # noqa: E402
from lib.admit import Admitted  # noqa: E402
from lib.shparse import parse  # noqa: E402

TOOLS: frozenset[str] = frozenset({"Bash"})
FLAGS: dict[str, hook_io.Flag] = {"--allow": hook_io.Flag(values=frozenset(shell.GIT_SETS))}
PARSER = hook_io.build_parser(Path(__file__).stem, FLAGS)
_TEXTS = {
    "coder": jail.R_CODER_GIT,
    "docs": jail.R_DOCS_BASH,
    "conductor": jail.R_CONDUCTOR_BASH,
    "specialist": jail.R_SPECIALIST_BASH,
    "read-only": jail.R_AUDITOR_BASH,
}
R_NO_GIT = "git is not granted to this agent (0044). Next: use the commands its agent file names."


def judge(hook_input: dict[str, object], flags: argparse.Namespace) -> str | None:
    grant: str | None = flags.allow
    cwd = hook_io.text(hook_input, "cwd")
    # 228 tail: the admission the agent's chain judged; a refused git is named by the grant.
    got = jail.held_admission(hook_input)
    if not isinstance(got, Admitted):
        if got.family != "git":
            return None
        return R_NO_GIT if grant is None else jail.refusal_text(got, _TEXTS[grant])
    script = parse(hook_io.text(hook_io.tool_input(hook_input), "command"))
    git_segments = [jail.admitted_tokens(script, d) for d in got.commands if d.family == "git"]
    if not git_segments:
        return None
    if grant is None:
        return R_NO_GIT
    charter: str | None = None
    if grant in {"docs", "specialist", "read-only", "conductor"}:
        charter = hook_io.hook_charter(cwd)
    grammar = jail._DOCS_GRAMMAR if grant == "docs" else None
    if grant == "conductor":
        grammar = jail._CONDUCTOR_GRAMMAR
    for segment in git_segments:
        if grant == "conductor":
            if shell._git_subcommand(segment) == "push":
                continue  # 0001: git_push judges the conductor's push.
            # 0078: no other conductor git reaches the charter root, nested or not.
            if jail._reaches_charter(segment, cwd, charter):
                return jail.R_CONDUCTOR_CHARTER
            sub, args, _ = shell._git_split(segment)
            if sub == "commit" and jail._commits_work_tree(args):
                return jail.R_CONDUCTOR_COMMIT_ALL
        granted = None if grant == "conductor" else charter
        if not jail._git_grammar_ok(segment, shell.GIT_SETS[grant], cwd, granted, grammar):
            return _TEXTS[grant]
    return None


decide, main = hook_io.entrypoint(judge, TOOLS, PARSER)

if __name__ == "__main__":
    sys.exit(main())
