# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0044, 0001: refuses remote git; with --conductor, only the train's branch pushed to origin.
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from lib import gh_policy, hook_io, jail  # noqa: E402
from lib.admit import Admitted  # noqa: E402
from lib.shparse import parse  # noqa: E402

TOOLS: frozenset[str] = frozenset({"Bash"})
FLAGS: dict[str, hook_io.Flag] = {"--conductor": hook_io.Flag()}
PARSER = hook_io.build_parser(Path(__file__).stem, FLAGS)


def judge(hook_input: dict[str, object], flags: argparse.Namespace) -> str | None:
    conductor: bool = flags.conductor
    cwd = hook_io.text(hook_input, "cwd")
    # 228 tail: the admission the agent's chain judged; a refused git by its typed subcommand.
    got = jail.held_admission(hook_input)
    if not isinstance(got, Admitted):
        sub = got.subcommand if got.family == "git" else ""
        if conductor and sub == "push":
            return jail.refusal_text(got, jail.R_CONDUCTOR_PUSH)
        remote = not conductor and sub in jail.REMOTE_GIT
        return jail.refusal_text(got, jail.R_REMOTE_GIT) if remote else None
    script = parse(hook_io.text(hook_io.tool_input(hook_input), "command"))
    for done in got.commands:
        sub = done.subcommand.text if done.family == "git" and done.subcommand else ""
        if conductor and sub == "push":
            tokens = jail.admitted_tokens(script, done)
            # issue 11, 0078: the train's branch, to origin of this repo or the charter root.
            reason = jail._conductor_push_reason(tokens, cwd, hook_io.hook_charter(cwd))
            # spec 4.2: then the approved verdict, or the operator's exception, on the exact tip.
            reason = reason or gh_policy.verdict_reason(cwd, "git push")
            if reason:
                return reason
        elif not conductor and sub in jail.REMOTE_GIT:
            return jail.R_REMOTE_GIT
    return None


decide, main = hook_io.entrypoint(judge, TOOLS, PARSER)

if __name__ == "__main__":
    sys.exit(main())
