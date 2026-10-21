# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0044, 0001: refuses remote git; with --conductor, only the train's branch pushed to origin.
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from lib import gh_policy, hook_io, jail, shell  # noqa: E402

TOOLS: frozenset[str] = frozenset({"Bash"})
FLAGS: dict[str, hook_io.Flag] = {"--conductor": hook_io.Flag()}
PARSER = hook_io.build_parser(Path(__file__).stem, FLAGS)


def judge(hook_input: dict[str, object], flags: argparse.Namespace) -> str | None:
    conductor: bool = flags.conductor
    cwd = hook_io.text(hook_input, "cwd")
    segments = shell.worker_segments(hook_io.text(hook_io.tool_input(hook_input), "command"))
    if segments is None:
        return shell.R_UNSUPPORTED
    for segment in filter(None, segments):
        if conductor:
            if shell._git_subcommand(segment) != "push":
                continue
            # issue 11, 0078: the train's branch, to origin of this repo or the charter root.
            reason = jail._conductor_push_reason(segment, cwd, hook_io.hook_charter(cwd))
            # spec 4.2: then the approved verdict, or the operator's exception, on the exact tip.
            reason = reason or gh_policy.verdict_reason(cwd, "git push")
            if reason:
                return reason
            continue
        exempt = shell._exempt_indices(segment)
        words = [shell._base(t) for i, t in enumerate(segment) if i not in exempt]
        sub = shell._git_subcommand(segment) if shell._base(segment[0]) == "git" else None
        # I3a: a local subcommand's operands (stash push) go to the git allowlist.
        if sub in jail.REMOTE_GIT or (
            sub not in shell.CODER_GIT and "git" in words and jail.REMOTE_GIT & set(words)
        ):
            return jail.R_REMOTE_GIT
    return None


decide, main = hook_io.entrypoint(judge, TOOLS, PARSER)

if __name__ == "__main__":
    sys.exit(main())
