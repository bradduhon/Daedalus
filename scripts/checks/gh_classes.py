# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0028, 0044: the gh deny classes for every agent; --conductor adds the conductor's gh rules.
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
    agent = hook_io.agent(hook_input)
    cwd = hook_io.text(hook_input, "cwd")
    command = hook_io.text(hook_io.tool_input(hook_input), "command")
    reason = jail._gh_gate(agent, cwd, command)
    if reason or not conductor:
        return reason
    segments = shell.worker_segments(command)
    if segments is None:
        return shell.R_UNSUPPORTED
    for segment in filter(None, segments):
        if shell._cmd_name(segment) != "gh":
            continue
        if jail._gh_repo_flag(segment):
            # 0078: the one -R form is gh pr create on the declared charter root's origin.
            if not jail._charter_pr_create_ok(segment, cwd, hook_io.hook_charter(cwd)):
                return jail.R_CONDUCTOR_REPO
        if not jail._gh_body_file_ok(segment, cwd):
            return jail.R_BODY_FILE
        reason = jail._gh_write_reason(segment)
        if reason:
            return reason
        if not jail._gh_allowed(segment):
            return gh_policy.conductor_gh_refusal()
        # spec 4.2: pr create meets the push's verdict gate, from the train branch only.
        if gh_policy.classify(segment)[1] == "pr create":
            reason = gh_policy.pr_create_reason(segment, cwd)
            if reason:
                return reason
    return None


decide, main = hook_io.entrypoint(judge, TOOLS, PARSER)

if __name__ == "__main__":
    sys.exit(main())
