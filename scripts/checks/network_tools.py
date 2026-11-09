# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0044: refuses web tools without --web, and network commands in Bash; --gh exempts gh.
# 0196: every package install is refused; a coder's frozen form passes when the manifest lists it.
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from lib import hook_io, jail, shell  # noqa: E402
from lib.admit import Admitted  # noqa: E402
from lib.shparse import parse  # noqa: E402

TOOLS: frozenset[str] = frozenset({"Bash"} | jail.WEB_TOOLS)
FLAGS: dict[str, hook_io.Flag] = {"--web": hook_io.Flag(), "--gh": hook_io.Flag()}
PARSER = hook_io.build_parser(Path(__file__).stem, FLAGS)
CODER = "coder"


def _coder_reason(hook_input: dict[str, object]) -> str | None:
    # 228 S3b: a network tool is off the coder's table, so admission refuses it by name.
    call = jail.coder_call(hook_input)
    if not isinstance(call.got, Admitted):
        return jail.coder_refusal(call)
    base = jail.coder_base(call, call.got)
    _, commands = jail.lead_cd(call.got)
    # issue 55: a link or versioned path to the claude binary, by its real file.
    return shell.R_CLAUDE_PATH if any(jail.claude_word(c, base) for c in commands) else None


def judge(hook_input: dict[str, object], flags: argparse.Namespace) -> str | None:
    web: bool = flags.web
    gh: bool = flags.gh
    if hook_io.text(hook_input, "tool_name") in jail.WEB_TOOLS:
        if web:
            return None
        return jail.R_CONDUCTOR_WEB if gh else jail.R_WEB_RESEARCHER_ONLY
    # 0044: --gh is the conductor's flag; the coder's agent file never sets it.
    if hook_io.agent(hook_input) == CODER and not gh:
        return _coder_reason(hook_input)
    banned = jail.NETWORK_TOOLS - {"gh"} if gh else jail.NETWORK_TOOLS
    return _worker_reason(hook_input, banned)


def _worker_reason(hook_input: dict[str, object], banned: frozenset[str]) -> str | None:
    # 228 tail: the admission the agent's chain judged; a refused command by its typed family.
    got = jail.held_admission(hook_input)
    command = hook_io.text(hook_io.tool_input(hook_input), "command")
    cwd = hook_io.text(hook_input, "cwd")
    script = parse(command)
    if not isinstance(got, Admitted):
        if got.family in banned:
            return jail.refusal_text(got, jail.R_NETWORK)
        # issue 55: a refused command word that runs the claude binary by link or path.
        claude = jail.refusal_constant(script, got, cwd) == shell.R_CLAUDE_PATH
        return jail.refusal_text(got, shell.R_CLAUDE_PATH) if claude else None
    base = jail.admitted_base(script, got, cwd)
    for done in jail.lead_cd(got)[1]:
        if {done.family, *(shell.command_family(w.text) for w in done.wrappers)} & banned:
            return jail.R_NETWORK
        tokens = jail.admitted_tokens(script, done)
        # 0196: the frozen form was the coder's alone; every other agent's install refuses.
        reason = jail.install_reason(tokens, frozenset) or jail.download_reason(tokens)
        if reason:
            return reason
        # issue 55: a link or versioned path to the claude binary, by its real file.
        if jail.claude_word(done, base):
            return shell.R_CLAUDE_PATH
    return None


decide, main = hook_io.entrypoint(judge, TOOLS, PARSER)

if __name__ == "__main__":
    sys.exit(main())
