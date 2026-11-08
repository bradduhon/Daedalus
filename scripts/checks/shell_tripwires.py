# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0044, 8.5: the worker shell model; unsupported constructs, tripwires, env prefix, hygiene.
# 228 S3b: the coder's call is admitted on its parse, then its typed record meets the hygiene.
from __future__ import annotations

import argparse
import os
import sys
from collections.abc import Callable
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from lib import hook_io, jail, shell  # noqa: E402
from lib.admit import Admitted, AdmittedCommand  # noqa: E402

TOOLS: frozenset[str] = frozenset({"Bash"})
FLAGS: dict[str, hook_io.Flag] = {}
PARSER = hook_io.build_parser(Path(__file__).stem, FLAGS)
CODER = "coder"


def _own_script(cwd: str, base: str | None) -> Callable[[str], bool]:
    # B2: the script resolves under a unit worktree; relative needs a followed working folder.
    def inside(path: str) -> bool:
        if not os.path.isabs(cwd) or (base is None and not os.path.isabs(path)):
            return False
        return jail._in_unit_worktree(shell._abs(path, base or cwd), cwd)

    return inside


def _coder_hygiene(call: jail.CoderCall, done: AdmittedCommand, base: str) -> str | None:
    # 228 S3b: the tripwires and hygiene rules an admitted coder command can still meet.
    tokens = jail.admitted_tokens(call.script, done)
    if jail.claude_word(done, base):
        return shell.R_CLAUDE_PATH
    reason: str | None = None
    if done.family == "git":
        reason = shell._git_reason(tokens, [], main=False)
    elif done.family == "rm":
        reason = shell._rm_reason(tokens[1:])
    if reason is not None:
        return shell.R_UNSUPPORTED if reason == shell._FALLBACK else reason
    own = _own_script(call.cwd, base)
    # B2, 104, RCP: a python script runs from a unit worktree, or is the citation helper.
    script = done.script.text if done.family == "python" and done.script else None
    if script is not None and not own(script) and not shell._is_cite(tokens, own):
        return shell.R_INLINE
    paths = [t.text for t in (*done.reads, *done.writes)]
    if done.family == "rsync" and shell._rsync_remote(["--", *paths]):
        return shell.R_RSYNC_REMOTE
    options = {o.text for o in done.options}
    if done.family == "find" and any(o in shell._FIND_DENY or "-fprint" in o for o in options):
        return shell.R_FIND_WRITE
    return None


def _coder_reason(hook_input: dict[str, object]) -> str | None:
    call = jail.coder_call(hook_input)
    got = call.got
    if not isinstance(got, Admitted):
        return jail.coder_refusal(call)  # 228 S3b: the refusal names the word; no regex fallback.
    base = jail.coder_base(call, got)
    _, commands = jail.lead_cd(got)
    return next((r for c in commands if (r := _coder_hygiene(call, c, base))), None)


def judge(hook_input: dict[str, object], flags: argparse.Namespace) -> str | None:
    command = hook_io.text(hook_io.tool_input(hook_input), "command")
    agent = hook_io.agent(hook_input)
    if agent == CODER:
        return _coder_reason(hook_input)
    chain = shell.worker_parse(command)
    if chain is None:
        return shell.R_UNSUPPORTED
    for segment in chain.tokens:
        reason = shell._segment_reason(segment, 0, main=False)
        if reason == shell._FALLBACK:
            reason = shell._regex_tripwire(command)
        if reason:
            return reason
    if not all(chain.segments):
        return shell.R_ENV
    cwd = hook_io.text(hook_input, "cwd")
    bases = shell.chain_bases(chain, cwd, jail.DIR_CHANGE_CMDS)
    for i, segment in enumerate(chain.segments):
        words = shell._raw_words(chain.raws[i])[len(chain.tokens[i]) - len(segment) :]
        base = bases[i] if bases else cwd
        reason = shell._worker_hygiene(segment, agent, words, base)
        if reason:
            return reason
    return None


decide, main = hook_io.entrypoint(judge, TOOLS, PARSER)

if __name__ == "__main__":
    sys.exit(main())
