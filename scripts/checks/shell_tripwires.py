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
from lib.admit import Admitted, AdmittedCommand, Refusal, role_for  # noqa: E402
from lib.shparse import BraceList, Literal, Param, Script, Tilde, Word  # noqa: E402

TOOLS: frozenset[str] = frozenset({"Bash"})
FLAGS: dict[str, hook_io.Flag] = {}
PARSER = hook_io.build_parser(Path(__file__).stem, FLAGS)
CODER = "coder"
# 8.5, 228 tail: the refusal classes a worker's shell check names before its command check.
_WORKER_CLASSES = frozenset(
    {shell.R_UNSUPPORTED, shell.R_CLAUDE_PATH, shell.R_INLINE, shell.R_ENV, shell.R_HYGIENE}
    | {shell.R_VARIABLE, shell.R_ARCHIVE, shell.R_SHELL_VARS, shell.R_SHELL_STATE}
    | {shell.R_CONFINE_FORM}
)


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
    reason = jail.admitted_tripwire(call.script, done)
    if reason is not None:
        return reason
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


def _own_python(agent: str, tokens: list[str]) -> bool:
    # 0060, 0230, F1: the plugin script a role's own table admits by its python row.
    from checks.command_allowlist import train_script_ok

    if agent == "charter-docs":
        return shell._is_append_ledger(tokens)
    if agent == "orchestrator":
        return train_script_ok(tokens)
    return agent == "verifier" and shell.claims_ok(tokens)


def _ledger_literal(refused: Refusal, agent: str) -> str | None:
    # F1, O7, 269: charter-docs refused at ${CLAUDE_PLUGIN_ROOT}, which agent Bash leaves empty.
    named = agent == "charter-docs" and "CLAUDE_PLUGIN_ROOT" in refused.params
    return shell.R_LEDGER_LITERAL if named else None


def _built_word(word: Word) -> bool:
    # O4, 228 tail: a parameter, ~, brace list or $'...' part, or $ { } outside single quotes.
    for part in word.parts:
        if isinstance(part, Param | Tilde | BraceList):
            return True
        if isinstance(part, Literal) and part.quoted != "'":
            if part.quoted in ("$'", '$"') or set("${}") & set(part.text):
                return True
    return False


def _typed_hygiene(script: Script, done: AdmittedCommand, agent: str, base: str) -> str | None:
    # 8.5, 228 tail: the tripwires and hygiene an admitted record meets, read from its parse.
    tokens = jail.admitted_tokens(script, done)
    if jail.claude_word(done, base):
        return shell.R_CLAUDE_PATH
    if done.family == "assignment" or any(
        not shell._SAFE_ENV.match(a.text) for a in done.assignments
    ):
        return shell.R_ENV
    families = {done.family, *(shell.command_family(w.text) for w in done.wrappers)}
    if families & shell.ARCHIVE_CMDS:
        return shell.R_ARCHIVE
    if done.family in shell.SHELL_VAR_CMDS:
        return shell.R_SHELL_VARS
    if done.family in shell.SHELL_STATE_CMDS:
        return shell.R_SHELL_STATE
    reason = jail.admitted_tripwire(script, done)
    if reason is not None:
        return reason
    if done.family == "git":
        sub, args, globals_ = shell._git_split(tokens)
        writes = sub == "config" and [a for a in args if a.startswith("-")] not in (
            ["--get"],
            ["--list"],
        )
        if shell._git_config_override(globals_) or writes:
            return shell.R_GIT_CONFIG
    paths = [t.text for t in (*done.reads, *done.writes)]
    if done.family == "rsync" and shell._rsync_remote(["--", *paths]):
        return shell.R_RSYNC_REMOTE
    options = {o.text for o in done.options}
    if done.family == "find" and any(o in shell._FIND_DENY or "-fprint" in o for o in options):
        return shell.R_FIND_WRITE
    wrapped = [w for w in done.wrappers if shell.command_family(w.text) != shell.CONFINE]
    runner = done.family in shell.WORKER_WRAPPERS or done.family == "python"
    if wrapped or (runner and not _own_python(agent, tokens)):
        if wrapped or not shell._tester_runner_ok(done.family, tokens):
            return shell.R_INLINE
    inner = shell.js_inner(tokens)
    if inner and shell._base(inner[0]) == "bun" and shell.bun_inline(inner):
        return shell.R_INLINE
    if inner and shell.command_family(inner[0]) in shell.WORKER_WRAPPERS:
        if not shell._tester_runner_ok(shell._base(inner[0]), inner):
            return shell.R_INLINE
    exempt = shell._exempt_indices(tokens) | ({1} if _own_python(agent, tokens) else set())
    words = jail.admitted_words(script, done)
    if any(_built_word(w) for i, w in enumerate(words) if i not in exempt):
        return shell.R_HYGIENE
    return None


def _worker_class(refused: Refusal, agent: str, cwd: str) -> str | None:
    # 8.5, 228 tail: the shell classes this check names; an option-row class (find, rsync, a
    # network word) and a python call of a role with its own python row are its command check's.
    constant = jail.refusal_constant(None, refused, cwd)
    role = role_for(agent)
    python_row = role.ledger or role.train or role.claims or role.runner in ("audit", "unit")
    if constant == shell.R_INLINE and refused.family == "python" and python_row:
        return None
    return constant if constant in _WORKER_CLASSES else None


def _worker_reason(hook_input: dict[str, object], agent: str) -> str | None:
    # 228 tail: a refusal of the agent's own grammar is named by its class constant (SA-7); with
    # none, the admitted record main's grammar types meets the tripwires, else the command check.
    command = hook_io.text(hook_io.tool_input(hook_input), "command")
    cwd = hook_io.text(hook_input, "cwd")
    script, own = jail._admission(command, agent, cwd)
    if isinstance(own, Refusal):
        constant = _ledger_literal(own, agent) or _worker_class(own, agent, cwd)
        if constant:
            return jail.refusal_text(own, constant)
    got = jail.held_admission(hook_input)
    if not isinstance(got, Admitted):
        return None
    base = jail.admitted_base(script, got, cwd)
    _, commands = jail.lead_cd(got)
    return next((r for c in commands if (r := _typed_hygiene(script, c, agent, base))), None)


def judge(hook_input: dict[str, object], flags: argparse.Namespace) -> str | None:
    agent = hook_io.agent(hook_input)
    if agent == CODER:
        return _coder_reason(hook_input)
    return _worker_reason(hook_input, agent)


decide, main = hook_io.entrypoint(judge, TOOLS, PARSER)

if __name__ == "__main__":
    sys.exit(main())
