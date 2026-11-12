# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0048: a coder's test command starts with the kernel wrapper. Issue 86: on a kernel where the
# doctor's probe finds no Landlock, no seccomp filter or an error, the test command is refused.
# 228 S3b: the call is admitted on its parse; the checks below read the Admitted record.
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import daedalus_confine  # noqa: E402
from checks import command_allowlist, shell_tripwires  # noqa: E402
from lib import hook_io, jail, shell  # noqa: E402
from lib.admit import Admitted, AdmittedCommand  # noqa: E402
from lib.project_root import project_root  # noqa: E402
from lib.shparse import parse, walk  # noqa: E402

TOOLS: frozenset[str] = frozenset({"Bash"})
FLAGS: dict[str, hook_io.Flag] = {}
PARSER = hook_io.build_parser(Path(__file__).stem, FLAGS)
R_CONFINE = (
    "a test command runs under the kernel wrapper on this machine, so its writes stay in the "
    f"unit worktree and it opens no network socket (0048). {shell.CONFINE_NEXT}"
)
R_CONFINE_UNIT = (
    "the kernel wrapper's --unit names a unit worktree of this repository, and the command runs "
    f"from inside that worktree (0048). Next: cd <your unit worktree> && {shell.CONFINE_PATH} "
    "--unit <that worktree> -- <the command>."
)


def _declared_tests(cwd: str) -> frozenset[tuple[str, ...]]:
    # 0048, 0192, 228 S3b: each command of each unit_test_cmd entry as parsed words, bar its cd.
    if not os.path.isabs(cwd):
        return frozenset()
    loaded = jail._manifest_at(os.path.realpath(str(project_root(Path(cwd)))))
    commands = () if isinstance(loaded, str) else loaded.unit_test_cmd or ()
    found: set[tuple[str, ...]] = set()
    for command in commands:
        for cmd, _ in walk(parse(command)):
            # 269: an operator's declared form as all-literal words, as admit reads one (B2).
            tokens = [w.literal for w in cmd.words if w.literal is not None]
            whole = bool(tokens) and len(tokens) == len(cmd.words)
            if whole and shell.command_family(tokens[0]) not in jail.DIR_CHANGE_CMDS:
                found.add(tuple(tokens))
    return frozenset(found)


def _is_test(done: AdmittedCommand, tokens: list[str], base: str, cwd: str) -> bool:
    # 0048, Plan 6 section 10.3: a declared unit_test_cmd, a worktree file by its path, a
    # worktree python script (104), or a runner with its test verb.
    form = jail.install_form(tokens)
    if form is not None and form.frozen:
        return False  # 228 S3d: 0196 frozen install needs the network, so never wrapped.
    if tuple(tokens) in _declared_tests(cwd):
        return True
    if done.script is not None and done.script.span == done.word.span:
        return True  # 228 S3d: the path word S3c typed as a script runs under the wrapper (0048).
    if done.family == "python" and done.script is not None:
        return shell_tripwires._own_script(cwd, base)(done.script.text)
    return shell._tester_runner_ok(done.family, tokens)


def _terraform_reason(done: AdmittedCommand, base: str, cwd: str) -> str | None:
    # 0158, 0159: a coder's admitted form meets the terraform class's switches, its fmt
    # folder sits in a unit worktree; admit has refused every other form.
    if done.family != "terraform" or done.subcommand is None:
        return None
    for path in (r.text for r in done.reads if r != done.unit):
        target = shell._abs(path, base)
        if not os.path.isabs(cwd) or jail._unit_parts(target, cwd) is None:
            return shell.R_TERRAFORM_OPERATOR
    chdir = [f"-chdir={done.cd_target.text}"] if done.cd_target is not None else []
    sub = done.subcommand.text
    # 184: the init form meets the same switches, and only wrapped.
    form = list(shell.TERRAFORM_INIT) if sub == "init" else [sub] if sub == "validate" else []
    form = form or ["fmt", "-check"]
    wrapped = done.unit is not None
    reason = command_allowlist.terraform_reason([done.word.text, *chdir, *form], cwd, wrapped)
    # 0265: validate runs from the run after hand-in; under the wrapper it never reaches a provider.
    return reason or (shell.R_TERRAFORM_VALIDATE_RUN if sub == "validate" else None)


def _wrapped_reason(unit: str, base: str, cwd: str) -> str | None:
    parts = jail._unit_parts(unit, cwd) if os.path.isabs(unit) and os.path.isabs(cwd) else None
    inside = shell._under(os.path.realpath(base), os.path.realpath(unit))
    return None if parts is not None and len(parts) == 1 and inside else R_CONFINE_UNIT


def judge(hook_input: dict[str, object], flags: argparse.Namespace) -> str | None:
    call = jail.coder_call(hook_input)
    got = call.got
    if not isinstance(got, Admitted):
        return jail.coder_refusal(call)
    cwd = call.cwd
    # 0048, issue 86: an unusable kernel refuses every test command, wrapped or bare.
    kernel = daedalus_confine.unusable(daedalus_confine.kernel_support())
    base = jail.coder_base(call, got)
    _, commands = jail.lead_cd(got)
    for done in commands:
        refused = _terraform_reason(done, base, cwd)
        if refused:
            return refused
        if done.unit is not None:
            reason = _wrapped_reason(done.unit.text, base, cwd) or kernel
        else:
            tokens = jail.admitted_tokens(call.script, done)
            reason = (kernel or R_CONFINE) if _is_test(done, tokens, base, cwd) else None
        if reason:
            return reason
    return None


decide, main = hook_io.entrypoint(judge, TOOLS, PARSER)

if __name__ == "__main__":
    sys.exit(main())
