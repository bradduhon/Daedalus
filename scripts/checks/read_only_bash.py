# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0044: every Bash segment is a read-only command or a git read from the named grant.
# 0109, spec 3.1: --test-runner adds one pytest form bound to the audit folder or a unit worktree.
from __future__ import annotations

import argparse
import os
import re
import sys
from collections.abc import Callable
from pathlib import Path
from typing import NamedTuple

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from lib import hook_io, jail, passes, shell, train_state  # noqa: E402
from lib.admit import Admitted, Refusal, Role, admit_role  # noqa: E402
from lib.audit import project_root  # noqa: E402
from lib.shparse import Script, parse, walk  # noqa: E402
from lib.workspace import WORKTREES_DIR, audit_unit, worktree_path  # noqa: E402

TOOLS: frozenset[str] = frozenset({"Bash"})
RUNNERS = frozenset({"audit", "unit"})
FLAGS: dict[str, hook_io.Flag] = {
    "--git": hook_io.Flag(values=frozenset(shell.GIT_SETS)),
    "--test-runner": hook_io.Flag(values=RUNNERS),
    # 0186, 0188: the terraform rulebook's two checks, bare or wrapped, under their manifest gates.
    "--terraform": hook_io.Flag(),
}
PARSER = hook_io.build_parser(Path(__file__).stem, FLAGS)
PYTEST = ("python3", "-m", "pytest")
R_TEST_RUN = (
    "the {runner} test run is python3 -m pytest <absolute paths under {where}> -q "
    "[-p no:cacheprovider] [--rootdir {rootdir}] [-k <expr>] (0109). "
    "Next: send that form only, one path or node id per test file."
)
R_TEST_RUN_NO_TRAIN = (
    "the {runner} test run needs an active train in this repository, and none is marked (0109). "
    "Next: run tests only inside a train's audit or verify step."
)
R_CD_CHAIN = (
    "a read chain changes folder only with one leading cd <absolute path> joined by &&, and no "
    "git command, test run or terraform check follows it (spec 7.1, 0188). Next: drop the cd "
    "and pass absolute paths."
)
# spec 7.1: read-only flags jail._GIT_GRAMMAR lacks, judged as a stand-in flag its row admits,
# so a flag that takes a value still swallows the same next token.
LOG_STAND_INS = {"--first-parent": "--oneline", "--graph": "--oneline"}
_GREP_PERL = re.compile(r"-[A-Za-z]*P[A-Za-z]*")


def _log_ok(args: list[str], cwd: str) -> bool:
    return jail._GIT_GRAMMAR["log"]([LOG_STAND_INS.get(a, a) for a in args], cwd)


def _grep_ok(args: list[str], cwd: str) -> bool:
    # spec 7.1: -P reads as -E does; it stands in as n inside its short-flag bundle.
    perl = [a.replace("P", "n") if _GREP_PERL.fullmatch(a) else a for a in args]
    return jail._GIT_GRAMMAR["grep"](perl, cwd)


def _branch_ok(args: list[str], cwd: str) -> bool:
    # spec 7.1: with --list every operand is a pattern git lists by, never a branch it creates.
    flags = [a for a in args if a.startswith("-")] if "--list" in args else args
    return jail._GIT_GRAMMAR["branch"](flags, cwd)


READ_GIT_GRAMMAR: dict[str, Callable[[list[str], str], bool]] = {
    **jail._GIT_GRAMMAR,
    "log": _log_ok,
    "grep": _grep_ok,
    "branch": _branch_ok,
}


R_TEST_RUN_AUDIT = (
    "the unit test run never reads the audit worktree {tree}; it holds the auditor's tests, "
    "not a coder's unit (spec 4). Next: run the tests under the unit worktree you verify, "
    "one absolute path per test file."
)


class Bound(NamedTuple):
    roots: tuple[str, ...]
    rootdir: str


def _reason(grant: str | None) -> str:
    if grant == "read-only":
        return jail.R_AUDITOR_BASH
    if grant == "specialist":
        return jail.R_SPECIALIST_BASH
    subs = ", ".join(sorted(shell.GIT_SETS[grant])) if grant else ""
    reads = f"read-only inspection and git {subs}" if subs else "read-only inspection"
    return f"Bash is limited to {reads}. Next: use those only."


def _pytest_args(tokens: list[str]) -> list[str] | None:
    # issue 56: the arguments of a pytest run in any spelling the coder grammar admits.
    name = shell._base(tokens[0])
    if name in {"pytest", "py.test"}:
        return tokens[1:]
    if name.startswith("python") and tokens[1:3] == ["-m", "pytest"]:
        return tokens[3:]
    return None


def _bounds(runner: str, cwd: str) -> list[Bound] | None:
    # pin C4 -> C1: the audit worktree is <repo>/.claude/worktrees/<train-id>-audit.
    repo = project_root(cwd)
    train = train_state.active_train(repo)
    if train is None:
        return None
    if runner == "audit":
        tree = str(worktree_path(repo, f"{train}-audit"))
        scratch = str(repo / "docs" / ".tmp" / "daedalus" / train / "audit")
        return [Bound((scratch, f"{tree}/tests/adversarial"), tree)]
    home = str(repo / WORKTREES_DIR)
    # spec 4: the audit worktree is a recorded unit, never a unit test run's bound.
    paths = [
        str(u.get("path") or "") for u in _units(repo, train) if not train_state.is_audit_unit(u)
    ]
    return [Bound((p,), p) for p in paths if os.path.isabs(p) and shell._under(p, home)]


def _units(repo: Path, train: str) -> list[dict[str, object]]:
    try:
        return train_state.units(train_state.load(repo, train))
    except train_state.TrainStateError:
        return []


def _audit_tree(tokens: list[str], cwd: str) -> str | None:
    # spec 4: the audit worktree a unit test run names, by its flag or its <train-id>-audit name.
    repo = project_root(cwd)
    train = train_state.active_train(repo)
    if train is None:
        return None
    trees = {str(worktree_path(repo, audit_unit(train)))}
    trees |= {str(u.get("path") or "") for u in _units(repo, train) if train_state.is_audit_unit(u)}
    for arg in _pytest_args(tokens) or []:
        file = arg.split("::", 1)[0]
        for tree in sorted(t for t in trees if os.path.isabs(t)):
            if os.path.isabs(file) and shell._under(file, tree):
                return tree
    return None


def _path_ok(arg: str, roots: tuple[str, ...]) -> bool:
    # 0109: a path or node id; the file part is absolute, has no .., and resolves under a root.
    file = arg.split("::", 1)[0]
    if not os.path.isabs(file) or ".." in file.split("/"):
        return False
    return any(shell._under(file, root) for root in roots)


def _test_run_ok(tokens: list[str], bound: Bound) -> bool:
    if tuple(tokens[:3]) != PYTEST:
        return False
    args = tokens[3:]
    seen: set[str] = set()
    paths: list[str] = []
    i = 0
    while i < len(args):
        arg = args[i]
        if arg in {"-p", "--rootdir", "-k"} and arg not in seen and i + 1 < len(args):
            value = args[i + 1]
            if arg == "-p" and value != "no:cacheprovider":
                return False
            if arg == "--rootdir" and not (
                os.path.isabs(value) and os.path.realpath(value) == os.path.realpath(bound.rootdir)
            ):
                return False
            seen.add(arg)
            i += 2
        elif arg == "-q" and arg not in seen:
            seen.add(arg)
            i += 1
        elif arg.startswith("-"):
            return False
        else:
            paths.append(arg)
            i += 1
    return "-q" in seen and bool(paths) and all(_path_ok(p, bound.roots) for p in paths)


def _test_run_reason(tokens: list[str], runner: str, cwd: str) -> str | None:
    bounds = _bounds(runner, cwd)
    if bounds is None:
        return R_TEST_RUN_NO_TRAIN.format(runner=runner)
    tree = _audit_tree(tokens, cwd) if runner == "unit" else None
    if tree is not None:
        return R_TEST_RUN_AUDIT.format(tree=tree)
    if any(_test_run_ok(tokens, bound) for bound in bounds):
        return None
    if runner == "audit" and bounds:
        where, rootdir = " or ".join(bounds[0].roots), bounds[0].rootdir
    else:
        where, rootdir = "one unit worktree this train records", "<that worktree>"
    return R_TEST_RUN.format(runner=runner, where=where, rootdir=rootdir)


def _terraform_reason(tokens: list[str], cwd: str) -> str | None:
    # 0186, 0188: the command_allowlist terraform class verbatim; no other form widens.
    from checks.command_allowlist import terraform_reason, wrapped_terraform_reason

    if tokens[:1] == ["terraform"]:
        return terraform_reason(tokens, cwd)
    return wrapped_terraform_reason(tokens, cwd)


def _terraform_form(tokens: list[str]) -> bool:
    return bool(tokens) and (tokens[0] == "terraform" or shell._base(tokens[0]) == shell.CONFINE)


def role(agent: str, grant: str | None, runner: str | None, terraform: bool) -> Role:
    # 228 S3: the hook flags name the grant; admit judges by the read Role they build.
    git = (shell.GIT_SETS[grant], READ_GIT_GRAMMAR) if grant else None
    wrappers = frozenset({shell.CONFINE}) if terraform else frozenset()
    # 0230: the unit test-runner grant is the verifier's; it carries the claims call too.
    claims = runner == "unit"
    return Role(
        agent,
        shell.READ_ONLY_CMDS,
        git,
        runner=runner,
        terraform=terraform,
        wrappers=wrappers,
        claims=claims,
    )


def _refusal(
    script: Script, refused: Refusal, grant: str | None, runner: str | None, flags: tuple[bool, str]
) -> str:
    # 228 S3: the grammar's refusal under the constant this check showed for its class (SA-7).
    terraform, cwd = flags
    cmd = jail.refused_command(script, refused)
    tokens = jail.literal_tokens(cmd)
    name = shell.command_family(tokens[0]) if tokens else ""
    word = jail.refused_word(cmd, refused)
    constant: str | None = None
    if terraform and _terraform_form(tokens):
        constant = _terraform_reason(tokens, cwd)
    elif runner is not None and tokens and _pytest_args(tokens) is not None:
        constant = _test_run_reason(tokens, runner, cwd)
    elif name in shell.SEARCH_CMDS and jail.rewritten(word):
        constant = jail.R_RG_OPAQUE
    elif name == "rg" and jail.rg_program(tokens[1:]):
        constant = jail.R_RG_PROGRAM
    elif name in shell.READ_ONLY_WRITE_OPTS and jail.rewritten(word):
        constant = shell.R_READ_EXPANSION
    elif name in jail.DIR_CHANGE_CMDS:
        constant = R_CD_CHAIN
    return jail.refusal_text(refused, constant or _reason(grant))


def _later(
    parsed: tuple[Script, str],
    got: Admitted,
    grant: str | None,
    runner: str | None,
    flags: tuple[bool, str],
) -> str | None:
    # 228 S3: the checks that read the Admitted record: the cd chain, git -C, rg programs,
    # the test run's train bounds and the terraform class's manifest gates.
    terraform, cwd = flags
    script, command = parsed
    by_span = {cmd.span: cmd for cmd, _ in walk(script)}
    commands = list(got.commands)
    moved = bool(commands) and commands[0].family == "cd"
    for done in commands[1:] if moved else commands:
        tokens = jail.literal_tokens(by_span.get(done.span))
        quoted = command[done.span[0] : done.span[1]]
        if moved and (done.family in {"git", "terraform"} or done.module or done.wrappers):
            return jail.refused_at(R_CD_CHAIN, f"{done.word.text} after a leading cd", quoted)
        options = [o.text for o in done.options]
        if done.family == "rg" and jail.rg_program(options):
            return jail.refused_at(jail.R_RG_PROGRAM, "an rg option runs a program", quoted)
        if terraform and _terraform_form(tokens):
            reason = _terraform_reason(tokens, cwd)
        elif runner is not None and done.module is not None:
            reason = _test_run_reason(tokens, runner, cwd)
        else:
            continue
        if reason is not None:
            return jail.refused_at(reason, "the run is off its bounds", quoted)
    outside = jail.git_dir_outside(got, cwd, hook_io.hook_charter(cwd))
    return None if outside is None else f"{_reason(grant)} {outside}"


def judge(hook_input: dict[str, object], flags: argparse.Namespace) -> str | None:
    grant: str | None = flags.git
    runner: str | None = flags.test_runner
    terraform: bool = flags.terraform
    cwd = hook_io.text(hook_input, "cwd")
    command = hook_io.text(hook_io.tool_input(hook_input), "command")
    agent = hook_io.agent(hook_input)
    script = parse(command)
    for cmd, _ in walk(script):
        args = _pytest_args(jail.literal_tokens(cmd)) if cmd.words else None
        if args is not None and any(a.startswith("--basetemp") for a in args):
            return jail.R_BASETEMP_AGENT.format(agent=agent)
    got = admit_role(script, role(agent, grant, runner, terraform), cwd, text=command)
    if isinstance(got, Refusal) and passes.pass_admits(
        project_root(cwd), agent, command, cwd, hook_input
    ):
        return None  # 233: a sealed pass for this exact call, consumed and recorded.
    if isinstance(got, Refusal):
        return _refusal(script, got, grant, runner, (terraform, cwd))
    return _later((script, command), got, grant, runner, (terraform, cwd))


decide, main = hook_io.entrypoint(judge, TOOLS, PARSER)

if __name__ == "__main__":
    sys.exit(main())
