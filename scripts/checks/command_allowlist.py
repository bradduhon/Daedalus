# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0044: every Bash segment runs a command the --allow list names; nothing else runs.
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from lib import hook_io, jail, shell  # noqa: E402
from lib.audit import project_root  # noqa: E402

TOOLS: frozenset[str] = frozenset({"Bash"})
NAMES = frozenset({"append_ledger", "git", "gh", "gitleaks", "read", "train", "inspect"})
FLAGS: dict[str, hook_io.Flag] = {"--allow": hook_io.Flag(values=NAMES, many=True)}
PARSER = hook_io.build_parser(Path(__file__).stem, FLAGS)
_SCRIPTS = os.path.realpath(Path(__file__).resolve().parents[1])
# 0060: the train class, script to its admitted first arguments; stop, resume and the
# operator's exception record stay with the main session.
TRAIN_SCRIPTS: dict[str, frozenset[str] | None] = {
    "daedalus_train.py": frozenset(
        {"progress", "choice", "plan", "verdict", "state", "step", "check-reply", "model"}
    ),
    "daedalus_workspace.py": frozenset({"create", "lock", "refresh", "finish"}),
    "daedalus_doctor.py": frozenset({"--print-cache-dir"}),
    "audit_report.py": None,
    "validate_plan.py": None,
}
# 0060: the inspect class is the auditor's read-only set plus the unit-descent check.
INSPECT_GIT = shell.READ_ONLY_GIT | {"merge-base"}
R_ORCHESTRATOR_BASH = (
    "the orchestrator's Bash runs only daedalus_train.py, daedalus_workspace.py create, lock, "
    "refresh and finish, daedalus_doctor.py --print-cache-dir, audit_report.py and "
    "validate_plan.py by their absolute plugin path, and read-only inspection with git reads "
    "(0060). Next: use those only; a stop, a resume, an exception record, a push and a merge "
    "into main belong to the main session and the operator."
)
# issue 63, pin C3 -> C4: a train script's --repo or --cwd is the project root of the hook cwd.
REPO_FLAGS = ("--repo", "--cwd")
R_TRAIN_REPO = (
    "{flag} {given} is not the project root of the working directory ({root}). "
    "Next: run the command from {given}, or pass {flag} {root}."
)


def _reason(allowed: frozenset[str]) -> str:
    if allowed == {"append_ledger", "git", "read"}:
        return jail.R_DOCS_BASH
    if allowed == {"git", "gh", "gitleaks"}:
        return jail.R_CONDUCTOR_BASH
    if allowed == {"train", "inspect"}:
        return R_ORCHESTRATOR_BASH
    names = ", ".join(sorted(allowed)) or "no command"
    return f"Bash is limited to {names}. Next: use those only."


def _repo_values(args: list[str]) -> list[tuple[str, str]] | None:
    # issue 63: every --repo/--cwd value, joined or split; None for an abbreviation or no value.
    found: list[tuple[str, str]] = []
    for idx, arg in enumerate(args):
        flag, eq, value = arg.partition("=")
        if flag in REPO_FLAGS:
            if not eq:
                value = args[idx + 1] if idx + 1 < len(args) else ""
            if not value:
                return None
            found.append((flag, value))
        elif len(flag) > 2 and any(f.startswith(flag) for f in REPO_FLAGS):
            return None  # argparse would expand --rep to --repo, out of this check's sight.
    return found


def train_repo_reason(segment: list[str], cwd: str) -> str | None:
    # issue 63, pin C3 -> C4: names both paths; None when every value is the project root.
    root = os.path.realpath(project_root(cwd)) if os.path.isabs(cwd) else ""
    values = _repo_values(segment[2:])
    if values is None:
        return R_TRAIN_REPO.format(flag="--repo", given="(unreadable)", root=root or cwd)
    for flag, given in values:
        if not root or os.path.realpath(os.path.join(cwd, given)) != root:
            return R_TRAIN_REPO.format(flag=flag, given=given, root=root or cwd)
    return None


def train_script_ok(segment: list[str], cwd: str | None = None) -> bool:
    # 0060: `python3 <absolute plugin script> <admitted first argument> ...`, nothing else.
    if len(segment) < 2 or segment[0] != "python3":
        return False
    script = segment[1]
    if not script.startswith("/") or ".." in script.split("/"):
        return False
    real = os.path.realpath(script)
    name = os.path.basename(real)
    if os.path.dirname(real) != _SCRIPTS or name not in TRAIN_SCRIPTS:
        return False
    first = TRAIN_SCRIPTS[name]
    if first is not None and (len(segment) < 3 or segment[2] not in first):
        return False
    return cwd is None or train_repo_reason(segment, cwd) is None


def _read_roots(cwd: str) -> tuple[list[str], str]:
    # 0084: the read class reaches the charter root and the project's docs/, scratch included.
    base = str(project_root(cwd))
    charter = hook_io.hook_config(cwd).charter_root
    roots = [f"{base}/docs"] + ([str(charter)] if charter else [])
    return roots, base


def judge(hook_input: dict[str, object], flags: argparse.Namespace) -> str | None:
    allowed: frozenset[str] = frozenset(flags.allow or ())
    command = hook_io.text(hook_io.tool_input(hook_input), "command")
    chain = shell.worker_parse(command)
    if chain is None:
        return shell.R_UNSUPPORTED
    cwd = hook_io.text(hook_input, "cwd")
    for segment, raw in zip(chain.segments, chain.raws, strict=True):
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
        if "read" in allowed and name in shell.DOCS_READS:
            roots, base = _read_roots(cwd)
            if shell.docs_read_ok(segment, raw, roots, cwd, base):
                continue
        if "train" in allowed and train_script_ok(segment):
            mismatch = train_repo_reason(segment, cwd)
            if mismatch is not None:
                return mismatch
            continue
        if "inspect" in allowed and jail._read_only_segment(
            segment, INSPECT_GIT, cwd, hook_io.hook_charter(cwd)
        ):
            continue
        return _reason(allowed)
    return None


decide, main = hook_io.entrypoint(judge, TOOLS, PARSER)

if __name__ == "__main__":
    sys.exit(main())
