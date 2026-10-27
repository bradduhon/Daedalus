# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0044: every Bash segment runs a command the --allow list names; nothing else runs.
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from checks.read_only_bash import read_segment_ok  # noqa: E402
from lib import hook_io, jail, shell  # noqa: E402
from lib.audit import project_root  # noqa: E402
from lib.manifest import ManifestError, manifest_path  # noqa: E402
from lib.manifest import load as load_manifest  # noqa: E402

TOOLS: frozenset[str] = frozenset({"Bash"})
NAMES = frozenset(
    {"append_ledger", "git", "gh", "gitleaks", "read", "train", "inspect", "terraform"}
)
FLAGS: dict[str, hook_io.Flag] = {"--allow": hook_io.Flag(values=NAMES, many=True)}
PARSER = hook_io.build_parser(Path(__file__).stem, FLAGS)
_SCRIPTS = os.path.realpath(Path(__file__).resolve().parents[1])
# 0060, 0119: the train class, script to its admitted first arguments; stop, resume, reaudit
# and the operator's exception record stay with the main session. W3.2: summary is the recipe's.
TRAIN_SCRIPTS: dict[str, frozenset[str] | None] = {
    "daedalus_train.py": frozenset(
        {"progress", "choice", "plan", "verdict", "state", "step", "check-reply", "model"}
        | {"ledger", "summary"}
        # 0156: the contract skip check the orchestrator runs before any contract-spec start.
        | {"contract"}
    ),
    "daedalus_workspace.py": frozenset({"create", "lock", "refresh", "finish"}),
    "daedalus_doctor.py": frozenset({"--print-cache-dir", "--check-tools"}),
    "audit_report.py": None,
    "validate_plan.py": None,
    # Pins MAP -> REQ, SRC -> MAP: the dependency map, and both frozen source forms (flag D).
    "daedalus_map.py": frozenset({"--repo"}),
    "freeze_sources.py": frozenset({"--train", "--verify", "--baselines-only"}),
}
# 0060: the inspect class is the auditor's read-only set plus the unit-descent check.
INSPECT_GIT = shell.READ_ONLY_GIT | {"merge-base"}
R_ORCHESTRATOR_BASH = (
    "the orchestrator's Bash runs only daedalus_train.py with its train subcommands and ledger, "
    "daedalus_workspace.py create, lock, refresh and finish, daedalus_doctor.py "
    "--print-cache-dir and --check-tools, audit_report.py, validate_plan.py, daedalus_map.py "
    "--repo and freeze_sources.py --train, --baselines-only or --verify by their absolute "
    "plugin path, and "
    "read-only inspection with git reads, date -u and sed -n line ranges (0060, 0119). "
    "Next: use those only; a stop, a resume, a reaudit, an exception record, a push and a merge "
    "into main belong to the main session and the operator."
)
# spec 7.1: date prints the clock in UTC; -s, --set and a bare MMDDhhmm operand would set it.
DATE_UTC = frozenset({"-u", "--utc", "--universal"})
# issue 63, pin C3 -> C4: a train script's --repo or --cwd is the project root of the hook cwd.
REPO_FLAGS = ("--repo", "--cwd")
R_TRAIN_REPO = (
    "{flag} {given} is not the project root of the working directory ({root}). "
    "Next: run the command from {given}, or pass {flag} {root}."
)
# MAP -> REQ: the map writes only into the active train's map folder, else the train scratch.
MAP_SCRIPT = "daedalus_map.py"
OUT_FLAG = "--out"
R_MAP_OUT = (
    "daedalus_map.py writes its map only into {allowed}; --out {given} is outside it. "
    "Next: pass --out {allowed}."
)


# 0132: the terraform class, `terraform [-chdir=<folder in the project>] fmt -check | validate`.
TERRAFORM_FORMS = (("fmt", "-check"), ("validate",))
R_TERRAFORM = (
    "the terraform class runs only `terraform fmt -check` and `terraform validate`, each with an "
    "optional -chdir=<absolute folder inside the project> (0132), and validate only while "
    "features.terraform_validate is true (0158). Next: send one of those forms; "
    "init, plan, apply and every other subcommand stay with the operator."
)
R_TERRAFORM_VALIDATE_OFF = (
    "features.terraform_validate is not true in {manifest}, so the terraform class refuses "
    "`terraform validate`, which would start the provider programs under .terraform/providers "
    "(0158). Next: judge the files by reading them and mark the validate check N/A, or ask the "
    "operator to set features.terraform_validate to true in service-manifest.json."
)
R_TERRAFORM_OFF = (
    "features.terraform_tools is false in {manifest}, so the terraform class runs nothing "
    "(0132). Next: judge the Terraform files by reading them, and report the skipped checks."
)
R_TERRAFORM_MANIFEST = (
    "the service manifest could not be read, so the terraform class runs nothing (0132): {cause}"
)


def terraform_reason(segment: list[str], cwd: str) -> str | None:
    # 0132: None admits the segment; a refusal names the form or the manifest switch.
    if segment[:1] != ["terraform"]:
        return R_TERRAFORM  # 0132: the binary on PATH only, never a path to another binary.
    rest = segment[1:]
    chdir = rest[0].removeprefix("-chdir=") if rest[:1] and rest[0].startswith("-chdir=") else None
    if chdir is not None:
        rest = rest[1:]
    if tuple(rest) not in TERRAFORM_FORMS or not os.path.isabs(cwd):
        return R_TERRAFORM
    root = os.path.realpath(project_root(cwd))
    if chdir is not None:
        real = os.path.realpath(chdir)
        if not os.path.isabs(chdir) or ".." in chdir.split("/") or not shell._under(real, root):
            return R_TERRAFORM
    try:
        loaded = load_manifest(Path(root))
    except ManifestError as exc:
        return R_TERRAFORM_MANIFEST.format(cause=exc)
    if loaded is not None and loaded.features.terraform_tools is False:
        return R_TERRAFORM_OFF.format(manifest=manifest_path(Path(root)))
    # 0159-DAE-PLT: validate off by default - deviation from the global Terraform rule
    if rest == ["validate"] and (loaded is None or loaded.features.terraform_validate is not True):
        return R_TERRAFORM_VALIDATE_OFF.format(manifest=manifest_path(Path(root)))
    return None


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


def _out_values(args: list[str]) -> list[str] | None:
    # MAP -> REQ: every --out value, joined or split; None for an abbreviation or no value.
    found: list[str] = []
    for idx, arg in enumerate(args):
        flag, eq, value = arg.partition("=")
        if flag == OUT_FLAG:
            if not eq:
                value = args[idx + 1] if idx + 1 < len(args) else ""
            if not value:
                return None
            found.append(value)
        elif len(flag) > 2 and OUT_FLAG.startswith(flag):
            return None
    return found


def map_out_reason(segment: list[str], cwd: str) -> str | None:
    # MAP -> REQ: one --out, resolving to <repo>/docs/.tmp/daedalus/<train-id>/map.
    if os.path.basename(os.path.realpath(segment[1])) != MAP_SCRIPT:
        return None
    root = os.path.realpath(project_root(cwd)) if os.path.isabs(cwd) else cwd
    scratch = os.path.join(root, "docs", ".tmp", "daedalus")
    branch = jail._train_branch(cwd) if os.path.isabs(cwd) else None
    train = branch.removeprefix("daedalus/") if branch else ""
    allowed = os.path.join(scratch, train, "map") if train else scratch + os.sep
    values = _out_values(segment[2:])
    if values is None or len(values) != 1:
        return R_MAP_OUT.format(allowed=allowed, given="(one value)")
    # MAP -> REQ: a relative --out joins the project root, as daedalus_map.py joins it to --repo.
    real = os.path.realpath(os.path.join(root, values[0]))
    ok = real == allowed if train else real.startswith(allowed)
    return None if ok else R_MAP_OUT.format(allowed=allowed, given=values[0])


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


def date_ok(segment: list[str]) -> bool:
    # spec 7.1: `date -u [+FORMAT]`, nothing else.
    rest = segment[2:]
    return (
        segment[:1] == ["date"]
        and segment[1:2] != []
        and segment[1] in DATE_UTC
        and (rest == [] or (len(rest) == 1 and rest[0].startswith("+")))
    )


def sed_print_ok(segment: list[str]) -> bool:
    # spec 7.1: `sed -n <ranges>p <file>...`; GNU sed takes a later -i, so no operand is a flag.
    return (
        len(segment) >= 4
        and segment[:2] == ["sed", "-n"]
        and shell._SED_PRINT.fullmatch(segment[2]) is not None
        and not any(arg.startswith("-") for arg in segment[3:])
    )


def _inspect_ok(segment: list[str], cwd: str) -> bool:
    # 0060, spec 7.1: the auditor's read set, the merge-base check, date -u and sed -n ranges.
    charter = hook_io.hook_charter(cwd)
    return (
        read_segment_ok(segment, INSPECT_GIT, cwd, charter)
        or date_ok(segment)
        or sed_print_ok(segment)
    )


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
            mismatch = train_repo_reason(segment, cwd) or map_out_reason(segment, cwd)
            if mismatch is not None:
                return mismatch
            continue
        if "inspect" in allowed and _inspect_ok(segment, cwd):
            continue
        if "terraform" in allowed and name == "terraform":
            refused = terraform_reason(segment, cwd)
            if refused is not None:
                return refused
            continue
        return _reason(allowed)
    return None


decide, main = hook_io.entrypoint(judge, TOOLS, PARSER)

if __name__ == "__main__":
    sys.exit(main())
