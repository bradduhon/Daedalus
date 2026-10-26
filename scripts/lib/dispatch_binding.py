# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# issue 29, 0044: the coder dispatch, the warm resume rebind and the coder's first-write claim.
# lib.jail imports this module, so lib.jail names are imported at call time.
from __future__ import annotations

import hashlib
import os
import re
from pathlib import Path

from lib import plan_record, unit_binding
from lib.audit_proof import SUMMARY_DIR
from lib.config import DEFAULT_MAX_CONCURRENT_BUILDERS
from lib.narrow import integer
from lib.project_root import project_root
from lib.shell import _abs, _base, _git_split
from lib.train_scope import policed_outside_train
from lib.train_state import TRAIN_ID, TrainStateError, active_train, is_audit_unit
from lib.train_state import load as load_train
from lib.train_state import units as units_of
from lib.unit_binding import claim, rebind, record_dispatch
from lib.workspace import UNMARK_NEXT, train_marker

R_NO_TRAIN = (
    "a repo-coder writes only inside a Daedalus train (issue 29). "
    "Next: start coders from /daedalus:build-train."
)
R_WORKTREE_LINE = (
    "a repo-coder dispatched during a train names its unit on exactly one line "
    "'Worktree: <absolute path>' (issue 29). Next: name the unit worktree on one Worktree: line."
)
R_TWO_UNITS = (
    "one command may write into one unit worktree only (issue 29). "
    "Next: write only in the unit worktree you were dispatched to."
)
R_NO_CODER_ID = (
    "the hook input has neither agent_id nor session_id, so the coder cannot be bound "
    "(issue 29). Next: report this hook payload to the operator."
)
R_NOT_PRINTED = (
    "the train runner did not print a dispatch of {agent} for stage {stage}, and {agent} is no "
    "consult agent of gate {gate} (0024). Next: run daedalus_train.py step and dispatch only "
    "the agent it prints, or a consult agent of the current gate."
)
R_NO_PLAN = (
    "a repo-coder starts during a train only after the train's recorded plan validates "
    "(spec 4.1, 0088): {why} Next: run /daedalus:plan to write and record this train's plan, "
    "then dispatch the coder again."
)
R_RESUME_LINE = (
    "a resume that hands a coder a unit names it on exactly one line "
    "'Worktree: <absolute path>' (0086). Next: name the unit worktree on one Worktree: line."
)
R_RESUME_TARGET = (
    "a resume carrying a Worktree: line names the coder in its to field (0086). "
    "Next: address the coder by the agent id its first dispatch returned."
)
R_RESUME_UNBOUND = (
    "coder {coder} holds no unit in train {train}, so a resume cannot move it to unit {unit} "
    "(0086). Next: resume it without the Worktree: line while it is on its first unit, or "
    "dispatch a cold coder for unit {unit}."
)
R_AUDIT_UNIT = (
    "{path} is the audit worktree of train {train}; it holds the auditor's tests, not a coder's "
    "unit (spec 4). Next: name the coder's own unit worktree on the Worktree: line, as "
    "daedalus_workspace.py create printed it."
)
R_DOCS_WORKTREE = (
    "a docs-writer dispatched during train {train} names exactly one line 'Worktree: {docs}', "
    "the train's docs worktree, and no other worktree (0134). Next: create it with "
    "daedalus_workspace.py create --name {name} and name it on one Worktree: line."
)
R_DOCS_REBIND = (
    "the docs worktree {name} takes only the docs-writer its own dispatch names, and a resume "
    "never moves an agent onto it (0134). Next: dispatch the docs-writer with one Worktree: "
    "line naming the docs worktree, and resume coders only onto their own units."
)
# 0134: the docs stage worktree, beside the audit worktree's <train-id>-audit.
DOCS_SUFFIX = "-docs"
DOCS_WRITER = "docs-writer"
# 0134: the only files the docs-writer writes, relative to its docs worktree.
PUBLIC_DOCS = (
    "README.md",
    "docs/howto/README.md",
    "docs/guardrails.md",
    "docs/project-requirements.md",
)
DISPATCH_TOOLS = frozenset({"Agent", "Task"})
RESUME_TOOLS = frozenset({"SendMessage"})
_WORKTREE_LINE = re.compile(r"Worktree: (/\S+)")
_SHA256 = re.compile(r"[0-9a-f]{64}")
# issue 29: git forms that change a unit's index, history or files; -C names the unit.
_UNIT_GIT_WRITES = frozenset({"add", "stage", "commit", "stash", "restore", "checkout"})


def _step_reason(tool_input: dict[str, object], cwd: str) -> str | None:
    # 4.8, AC-3, AC-6: in a defined train the Agent gate is default deny, scoped to one stage.
    from lib.jail import _train_active, normalize_agent
    from lib.train_runner import MODE_DEFINED, RunnerError, allowed_dispatch

    if not os.path.isabs(cwd) or not _train_active(cwd):
        return None
    repo = project_root(Path(cwd))
    train = active_train(repo)
    if train is None:
        return None
    try:
        state = load_train(repo, train)
        if state.get("mode") != MODE_DEFINED:
            return None
        allowed, stage, gate = allowed_dispatch(state)
    except (TrainStateError, RunnerError) as exc:
        return str(exc)
    raw = str(tool_input.get("subagent_type") or "")
    agent = normalize_agent(raw)
    if agent != raw and agent in allowed:
        return None
    return R_NOT_PRINTED.format(agent=agent or "an unnamed agent", stage=stage, gate=gate)


def _other_train(repo: Path, path: Path, train: str) -> str | None:
    # spec 4.1: a plan under another train's scratch folder never opens this train's gate.
    roots = (repo / SUMMARY_DIR, Path(os.path.realpath(repo / SUMMARY_DIR)))
    for candidate in (Path(os.path.normpath(path)), Path(os.path.realpath(path))):
        for root in roots:
            parts = candidate.relative_to(root).parts if candidate.is_relative_to(root) else ()
            if parts and TRAIN_ID.fullmatch(parts[0]) and parts[0] != train:
                return parts[0]
    return None


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _plan_defect(repo: Path, train: str, state: dict[str, object]) -> str | None:
    # spec 4.1, 0086: the hash covers the raw file bytes; validate runs at the train's builder cap.
    record = state.get("plan")
    if not isinstance(record, dict):
        return f"the state of train {train} records no plan."
    raw, sha = record.get("path"), record.get("sha256")
    if not isinstance(raw, str) or not raw or not isinstance(sha, str):
        return f"the plan record of train {train} needs a path and a sha256, both strings."
    if not _SHA256.fullmatch(sha):
        return f"the plan record of train {train} has a sha256 that is not 64 lowercase hex."
    path = repo / raw
    other = _other_train(repo, path, train)
    if other is not None:
        return f"the plan {raw} sits under train {other}, not train {train}."
    try:
        before = _digest(path)
        plan = plan_record.load(path)
        after = _digest(path)
    except (OSError, plan_record.PlanError) as exc:
        return f"the plan file {raw} could not be read ({exc})."
    if before != sha or after != sha:
        return (
            f"the plan file {raw} hashes to {after}, not {sha}; it changed after it was recorded."
        )
    cap = integer(state, "max_concurrent_builders", DEFAULT_MAX_CONCURRENT_BUILDERS)
    defects = plan_record.validate(plan, cap)
    if defects:
        return f"the plan {raw} has {len(defects)} defect(s): {' '.join(defects)}"
    return None


def _names_a_coder(subagent: str) -> bool:
    # issue 29: fail closed; a repo-coder under any namespace meets the coder plan gate.
    return subagent.rpartition(":")[2] == "repo-coder"


def _ours(subagent: str, agent: str) -> bool:
    # W1.3: train_scope's namespace check decides which dispatch records a unit binding.
    prefix, sep, name = subagent.partition(":")
    return (name if sep else prefix) == agent and policed_outside_train(subagent)


def _dispatch_reason(tool_input: dict[str, object], cwd: str) -> str | None:
    # issue 29: during a train a coder dispatch names exactly one recorded unit, once.
    from lib.jail import _train_active

    step = _step_reason(tool_input, cwd)
    if step is not None:
        return step
    subagent = str(tool_input.get("subagent_type") or "")
    if _names_docs_writer(subagent):
        return _docs_dispatch_reason(tool_input, cwd, subagent)
    if not _names_a_coder(subagent) or not os.path.isabs(cwd):
        return None
    if not _train_active(cwd):
        return None
    repo = project_root(Path(cwd))
    train = active_train(repo)
    if train is None:
        marker = train_marker(repo)
        return f"{marker} names no train id. " + UNMARK_NEXT.format(repo=repo)
    lines = _worktree_lines(str(tool_input.get("prompt") or ""))
    match = _WORKTREE_LINE.fullmatch(lines[0]) if len(lines) == 1 else None
    if match is None:
        return R_WORKTREE_LINE
    try:
        state = load_train(repo, train)
    except TrainStateError as exc:
        return str(exc)
    # spec 4.1: checked before record_dispatch, so a refused coder is never recorded.
    why = _plan_defect(repo, train, state)
    if why is not None:
        return R_NO_PLAN.format(why=why)
    unit, refused = _coder_unit(state, match.group(1), train)
    if refused is not None:
        return refused
    if not _ours(subagent, "repo-coder"):
        return unit_binding.held_reason(repo, train, unit)  # issue 29: once, never bound.
    return record_dispatch(repo, train, unit)


def docs_unit(train_id: str) -> str:
    # 0134: the docs stage worktree is the train unit named <train-id>-docs.
    return f"{train_id}{DOCS_SUFFIX}"


def _names_docs_writer(subagent: str) -> bool:
    # 0134: fail closed; a docs-writer under any namespace meets the docs worktree gate.
    return subagent.rpartition(":")[2] == DOCS_WRITER


def _docs_dispatch_reason(tool_input: dict[str, object], cwd: str, subagent: str) -> str | None:
    # 0134: during a train a docs-writer dispatch names the docs worktree alone, once.
    from lib.jail import _train_active

    if not os.path.isabs(cwd) or not _train_active(cwd):
        return None
    repo = project_root(Path(cwd))
    train = active_train(repo)
    if train is None:
        return f"{train_marker(repo)} names no train id. " + UNMARK_NEXT.format(repo=repo)
    try:
        state = load_train(repo, train)
    except TrainStateError as exc:
        return str(exc)
    name = docs_unit(train)
    lines = _worktree_lines(str(tool_input.get("prompt") or ""))
    match = _WORKTREE_LINE.fullmatch(lines[0]) if len(lines) == 1 else None
    unit = _unit_named(state, match.group(1)) if match else None
    if unit is None or unit.get("name") != name:
        docs = next((str(u["path"]) for u in units_of(state) if u.get("name") == name), None)
        return R_DOCS_WORKTREE.format(train=train, docs=docs or "<docs worktree path>", name=name)
    if not _ours(subagent, DOCS_WRITER):
        return unit_binding.held_reason(repo, train, name)
    return record_dispatch(repo, train, name)


def _worktree_lines(text: str) -> list[str]:
    return [line for line in text.splitlines() if line.startswith("Worktree:")]


def _unit_named(state: dict[str, object], path: str) -> dict[str, object] | None:
    # issue 29: the recorded unit whose worktree the line names, compared by real path.
    named = os.path.realpath(path)
    for unit in units_of(state):
        if unit.get("path") and unit.get("name"):
            if os.path.realpath(str(unit["path"])) == named:
                return unit
    return None


def _coder_unit(state: dict[str, object], path: str, train: str) -> tuple[str, str | None]:
    # spec 4: the unit a coder may take, or the refusal; the audit worktree is never one.
    unit = _unit_named(state, path)
    if unit is None:
        return "", _not_a_unit(path, train)
    if is_audit_unit(unit):
        return "", R_AUDIT_UNIT.format(path=path, train=train)
    return str(unit["name"]), None


def _not_a_unit(path: str, train: str) -> str:
    return (
        f"{path} is not a unit worktree of train {train}. "
        "Next: name the unit worktree on one Worktree: line, as daedalus_workspace.py create "
        "printed it."
    )


def _strings(value: object) -> list[str]:
    # 0086: every text a structured message carries, so no Worktree: line hides in a field.
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [s for item in value.values() for s in _strings(item)]
    if isinstance(value, list):
        return [s for item in value for s in _strings(item)]
    return []


def _resume_reason(tool_input: dict[str, object], cwd: str) -> str | None:
    # 0086, spec 8: a resume naming another unit's worktree rebinds the coder before it is sent.
    from lib.jail import _train_active

    # 0086: every field but the target, since the message key is ASSUMED, not verified live.
    fields = {key: value for key, value in tool_input.items() if key != "to"}
    lines = _worktree_lines("\n".join(_strings(fields)))
    if not lines or not os.path.isabs(cwd) or not _train_active(cwd):
        return None
    repo = project_root(Path(cwd))
    train = active_train(repo)
    if train is None:
        return f"{train_marker(repo)} names no train id. " + UNMARK_NEXT.format(repo=repo)
    match = _WORKTREE_LINE.fullmatch(lines[0]) if len(lines) == 1 else None
    if match is None:
        return R_RESUME_LINE
    coder = str(tool_input.get("to") or "")
    if not coder:
        return R_RESUME_TARGET
    try:
        state = load_train(repo, train)
        bound = unit_binding._read(unit_binding.bindings_path(repo, train))
    except TrainStateError as exc:
        return str(exc)
    why = _plan_defect(repo, train, state)
    if why is not None:
        return R_NO_PLAN.format(why=why)
    unit, refused = _coder_unit(state, match.group(1), train)
    if refused is not None:
        return refused
    if bound.get(unit, {}).get("agent_id") == coder:
        return None  # 0086: the runner's queue rebound it already, or the coder holds this unit.
    if unit == docs_unit(train):
        return R_DOCS_REBIND.format(name=unit)
    held = [name for name, record in bound.items() if record.get("agent_id") == coder]
    if not held:
        return R_RESUME_UNBOUND.format(coder=coder, train=train, unit=unit)
    return rebind(repo, train, coder, held[0], unit)


def _segment_units(segment: list[str], cwd: str) -> set[str]:
    from lib.jail import CODER_WRITE_CMDS, _git_dir, _in_place, _unit_parts, _write_operands

    name = _base(segment[0])
    targets: list[str] = []
    if name == "git":
        sub, args, globals_ = _git_split(segment)
        if sub in _UNIT_GIT_WRITES:
            base = _git_dir(globals_, cwd)
            targets = [base, *(_abs(a, base) for a in args[1:] if args[:1] == ["--"])]
    elif name in CODER_WRITE_CMDS or (name in {"sed", "perl"} and _in_place(name, segment[1:])):
        targets = [_abs(a, cwd) for a in _write_operands(name, segment[1:]) if a != "-"]
    units: set[str] = set()
    for target in targets:
        parts = _unit_parts(target, cwd)
        if parts is not None:
            units.add(parts[0])
    return units


def _binding_reason(hook_input: dict[str, object], cwd: str, units: set[str]) -> str | None:
    # issue 29: the first write claims the dispatched unit; every later write stays in it.
    if not units:
        return None
    repo = project_root(Path(cwd))
    train = active_train(repo)
    if train is None:
        return R_NO_TRAIN
    if len(units) > 1:
        return R_TWO_UNITS
    # B1: a coder run as the session agent (--agent) has no agent_id; its session binds.
    session = str(hook_input.get("session_id") or "")
    coder = str(hook_input.get("agent_id") or "") or (f"session:{session}" if session else "")
    if not coder:
        return R_NO_CODER_ID
    return claim(repo, train, coder, next(iter(units)))
