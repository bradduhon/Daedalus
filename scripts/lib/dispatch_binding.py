# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# issue 29, 0044: the main session's coder dispatch and the coder's first-write unit claim.
# lib.jail imports this module, so lib.jail names are imported at call time.
from __future__ import annotations

import os
import re
from pathlib import Path

from lib.project_root import project_root
from lib.shell import _abs, _base, _git_split
from lib.train_state import TrainStateError, active_train
from lib.train_state import load as load_train
from lib.unit_binding import claim, record_dispatch
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
DISPATCH_TOOLS = frozenset({"Agent", "Task"})
_WORKTREE_LINE = re.compile(r"Worktree: (/\S+)")
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


def _dispatch_reason(tool_input: dict[str, object], cwd: str) -> str | None:
    # issue 29: during a train a coder dispatch names exactly one recorded unit, once.
    from lib.jail import _train_active

    step = _step_reason(tool_input, cwd)
    if step is not None:
        return step
    subagent = str(tool_input.get("subagent_type") or "")
    if subagent.rpartition(":")[2] != "repo-coder" or not os.path.isabs(cwd):
        return None
    if not _train_active(cwd):
        return None
    repo = project_root(Path(cwd))
    train = active_train(repo)
    if train is None:
        marker = train_marker(repo)
        return f"{marker} names no train id. " + UNMARK_NEXT.format(repo=repo)
    prompt = str(tool_input.get("prompt") or "")
    lines = [line for line in prompt.splitlines() if line.startswith("Worktree:")]
    match = _WORKTREE_LINE.fullmatch(lines[0]) if len(lines) == 1 else None
    if match is None:
        return R_WORKTREE_LINE
    try:
        units = load_train(repo, train).get("units") or []
    except TrainStateError as exc:
        return str(exc)
    named = os.path.realpath(match.group(1))
    for unit in units:
        if isinstance(unit, dict) and unit.get("path") and unit.get("name"):
            if os.path.realpath(str(unit["path"])) == named:
                return record_dispatch(repo, train, str(unit["name"]))
    return (
        f"{match.group(1)} is not a unit worktree of train {train}. "
        "Next: name the unit worktree on one Worktree: line, as daedalus_workspace.py create "
        "printed it."
    )


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
