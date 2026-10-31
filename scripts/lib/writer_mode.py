# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0190: the writer's document kind, recorded by the dispatch gate and bound on the writer's
# first routed call; the router then runs that kind's hooks only, so no writer holds both jails.
from __future__ import annotations

import json
import os
from contextlib import AbstractContextManager
from pathlib import Path

from lib import train_state
from lib.project_root import project_root
from lib.train_state import TrainStateError, active_train

WRITER = "writer"
PUBLIC_DOCS, DERIVED = "public-docs", "derived"
KINDS = (PUBLIC_DOCS, DERIVED)
R_NO_RUN = (
    "the writer works only inside a marked run that recorded its dispatch (0190). "
    "Next: dispatch the writer from the document phase of a run."
)
R_NO_ID = (
    "the hook input has neither agent_id nor session_id, so the writer's kind cannot be bound "
    "(0190). Next: report this hook payload to the operator."
)
R_NO_DISPATCH = (
    "writer {agent} holds no recorded kind in train {train}, and no writer dispatch waits for it "
    "(0190). Next: dispatch the writer again from the document phase."
)
R_PENDING = (
    "a writer dispatched as {kind} in train {train} has made no call yet, so no second writer "
    "starts before it (0190). Next: wait for that writer to start, or stop the run."
)


def records_path(repo: Path, train_id: str) -> Path:
    return train_state.state_path(repo, train_id).with_name(f"{train_id}.writers.json")


def _locked(repo: Path, train_id: str) -> AbstractContextManager[Path]:
    path = records_path(repo, train_id)
    return train_state.locked_file(repo, path, f"{train_id}.writers.lock", "writer kind lock")


def _read(path: Path) -> tuple[str | None, dict[str, str]]:
    # 0190: (the kind a dispatch left waiting, the kind bound to each writer id).
    try:
        data: object = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None, {}
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        raise TrainStateError(
            f"{path} is not readable JSON ({exc}). Next: stop the run and start a new one."
        ) from exc
    pending = data.get("pending") if isinstance(data, dict) else None
    agents = data.get("agents") if isinstance(data, dict) else None
    if (
        pending not in (None, *KINDS)
        or not isinstance(agents, dict)
        or not all(kind in KINDS for kind in agents.values())
    ):
        raise TrainStateError(f"{path} is not a writer record. Next: stop the run and start anew.")
    return (None if pending is None else str(pending)), {str(k): str(v) for k, v in agents.items()}


def _write(path: Path, pending: str | None, agents: dict[str, str]) -> None:
    train_state._write(path, {"pending": pending, "agents": agents})


def pending_reason(repo: Path, train_id: str) -> str | None:
    # 0190: read-only; a dispatch checks this before it records anything else.
    try:
        pending, _ = _read(records_path(repo, train_id))
    except TrainStateError as exc:
        return str(exc)
    return None if pending is None else R_PENDING.format(kind=pending, train=train_id)


def record_dispatch(repo: Path, train_id: str, kind: str) -> str | None:
    try:
        with _locked(repo, train_id) as path:
            pending, agents = _read(path)
            if pending is not None:
                return R_PENDING.format(kind=pending, train=train_id)
            _write(path, kind, agents)
    except TrainStateError as exc:
        return str(exc)
    return None


def _agent_id(hook_input: dict[str, object]) -> str:
    # B1: a writer run as the session agent (--agent) has no agent_id; its session binds.
    session = str(hook_input.get("session_id") or "")
    return str(hook_input.get("agent_id") or "") or (f"session:{session}" if session else "")


def _run(hook_input: dict[str, object]) -> tuple[Path, str] | str:
    cwd = str(hook_input.get("cwd") or "")
    if not os.path.isabs(cwd):
        return R_NO_RUN
    repo = project_root(Path(cwd))
    train = active_train(repo)
    return R_NO_RUN if train is None else (repo, train)


def kind_of(hook_input: dict[str, object]) -> tuple[str | None, str | None]:
    # 0190: (kind, refusal); an unbound writer takes the waiting kind on its first call, once.
    run = _run(hook_input)
    if isinstance(run, str):
        return None, run
    repo, train = run
    agent = _agent_id(hook_input)
    if not agent:
        return None, R_NO_ID
    try:
        with _locked(repo, train) as path:
            pending, agents = _read(path)
            if agent in agents:
                return agents[agent], None
            if pending is None:
                return None, R_NO_DISPATCH.format(agent=agent, train=train)
            agents[agent] = pending
            _write(path, None, agents)
    except TrainStateError as exc:
        return None, str(exc)
    return pending, None


def bound_kind(hook_input: dict[str, object]) -> str | None:
    # 0190: read-only lookup for the checks the router runs after the writer's own hooks.
    run = _run(hook_input)
    if isinstance(run, str):
        return None
    try:
        _, agents = _read(records_path(*run))
    except TrainStateError:
        return None
    return agents.get(_agent_id(hook_input))
