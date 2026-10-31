# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0190: the writer's document kind. Every dispatch queues its kind; a writer's first routed call
# binds the one waiting entry, and with two or more waiting every unbound writer is refused.
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
# 0190: a dispatch whose kind could not be read still queues, so it never borrows another's.
NONE = "none"
_ENTRIES = (*KINDS, NONE)
CLEAR = "python3 <plugin>/scripts/daedalus_train.py writer-clear --repo <repo>"
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
R_NO_KIND = (
    "writer {agent} was dispatched in train {train} with a brief whose kind could not be read, "
    "so it takes neither kind's write limits (0190). Next: stop this writer and dispatch a new "
    "one with one Worktree: line naming the docs worktree, or with no Worktree: line once the "
    "sources are frozen."
)
R_PENDING = (
    "a writer dispatched as {kind} in train {train} has made no call yet, so no second writer "
    "starts before it (0190). Next: wait for that writer to start, or stop the run."
)
R_QUEUED = (
    "{n} writer dispatches now wait in train {train} ({kinds}), so no writer can take a kind "
    "until the queue is cleared (0190). Next: stop those writers, run " + CLEAR + " from your "
    "own shell or this session, then dispatch one writer at a time."
)
R_AMBIGUOUS = (
    "writer {agent} takes no kind: {n} writer dispatches wait in train {train} ({kinds}), and "
    "nothing tells which one started this writer (0190). Next: stop those writers, run "
    + CLEAR
    + " from the main session, then dispatch one writer at a time."
)


def records_path(repo: Path, train_id: str) -> Path:
    return train_state.state_path(repo, train_id).with_name(f"{train_id}.writers.json")


def _locked(repo: Path, train_id: str) -> AbstractContextManager[Path]:
    path = records_path(repo, train_id)
    return train_state.locked_file(repo, path, f"{train_id}.writers.lock", "writer kind lock")


def _read(path: Path) -> tuple[list[str], dict[str, str]]:
    # 0190: (the queue of waiting dispatch kinds, oldest first; the kind bound to each writer id).
    try:
        data: object = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return [], {}
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        raise TrainStateError(
            f"{path} is not readable JSON ({exc}). Next: stop the run and start a new one."
        ) from exc
    pending = data.get("pending") if isinstance(data, dict) else None
    agents = data.get("agents") if isinstance(data, dict) else None
    if (
        not isinstance(pending, list)
        or not all(kind in _ENTRIES for kind in pending)
        or not isinstance(agents, dict)
        or not all(kind in _ENTRIES for kind in agents.values())
    ):
        raise TrainStateError(f"{path} is not a writer record. Next: stop the run and start anew.")
    return [str(kind) for kind in pending], {str(k): str(v) for k, v in agents.items()}


def _write(path: Path, pending: list[str], agents: dict[str, str]) -> None:
    train_state._write(path, {"pending": pending, "agents": agents})


def pending_reason(repo: Path, train_id: str) -> str | None:
    # 0190: read-only; a refusable dispatch checks this before it records anything else.
    try:
        pending, _ = _read(records_path(repo, train_id))
    except TrainStateError as exc:
        return str(exc)
    return R_PENDING.format(kind=", ".join(pending), train=train_id) if pending else None


def record_dispatch(repo: Path, train_id: str, kind: str) -> str | None:
    # 0190: a dispatch the gate can refuse records only into an empty queue.
    try:
        with _locked(repo, train_id) as path:
            pending, agents = _read(path)
            if pending:
                return R_PENDING.format(kind=", ".join(pending), train=train_id)
            _write(path, [kind], agents)
    except TrainStateError as exc:
        return str(exc)
    return None


def queue_dispatch(repo: Path, train_id: str, kind: str) -> str | None:
    # 0190: a dispatch that runs even when warned is always queued; two or more waiting warn.
    try:
        with _locked(repo, train_id) as path:
            pending, agents = _read(path)
            pending.append(kind)
            _write(path, pending, agents)
    except TrainStateError as exc:
        return str(exc)
    if len(pending) < 2:
        return None
    return R_QUEUED.format(n=len(pending), train=train_id, kinds=", ".join(pending))


def clear(repo: Path, train_id: str) -> int:
    # 0190: empties the queue and keeps every bound writer's kind; returns the entries removed.
    path = records_path(repo, train_id)
    if not path.is_file():
        return 0
    with _locked(repo, train_id) as locked:
        pending, agents = _read(locked)
        _write(locked, [], agents)
    return len(pending)


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


def _bound(agent: str, train: str, kind: str) -> tuple[str | None, str | None]:
    if kind == NONE:
        return None, R_NO_KIND.format(agent=agent, train=train)
    return kind, None


def kind_of(hook_input: dict[str, object]) -> tuple[str | None, str | None]:
    # 0190: (kind, refusal); an unbound writer takes the one waiting kind on its first call.
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
                return _bound(agent, train, agents[agent])
            if not pending:
                return None, R_NO_DISPATCH.format(agent=agent, train=train)
            if len(pending) > 1:
                kinds = ", ".join(pending)
                return None, R_AMBIGUOUS.format(
                    agent=agent, n=len(pending), train=train, kinds=kinds
                )
            agents[agent] = pending[0]
            _write(path, [], agents)
    except TrainStateError as exc:
        return None, str(exc)
    return _bound(agent, train, pending[0])


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


def bound_kinds(repo: Path) -> dict[str, str]:
    # 0190: every writer id bound in any run of this repo; an unreadable record adds nothing.
    out: dict[str, str] = {}
    for path in sorted((repo / train_state.STATE_DIR).glob("*.writers.json")):
        try:
            out.update(_read(path)[1])
        except TrainStateError:
            continue
    return out
