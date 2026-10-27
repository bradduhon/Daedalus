# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import json
import os
import re
from collections.abc import Callable, Iterator, Mapping
from contextlib import AbstractContextManager, ExitStack, contextmanager
from pathlib import Path

from lib import atomic, locks

# 0024: one state file per train; only scripts write here (the jail refuses tool writes).
STATE_DIR = Path(".claude") / "daedalus" / "trains"
# 0023: a train is active while this file names its id on the first line.
TRAIN_MARKER = Path(".claude") / "daedalus" / "train.active"
TRAIN_ID = re.compile(r"[0-9]{8}-[0-9]{6}")
LOCK_TIMEOUT_S = 5.0
# 0085, 0089: plan {path, sha256}, verdict {status, tip, round, seq}.
# 0133: exemptions {"<round>": {"<finding id>": {ledger_id, tip, tracking[, other]}}}.
PLAN, CHOICES, VERDICT, EXEMPTIONS, PHASE, WEIGHT = (
    "plan",
    "choices",
    "verdict",
    "exemptions",
    "phase",
    "weight",
)
APPROVED, REJECTED = "approved", "rejected"
# 0156: true once the contract subcommand found a one-file plan; lock --no-contract needs it.
CONTRACT_SKIP = "contract_skip"
# 0131, 0134: the docs verifier's record {status, tip[, findings, exemptions]}, apart from VERDICT.
DOCS_VERDICT, VERIFIED, REFUTED = "docs_verdict", "verified", "refuted"
# 0134: the docs writer's worktree is the unit <train-id>-docstage; no plan unit slug ends so.
DOCS_SUFFIX = "-docstage"
# 0139, 0142: how an exemption is tracked, each stored value with the operator's plain label.
TRACKING = {
    "dropped": "Skip it",
    "issue": "Track it",
    "local": "Exempt it",
    "other": "Other",
}
# 0142: these answers leave no tracked issue, so the pull request body carries a Deviation: line.
UNTRACKED = frozenset({"dropped", "local"})
# issue 57: the audit-log seq hooks-live saw first; verdict searches read only records after it.
START_SEQ = "start_seq"
# issue 60: the session start_seq belongs to, and each session's first bound, so a push
# session's hooks-live never strands the build session's bound.
AUDIT_SESSION, AUDIT_BOUNDS = "audit_session", "audit_bounds"
# 0109: one finding map per audit round, {"<n>": {"<key>": {"severity", "class"}}}.
AUDIT_ROUNDS = "audit_rounds"
# spec 4, pin C4 -> C1: the audit worktree is the unit <train-id>-audit, flagged "audit": true.
AUDIT, AUDIT_SUFFIX = "audit", "-audit"
_AUDIT_NAME = re.compile(rf"{TRAIN_ID.pattern}{AUDIT_SUFFIX}")


class TrainStateError(RuntimeError):
    pass


def state_path(repo: Path, train_id: str) -> Path:
    if not TRAIN_ID.fullmatch(train_id):
        raise TrainStateError(
            f"train id {train_id!r} is not YYYYMMDD-HHMMSS. Next: pass the train's own id."
        )
    return repo / STATE_DIR / f"{train_id}.json"


def _refuse_links(repo: Path, path: Path) -> None:
    for part in (repo / ".claude", repo / ".claude" / "daedalus", path.parent, path):
        try:
            atomic.refuse_links(part)
        except atomic.LinkRefused as exc:
            raise TrainStateError(str(exc)) from exc


def _state_dir(repo: Path, path: Path) -> Path:
    _refuse_links(repo, path)
    data = path.parent.parent
    if not data.is_dir():
        raise TrainStateError(
            f"{data} is missing, so the audit hooks have not run here. "
            "Next: run the Daedalus health check (/daedalus:doctor)."
        )
    try:
        path.parent.mkdir(mode=0o700, exist_ok=True)
        os.chmod(path.parent, 0o700)
    except OSError as exc:
        raise TrainStateError(
            f"cannot create {path.parent} ({exc}). Next: make {data} a writable directory."
        ) from exc
    return path.parent


@contextmanager
def locked_file(repo: Path, path: Path, lock_name: str, label: str) -> Iterator[Path]:
    # 75: the train state and bindings locks open through locks.locked, so a FIFO is refused.
    lock = _state_dir(repo, path) / lock_name
    with ExitStack() as stack:
        try:
            stack.enter_context(locks.locked(lock, LOCK_TIMEOUT_S, label))
        except locks.LockHeld as exc:
            raise TrainStateError(str(exc)) from exc
        except OSError as exc:
            raise TrainStateError(
                f"cannot open {lock} ({exc}). "
                "Next: delete it from your own shell if it is a symlink or not a regular file."
            ) from exc
        yield path


def _locked(repo: Path, train_id: str) -> AbstractContextManager[Path]:
    path = state_path(repo, train_id)
    return locked_file(repo, path, f"{train_id}.lock", "train state lock")


def _read(path: Path) -> dict[str, object]:
    # 0080: parsed as object and narrowed; callers narrow each field they read.
    if path.is_symlink():
        raise TrainStateError(f"{path} is a symlink. Next: delete it from your own shell.")
    try:
        data: object = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise TrainStateError(
            f"no train state at {path}. Next: run /daedalus:build-train to start a train."
        ) from exc
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        raise TrainStateError(
            f"{path} is not readable JSON ({exc}). Next: move it aside and rerun the train."
        ) from exc
    if not isinstance(data, dict):
        raise TrainStateError(f"{path} is not a JSON object. Next: move it aside and rerun.")
    return {str(key): value for key, value in data.items()}


def _write(path: Path, state: dict[str, object]) -> None:
    # 0024: temp file plus os.replace, so a reader never sees a partial state.
    try:
        atomic.write_atomic(path, json.dumps(state, indent=2, sort_keys=True) + "\n", 0o600)
    except OSError as exc:
        raise TrainStateError(
            f"cannot write {path} ({exc}). Next: free space or fix permissions, then rerun."
        ) from exc


def load(repo: Path, train_id: str) -> dict[str, object]:
    path = state_path(repo, train_id)
    _refuse_links(repo, path)
    return _read(path)


def save(repo: Path, train_id: str, state: dict[str, object]) -> None:
    with _locked(repo, train_id) as path:
        _write(path, state)


def update(repo: Path, train_id: str, **fields: object) -> dict[str, object]:
    with _locked(repo, train_id) as path:
        state = _read(path)
        state.update(fields)
        _write(path, state)
    return state


def change(
    repo: Path, train_id: str, edit: Callable[[dict[str, object]], None]
) -> dict[str, object]:
    # 0024: one read-edit-write under the lock, so two runner calls never lose a field.
    with _locked(repo, train_id) as path:
        state = _read(path)
        edit(state)
        _write(path, state)
    return state


def start_seq(state: dict[str, object]) -> int | None:
    value = state.get(START_SEQ)
    if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
        return value
    return None


def record(state: dict[str, object], key: str) -> dict[str, object]:
    # 0080: one object field, narrowed; anything else reads as empty.
    raw = state.get(key)
    return {str(k): v for k, v in raw.items()} if isinstance(raw, dict) else {}


def audit_session(state: dict[str, object]) -> str | None:
    value = state.get(AUDIT_SESSION)
    return value if isinstance(value, str) and value else None


def _bounds(state: dict[str, object]) -> dict[str, int]:
    raw = state.get(AUDIT_BOUNDS)
    items = raw.items() if isinstance(raw, dict) else ()
    return {
        str(k): v for k, v in items if isinstance(v, int) and not isinstance(v, bool) and v >= 0
    }


def session_bound(state: dict[str, object], session: str) -> int | None:
    # issue 60: a state from before audit_session keeps its one bound for every session.
    if audit_session(state) is None:
        return start_seq(state)
    return _bounds(state).get(session)


def mark_start(repo: Path, train_id: str, seq: int, session: str | None = None) -> int:
    # issue 57: once per session; issue 60: a new session moves start_seq to its own bound.
    def edit(state: dict[str, object]) -> None:
        legacy = audit_session(state) is None and start_seq(state) is not None
        if session is None or legacy:
            if start_seq(state) is None:
                state[START_SEQ] = seq
            return
        if audit_session(state) != session:
            bounds = _bounds(state)
            state[START_SEQ] = bounds.setdefault(session, seq)
            state[AUDIT_SESSION] = session
            state[AUDIT_BOUNDS] = bounds

    found = start_seq(change(repo, train_id, edit))
    return seq if found is None else found


def units(state: dict[str, object]) -> list[dict[str, object]]:
    raw = state.get("units")
    items = raw if isinstance(raw, list) else []
    return [{str(k): v for k, v in item.items()} for item in items if isinstance(item, dict)]


def is_audit_unit(unit: Mapping[str, object]) -> bool:
    # spec 4: the flag marks the audit worktree; a unit recorded before D2 carries only the name.
    if unit.get(AUDIT) is True:
        return True
    name = unit.get("name")
    return isinstance(name, str) and _AUDIT_NAME.fullmatch(name) is not None


def add_unit(
    repo: Path,
    train_id: str,
    name: str,
    branch: str,
    path: Path,
    base: str | None = None,
    audit: bool = False,
) -> None:
    # 0072: the base ref is kept, so a unit stacked on another unit waits for it to return.
    with _locked(repo, train_id) as target:
        state = _read(target)
        recorded = units(state)
        if any(unit.get("name") == name for unit in recorded):
            raise TrainStateError(
                f"unit {name} is already recorded for train {train_id}. Next: pick a new unit name."
            )
        entry: dict[str, object] = {"name": name, "branch": branch, "path": str(path)}
        if base is not None:
            entry["base"] = base
        if audit:
            entry[AUDIT] = True
        state["units"] = [*recorded, entry]
        _write(target, state)


def mark_audit(repo: Path, train_id: str, name: str) -> None:
    # spec 4: an audit unit recorded before D2 gains the flag on its next re-add.
    def edit(state: dict[str, object]) -> None:
        recorded = units(state)
        for unit in recorded:
            if unit.get("name") == name:
                unit[AUDIT] = True
        state["units"] = recorded

    change(repo, train_id, edit)


def active_train(repo: Path) -> str | None:
    marker = repo / TRAIN_MARKER
    try:
        lines = marker.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError):
        return None
    if lines and TRAIN_ID.fullmatch(lines[0]):
        return lines[0]
    return None
