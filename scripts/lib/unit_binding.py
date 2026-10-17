# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import json
import os
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from lib import train_state
from lib.locks import bounded_flock
from lib.train_state import TrainStateError

# issue 29: one coder per unit worktree; the dispatch records the unit, the first write binds it.
LOCK_TIMEOUT_S = 5.0
WRITE_NEXT = "Next: write only in the unit worktree you were dispatched to."


def bindings_path(repo: Path, train_id: str) -> Path:
    return train_state.state_path(repo, train_id).with_name(f"{train_id}.bindings.json")


@contextmanager
def _locked(repo: Path, train_id: str) -> Iterator[Path]:
    path = bindings_path(repo, train_id)
    directory = train_state._state_dir(repo, path)
    lock = directory / f"{train_id}.bindings.lock"
    try:
        fd = os.open(lock, os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    except OSError as exc:
        raise TrainStateError(
            f"cannot open {lock} ({exc}). Next: delete it from your own shell if it is a symlink."
        ) from exc
    with os.fdopen(fd, "w") as handle:
        try:
            bounded_flock(handle, LOCK_TIMEOUT_S, label="unit binding lock")
        except RuntimeError as exc:
            raise TrainStateError(str(exc)) from exc
        yield path


def _read(path: Path) -> dict[str, dict[str, Any]]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        raise TrainStateError(
            f"{path} is not readable JSON ({exc}). Next: stop the train and start a new one."
        ) from exc
    units = data.get("units") if isinstance(data, dict) else None
    if not isinstance(units, dict) or not all(isinstance(v, dict) for v in units.values()):
        raise TrainStateError(f"{path} has no units object. Next: stop the train and start anew.")
    return units


def record_dispatch(repo: Path, train_id: str, unit_name: str) -> str | None:
    try:
        with _locked(repo, train_id) as path:
            units = _read(path)
            if unit_name in units:
                holder = units[unit_name].get("agent_id")
                if holder:
                    return (
                        f"unit {unit_name} is bound to coder {holder} (issue 29). "
                        "Next: resume that coder with SendMessage."
                    )
                return (
                    f"unit {unit_name} was already dispatched to a coder that has not written "
                    "yet (issue 29). Next: wait for that coder, or stop the train."
                )
            units[unit_name] = {"agent_id": None}
            train_state._write(path, {"units": units})
    except TrainStateError as exc:
        return str(exc)
    return None


def claim(repo: Path, train_id: str, agent_id: str, unit_name: str) -> str | None:
    try:
        with _locked(repo, train_id) as path:
            units = _read(path)
            record = units.get(unit_name)
            if record is None:
                return (
                    f"unit {unit_name} was never dispatched in train {train_id}. "
                    "Next: dispatch a repo-coder with one Worktree: line naming it."
                )
            holder = record.get("agent_id")
            if holder == agent_id:
                return None
            if holder:
                return f"unit {unit_name} belongs to coder {holder} (issue 29). {WRITE_NEXT}"
            mine = [name for name, rec in units.items() if rec.get("agent_id") == agent_id]
            if mine:
                return (
                    f"coder {agent_id} is bound to unit {mine[0]}, not {unit_name} (issue 29). "
                    f"{WRITE_NEXT}"
                )
            record["agent_id"] = agent_id
            train_state._write(path, {"units": units})
    except TrainStateError as exc:
        return str(exc)
    return None
