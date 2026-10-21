# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import json
from contextlib import AbstractContextManager
from pathlib import Path

from lib import train_state
from lib.train_state import TrainStateError

# issue 29: one coder per unit worktree; the dispatch records the unit, the first write binds it.
WRITE_NEXT = "Next: write only in the unit worktree you were dispatched to."


def bindings_path(repo: Path, train_id: str) -> Path:
    return train_state.state_path(repo, train_id).with_name(f"{train_id}.bindings.json")


def _locked(repo: Path, train_id: str) -> AbstractContextManager[Path]:
    # 75: the bindings lock opens through locks.locked, via the one train-state lock helper.
    path = bindings_path(repo, train_id)
    return train_state.locked_file(repo, path, f"{train_id}.bindings.lock", "unit binding lock")


def _read(path: Path) -> dict[str, dict[str, object]]:
    try:
        data: object = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        raise TrainStateError(
            f"{path} is not readable JSON ({exc}). Next: stop the train and start a new one."
        ) from exc
    units: object = data.get("units") if isinstance(data, dict) else None
    if not isinstance(units, dict) or not all(isinstance(v, dict) for v in units.values()):
        raise TrainStateError(f"{path} has no units object. Next: stop the train and start anew.")
    # issue 51: rebuilt as typed dicts so the untyped json value stops at this reader.
    return {str(name): {str(k): v for k, v in rec.items()} for name, rec in units.items()}


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


def rebind(repo: Path, train_id: str, agent_id: str, from_unit: str, to_unit: str) -> str | None:
    # 0086: a returned coder resumes on the unit stacked on its own; its old unit closes.
    try:
        with _locked(repo, train_id) as path:
            units = _read(path)
            if to_unit in units:
                return (
                    f"unit {to_unit} was already dispatched (0086). "
                    "Next: wait for that coder, or stop the train."
                )
            holder = units.get(from_unit, {}).get("agent_id")
            if holder not in (None, agent_id):
                return (
                    f"unit {from_unit} is bound to coder {holder}, not {agent_id} (0086). "
                    "Next: resume the coder that built the base unit, or stop the train."
                )
            units[from_unit] = {"agent_id": None, "retired_to": to_unit}
            units[to_unit] = {"agent_id": agent_id}
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
            if record.get("finished"):
                return f"unit {unit_name} is merged and finished (0121). {WRITE_NEXT}"
            moved = record.get("retired_to")
            if moved:
                return (
                    f"unit {unit_name} is finished; its coder moved on to unit {moved} "
                    f"(0086). {WRITE_NEXT}"
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


def mark_finished(repo: Path, train_id: str, unit: str) -> str | None:
    # 0121: the smallest finished mark the merge subcommand needs; D2 extends it.
    try:
        with _locked(repo, train_id) as path:
            units = _read(path)
            units[unit] = {**units.get(unit, {"agent_id": None}), "finished": True}
            train_state._write(path, {"units": units})
    except TrainStateError as exc:
        return str(exc)
    return None
