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


def _load(path: Path) -> tuple[dict[str, dict[str, object]], list[str]]:
    try:
        data: object = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}, []
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        raise TrainStateError(
            f"{path} is not readable JSON ({exc}). Next: stop the train and start a new one."
        ) from exc
    units: object = data.get("units") if isinstance(data, dict) else None
    if not isinstance(units, dict) or not all(isinstance(v, dict) for v in units.values()):
        raise TrainStateError(f"{path} has no units object. Next: stop the train and start anew.")
    top: object = data.get("retired", []) if isinstance(data, dict) else []
    if not isinstance(top, list) or not all(isinstance(a, str) for a in top):
        raise TrainStateError(
            f"{path} has a retired entry that is not a list of coder ids. "
            "Next: stop the train and start anew."
        )
    # issue 51: rebuilt as typed dicts so the untyped json value stops at this reader.
    typed = {str(name): {str(k): v for k, v in rec.items()} for name, rec in units.items()}
    # issue 187: the train-wide set also folds in per-unit lists, so an old file keeps them.
    retired = list(top)
    for rec in typed.values():
        old = rec.get("retired")
        retired += [a for a in old if isinstance(a, str) and a] if isinstance(old, list) else []
    return typed, list(dict.fromkeys(retired))


def _read(path: Path) -> dict[str, dict[str, object]]:
    return _load(path)[0]


def _save(path: Path, units: dict[str, dict[str, object]], retired: list[str]) -> None:
    # issue 187: every write carries the train-wide retired set, so a rebind never drops it.
    train_state._write(path, {"units": units, **({"retired": retired} if retired else {})})


def _held(units: dict[str, dict[str, object]], unit_name: str) -> str | None:
    # issue 29: a unit already dispatched or bound takes no second coder.
    if unit_name not in units or units[unit_name].get("released"):
        return None
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


def held_reason(repo: Path, train_id: str, unit_name: str) -> str | None:
    # issue 29: read-only once check for a coder dispatch that records no binding.
    try:
        return _held(_read(bindings_path(repo, train_id)), unit_name)
    except TrainStateError as exc:
        return str(exc)


def record_dispatch(repo: Path, train_id: str, unit_name: str) -> str | None:
    try:
        with _locked(repo, train_id) as path:
            units, retired = _load(path)
            held = _held(units, unit_name)
            if held is not None:
                return held
            units[unit_name] = {"agent_id": None, **_retired(units.get(unit_name, {}))}
            _save(path, units, retired)
    except TrainStateError as exc:
        return str(exc)
    return None


def _retired(record: dict[str, object]) -> dict[str, object]:
    retired = record.get("retired")
    return {"retired": list(retired)} if isinstance(retired, list) and retired else {}


def release(repo: Path, train_id: str, unit_name: str) -> str | None:
    # 0187, issue 115: a second refutation frees the unit for one fresh coder; the old one retires.
    try:
        with _locked(repo, train_id) as path:
            units, everywhere = _load(path)
            record = units.get(unit_name, {})
            old = record.get("retired")
            retired = [a for a in old if isinstance(a, str)] if isinstance(old, list) else []
            holder = record.get("agent_id")
            if isinstance(holder, str) and holder:
                retired += [] if holder in retired else [holder]
                everywhere += [] if holder in everywhere else [holder]
            units[unit_name] = {"agent_id": None, "released": True, "retired": retired}
            _save(path, units, everywhere)
    except TrainStateError as exc:
        return str(exc)
    return None


def rebind(repo: Path, train_id: str, agent_id: str, from_unit: str, to_unit: str) -> str | None:
    # 0086: a returned coder resumes on the unit stacked on its own; its old unit closes.
    try:
        with _locked(repo, train_id) as path:
            units, retired = _load(path)
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
            _save(path, units, retired)
    except TrainStateError as exc:
        return str(exc)
    return None


def claim(repo: Path, train_id: str, agent_id: str, unit_name: str) -> str | None:
    try:
        with _locked(repo, train_id) as path:
            units, everywhere = _load(path)
            record = units.get(unit_name)
            if record is None:
                # issue 306: only a dispatch from a session inside the run records the unit.
                return (
                    f"unit {unit_name} was never dispatched in train {train_id}: the dispatch "
                    f"that started this coder came from a session folder outside {repo}, or "
                    "carried no single Worktree: line naming the unit, so no record was made. "
                    f"Next: start a new coder from a session inside {repo}, with one Worktree: "
                    "line naming the unit."
                )
            if record.get("finished"):
                return f"unit {unit_name} is merged and finished (0121). {WRITE_NEXT}"
            moved = record.get("retired_to")
            if moved:
                return (
                    f"unit {unit_name} is finished; its coder moved on to unit {moved} "
                    f"(0086). {WRITE_NEXT}"
                )
            retired = record.get("retired")
            # issue 187: a released unit takes the first coder retired from no unit at all.
            mine_retired = isinstance(retired, list) and agent_id in retired
            if mine_retired or (record.get("released") and agent_id in everywhere):
                return (
                    f"unit {unit_name} goes to a fresh coder after its second refutation "
                    f"(0187). {WRITE_NEXT}"
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
            record.pop("released", None)
            _save(path, units, everywhere)
    except TrainStateError as exc:
        return str(exc)
    return None


def mark_finished(repo: Path, train_id: str, unit: str) -> str | None:
    # spec 4, 0121: finish and merge mark each merged unit; claim refuses it, progress reads done.
    try:
        with _locked(repo, train_id) as path:
            units, retired = _load(path)
            units[unit] = {**units.get(unit, {"agent_id": None}), "finished": True}
            _save(path, units, retired)
    except TrainStateError as exc:
        return str(exc)
    return None


def bound_units(repo: Path, train_id: str) -> dict[str, str]:
    # issue 181: read-only map of coder agent id to unit name, a retired coder after the holder.
    try:
        units = _read(bindings_path(repo, train_id))
    except TrainStateError:
        return {}
    bound: dict[str, str] = {}
    for name, rec in units.items():
        holder = rec.get("agent_id")
        if isinstance(holder, str) and holder:
            bound[holder] = name
    for name, rec in units.items():
        retired = rec.get("retired")
        for agent_id in retired if isinstance(retired, list) else []:
            if isinstance(agent_id, str) and agent_id:
                bound.setdefault(agent_id, name)
    return bound
