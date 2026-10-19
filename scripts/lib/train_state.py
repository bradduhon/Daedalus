# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import json
import os
import re
import tempfile
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path

from lib.locks import bounded_flock

# 0024: one state file per train; only scripts write here (the jail refuses tool writes).
STATE_DIR = Path(".claude") / "daedalus" / "trains"
# 0023: a train is active while this file names its id on the first line.
TRAIN_MARKER = Path(".claude") / "daedalus" / "train.active"
TRAIN_ID = re.compile(r"[0-9]{8}-[0-9]{6}")
LOCK_TIMEOUT_S = 5.0


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
        if part.is_symlink():
            raise TrainStateError(
                f"{part} is a symlink. Next: delete it from your own shell, then rerun."
            )


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
def _locked(repo: Path, train_id: str) -> Iterator[Path]:
    path = state_path(repo, train_id)
    directory = _state_dir(repo, path)
    lock = directory / f"{train_id}.lock"
    try:
        fd = os.open(lock, os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    except OSError as exc:
        raise TrainStateError(
            f"cannot open {lock} ({exc}). Next: delete it from your own shell if it is a symlink."
        ) from exc
    with os.fdopen(fd, "w") as handle:
        try:
            bounded_flock(handle, LOCK_TIMEOUT_S, label="train state lock")
        except RuntimeError as exc:
            raise TrainStateError(str(exc)) from exc
        yield path


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
    tmp: Path | None = None
    try:
        fd, name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
        tmp = Path(name)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(state, handle, indent=2, sort_keys=True)
            handle.write("\n")
        os.replace(tmp, path)
    except OSError as exc:
        if tmp is not None:
            tmp.unlink(missing_ok=True)
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


def units(state: dict[str, object]) -> list[dict[str, object]]:
    raw = state.get("units")
    items = raw if isinstance(raw, list) else []
    return [{str(k): v for k, v in item.items()} for item in items if isinstance(item, dict)]


def add_unit(
    repo: Path, train_id: str, name: str, branch: str, path: Path, base: str | None = None
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
        state["units"] = [*recorded, entry]
        _write(target, state)


def active_train(repo: Path) -> str | None:
    marker = repo / TRAIN_MARKER
    try:
        lines = marker.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError):
        return None
    if lines and TRAIN_ID.fullmatch(lines[0]):
        return lines[0]
    return None
