# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 75, W1.1: a FIFO planted at any lock path is refused inside one second, never waited on.
from __future__ import annotations

import os
import threading
import time
from collections.abc import Callable
from contextlib import ExitStack
from pathlib import Path
from typing import Any

import pytest
from lib import audit, fetch, locks, train_state, unit_binding

from tests.conftest import write_train_marker

TRAIN = "20261016-120000"
BOUND_S = 1.0


def _within_bound(call: Callable[[], object]) -> BaseException | object:
    # A hung open cannot be interrupted, so the call runs on a daemon thread the test abandons.
    box: list[BaseException | object] = []

    def target() -> None:
        try:
            box.append(call())
        except BaseException as exc:  # noqa: BLE001
            box.append(exc)

    worker = threading.Thread(target=target, daemon=True)
    started = time.monotonic()
    worker.start()
    worker.join(BOUND_S)
    assert not worker.is_alive(), f"the call hung for {BOUND_S:g} s on a FIFO lock"
    assert time.monotonic() - started < BOUND_S
    return box[0]


@pytest.fixture
def repo(project_data: Path) -> Path:
    return project_data.parent.parent


def _trains(repo: Path) -> Path:
    folder = repo / train_state.STATE_DIR
    folder.mkdir(mode=0o700, exist_ok=True)
    return folder


def test_open_lock_refuses_a_fifo(tmp_path: Path) -> None:
    lock = tmp_path / "x.lock"
    os.mkfifo(lock)
    found = _within_bound(lambda: locks.open_lock(lock))
    assert isinstance(found, locks.LockRefused) and isinstance(found, OSError)
    assert str(found) == f"lock {lock} is not a regular file. Next: remove it and retry."


def test_locked_refuses_a_fifo(tmp_path: Path) -> None:
    lock = tmp_path / "x.lock"
    os.mkfifo(lock)

    def enter() -> None:
        with locks.locked(lock):
            pass

    assert isinstance(_within_bound(enter), locks.LockRefused)


def test_train_state_lock_refuses_a_fifo(repo: Path) -> None:
    os.mkfifo(_trains(repo) / f"{TRAIN}.lock")
    found = _within_bound(lambda: train_state.save(repo, TRAIN, {"train_id": TRAIN}))
    assert isinstance(found, train_state.TrainStateError)
    assert "is not a regular file" in str(found) and "Next:" in str(found)
    assert not train_state.state_path(repo, TRAIN).exists()


def test_bindings_lock_refuses_a_fifo(repo: Path) -> None:
    os.mkfifo(_trains(repo) / f"{TRAIN}.bindings.lock")
    found = _within_bound(lambda: unit_binding.record_dispatch(repo, TRAIN, f"{TRAIN}-u1"))
    assert isinstance(found, str) and "is not a regular file" in found and "Next:" in found
    found = _within_bound(lambda: unit_binding.mark_finished(repo, TRAIN, f"{TRAIN}-u1"))
    assert isinstance(found, str) and "is not a regular file" in found


def test_audit_lock_refuses_a_fifo(repo: Path, hook_input: Any) -> None:
    write_train_marker(repo)
    folder = repo / ".claude" / "daedalus" / "audit"
    folder.mkdir(mode=0o700)
    os.mkfifo(folder / "sess-test.lock")
    found = _within_bound(lambda: audit.audit_append(hook_input()))
    assert isinstance(found, audit.AuditLockError)
    assert "is not a regular file" in str(found) and "Next:" in str(found)
    found = _within_bound(lambda: audit.read_log(folder / "sess-test.jsonl"))
    assert isinstance(found, audit.AuditLockError)


def test_rotation_lock_refuses_a_fifo(tmp_path: Path) -> None:
    log = tmp_path / "old.jsonl"
    log.write_text("", encoding="utf-8")
    os.mkfifo(tmp_path / "old.lock")

    def take() -> bool:
        with ExitStack() as stack:
            return audit._try_lock(log, stack)

    assert isinstance(_within_bound(take), locks.LockRefused)


def test_refresh_lock_refuses_a_fifo(tmp_path: Path) -> None:
    os.mkfifo(tmp_path / fetch.LOCK)

    def enter() -> None:
        with fetch._locked(tmp_path):
            pass

    found = _within_bound(enter)
    assert isinstance(found, fetch.RefreshError) and "is not a regular file. Next:" in str(found)


# The ledger lock is covered by tests/test_append_ledger.py::test_fifo_at_lock_path_fails_fast.
