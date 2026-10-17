# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest
from lib import train_state
from lib.train_state import (
    STATE_DIR,
    TrainStateError,
    active_train,
    add_unit,
    load,
    save,
    state_path,
    update,
)

TRAIN = "20261016-120000"


@pytest.fixture
def repo(project_data: Path) -> Path:
    return project_data.parent.parent


def test_save_and_load_round_trip(repo: Path) -> None:
    save(repo, TRAIN, {"train_id": TRAIN, "base_branch": "main"})
    assert load(repo, TRAIN) == {"train_id": TRAIN, "base_branch": "main"}
    path = state_path(repo, TRAIN)
    assert path == repo / STATE_DIR / f"{TRAIN}.json"
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700
    assert sorted(p.name for p in path.parent.iterdir()) == [f"{TRAIN}.json", f"{TRAIN}.lock"]


def test_update_merges_keys(repo: Path) -> None:
    save(repo, TRAIN, {"train_id": TRAIN, "base_branch": "main"})
    merged = update(repo, TRAIN, lock_sha="abc", packet_version=2)
    assert merged == {
        "train_id": TRAIN,
        "base_branch": "main",
        "lock_sha": "abc",
        "packet_version": 2,
    }
    assert load(repo, TRAIN) == merged


def test_add_unit_appends_in_order_and_refuses_a_duplicate(repo: Path) -> None:
    save(repo, TRAIN, {"train_id": TRAIN})
    add_unit(repo, TRAIN, "u1", "daedalus-unit/u1", repo / "w1")
    add_unit(repo, TRAIN, "u2", "daedalus-unit/u2", repo / "w2")
    assert load(repo, TRAIN)["units"] == [
        {"name": "u1", "branch": "daedalus-unit/u1", "path": str(repo / "w1")},
        {"name": "u2", "branch": "daedalus-unit/u2", "path": str(repo / "w2")},
    ]
    with pytest.raises(TrainStateError, match="Next:"):
        add_unit(repo, TRAIN, "u1", "daedalus-unit/u1", repo / "w1")
    assert len(load(repo, TRAIN)["units"]) == 2


def test_save_is_atomic(repo: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    save(repo, TRAIN, {"train_id": TRAIN, "v": 1})

    def _fail(src: str, dst: str) -> None:
        raise OSError("disk full")

    monkeypatch.setattr(train_state.os, "replace", _fail)
    with pytest.raises(TrainStateError, match="Next:"):
        save(repo, TRAIN, {"train_id": TRAIN, "v": 2})
    monkeypatch.undo()
    assert load(repo, TRAIN) == {"train_id": TRAIN, "v": 1}
    assert sorted(p.name for p in (repo / STATE_DIR).iterdir()) == [
        f"{TRAIN}.json",
        f"{TRAIN}.lock",
    ]


def test_symlinked_state_dir_is_refused(repo: Path, tmp_path: Path) -> None:
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (repo / STATE_DIR).symlink_to(elsewhere)
    with pytest.raises(TrainStateError, match="Next:"):
        save(repo, TRAIN, {"train_id": TRAIN})
    assert list(elsewhere.iterdir()) == []


def test_symlinked_state_file_is_refused(repo: Path, tmp_path: Path) -> None:
    target = tmp_path / "target.json"
    target.write_text("{}")
    (repo / STATE_DIR).mkdir(mode=0o700)
    state_path(repo, TRAIN).symlink_to(target)
    with pytest.raises(TrainStateError, match="Next:"):
        save(repo, TRAIN, {"train_id": TRAIN})
    with pytest.raises(TrainStateError, match="Next:"):
        load(repo, TRAIN)
    assert target.read_text() == "{}"


def test_load_of_a_missing_train_names_next(repo: Path) -> None:
    with pytest.raises(TrainStateError, match="Next:"):
        load(repo, TRAIN)


@pytest.mark.parametrize("train", ["../x", "", "2026-10-16"])
def test_a_bad_train_id_is_refused(repo: Path, train: str) -> None:
    with pytest.raises(TrainStateError, match="Next:"):
        state_path(repo, train)


def test_active_train_reads_the_marker(repo: Path) -> None:
    marker = repo / ".claude" / "daedalus" / "train.active"
    assert active_train(repo) is None
    marker.write_text(f"{TRAIN}\n")
    assert active_train(repo) == TRAIN
    marker.write_text("../x\n")
    assert active_train(repo) is None
    marker.write_text("")
    assert active_train(repo) is None
    os.chmod(marker, 0)
    try:
        assert active_train(repo) is None or os.geteuid() == 0
    finally:
        os.chmod(marker, 0o600)
