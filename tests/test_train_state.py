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


def test_save_and_load_round_trip(data_repo: Path) -> None:
    save(data_repo, TRAIN, {"train_id": TRAIN, "base_branch": "main"})
    assert load(data_repo, TRAIN) == {"train_id": TRAIN, "base_branch": "main"}
    path = state_path(data_repo, TRAIN)
    assert path == data_repo / STATE_DIR / f"{TRAIN}.json"
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700
    assert sorted(p.name for p in path.parent.iterdir()) == [f"{TRAIN}.json", f"{TRAIN}.lock"]


def test_update_merges_keys(data_repo: Path) -> None:
    save(data_repo, TRAIN, {"train_id": TRAIN, "base_branch": "main"})
    merged = update(data_repo, TRAIN, lock_sha="abc", packet_version=2)
    assert merged == {
        "train_id": TRAIN,
        "base_branch": "main",
        "lock_sha": "abc",
        "packet_version": 2,
    }
    assert load(data_repo, TRAIN) == merged


def test_add_unit_appends_in_order_and_refuses_a_duplicate(data_repo: Path) -> None:
    save(data_repo, TRAIN, {"train_id": TRAIN})
    add_unit(data_repo, TRAIN, "u1", "daedalus-unit/u1", data_repo / "w1")
    add_unit(data_repo, TRAIN, "u2", "daedalus-unit/u2", data_repo / "w2")
    assert load(data_repo, TRAIN)["units"] == [
        {"name": "u1", "branch": "daedalus-unit/u1", "path": str(data_repo / "w1")},
        {"name": "u2", "branch": "daedalus-unit/u2", "path": str(data_repo / "w2")},
    ]
    with pytest.raises(TrainStateError, match="Next:"):
        add_unit(data_repo, TRAIN, "u1", "daedalus-unit/u1", data_repo / "w1")
    assert len(load(data_repo, TRAIN)["units"]) == 2


def test_add_unit_writes_the_audit_flag_only_when_asked(data_repo: Path) -> None:
    # pin D2 -> D1: the audit unit entry carries "audit": true; a coder unit carries no key.
    save(data_repo, TRAIN, {"train_id": TRAIN})
    add_unit(data_repo, TRAIN, f"{TRAIN}-u1", "b1", data_repo / "w1")
    add_unit(data_repo, TRAIN, f"{TRAIN}-audit", "b2", data_repo / "w2", "daedalus/x", audit=True)
    coder, audit = train_state.units(load(data_repo, TRAIN))
    assert "audit" not in coder and audit["audit"] is True and audit["base"] == "daedalus/x"
    assert not train_state.is_audit_unit(coder) and train_state.is_audit_unit(audit)


@pytest.mark.parametrize(
    ("unit", "audit"),
    [
        ({"name": "u1", "audit": True}, True),
        ({"name": f"{TRAIN}-audit"}, True),
        ({"name": f"{TRAIN}-u1"}, False),
        ({"name": f"{TRAIN}-audit-x"}, False),
        ({"name": "x-audit"}, False),
        ({"name": f"{TRAIN}-u1", "audit": "true"}, False),
        ({"name": 7}, False),
        ({}, False),
    ],
)
def test_is_audit_unit_reads_the_flag_or_a_pre_d2_name(
    unit: dict[str, object], audit: bool
) -> None:
    # spec 4: a state written before D2 names the audit unit <train-id>-audit with no flag.
    assert train_state.is_audit_unit(unit) is audit


def test_mark_audit_flags_a_recorded_unit_and_keeps_the_rest(data_repo: Path) -> None:
    save(data_repo, TRAIN, {"train_id": TRAIN, "phase": "build"})
    add_unit(data_repo, TRAIN, f"{TRAIN}-u1", "b1", data_repo / "w1")
    add_unit(data_repo, TRAIN, f"{TRAIN}-audit", "b2", data_repo / "w2")
    train_state.mark_audit(data_repo, TRAIN, f"{TRAIN}-audit")
    state = load(data_repo, TRAIN)
    coder, audit = train_state.units(state)
    assert audit["audit"] is True and "audit" not in coder and state["phase"] == "build"


def test_save_is_atomic(data_repo: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    save(data_repo, TRAIN, {"train_id": TRAIN, "v": 1})

    def _fail(src: str, dst: str) -> None:
        raise OSError("disk full")

    monkeypatch.setattr(train_state.os, "replace", _fail)
    with pytest.raises(TrainStateError, match="Next:"):
        save(data_repo, TRAIN, {"train_id": TRAIN, "v": 2})
    monkeypatch.undo()
    assert load(data_repo, TRAIN) == {"train_id": TRAIN, "v": 1}
    assert sorted(p.name for p in (data_repo / STATE_DIR).iterdir()) == [
        f"{TRAIN}.json",
        f"{TRAIN}.lock",
    ]


def test_symlinked_state_dir_is_refused(data_repo: Path, tmp_path: Path) -> None:
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (data_repo / STATE_DIR).symlink_to(elsewhere)
    with pytest.raises(TrainStateError, match="Next:"):
        save(data_repo, TRAIN, {"train_id": TRAIN})
    assert list(elsewhere.iterdir()) == []


def test_symlinked_state_file_is_refused(data_repo: Path, tmp_path: Path) -> None:
    target = tmp_path / "target.json"
    target.write_text("{}")
    (data_repo / STATE_DIR).mkdir(mode=0o700)
    state_path(data_repo, TRAIN).symlink_to(target)
    with pytest.raises(TrainStateError, match="Next:"):
        save(data_repo, TRAIN, {"train_id": TRAIN})
    with pytest.raises(TrainStateError, match="Next:"):
        load(data_repo, TRAIN)
    assert target.read_text() == "{}"


def test_load_of_a_missing_train_names_next(data_repo: Path) -> None:
    with pytest.raises(TrainStateError, match="Next:"):
        load(data_repo, TRAIN)


@pytest.mark.parametrize("train", ["../x", "", "2026-10-16"])
def test_a_bad_train_id_is_refused(data_repo: Path, train: str) -> None:
    with pytest.raises(TrainStateError, match="Next:"):
        state_path(data_repo, train)


def test_mark_start_writes_start_seq_once(data_repo: Path) -> None:
    # issue 57: the first hooks-live sets the bound; a later one never moves it.
    save(data_repo, TRAIN, {"train_id": TRAIN})
    assert train_state.start_seq(load(data_repo, TRAIN)) is None
    assert train_state.mark_start(data_repo, TRAIN, 0) == 0
    assert train_state.mark_start(data_repo, TRAIN, 40) == 0
    assert load(data_repo, TRAIN)[train_state.START_SEQ] == 0


def test_mark_start_moves_the_bound_once_per_new_session(data_repo: Path) -> None:
    # issue 60: a new session resets start_seq to its own bound; each session keeps its first.
    save(data_repo, TRAIN, {"train_id": TRAIN})
    assert train_state.mark_start(data_repo, TRAIN, 30, "build") == 30
    assert train_state.mark_start(data_repo, TRAIN, 45, "build") == 30
    assert train_state.mark_start(data_repo, TRAIN, 4, "resumed") == 4
    state = load(data_repo, TRAIN)
    assert state[train_state.AUDIT_SESSION] == "resumed"
    assert state[train_state.AUDIT_BOUNDS] == {"build": 30, "resumed": 4}
    assert train_state.session_bound(state, "build") == 30
    assert train_state.session_bound(state, "resumed") == 4
    assert train_state.session_bound(state, "never") is None
    assert train_state.mark_start(data_repo, TRAIN, 99, "build") == 30
    assert load(data_repo, TRAIN)[train_state.AUDIT_SESSION] == "build"


def test_mark_start_keeps_a_bound_written_before_audit_session(data_repo: Path) -> None:
    # issue 60: a train started before audit_session keeps its one bound for every session.
    save(data_repo, TRAIN, {"train_id": TRAIN, train_state.START_SEQ: 12})
    assert train_state.mark_start(data_repo, TRAIN, 3, "later") == 12
    state = load(data_repo, TRAIN)
    assert train_state.AUDIT_SESSION not in state
    assert train_state.session_bound(state, "any") == 12


@pytest.mark.parametrize("bounds", [None, "x", {"s": True}, {"s": -1}, {"s": "3"}], ids=str)
def test_session_bound_narrows_the_bounds_field(bounds: object) -> None:
    state = {train_state.AUDIT_SESSION: "s", train_state.AUDIT_BOUNDS: bounds}
    assert train_state.session_bound(state, "s") is None


def test_record_reads_an_object_field_or_empty() -> None:
    assert train_state.record({"verdict": {"tip": "t"}}, "verdict") == {"tip": "t"}
    assert train_state.record({"verdict": ["t"]}, "verdict") == {}
    assert train_state.record({}, "verdict") == {}


@pytest.mark.parametrize("value", [True, -1, "3", 2.0, None])
def test_start_seq_reads_only_a_non_negative_int(data_repo: Path, value: object) -> None:
    assert train_state.start_seq({train_state.START_SEQ: value}) is None
    save(data_repo, TRAIN, {"train_id": TRAIN, train_state.START_SEQ: value})
    assert train_state.mark_start(data_repo, TRAIN, 9) == 9


def test_active_train_reads_the_marker(data_repo: Path) -> None:
    marker = data_repo / ".claude" / "daedalus" / "train.active"
    assert active_train(data_repo) is None
    marker.write_text(f"{TRAIN}\n")
    assert active_train(data_repo) == TRAIN
    marker.write_text("../x\n")
    assert active_train(data_repo) is None
    marker.write_text("")
    assert active_train(data_repo) is None
    os.chmod(marker, 0)
    try:
        assert active_train(data_repo) is None or os.geteuid() == 0
    finally:
        os.chmod(marker, 0o600)
