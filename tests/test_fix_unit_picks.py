# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 339: the operator's per-finding pick record, and the fix-unit check that reads it.
from __future__ import annotations

from pathlib import Path

import pytest
from lib import train_runner, train_state

from tests.conftest import git
from tests.test_fix_units import (
    REQ_F1,
    REQ_F3,
    _fix,
    _fixture,
    _picked,
    _refusal,
    _rejected,
    _shot,
)
from tests.test_records_in_one_call import TRAIN, _built, _cli, _ok, _verdict
from tests.test_records_in_one_call import fixed as fixed  # noqa: F401
from tests.test_workspace_train import REFUTED_REPLY, VERIFIED_REPLY

pytestmark = pytest.mark.usefixtures("isolated_env", "fixed")


def _round_one(tmp_path: Path) -> Path:
    # Both planned units merged and round 1 rejected with F1 and F2, before any pick.
    root = _fixture(tmp_path / "repo")
    for uid in ("U1", "U2"):
        _ok(train_runner.dispatch_unit(root, uid))
        _verdict(root, _built(root, uid), VERIFIED_REPLY)
    _ok(train_runner.finish_unit(root, "U1"))
    _ok(train_runner.finish_unit(root, "U2"))
    _rejected(root, 1, "F1", "F2")
    return root


def _state(root: Path) -> dict[str, object]:
    return train_state.load(root, TRAIN)


def _one_refusal(outcome: train_runner.Outcome, needle: str) -> None:
    assert outcome.code == 1 and len(outcome.lines) == 1, outcome.lines
    assert needle in outcome.lines[0] and outcome.lines[0].count("Next:") == 1, outcome.lines


@pytest.mark.parametrize(
    ("round_", "keys", "word", "needle"),
    [
        (2, ("F1",), "fix", "records no rejected audit verdict for round 2"),
        (0, ("F1",), "fix", "records no rejected audit verdict for round 0"),
        (1, ("F9",), "fix", "finding 'F9' is not in the rejected round 1"),
        (1, ("F1", "F9"), "fix", "finding 'F9' is not in the rejected round 1"),
        (1, ("F1",), "Fix it now", "--pick 'Fix it now' is not fix, skip or stop"),
        (1, ("F1",), "", "--pick '' is not fix, skip or stop"),
        (1, (), "fix", "pick names no finding"),
    ],
)
def test_each_pick_refusal_changes_nothing(
    tmp_path: Path, round_: int, keys: tuple[str, ...], word: str, needle: str
) -> None:
    root = _round_one(tmp_path)
    before = _state(root)
    _one_refusal(train_runner.record_pick(root, round_, list(keys), word), needle)
    assert _state(root) == before


def test_a_pick_on_an_approved_round_is_refused(tmp_path: Path) -> None:
    root = _round_one(tmp_path)
    tip = git(root, "rev-parse", "HEAD").stdout.strip()
    approved = {"status": "approved", "tip": tip, "round": 1, "seq": 0}
    train_state.update(root, TRAIN, verdict=approved)
    before = _state(root)
    refused = train_runner.record_pick(root, 1, ["F1"], "fix")
    _one_refusal(refused, "records no rejected audit verdict for round 1")
    assert _state(root) == before


def test_a_repeat_pick_replaces_the_first(tmp_path: Path) -> None:
    root = _round_one(tmp_path)
    assert _picked(root, 1, "F1") == ["pick round=1 F1: Fix it now"]
    assert _picked(root, 1, "F1", "F2", word="skip") == [
        "pick round=1 F1: Skip, track or exempt it",
        "pick round=1 F2: Skip, track or exempt it",
    ]
    assert _state(root)[train_state.PICKS] == {"1": {"F1": "skip", "F2": "skip"}}
    before = _shot(root)
    _refusal(root, _fix(root), "finding 'F1' of round 1 has no recorded `Fix it now` pick")
    assert _shot(root) == before


def test_pick_runs_from_the_command_line_with_one_next_line_on_a_refusal(tmp_path: Path) -> None:
    root = _round_one(tmp_path)
    head = ("pick", "--round", "1", "--finding", "F1", "--finding", "F2")
    code, out = _cli(root, *head, "--pick", "stop")
    assert (code, out) == (0, "pick round=1 F1: Stop the run\npick round=1 F2: Stop the run\n")
    before = _state(root)
    code, out = _cli(root, *head, "--pick", "later")
    assert code == 1 and out.count("\n") == 1 and out.count("Next:") == 1, out
    assert "--pick 'later' is not fix, skip or stop" in out
    assert _state(root) == before


@pytest.mark.parametrize(
    ("picks", "findings", "reqs", "needle"),
    [
        ((), ("F1",), (REQ_F1,), "finding 'F1' of round 1 has no"),
        ((("skip", "F1"),), ("F1",), (REQ_F1,), "finding 'F1' of round 1 has no"),
        ((("stop", "F1"),), ("F1",), (REQ_F1,), "finding 'F1' of round 1 has no"),
        (
            (("fix", "F1"), ("skip", "F2")),
            ("F1", "F2"),
            (REQ_F1, REQ_F3),
            "finding 'F2' of round 1 has no",
        ),
        ((("fix", "F1"),), ("F1", "F2"), (REQ_F1, REQ_F3), "finding 'F2' of round 1 has no"),
    ],
)
def test_fix_unit_refuses_a_finding_without_a_fix_pick(
    tmp_path: Path,
    picks: tuple[tuple[str, str], ...],
    findings: tuple[str, ...],
    reqs: tuple[str, ...],
    needle: str,
) -> None:
    root = _round_one(tmp_path)
    for word, key in picks:
        _picked(root, 1, key, word=word)
    before = _shot(root)
    _refusal(root, _fix(root, findings=findings, reqs=reqs), needle)
    # The plan bytes, the recorded plan hash and the fix unit record are as they were.
    assert _shot(root) == before


def test_a_fix_pick_in_another_round_does_not_count(tmp_path: Path) -> None:
    root = _round_one(tmp_path)
    _picked(root, 1, "F1")
    _rejected(root, 2, "F1")
    before = _shot(root)
    _refusal(root, _fix(root), "finding 'F1' of round 2 has no recorded `Fix it now` pick")
    assert _shot(root) == before
    _picked(root, 2, "F1")
    _ok(_fix(root))
    entry = train_state.record(_state(root), train_state.FIX_UNITS)["fix1-u1"]
    assert entry == {"fixes": ["U1"], "findings": ["F1"], "round": 2}


def test_a_row_needs_no_pick(tmp_path: Path) -> None:
    # A refuted verifier row is routed by the verify phase; no operator pick stands behind it.
    root = _fixture(tmp_path / "repo")
    _ok(train_runner.dispatch_unit(root, "U2"))
    _verdict(root, _built(root, "U2"), REFUTED_REPLY)
    _ok(_fix(root, fixes=("U2",), findings=(), rows=(1,), files=("web/u2.html",)))
    state = _state(root)
    assert train_state.PICKS not in state
    assert train_state.record(state, train_state.FIX_UNITS)["fix1-u1"]["rows"] == [1]  # type: ignore[index]
