# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# spec 6: the progress note reads a unit the runner never dispatched from the bindings file.
from __future__ import annotations

from pathlib import Path

from lib import train_runner, train_state, unit_binding

from tests import test_train_runner as runner_tests
from tests.test_train_runner import _plan, _probe_stage, _started, _state, _units, _write_train

# The runner tests' fixtures: a temp HOME, a plugin root and a one-commit repository.
_isolated_env = runner_tests._isolated_env
plugin = runner_tests.plugin
repo = runner_tests.repo


def _hand_driven(repo: Path, plugin: Path) -> str:
    # A recipe the orchestrator drives by hand: the runner's queue holds no coder dispatch.
    _write_train(plugin, [_probe_stage()], ("repository",))
    _started(repo, plugin)
    _units(repo, ["a1", "a2", "a3", "audit"], stacked={"a2": "a1"})
    _plan(repo)
    return str(_state(repo)["train_id"])


def _unit_lines(outcome: train_runner.Outcome) -> list[str]:
    return outcome.lines[1 : outcome.lines.index("Choices: none")]


def test_a_dispatched_unit_runs_and_its_stacked_unit_waits(repo: Path, plugin: Path) -> None:
    train = _hand_driven(repo, plugin)
    assert unit_binding.record_dispatch(repo, train, f"{train}-a1") is None
    assert unit_binding.claim(repo, train, "coder-1", f"{train}-a1") is None
    outcome = train_runner.progress(repo)
    assert outcome.code == 0, outcome.lines
    assert _unit_lines(outcome) == [
        "A1 first piece: running (coder)",
        "A2 second piece: waiting on A1",
        "a3: queued",
    ]


def test_a_retired_unit_is_done_and_the_warm_unit_runs(repo: Path, plugin: Path) -> None:
    # 0086: the coder moved on from a1 to a2, so a1 is complete.
    train = _hand_driven(repo, plugin)
    assert unit_binding.record_dispatch(repo, train, f"{train}-a1") is None
    assert unit_binding.claim(repo, train, "coder-1", f"{train}-a1") is None
    assert unit_binding.rebind(repo, train, "coder-1", f"{train}-a1", f"{train}-a2") is None
    outcome = train_runner.progress(repo)
    assert outcome.code == 0, outcome.lines
    assert _unit_lines(outcome) == [
        "A1 first piece: done",
        "A2 second piece: running (coder)",
        "a3: queued",
    ]
    text = "\n".join(outcome.lines)
    assert "coder-1" not in text and str(repo) not in text


def test_the_audit_unit_is_never_listed(repo: Path, plugin: Path) -> None:
    # pin C4 -> C7: the audit worktree is a recorded unit but not a line of the note.
    train = _hand_driven(repo, plugin)
    assert unit_binding.record_dispatch(repo, train, f"{train}-audit") is None
    outcome = train_runner.progress(repo)
    assert outcome.code == 0, outcome.lines
    assert not any(line.lower().startswith("audit") for line in outcome.lines)
    assert any(u["name"] == f"{train}-audit" for u in train_state.units(_state(repo)))


def test_a_finished_unit_reads_done_and_frees_its_stacked_unit(repo: Path, plugin: Path) -> None:
    # spec 4: finish marks each merged unit, so a hand-driven unit reads done, not running.
    train = _hand_driven(repo, plugin)
    assert unit_binding.record_dispatch(repo, train, f"{train}-a1") is None
    assert unit_binding.claim(repo, train, "coder-1", f"{train}-a1") is None
    assert unit_binding.mark_finished(repo, train, f"{train}-a1") is None
    assert unit_binding.mark_finished(repo, train, f"{train}-a3") is None
    outcome = train_runner.progress(repo)
    assert outcome.code == 0, outcome.lines
    assert _unit_lines(outcome) == ["A1 first piece: done", "A2 second piece: queued", "a3: done"]


def test_a_finished_mark_wins_over_a_runner_dispatch_record(repo: Path, plugin: Path) -> None:
    # spec 4: _done reads finished before the dispatch status and before retired_to.
    train = _hand_driven(repo, plugin)
    name = f"{train}-a1"
    dispatch = {"unit": name, "agent": "coder", "status": train_runner.DISPATCHED}
    train_state.update(repo, train, dispatches=[dispatch])
    assert _unit_lines(train_runner.progress(repo))[0] == "A1 first piece: running (coder)"
    assert unit_binding.mark_finished(repo, train, name) is None
    assert _unit_lines(train_runner.progress(repo))[0] == "A1 first piece: done"


def test_a_flagged_audit_unit_is_never_listed(repo: Path, plugin: Path) -> None:
    # issue 71: the flag, not only the <train-id>-audit name, keeps the audit unit off the note.
    train = _hand_driven(repo, plugin)
    tree = repo / ".claude" / "worktrees" / f"{train}-probe"
    train_state.add_unit(repo, train, f"{train}-probe", "b", tree, audit=True)
    outcome = train_runner.progress(repo)
    assert outcome.code == 0, outcome.lines
    assert not any("probe" in line for line in outcome.lines)


def test_an_unreadable_bindings_file_stops_without_a_path(repo: Path, plugin: Path) -> None:
    train = _hand_driven(repo, plugin)
    unit_binding.bindings_path(repo, train).write_text("{not json", encoding="utf-8")
    outcome = train_runner.progress(repo)
    assert outcome.code == train_runner.EXIT_STOP
    assert outcome.lines == [train_runner.BINDINGS_UNREADABLE]
    assert str(repo) not in outcome.lines[0]
