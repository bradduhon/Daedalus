# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0267, 0270, 0280: the model command answers a unit's coder and verifier from the unit's class.
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest
from lib import operator_file, train_runner, train_state, work_classes

from tests.conftest import SCRIPTS_DIR, git
from tests.test_workspace_train import (
    PLAN_BLOCK,
    REFUTED_REPLY,
    _dispatch,
    _model_train,
    _verifier_stop,
)
from tests.test_workspace_train import repo as repo  # noqa: F401

# 0020: a temp HOME and git identity for every test here.
pytestmark = pytest.mark.usefixtures("isolated_env")
REASON = "it proves who calls"
CLASSED = PLAN_BLOCK.replace("base: integration\n", "base: integration | class: Plumbing\n", 1)
CLASSED = CLASSED.replace(
    "files: u2.txt | base: integration\n",
    f"files: u2.txt | base: integration | class: AuthN | place: u2.txt:login | "
    f"class_reason: {REASON}\n",
)
U1_LINE = "{agent} U1: {model} | class: Plumbing"
U2_LINE = "{agent} U2: {model} | class: AuthN | class_reason: " + REASON


def _model(repo: Path, agent: str, unit: str) -> tuple[int, list[str]]:  # noqa: F811
    argv = [sys.executable, str(SCRIPTS_DIR / "daedalus_train.py"), "model", "--repo", str(repo)]
    done = subprocess.run(
        [*argv, "--agent", agent, "--unit", unit],
        capture_output=True,
        text=True,
        check=False,
        cwd=repo,
    )
    return done.returncode, done.stdout.splitlines()


def _answers(repo: Path, u1: str, u2: str) -> None:  # noqa: F811
    for agent in ("coder", "verifier"):
        assert _model(repo, agent, "U1") == (0, [u1, U1_LINE.format(agent=agent, model=u1)])
        assert _model(repo, agent, "U2") == (0, [u2, U2_LINE.format(agent=agent, model=u2)])


def _operator(body: dict[str, object]) -> None:
    path = Path.home() / operator_file.OPERATOR_FILE
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(body), encoding="utf-8")


def _override(repo: Path, body: dict[str, object]) -> None:  # noqa: F811
    config = repo / ".claude" / "daedalus" / "config.json"
    held = json.loads(config.read_text(encoding="utf-8")) if config.is_file() else {}
    held["personal_overrides"] = body
    config.write_text(json.dumps(held), encoding="utf-8")


def test_the_class_picks_coder_and_verifier_at_zero_one_and_two_refutations(
    repo: Path,  # noqa: F811
) -> None:
    _, u1, u2 = _model_train(repo, block=CLASSED)
    _answers(repo, "sonnet", "opus")
    for n in (1, 2):
        for unit, uid, model in ((u1, "U1", "sonnet"), (u2, "U2", "opus")):
            _dispatch(repo, unit, "Agent" if n == 1 else "SendMessage")
            _verifier_stop(repo, REFUTED_REPLY, unit)
            routed = train_runner.route_unit(repo, uid, "REFUTED")
            assert routed.lines == [f"route {uid}: fix model={model} refutations={n} checks=0"]
        _answers(repo, "sonnet", "opus")
    # 0161, 0133: the third still goes to the operator, on the model the unit ran on.
    _dispatch(repo, u2, "SendMessage")
    _verifier_stop(repo, REFUTED_REPLY, u2)
    third = train_runner.route_unit(repo, "U2", "REFUTED")
    assert third.lines == ["route U2: operator model=opus refutations=3 checks=0"]


@pytest.mark.parametrize(
    "name", ["Injection sinks", "Isolation and confinement", "Supply chain", "Redaction"]
)
def test_a_unit_of_a_0285_class_gets_opus_from_the_model_command(
    repo: Path,  # noqa: F811
    name: str,
) -> None:
    _model_train(repo, block=CLASSED.replace("class: AuthN", f"class: {name}"))
    for agent in ("coder", "verifier"):
        code, lines = _model(repo, agent, "U2")
        assert code == 0 and lines[0] == "opus"
        assert lines[1] == f"{agent} U2: opus | class: {name} | class_reason: {REASON}"


def test_the_coder_call_records_its_model_once_and_the_verifier_call_records_nothing(
    repo: Path,  # noqa: F811
) -> None:
    train, _, _ = _model_train(repo, block=CLASSED)
    for _ in range(2):
        assert _model(repo, "coder", "U2")[0] == 0
        assert _model(repo, "verifier", "U1")[0] == 0
    units = {u["name"]: u for u in train_state.units(train_state.load(repo, train))}
    assert units[f"{train}-u2"]["coders"] == [{"model": "opus", "class": "AuthN"}]
    assert "coders" not in units[f"{train}-u1"]


def test_a_user_mapping_moves_both_answers(repo: Path) -> None:  # noqa: F811
    _model_train(repo, block=CLASSED)
    _operator({"class_models": {"Plumbing": "haiku", "AuthN": "fable"}})
    _answers(repo, "haiku", "fable")


def test_a_project_override_lowers_authn_for_that_repository_only(
    repo: Path,  # noqa: F811
    tmp_path: Path,
) -> None:
    _model_train(repo, block=CLASSED)
    _override(repo, {"class_models": {"AuthN": "sonnet"}})
    _answers(repo, "sonnet", "sonnet")
    other = tmp_path.resolve() / "other"
    other.mkdir()
    git(other, "init", "-q", "-b", "main")
    assert work_classes.model_for("AuthN", operator_file.load(other)) == "opus"
    _override(repo, {})
    _answers(repo, "sonnet", "opus")


def test_an_old_plan_with_no_class_fields_answers_the_middle_model(repo: Path) -> None:  # noqa: F811
    _model_train(repo)
    for agent in ("coder", "verifier"):
        for uid in ("U1", "U2"):
            line = f"{agent} {uid}: sonnet | class: Plumbing"
            assert _model(repo, agent, uid) == (0, ["sonnet", line])


def test_a_class_the_settings_no_longer_hold_is_refused(repo: Path) -> None:  # noqa: F811
    _model_train(repo, block=CLASSED)
    rows = [{"name": "Plumbing", "definition": "Any other work."}]
    _operator({"work_classes": rows, "class_models": {"Plumbing": "sonnet"}})
    for agent in ("coder", "verifier"):
        code, lines = _model(repo, agent, "U2")
        assert code == 1 and len(lines) == 1
        assert lines[0].startswith(
            "unit U2 names the class AuthN, which the work classes settings no longer hold."
        )
        assert "Next: add AuthN back to work_classes, or give unit U2 a class" in lines[0]
    assert _model(repo, "coder", "U1")[1][0] == "sonnet"


def test_a_settings_error_is_refused_never_the_middle_model(repo: Path) -> None:  # noqa: F811
    _model_train(repo, block=CLASSED)
    _operator({"class_models": []})
    code, lines = _model(repo, "verifier", "U1")
    assert code == 1 and "class_models must be an object" in lines[0]
    assert lines[-1] == train_runner._MODEL_SETTINGS_NEXT


def test_an_unknown_unit_and_a_run_with_no_plan_are_refused(repo: Path) -> None:  # noqa: F811
    train, _, _ = _model_train(repo, block=CLASSED)
    for agent in ("coder", "verifier"):
        code, lines = _model(repo, agent, "U9")
        assert code == 1 and "the recorded plan names no unit U9" in lines[0]
        assert "Next:" in lines[0]
    train_state.change(repo, train, lambda state: state.pop(train_state.PLAN))
    code, lines = _model(repo, "verifier", "U1")
    assert code == 1 and lines[0].startswith(f"run {train} records no plan, so unit U1")
    assert "Next: record the plan" in lines[0]


def test_model_unit_takes_only_the_coder_and_the_verifier(repo: Path) -> None:  # noqa: F811
    _model_train(repo, block=CLASSED)
    for agent in ("planner", "auditor"):
        code, lines = _model(repo, agent, "U1")
        assert code == 1 and "model --unit picks a coder's or a verifier's model" in lines[0]
        assert "Next:" in lines[0]
