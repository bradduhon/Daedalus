# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import copy
import json
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path

import pytest
from lib.train_definition import Definition, DefinitionError, load, validate

from tests.conftest import REPO_ROOT, SCRIPTS_DIR

FIXTURES = REPO_ROOT / "tests" / "fixtures" / "trains"
INVALID = sorted(p.stem for p in FIXTURES.glob("*.json") if p.stem != "valid")


def _defects(name: str) -> list[str]:
    return validate(load(FIXTURES / f"{name}.json"), REPO_ROOT, "plugin")


def _only(check: int, name: str) -> str:
    # 0033: each invalid fixture carries defects of its own check and no other.
    defects = _defects(name)
    assert defects, name
    assert all(line.startswith(f"check {check}: ") for line in defects), defects
    return "\n".join(defects)


def _cli(path: Path) -> subprocess.CompletedProcess[str]:
    script = SCRIPTS_DIR / "validate_train.py"
    return subprocess.run(
        [sys.executable, str(script), str(path)], capture_output=True, text=True, check=False
    )


def test_check1_refuses_a_missing_top_level_field() -> None:
    assert "off_contract" in _only(1, "check1")


def test_check2_refuses_a_stage_missing_a_required_field() -> None:
    text = _only(2, "check2")
    assert "stage lock" in text and "proof" in text


def test_check3_refuses_an_agent_without_a_file() -> None:
    text = _only(3, "check3")
    assert "ghost-agent" in text and "agents/ghost-agent.md" in text


def test_check4_refuses_a_reply_line_outside_the_status_contract() -> None:
    text = _only(4, "check4")
    assert "## Locked Packet" in text and "contract-spec" in text


def test_check5_refuses_a_touch_class_the_hooks_do_not_grant() -> None:
    text = _only(5, "check5")
    assert "docs" in text and "unit-src-tests" in text


def test_check6_refuses_an_unrouted_outcome() -> None:
    text = _only(6, "check6")
    assert "waiting" in text and "stage lock" in text


def test_check8_refuses_gates_out_of_order_and_back_without_rounds() -> None:
    defects = _only(8, "check8").splitlines()
    assert len(defects) == 2
    assert any("gate" in line and "order" in line for line in defects)
    assert any("rounds=" in line for line in defects)


def test_check9_refuses_a_missing_route_target_or_consult() -> None:
    defects = _only(9, "check9").splitlines()
    assert len(defects) == 2
    assert any("nowhere" in line for line in defects)
    assert any("ghost-agent" in line for line in defects)


def test_check10_refuses_a_missing_template_or_unresolved_placeholder() -> None:
    defects = _only(10, "check10").splitlines()
    assert len(defects) == 2
    assert any("tests/fixtures/trains/missing/contract.md" in line for line in defects)
    assert any("{verdict_text}" in line for line in defects)


def test_check11_refuses_a_next_line_without_four_plain_words() -> None:
    defects = _only(11, "check11").splitlines()
    assert len(defects) == 2
    assert any("description" in line for line in defects)
    assert any("/daedalus:build-train" in line for line in defects)


@pytest.mark.parametrize("name", ["check13-empty", "check13-unknown"])
def test_check13_refuses_an_empty_or_unknown_scope_kind(name: str) -> None:
    assert "scopes" in _only(13, name)


def test_check13_refuses_a_when_on_an_unknown_feature() -> None:
    assert "features.gitleaks" in _only(13, "check13-when")


def test_valid_fixture_prints_the_ok_line() -> None:
    assert _defects("valid") == []
    result = _cli(FIXTURES / "valid.json")
    assert (result.returncode, result.stdout, result.stderr) == (
        0,
        "OK train valid v1: 4 stages\n",
        "",
    )


@pytest.mark.parametrize("name", INVALID)
def test_cli_prints_each_defect_then_one_next_line(name: str) -> None:
    result = _cli(FIXTURES / f"{name}.json")
    lines = result.stdout.splitlines()
    assert result.returncode == 1
    assert lines[:-1] == _defects(name)
    assert lines[-1].startswith("Next: ") and sum("Next:" in line for line in lines) == 1


@pytest.mark.parametrize("text", ["{ not json", "[]", ""])
def test_cli_refuses_a_file_that_is_not_a_json_object(tmp_path: Path, text: str) -> None:
    target = tmp_path / "broken.json"
    target.write_text(text, encoding="utf-8")
    with pytest.raises(DefinitionError):
        load(target)
    result = _cli(target)
    lines = result.stdout.splitlines()
    assert result.returncode == 1 and len(lines) == 2
    assert lines[0].startswith("check 1: ") and lines[1].startswith("Next: ")


def test_cli_refuses_a_missing_file_and_bad_usage(tmp_path: Path) -> None:
    result = _cli(tmp_path / "absent.json")
    assert result.returncode == 1 and result.stdout.startswith("check 1: ")
    script = SCRIPTS_DIR / "validate_train.py"
    usage = subprocess.run([sys.executable, str(script)], capture_output=True, text=True)
    assert usage.returncode == 1 and "Next:" in usage.stderr


def _valid() -> dict[str, object]:
    raw = json.loads((FIXTURES / "valid.json").read_text(encoding="utf-8"))
    assert isinstance(raw, dict)
    return raw


def _stage(raw: dict[str, object], index: int) -> dict[str, object]:
    stages = raw["stages"]
    assert isinstance(stages, list) and isinstance(stages[index], dict)
    return stages[index]


def _sub(raw: dict[str, object], index: int, key: str) -> dict[str, object]:
    found = _stage(raw, index)[key]
    assert isinstance(found, dict)
    return found


Mutation = Callable[[dict[str, object]], None]

# 0033: each mutation of the valid fixture is caught by the named check.
MUTATIONS: list[tuple[int, str, Mutation]] = [
    (1, "unknown top field", lambda r: r.update(extra=1)),
    (1, "name differs from stem", lambda r: r.update(name="other")),
    (1, "name not a slug", lambda r: r.update(name="Valid")),
    (1, "version is a bool", lambda r: r.update(version=True)),
    (1, "version below one", lambda r: r.update(version=0)),
    (1, "empty description", lambda r: r.update(description="")),
    (1, "gates not a list", lambda r: r.update(gates="build")),
    (1, "repeated gate", lambda r: r.update(gates=["build", "build"])),
    (1, "consults not an object", lambda r: r.update(consults=[])),
    (1, "consults value not a list", lambda r: r.update(consults={"build": "x"})),
    (1, "stages empty", lambda r: r.update(stages=[])),
    (1, "stage not an object", lambda r: r.update(stages=[1])),
    (1, "off_contract not text", lambda r: r.update(off_contract=3)),
    (2, "unknown stage field", lambda r: _stage(r, 0).update(extra=1)),
    (2, "id not a slug", lambda r: _stage(r, 0).update(id="Contract")),
    (2, "repeated id", lambda r: _stage(r, 1).update(id="contract")),
    (2, "gate not text", lambda r: _stage(r, 0).update(gate=1)),
    (2, "agent empty", lambda r: _stage(r, 0).update(agent="")),
    (2, "scope not an object", lambda r: _stage(r, 0).update(scope=[])),
    (2, "scope lacks reply", lambda r: _sub(r, 0, "scope").pop("reply")),
    (2, "scope extra key", lambda r: _sub(r, 0, "scope").update(extra=1)),
    (2, "told empty", lambda r: _sub(r, 0, "scope").update(told="")),
    (2, "touch empty", lambda r: _sub(r, 0, "scope").update(touch=[])),
    (2, "touch unknown class", lambda r: _sub(r, 0, "scope").update(touch=["home"])),
    (2, "reply not strings", lambda r: _sub(r, 0, "scope").update(reply=[1])),
    (2, "proof not an object", lambda r: _stage(r, 0).update(proof="x")),
    (2, "script empty", lambda r: _sub(r, 0, "proof").update(script="")),
    (2, "exit empty", lambda r: _sub(r, 0, "proof").update(exit={})),
    (2, "exit code not a number", lambda r: _sub(r, 0, "proof").update(exit={"x": "pass"})),
    (2, "exit outcome empty", lambda r: _sub(r, 0, "proof").update(exit={"0": ""})),
    (2, "records not names", lambda r: _sub(r, 0, "proof").update(records=["a b"])),
    (2, "on_fail not an object", lambda r: _stage(r, 0).update(on_fail=[])),
    (2, "route not text", lambda r: _stage(r, 0).update(on_fail={"off-contract": 1})),
    (2, "verifies not text", lambda r: _stage(r, 0).update(verifies=1)),
    (2, "when empty", lambda r: _stage(r, 0).update(when="")),
    (2, "repeat unknown", lambda r: _stage(r, 0).update(repeat="per-gate")),
    (2, "parallel not a bool", lambda r: _stage(r, 2).update(parallel="yes")),
    (2, "parallel without repeat", lambda r: _stage(r, 0).update(parallel=True)),
    (3, "agent name walks out", lambda r: _stage(r, 0).update(agent="../contract-spec")),
    (5, "contract touches the unit", lambda r: _sub(r, 0, "scope").update(touch=["none"])),
    (6, "route the stage never produces", lambda r: _sub(r, 0, "on_fail").update(x="ask: Why?")),
    (6, "reply line with no pass", lambda r: _sub(r, 3, "proof").update(exit={"2": "blocked"})),
    (8, "stage gate undeclared", lambda r: _stage(r, 0).update(gate="design")),
    (
        8,
        "back to a later stage",
        lambda r: _stage(r, 0).update(on_fail={"off-contract": "back:code rounds=1"}),
    ),
    (
        8,
        "rounds zero",
        lambda r: _sub(r, 2, "on_fail").update(
            {"[STATUS: YIELD_CONTRACT]": "back:contract rounds=0"}
        ),
    ),
    (8, "back from off_contract", lambda r: r.update(off_contract="back:contract rounds=1")),
    (9, "route form unknown", lambda r: _stage(r, 1).update(on_fail={"stopped": "halt"})),
    (
        9,
        "consult a missing agent",
        lambda r: _stage(r, 3).update(on_fail={"blocked": "consult:ghost-agent"}),
    ),
    (9, "consults an undeclared gate", lambda r: r.update(consults={"design": []})),
    (10, "agent stage with no brief", lambda r: _sub(r, 0, "scope").update(told="none")),
    (10, "brief path walks out", lambda r: _sub(r, 0, "scope").update(told="../x.md")),
    (10, "script placeholder unknown", lambda r: _sub(r, 1, "proof").update(script="x {nope}")),
    (
        10,
        "own records are not earlier",
        lambda r: _sub(r, 1, "proof").update(script="x {lock_sha}"),
    ),
    (11, "ask is fine but stop is bare", lambda r: r.update(off_contract="stop: Next: rerun")),
    (13, "scopes not a list", lambda r: r.update(scopes="repository")),
    (13, "repeated scope", lambda r: r.update(scopes=["folder", "folder"])),
]


@pytest.mark.parametrize(
    ("check", "mutate"), [(c, m) for c, _, m in MUTATIONS], ids=[i for _, i, _ in MUTATIONS]
)
def test_each_mutation_is_caught_by_its_check(check: int, mutate: Mutation) -> None:
    raw = copy.deepcopy(_valid())
    mutate(raw)
    defects = validate(Definition(FIXTURES / "valid.json", raw), REPO_ROOT, "plugin")
    assert defects and all(line.startswith(f"check {check}: ") for line in defects), defects


def test_non_feature_when_is_left_to_the_runner() -> None:
    raw = copy.deepcopy(_valid())
    _stage(raw, 3)["when"] = "units.touched_sensitive"
    assert validate(Definition(FIXTURES / "valid.json", raw), REPO_ROOT, "plugin") == []


def test_project_brief_resolves_beside_the_definition(tmp_path: Path) -> None:
    # spec 3.1: a project definition's brief path is relative to the definition's own folder.
    raw = copy.deepcopy(_valid())
    for index, stem in ((0, "contract"), (2, "code"), (3, "ledger")):
        _sub(raw, index, "scope")["told"] = f"valid/{stem}.md"
        (tmp_path / "valid").mkdir(exist_ok=True)
        source = FIXTURES / "valid" / f"{stem}.md"
        (tmp_path / "valid" / f"{stem}.md").write_text(source.read_text(encoding="utf-8"))
    defn = Definition(tmp_path / "valid.json", raw)
    assert validate(defn, REPO_ROOT, "project") == []
    assert validate(defn, REPO_ROOT, "plugin") != []


def test_definition_reads_name_version_and_stages() -> None:
    defn = load(FIXTURES / "valid.json")
    assert (defn.name, defn.version, len(defn.stages)) == ("valid", 1, 4)
    odd = Definition(FIXTURES / "odd.json", {"name": 1, "version": "x", "stages": "y"})
    assert (odd.name, odd.version, odd.stages) == ("odd", 0, [])
