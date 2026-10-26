# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0128, pins REQ -> VER, MAP -> REQ, REQ -> MAP: requirement sections, needs, --map, --check-tools.
from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest
from lib import plan_record
from lib.config import Config
from lib.plan_record import is_need, load, ownership_defects, read_ownership, validate

from tests import test_dispatch_binding as binding
from tests.conftest import REPO_ROOT, fake_bin, run_cli
from tests.hook_chain import judge as decide
from tests.test_plan_record import checkout_file, requirement_sections

FIXTURES = REPO_ROOT / "tests" / "fixtures" / "plans"
TRAIN_PLAN = Path("docs/.tmp/daedalus/plan-20261025.md")
ONE = "unit: U1 | title: one | files: a.py | base: integration"
ONE_GRAPH = "graph: units=1 critical_path=1 width=1 overlap_only=none"
unit = binding.unit


def _write(tmp_path: Path, block: list[str], prose: str) -> Path:
    path = tmp_path / "plan.md"
    lines = "\n".join(block)
    path.write_text(f"# plan\n\n```plan\n{lines}\n```\n{prose}", encoding="utf-8")
    return path


def _defects(tmp_path: Path, prose: str, *block: str) -> list[str]:
    return validate(load(_write(tmp_path, list(block or (ONE, ONE_GRAPH)), prose)), 5)


def _section(*requirements: str, head: str = "### U1: one") -> str:
    numbered = "".join(f"{n}. {text}\n" for n, text in enumerate(requirements, 1))
    return f"\n{head}\n\nWhy this unit exists.\n\nRequirements:\n{numbered}"


def test_valid_fixture_reads_each_units_requirements() -> None:
    plan = load(FIXTURES / "valid.md")
    first = plan.section("U1")
    assert first is not None and first.title == "plan parser" and first.listed
    assert first.requirements == (
        "Add `a.load()` to `scripts/lib/a.py`.",
        "Cover it in tests/test_a.py.",
    )
    assert [s.unit for s in plan.sections] == ["U1", "U2", "U3", "U4", "U5"]
    assert validate(plan, 5) == []


def test_unit_without_a_section_is_refused() -> None:
    defects = validate(load(FIXTURES / "unit_without_requirements.md"), 5)
    assert defects == [
        "unit U2 has no requirement section; below the plan block write "
        f"{plan_record.SECTION_SHAPE}."
    ]


@pytest.mark.parametrize(
    "prose",
    [
        "\n### U1: one\n\nNo list here.\n",
        "\n### U1: one\n\nRequirements:\n\n1. Change `a.py`.\n",
        "\n### U1: one\n\nRequirements:\n- Change `a.py`.\n",
        "\n### U1: one\n\n## Notes\n\nRequirements:\n1. Change `a.py`.\n",
    ],
)
def test_section_with_no_requirement_is_refused(tmp_path: Path, prose: str) -> None:
    defects = _defects(tmp_path, prose)
    assert len(defects) == 1 and "unit U1 (line" in defects[0], defects
    assert "lists no requirement" in defects[0]


@pytest.mark.parametrize(
    ("text", "problem"),
    [
        ("Change `a.py`", "does not end in a period"),
        ("Change `a.py`. Then test it.", "holds more than one sentence"),
        ("Change the parser and its tests.", "names no backticked token and no path"),
        ("Change map.json keys.", "names no backticked token and no path"),
    ],
)
def test_requirement_in_another_shape_is_refused(tmp_path: Path, text: str, problem: str) -> None:
    defects = _defects(tmp_path, _section("Change `a.py`.", text))
    assert len(defects) == 1 and defects[0].startswith("requirement 2 of unit U1 "), defects
    assert problem in defects[0] and defects[0].endswith(text)


@pytest.mark.parametrize(
    "text",
    [
        "Change `a.py`.",
        "Change scripts/lib/a.py and its tests.",
        "Keep `README.md` equal to `reference_table()`, e.g. one row per key.",
        "Write `.claude/daedalus/trains/<id>.json` with mode 0600.",
    ],
)
def test_requirement_in_the_pinned_shape_passes(tmp_path: Path, text: str) -> None:
    assert _defects(tmp_path, _section(text)) == []


def test_numbering_gap_is_refused(tmp_path: Path) -> None:
    prose = "\n### U1: one\n\nRequirements:\n1. Change `a.py`.\n3. Change `b.py`.\n"
    defects = _defects(tmp_path, prose)
    assert defects == [
        "the requirement list of unit U1 breaks its numbering at: 3. Change `b.py`.; "
        "number the requirements 1, 2, 3 in order."
    ]


def test_list_ends_at_the_first_line_that_is_not_numbered(tmp_path: Path) -> None:
    prose = _section("Change `a.py`.") + "\nProse after the list. 2. Not a requirement\n"
    plan = load(_write(tmp_path, [ONE, ONE_GRAPH], prose))
    section = plan.section("U1")
    assert section is not None and section.requirements == ("Change `a.py`.",)
    assert validate(plan, 5) == []


def test_two_sections_for_one_unit_are_refused(tmp_path: Path) -> None:
    defects = _defects(tmp_path, _section("Change `a.py`.") + _section("Change `b.py`."))
    assert len(defects) == 1 and "unit U1 has 2 requirement sections" in defects[0], defects


def test_headings_inside_fenced_blocks_are_not_sections(tmp_path: Path) -> None:
    fenced = "\n```text\n" + _section("Change `a.py`.") + "```\n"
    defects = _defects(tmp_path, fenced)
    assert defects and "unit U1 has no requirement section" in defects[0], defects
    inside = ["### U1: one", "Requirements:", "1. Change `a.py`.", ONE, ONE_GRAPH]
    assert any("no requirement section" in d for d in _defects(tmp_path, "", *inside))


def test_a_heading_for_an_unknown_unit_is_prose(tmp_path: Path) -> None:
    prose = "\n### Waves: three of them\n" + _section("Change `a.py`.")
    assert _defects(tmp_path, prose) == []


def test_needs_field_is_read_and_validates(tmp_path: Path) -> None:
    line = f"{ONE} | needs: mypy, .venv/bin/ruff, service-manifest.json, contracts/"
    plan = load(_write(tmp_path, [line, ONE_GRAPH], requirement_sections(ONE)))
    assert plan.units[0].needs == ("mypy", ".venv/bin/ruff", "service-manifest.json", "contracts/")
    assert validate(plan, 5) == []
    assert load(FIXTURES / "valid.md").units[0].needs == ()


@pytest.mark.parametrize(
    ("value", "needle"),
    [
        ("", "an empty item"),
        ("mypy,,ruff", "an empty item"),
        ("mypy, ", "an empty item"),
        ("-rf", "needs -rf, which is neither"),
        ("/usr/bin/mypy", "needs /usr/bin/mypy, which is neither"),
        ("../outside", "needs ../outside, which is neither"),
        ("python3 -m mypy", "needs python3 -m mypy, which is neither"),
        ("mypy;rm", "needs mypy;rm, which is neither"),
        ("mypy, mypy", "names the need mypy twice"),
    ],
)
def test_malformed_needs_value_is_refused(tmp_path: Path, value: str, needle: str) -> None:
    defects = _defects(tmp_path, requirement_sections(ONE), f"{ONE} | needs: {value}", ONE_GRAPH)
    assert len(defects) == 1 and needle in defects[0], defects
    assert defects[0].startswith("unit U1 ")


@pytest.mark.parametrize(
    ("name", "ok"),
    [("mypy", True), (".venv/bin/pytest", True), ("docs/", True), (".", False), ("a b", False)],
)
def test_is_need_is_the_one_shape_check(name: str, ok: bool) -> None:
    assert is_need(name) is ok


def _map(tmp_path: Path, ownership: object) -> Path:
    path = tmp_path / "map.json"
    keys = {"imports": {}, "coverage": {}, "readers": {}, "duplicates": []}
    path.write_text(json.dumps({**keys, "ownership": ownership}), encoding="utf-8")
    return path


def _validate_cli(*args: str) -> subprocess.CompletedProcess[str]:
    return run_cli("validate_plan.py", *args)


def test_map_ownership_without_an_edge_is_a_defect() -> None:
    plan = load(FIXTURES / "valid.md")
    owners = {
        "README.md": ["U3", "U5"],
        "scripts/lib/a.py": ["U1"],
        "scripts/lib/shell.py": ["U3", "U4"],
        "tests/test_x.py": ["U1", "U2", "U4"],
        "docs/a.md": ["U4", "U5"],
    }
    assert ownership_defects(plan, owners) == [
        "the map gives docs/a.md to units U4 and U5 with neither an overlap edge nor a serial "
        "path between them.",
        "the map gives tests/test_x.py to units U1 and U4; U2 and U4 with neither an overlap "
        "edge nor a serial path between them.",
    ]
    assert ownership_defects(plan, {"x.py": ["U9"]}) == ["the map gives x.py to unknown unit U9."]


def test_validate_plan_reads_the_map(tmp_path: Path) -> None:
    valid = str(FIXTURES / "valid.md")
    clean = _validate_cli(valid, "--map", str(_map(tmp_path, {"README.md": ["U3", "U5"]})))
    assert clean.returncode == 0, clean.stdout + clean.stderr
    assert clean.stdout.startswith("OK plan: ")
    shared = _map(tmp_path, {"scripts/lib/b.py": ["U2", "U3"]})
    refused = _validate_cli(valid, "--max-concurrent", "5", "--map", str(shared))
    assert refused.returncode == 1
    lines = refused.stdout.splitlines()
    assert lines[0].startswith("the map gives scripts/lib/b.py to units U2 and U3")
    assert lines[-1].startswith("Next: ")


@pytest.mark.parametrize("body", ["not json", "[]", '{"ownership": []}', '{"ownership": {"a": 1}}'])
def test_a_malformed_map_is_refused_with_a_next_line(tmp_path: Path, body: str) -> None:
    path = tmp_path / "map.json"
    path.write_text(body, encoding="utf-8")
    with pytest.raises(plan_record.PlanError):
        read_ownership(path)
    proc = _validate_cli(str(FIXTURES / "valid.md"), "--map", str(path))
    assert proc.returncode == 1
    lines = proc.stdout.splitlines()
    assert str(path) in lines[-2] and lines[-1].startswith("Next: rerun daedalus_map.py")


@pytest.mark.parametrize("args", [["--map"], ["--map", "--max-concurrent", "5"]])
def test_map_flag_without_a_path_is_a_usage_error(args: list[str]) -> None:
    proc = _validate_cli(str(FIXTURES / "valid.md"), *args)
    assert proc.returncode == 1 and "--map <map.json>" in proc.stderr


def _check_tools(repo: Path, bin_dir: Path, value: str) -> subprocess.CompletedProcess[str]:
    env = {"PATH": str(bin_dir), "HOME": str(repo)}
    return run_cli("daedalus_doctor.py", "--repo", str(repo), "--check-tools", value, env=env)


def test_check_tools_prints_ok_and_miss_per_name(tmp_path: Path) -> None:
    bin_dir = fake_bin(tmp_path, ["mytool"])
    repo = tmp_path / "repo"
    (repo / ".venv" / "bin").mkdir(parents=True)
    ruff = repo / ".venv" / "bin" / "ruff"
    ruff.write_text("#!/bin/sh\n", encoding="utf-8")
    ruff.chmod(0o755)
    (repo / ".venv" / "bin" / "pytest").write_text("not executable\n", encoding="utf-8")
    ok = _check_tools(repo, bin_dir, "mytool,.venv/bin/ruff")
    assert ok.returncode == 0, ok.stderr
    assert ok.stdout.splitlines() == ["OK   tool mytool", "OK   tool .venv/bin/ruff"]
    miss = _check_tools(repo, bin_dir, "mytool,absent-tool,.venv/bin/pytest")
    assert miss.returncode == 1
    assert miss.stdout.splitlines() == [
        "OK   tool mytool",
        "MISS tool absent-tool",
        "MISS tool .venv/bin/pytest",
    ]


@pytest.mark.parametrize("value", ["", "mytool,,x", "/bin/sh", "../x", "mytool,-rf", "a b"])
def test_check_tools_refuses_a_malformed_name(tmp_path: Path, value: str) -> None:
    proc = _check_tools(tmp_path, fake_bin(tmp_path, ["mytool"]), value)
    assert proc.returncode == 1 and proc.stdout == ""
    assert "Next: " in proc.stderr


def test_coder_dispatch_with_a_plan_without_sections_is_refused(
    repo_cwd: Path, request: pytest.FixtureRequest
) -> None:
    worktree = request.getfixturevalue("unit")
    binding.seed_plan(repo_cwd, binding.TRAIN, FIXTURES / "unit_without_requirements.md")
    binding._refused(repo_cwd, worktree, "defect", "unit U2 has no requirement section")
    binding.seed_plan(repo_cwd, binding.TRAIN)
    d = decide(binding._dispatch(repo_cwd, worktree), Config())
    assert d.allow, d.reason


def _flat(path: Path) -> str:
    return " ".join(path.read_text(encoding="utf-8").split())


def test_orchestrator_copies_sections_and_checks_needs_per_wave() -> None:
    text = (REPO_ROOT / "agents" / "orchestrator.md").read_text(encoding="utf-8")
    phase2 = " ".join(text.split("## Phase 2", 1)[1].split("\nRead the last line", 1)[0].split())
    assert "the unit's requirement section of the plan verbatim" in phase2
    assert "`### <unit id>: <title>` heading through its last numbered requirement" in phase2
    check = "scripts/daedalus_doctor.py --check-tools <names> --repo <repo>`"
    assert check in phase2 and "`MISS tool <name>`" in phase2
    assert "before the first dispatch of each wave" in phase2
    assert "ask once per wave, never once per unit" in phase2
    assert phase2.index(check) < phase2.index("Then write the unit's brief file")


def test_planner_reads_the_map_and_writes_sections_and_needs() -> None:
    planner = _flat(REPO_ROOT / "agents" / "planner.md")
    for rule in (
        "Read the dependency map first when the brief names it",
        "Give each test module to one unit.",
        "Write each unit's requirement section and `needs:` field from the spec and the map",
        "cite the Standards Packet's `## Priorities` section",
        "its `ranking:` line, and the number of each `rule <n>:` line",
        "The heading line is `### <unit id>: <title>`.",
        "| needs: <tool or protected path>[, ...]",
    ):
        assert rule in planner, rule


def test_plan_skill_table_lists_needs() -> None:
    skill = _flat(REPO_ROOT / "skills" / "plan" / "SKILL.md")
    assert "| Shares files with | Needs | Version line |" in skill
    assert "Needs lists the unit line's `needs:` values (0128)" in skill


def test_the_train_plan_validates() -> None:
    # The train's own plan sits in the main checkout's scratch, which a unit worktree lacks.
    path = checkout_file(TRAIN_PLAN)
    if path is None:
        pytest.skip("the train's plan file is not present in this checkout")
    plan = load(path)
    assert validate(plan, 5) == []
    assert all(s.requirements for s in plan.sections if s.unit in {u.id for u in plan.units})
