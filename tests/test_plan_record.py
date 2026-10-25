# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import subprocess
from functools import partial
from pathlib import Path

import pytest
from lib.plan_record import Plan, PlanError, Version, graph_line, load, validate
from lib.workspace import _CLASS_LINE

from tests.conftest import REPO_ROOT, run_cli

FIXTURES = REPO_ROOT / "tests" / "fixtures" / "plans"
THIS_PLAN = Path("docs/private/superpowers/plans/2026-10-19-plan-7-efficiency.md")
ONE = "unit: U1 | title: one | files: a.py | base: integration"
TWO = "unit: U2 | title: two | files: b.py | base: integration"
BUMP = "unit: V1 | title: bump the version | files: VERSION | base: integration"
TWO_GRAPH = "graph: units=2 critical_path=1 width=2 overlap_only=none"
VERSION_LINE = "version: 4.0.0 | class: X | reason: renames a manifest key | unit: V1"
VERSION_SHAPE = "version: <x.y.z> | class: <X, Y or Z> | reason: <one line> | unit: <unit id>"


def _defects(name: str, max_concurrent: int = 5) -> list[str]:
    return validate(load(FIXTURES / f"{name}.md"), max_concurrent)


def _plan_text(tmp_path: Path, *lines: str) -> Plan:
    path = tmp_path / "plan.md"
    block = "\n".join(lines)
    path.write_text(f"# plan\n\n```plan\n{block}\n```\n", encoding="utf-8")
    return load(path)


_cli = partial(run_cli, "validate_plan.py")


def _this_plan() -> Path | None:
    # 0086: a unit worktree has no private clone; the main working tree may carry it.
    common = subprocess.run(
        ["git", "rev-parse", "--path-format=absolute", "--git-common-dir"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    ).stdout.strip()
    roots = [REPO_ROOT] + ([Path(common).parent] if common else [])
    return next((r / THIS_PLAN for r in roots if (r / THIS_PLAN).is_file()), None)


def test_valid_fixture_has_no_defects() -> None:
    assert _defects("valid") == []


def test_load_reads_units_edges_and_pins() -> None:
    plan = load(FIXTURES / "valid.md")
    assert [u.id for u in plan.units] == ["U1", "U2", "U3", "U4", "U5"]
    assert plan.units[4].files == ("docs/*.md", "README.md", "tests/fixtures/u5/")
    assert plan.units[1].base == "U1"
    overlap = plan.edges[2]
    assert (overlap.source, overlap.target, overlap.kind) == ("U3", "U4", "overlap")
    assert overlap.files == ("scripts/lib/shell.py",) and overlap.merge == ("U3", "U4")
    assert [(p.source, p.target) for p in plan.pins] == [("U1", "U5")]


def test_unit_without_files_is_refused() -> None:
    defects = _defects("unit_without_files")
    assert any("unit U2 lists no files" in d for d in defects), defects


def test_shared_file_without_overlap_edge_is_refused() -> None:
    defects = _defects("shared_file_without_overlap")
    assert any("U1 and U2 both change" in d and "no overlap edge" in d for d in defects), defects


def test_shared_file_on_a_serial_path_needs_no_overlap_edge(tmp_path: Path) -> None:
    # 0086: a serial path orders the two units, so their shared file cannot conflict.
    plan = _plan_text(
        tmp_path,
        "unit: U1 | title: one | files: README.md | base: integration",
        "unit: U2 | title: two | files: scripts/b.py | base: U1",
        "unit: U3 | title: three | files: README.md | base: U2",
        "edge: U1 -> U2 | kind: serial | why: b imports a",
        "edge: U2 -> U3 | kind: serial | why: c imports b",
        "graph: units=3 critical_path=3 width=1 overlap_only=none",
    )
    assert validate(plan, 5) == []


def test_edge_naming_an_unknown_unit_is_refused() -> None:
    defects = _defects("edge_unknown_unit")
    assert any("unknown unit U9" in d for d in defects), defects


def test_edge_without_a_kind_is_refused() -> None:
    defects = _defects("edge_without_kind")
    assert any("names no kind" in d for d in defects), defects


def test_edge_kind_must_match_its_arrow(tmp_path: Path) -> None:
    plan = _plan_text(
        tmp_path,
        ONE,
        TWO,
        "edge: U1 ~ U2 | kind: serial | why: b imports a",
        "graph: units=2 critical_path=1 width=2 overlap_only=none",
    )
    assert any("is written U1 -> U2" in d for d in validate(plan, 5))


def test_overlap_edge_without_merge_order_is_refused() -> None:
    defects = _defects("overlap_without_merge")
    assert any("U1 ~ U2 names no merge order" in d for d in defects), defects


def test_overlap_edge_merge_order_names_its_two_units(tmp_path: Path) -> None:
    plan = _plan_text(
        tmp_path,
        ONE,
        "unit: U2 | title: two | files: a.py | base: integration",
        "edge: U1 ~ U2 | kind: overlap | merge: U1 then U3",
        "graph: units=2 critical_path=1 width=2 overlap_only=U1~U2",
    )
    defects = validate(plan, 5)
    assert any("U1 ~ U2 names no files" in d for d in defects), defects
    assert any("merge order must name U1 and U2" in d for d in defects), defects


def test_serial_cycle_is_refused() -> None:
    defects = _defects("serial_cycle")
    assert any("serial edges form a cycle: U1 -> U2 -> U3 -> U1" in d for d in defects), defects


def test_graph_line_mismatch_is_refused() -> None:
    defects = _defects("graph_mismatch")
    assert "the graph line says critical_path=3; the plan computes critical_path=2." in defects
    assert "the graph line says width=3; the plan computes width=2." in defects
    assert not any("units=" in d for d in defects), defects


def test_graph_line_is_recomputed() -> None:
    plan = load(FIXTURES / "valid.md")
    assert graph_line(plan, 5) == "graph: units=5 critical_path=2 width=3 overlap_only=U3~U4"
    assert plan.graph == graph_line(plan, 5)


def test_missing_graph_line_names_the_computed_one(tmp_path: Path) -> None:
    plan = _plan_text(tmp_path, ONE)
    assert validate(plan, 5) == [
        "the plan block has no graph line; add: "
        "graph: units=1 critical_path=1 width=1 overlap_only=none"
    ]


def test_width_is_capped_at_max_concurrent() -> None:
    plan = load(FIXTURES / "valid.md")
    assert graph_line(plan, 2) == "graph: units=5 critical_path=2 width=2 overlap_only=U3~U4"
    assert validate(plan, 2) == ["the graph line says width=3; the plan computes width=2."]


def test_pin_is_not_an_edge(tmp_path: Path) -> None:
    # 0086: a pin neither orders two units nor excuses a shared file.
    plan = _plan_text(
        tmp_path,
        ONE,
        TWO,
        "unit: U3 | title: three | files: c.py, b.py | base: integration",
        "pin: U1 -> U2 | `a.load(path) -> A`",
        "pin: U2 -> U3 | `b.check() -> bool`",
        "graph: units=3 critical_path=1 width=3 overlap_only=none",
    )
    assert plan.edges == ()
    assert graph_line(plan, 5) == "graph: units=3 critical_path=1 width=3 overlap_only=none"
    defects = validate(plan, 5)
    assert defects == ["units U2 and U3 both change b.py but no overlap edge joins them."]


def test_pin_naming_an_unknown_unit_is_refused(tmp_path: Path) -> None:
    plan = _plan_text(
        tmp_path,
        ONE,
        "pin: U1 -> U7 | `a.load(path) -> A`",
        "graph: units=1 critical_path=1 width=1 overlap_only=none",
    )
    assert any("pin U1 -> U7 names unknown unit U7" in d for d in validate(plan, 5))


def test_base_names_integration_or_a_unit(tmp_path: Path) -> None:
    plan = _plan_text(
        tmp_path,
        "unit: U1 | title: one | files: a.py | base: main",
        "graph: units=1 critical_path=1 width=1 overlap_only=none",
    )
    assert any("unit U1 starts from main" in d for d in validate(plan, 5))


def test_unknown_line_and_duplicate_unit_are_refused(tmp_path: Path) -> None:
    plan = _plan_text(
        tmp_path,
        ONE,
        "unit: U1 | title: again | files: b.py | base: integration",
        "step: U1 runs first",
        "graph: units=1 critical_path=1 width=1 overlap_only=none",
    )
    defects = validate(plan, 5)
    assert any("unit U1 is declared twice" in d for d in defects), defects
    assert any("is not a unit, edge, pin, version or graph line" in d for d in defects), defects


def test_file_without_one_plan_block_is_refused(tmp_path: Path) -> None:
    path = tmp_path / "plan.md"
    path.write_text("# plan\n\nno block here\n", encoding="utf-8")
    assert validate(load(path), 5) == ["the file has no fenced plan block."]
    path.write_text("```plan\n```\n```plan\n```\n", encoding="utf-8")
    assert validate(load(path), 5) == ["the file has 2 fenced plan blocks; keep exactly one."]


def test_unreadable_file_raises_plan_error(tmp_path: Path) -> None:
    with pytest.raises(PlanError):
        load(tmp_path / "absent.md")


def test_valid_fixture_prints_the_ok_line() -> None:
    proc = _cli(str(FIXTURES / "valid.md"))
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert proc.stdout == "OK plan: graph: units=5 critical_path=2 width=3 overlap_only=U3~U4\n"


def test_cli_takes_max_concurrent() -> None:
    proc = _cli(str(FIXTURES / "valid.md"), "--max-concurrent", "2")
    assert proc.returncode == 1
    lines = proc.stdout.splitlines()
    assert lines[0] == "the graph line says width=3; the plan computes width=2."
    assert lines[-1].startswith("Next: ")


@pytest.mark.parametrize(
    "name",
    sorted(p.stem for p in FIXTURES.glob("*.md") if p.stem != "valid"),
)
def test_each_refusal_fixture_exits_one_with_a_next_line(name: str) -> None:
    proc = _cli(str(FIXTURES / f"{name}.md"))
    assert proc.returncode == 1
    lines = proc.stdout.splitlines()
    assert len(lines) >= 2 and lines[-1].startswith("Next: "), proc.stdout


@pytest.mark.parametrize("args", [[], ["a.md", "b.md"], ["a.md", "--max-concurrent", "0"]])
def test_cli_usage_errors_exit_one(args: list[str]) -> None:
    proc = _cli(*args)
    assert proc.returncode == 1
    assert "Next: " in proc.stderr


def test_cli_missing_file_exits_one() -> None:
    proc = _cli(str(FIXTURES / "absent.md"))
    assert proc.returncode == 1
    assert proc.stdout.splitlines()[-1].startswith("Next: ")


def test_this_plan_validates(tmp_path: Path) -> None:
    path = _this_plan()
    if path is None:
        pytest.skip("the private plan file is not present in this checkout")
    assert validate(load(path), 5) == []
    # Auditor check: the same plan with one edge kind removed is refused.
    text = path.read_text(encoding="utf-8")
    cut = text.replace("edge: A1 -> A3 | kind: serial | ", "edge: A1 -> A3 | ", 1)
    assert cut != text
    broken = tmp_path / "plan.md"
    broken.write_text(cut, encoding="utf-8")
    assert any("names no kind" in d for d in validate(load(broken), 5))


def test_version_line_is_parsed_and_validates(tmp_path: Path) -> None:
    # Spec 3.4, pin D4 -> D5: the optional version line and the summary line copied from it.
    plan = _plan_text(tmp_path, ONE, BUMP, VERSION_LINE, TWO_GRAPH)
    assert plan.version == Version("4.0.0", "X", "renames a manifest key", "V1")
    assert validate(plan, 5) == []
    assert plan.version.summary_line == "Version class: 4.0.0 X: renames a manifest key"
    assert _CLASS_LINE.fullmatch(plan.version.summary_line), "the release step must read it"


def test_plan_without_a_version_line_is_unchanged() -> None:
    plan = load(FIXTURES / "valid.md")
    assert plan.version is None
    assert validate(plan, 5) == []
    assert _cli(str(FIXTURES / "valid.md")).stdout.count("\n") == 1


@pytest.mark.parametrize(
    ("line", "defect"),
    [
        (
            "version: 4.0.0 | class: Y | reason: adds a step",
            "the version line names no unit; name the unit that edits the version sites.",
        ),
        (
            "version: 4.0.0 | class: Y | reason: adds a step | unit: U9",
            "the version line names unknown unit U9.",
        ),
        (
            "version: 4.0.0 | class: W | reason: adds a step | unit: V1",
            "the version line names class W; use X, Y or Z.",
        ),
        (
            "version: 4.0.0 | class: y | reason: adds a step | unit: V1",
            "the version line names class y; use X, Y or Z.",
        ),
        (
            "version: 4.0.0 | reason: adds a step | unit: V1",
            "the version line names class (none); use X, Y or Z.",
        ),
        (
            "version: 4.0 | class: Y | reason: adds a step | unit: V1",
            "the version line names version 4.0; write three dot-separated numbers, such as 4.0.0.",
        ),
        (
            "version: v4.0.0 | class: Y | reason: adds a step | unit: V1",
            "the version line names version v4.0.0; "
            "write three dot-separated numbers, such as 4.0.0.",
        ),
        (
            "version: 4.0.0-rc1 | class: Y | reason: adds a step | unit: V1",
            "the version line names version 4.0.0-rc1; "
            "write three dot-separated numbers, such as 4.0.0.",
        ),
        (
            "version: | class: Y | reason: adds a step | unit: V1",
            "the version line names version (none); "
            "write three dot-separated numbers, such as 4.0.0.",
        ),
        (
            "version: 4.0.0 | class: Y | unit: V1",
            "the version line names no reason; give the change in one line.",
        ),
        (
            "version: 4.0.0 | class: Y | reason: adds a step | unit: V1 | migration: none",
            "the version line has a field it does not know: migration: none",
        ),
    ],
)
def test_version_line_refusals(tmp_path: Path, line: str, defect: str) -> None:
    plan = _plan_text(tmp_path, ONE, BUMP, line, TWO_GRAPH)
    assert validate(plan, 5) == [defect]


def test_two_version_lines_are_refused(tmp_path: Path) -> None:
    plan = _plan_text(tmp_path, ONE, BUMP, VERSION_LINE, VERSION_LINE, TWO_GRAPH)
    assert validate(plan, 5) == ["the plan block has 2 version lines; keep at most one."]


def test_cli_prints_the_version_line_after_the_ok_line(tmp_path: Path) -> None:
    path = tmp_path / "plan.md"
    path.write_text(f"```plan\n{ONE}\n{BUMP}\n{VERSION_LINE}\n{TWO_GRAPH}\n```\n", encoding="utf-8")
    proc = _cli(str(path))
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert proc.stdout.splitlines() == [
        f"OK plan: {TWO_GRAPH}",
        "OK version: unit=V1 Version class: 4.0.0 X: renames a manifest key",
    ]
    path.write_text(path.read_text(encoding="utf-8").replace("class: X", "class: Q"), "utf-8")
    refused = _cli(str(path))
    assert refused.returncode == 1
    assert refused.stdout.splitlines()[0] == "the version line names class Q; use X, Y or Z."
    assert refused.stdout.splitlines()[-1].startswith("Next: ")


def test_planner_and_plan_skill_name_the_version_line() -> None:
    # Plan Choices: these assertions live here, not in tests/test_skills.py, which D5 owns.
    planner = " ".join((REPO_ROOT / "agents" / "planner.md").read_text(encoding="utf-8").split())
    block = planner.split("```plan", 1)[1].split("```", 1)[0]
    assert VERSION_SHAPE in block
    assert "When the spec's Version section bumps the version, cut it into one unit" in planner
    assert "keeps the version, write no version line" in planner
    skill = (REPO_ROOT / "skills" / "plan" / "SKILL.md").read_text(encoding="utf-8")
    step5 = skill.split("\n5. ", 1)[1].split("\n6. ", 1)[0]
    assert VERSION_SHAPE in step5
    step7 = skill.split("\n7. ", 1)[1].split("\n8. ", 1)[0]
    assert "`OK version: unit=<unit id> Version class: <x.y.z> <class>: <reason>`" in step7
    step8 = skill.split("\n8. ", 1)[1].split("\n9. ", 1)[0]
    header = "| Unit | What it builds | Starts from | Waits on | Shares files with | Version line |"
    assert header in step8
    assert VERSION_SHAPE in step8 and "a plan with no version line, leaves it empty" in step8
