# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0267, 0274, 0280: a plan's units carry a class, a place and a class_reason.
from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from lib import agent_models, work_classes
from lib.operator_file import Operator
from lib.plan_record import class_defects, load, split_place, validate
from lib.work_classes import MIDDLE_MODEL, MODEL_RANK, PLUMBING, above_middle

from tests.conftest import REPO_ROOT, run_cli
from tests.helpers import flatten_file

FIXTURES = REPO_ROOT / "tests" / "fixtures" / "plans"
GRAPH_ONE = "graph: units=1 critical_path=1 width=1 overlap_only=none"
GRAPH_TWO = "graph: units=2 critical_path=1 width=2 overlap_only=none"
BASE = "unit: U1 | title: login check | files: app/auth.py, docs/guide.md | base: integration"
SERVE = "unit: U2 | title: certificate endpoint | files: app/serve.py | base: integration"
AUTHN = (
    f"{BASE} | class: AuthN | place: app/auth.py:check_login | class_reason: it proves who calls"
)


def _write_plan(folder: Path, *lines: str) -> Path:
    units = [line for line in lines if line.startswith("unit:")]
    graph = GRAPH_ONE if len(units) == 1 else GRAPH_TWO
    sections = "".join(
        f"\n### {u.split(' | ')[0].partition(':')[2].strip()}: x\n\n"
        "Requirements:\n1. Build it in `app/`.\n"
        for u in units
    )
    path = folder / "plan.md"
    block = "\n".join([*lines, graph])
    path.write_text(f"# plan\n\n```plan\n{block}\n```\n{sections}", encoding="utf-8")
    return path


def _defects(tmp_path: Path, *lines: str, operator: Operator | None = None) -> list[str]:
    plan = load(_write_plan(tmp_path, *lines))
    return validate(plan, 5, operator or Operator())


def _env(home: Path) -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if k not in ("CLAUDE_PLUGIN_DATA", "HOME")}
    env["HOME"] = str(home)
    return env


def _repo(tmp_path: Path, override: object | None = None) -> Path:
    # A plain clone: .git is a folder; an override goes in the project's config.json.
    repo = tmp_path / "repo"
    (repo / ".git").mkdir(parents=True)
    if override is not None:
        (repo / ".claude" / "daedalus").mkdir(parents=True)
        (repo / ".claude" / "daedalus" / "config.json").write_text(
            json.dumps({"personal_overrides": override}), encoding="utf-8"
        )
    return repo


def _home(tmp_path: Path, body: object | None = None) -> Path:
    home = tmp_path / "home"
    (home / ".claude" / "daedalus").mkdir(parents=True)
    if body is not None:
        (home / ".claude" / "daedalus" / "operator.json").write_text(
            json.dumps(body), encoding="utf-8"
        )
    return home


def _mapped(name: str, model: str) -> Operator:
    rows = (*work_classes.DEFAULT_CLASSES, (name, "The work drafts a contract clause."))
    return Operator(work_classes=rows, class_models=(*work_classes.DEFAULT_MODELS, (name, model)))


def test_the_rank_tuple_holds_exactly_the_agent_models() -> None:
    assert sorted(MODEL_RANK) == sorted(agent_models.MODELS)
    assert len(MODEL_RANK) == len(agent_models.MODELS)
    assert MODEL_RANK == ("haiku", "sonnet", "opus", "fable")


def test_above_middle_answers_from_the_mapping() -> None:
    operator = Operator()
    assert above_middle("AuthN", operator)
    assert not above_middle(PLUMBING, operator)
    assert not above_middle("Mechanical", operator)
    assert not above_middle("Unlisted", operator)
    assert above_middle("Legal", _mapped("Legal", "fable"))
    assert not above_middle("Legal", _mapped("Legal", "haiku"))
    assert not above_middle("Legal", _mapped("Legal", MIDDLE_MODEL))


def test_the_three_fields_are_read_and_no_class_is_plumbing(tmp_path: Path) -> None:
    plan = load(_write_plan(tmp_path, AUTHN, SERVE))
    one, two = plan.units
    assert (one.work_class, one.place, one.class_reason) == (
        "AuthN",
        "app/auth.py:check_login",
        "it proves who calls",
    )
    assert one.effective_class == "AuthN"
    assert (two.work_class, two.place, two.class_reason) == (None, None, None)
    assert two.effective_class == PLUMBING
    assert _defects(tmp_path, AUTHN, SERVE) == []


@pytest.mark.parametrize("name", sorted(p.stem for p in FIXTURES.glob("*.md")))
def test_every_plan_fixture_validates_as_before_with_any_settings(name: str) -> None:
    plan = load(FIXTURES / f"{name}.md")
    assert all(u.work_class is None and u.place is None for u in plan.units)
    empty = Operator(work_classes=(), class_models=())
    assert validate(plan, 5, Operator()) == validate(plan, 5) == validate(plan, 5, empty)


@pytest.mark.parametrize(
    ("line", "defect"),
    [
        (
            f"{BASE} | class: Bogus",
            "unit U1 names the class Bogus, which the work classes list does not hold. Next: "
            "give unit U1 a class from the list validate_plan.py --classes prints, or add the "
            "class to work_classes.",
        ),
        (
            f"{BASE} | class: AuthN | class_reason: it proves who calls",
            "unit U1 has the class AuthN, whose model ranks above sonnet, and names no place. "
            "Next: give unit U1 a place: <file>:<named part>: a file from its files list and "
            "the named part of it where the work happens.",
        ),
        (
            f"{BASE} | class: AuthN | place: app/other.py:check | class_reason: it proves who",
            "unit U1 names the place file app/other.py, which is not in its files list. Next: "
            "name a file from unit U1's files list, or add that file to it.",
        ),
        (
            f"{BASE} | class: AuthN | place: app/auth.py:check_login",
            "unit U1 has the class AuthN, which is not Plumbing, and gives no class_reason. "
            "Next: give unit U1 a class_reason field, one line saying why the work has that "
            "class.",
        ),
        (
            f"{BASE} | class: Mechanical",
            "unit U1 has the class Mechanical, which is not Plumbing, and gives no "
            "class_reason. Next: give unit U1 a class_reason field, one line saying why the "
            "work has that class.",
        ),
    ],
)
def test_the_four_refusals(tmp_path: Path, line: str, defect: str) -> None:
    assert _defects(tmp_path, line) == [defect]


@pytest.mark.parametrize(
    "line",
    [
        f"{BASE} | class: Plumbing",
        f"{BASE} | class: Plumbing | class_reason: it only serves a file",
        f"{BASE} | class: Mechanical | class_reason: a rename only",
        f"{BASE} | class: AuthN | place: docs/guide.md:Section 2: scope | class_reason: login doc",
    ],
)
def test_plumbing_and_mechanical_need_no_place(tmp_path: Path, line: str) -> None:
    assert _defects(tmp_path, line) == []


def test_a_user_class_on_haiku_needs_no_place_and_on_fable_needs_one(tmp_path: Path) -> None:
    line = f"{BASE} | class: Legal | class_reason: it drafts a clause"
    assert _defects(tmp_path, line, operator=_mapped("Legal", "haiku")) == []
    refused = _defects(tmp_path, line, operator=_mapped("Legal", "fable"))
    assert len(refused) == 1 and "names no place" in refused[0]
    bare = f"{BASE} | class: Legal"
    refused = _defects(tmp_path, bare, operator=_mapped("Legal", "haiku"))
    assert len(refused) == 1 and "gives no class_reason" in refused[0]
    refused = _defects(tmp_path, bare, operator=_mapped("Legal", "fable"))
    assert len(refused) == 2
    assert "names no place" in refused[0] and "gives no class_reason" in refused[1]


def test_a_place_in_a_listed_folder_counts(tmp_path: Path) -> None:
    line = (
        "unit: U1 | title: t | files: app/ | base: integration | class: AuthZ | "
        "place: app/policy.py:allow | class_reason: it decides what a caller may do"
    )
    assert _defects(tmp_path, line) == []


def test_a_place_keeps_every_colon_of_its_named_part() -> None:
    assert split_place("a.md:Section 2: scope") == ("a.md", "Section 2: scope")
    assert split_place("app/auth.py:check_login") == ("app/auth.py", "check_login")


@pytest.mark.parametrize("place", ["a.md", ":Section 2", "a.md:", " : ", ""])
def test_a_place_with_no_colon_or_an_empty_side_is_refused(tmp_path: Path, place: str) -> None:
    assert split_place(place) is None
    line = f"{BASE} | class: Plumbing | place: {place}"
    shown = repr(place.strip())
    assert _defects(tmp_path, line) == [
        f"unit U1 has the place {shown}, which is not a file and the named part of it. Next: "
        "write unit U1's place: <file>:<named part>, both sides filled in."
    ]


def test_class_defects_check_only_lines_with_the_fields(tmp_path: Path) -> None:
    plan = load(_write_plan(tmp_path, BASE))
    assert class_defects(plan, Operator(work_classes=(), class_models=())) == []


def test_the_cli_validates_with_an_empty_home_in_a_plain_clone(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    plan = _write_plan(repo, AUTHN, SERVE)
    home = tmp_path / "empty-home"
    home.mkdir()
    proc = run_cli("validate_plan.py", str(plan), env=_env(home))
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert proc.stdout == f"OK plan: {GRAPH_TWO}\n"
    proc = run_cli("validate_plan.py", str(plan), "--repo", str(repo), env=_env(home))
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_the_cli_honours_a_project_override_that_removes_a_class(tmp_path: Path) -> None:
    rows = [{"name": PLUMBING, "definition": "Any other work."}]
    repo = _repo(tmp_path, {"work_classes": rows, "class_models": {PLUMBING: "sonnet"}})
    plan = _write_plan(repo, AUTHN)
    proc = run_cli("validate_plan.py", str(plan), "--repo", str(repo), env=_env(_home(tmp_path)))
    assert proc.returncode == 1
    lines = proc.stdout.splitlines()
    assert lines[0].startswith("unit U1 names the class AuthN, which the work classes list")
    assert lines[-1].startswith("Next: ")


def test_the_cli_refuses_a_broken_settings_file_only_for_a_classed_plan(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    home = _home(tmp_path, {"work_classes": "not a list"})
    plain = _write_plan(repo, BASE)
    assert run_cli("validate_plan.py", str(plain), env=_env(home)).returncode == 0
    classed = _write_plan(repo, AUTHN)
    proc = run_cli("validate_plan.py", str(classed), "--repo", str(repo), env=_env(home))
    assert proc.returncode == 1
    assert "work_classes" in proc.stdout and proc.stdout.splitlines()[-1].startswith("Next: ")


def test_classes_prints_the_effective_list_for_the_planner(tmp_path: Path) -> None:
    # 0235: a project mapping replaces the whole personal one; Tokens falls to the middle model.
    repo = _repo(tmp_path, {"class_models": {"AuthN": "haiku", "AuthZ": "fable"}})
    proc = run_cli("validate_plan.py", "--classes", "--repo", str(repo), env=_env(_home(tmp_path)))
    assert proc.returncode == 0, proc.stdout + proc.stderr
    lines = proc.stdout.splitlines()
    assert len(lines) == len(work_classes.DEFAULT_CLASSES)
    by_name = {line.split(" | ")[0]: line for line in lines}
    assert by_name["class: AuthN"].split(" | ")[1] == "place: not required"
    assert by_name["class: AuthZ"].split(" | ")[1] == "place: required"
    assert by_name[f"class: {PLUMBING}"].split(" | ")[1] == "place: not required"
    definition = dict(work_classes.DEFAULT_CLASSES)["Tokens"]
    assert (
        by_name["class: Tokens"]
        == f"class: Tokens | place: not required | definition: {definition}"
    )


def test_classes_with_an_empty_list_says_every_unit_is_plumbing(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    home = _home(tmp_path, {"work_classes": [], "class_models": {}})
    proc = run_cli("validate_plan.py", "--classes", "--repo", str(repo), env=_env(home))
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "every unit is Plumbing" in proc.stdout


@pytest.mark.parametrize(
    "args", [["--classes", "plan.md"], ["--classes", "--repo"], ["plan.md", "--repo"]]
)
def test_the_cli_refuses_a_bad_classes_or_repo_form(args: list[str]) -> None:
    proc = run_cli("validate_plan.py", *args)
    assert proc.returncode == 1
    assert "Next: " in proc.stderr


def test_the_planner_skill_and_readme_name_the_three_fields() -> None:
    planner = flatten_file(REPO_ROOT / "agents" / "planner.md")
    block = planner.split("```plan", 1)[1].split("```", 1)[0]
    assert "class: <class name> | place: <file>:<named part> | class_reason: <one line>" in block
    for rule in (
        "A unit with no `class:` field is `Plumbing`.",
        "a unit that only uses it is `Plumbing` (0274)",
        "An endpoint that serves a certificate is plumbing; the authentication in front of it "
        "is not.",
        "a file from the unit's own `files:` list and the named part of it where the work "
        "happens, a function in code or a section in a document",
        "one line saying why the work has that class",
    ):
        assert rule in planner, rule
    skill = flatten_file(REPO_ROOT / "skills" / "plan" / "SKILL.md")
    step5 = skill.split(" 5. ", 1)[1].split(" 6. ", 1)[0]
    assert "scripts/validate_plan.py --classes --repo <repo>` and paste its output" in step5
    step7 = skill.split(" 7. ", 1)[1].split(" 8. ", 1)[0]
    assert "validate_plan.py <path> --max-concurrent <n> --repo <repo>`" in step7
    step8 = skill.split(" 8. ", 1)[1].split(" 9. ", 1)[0]
    assert "| Unit | What it builds | Class | Starts from |" in step8
    assert "`Plumbing` when the line has none (0280)" in step8
    assert "for every class but `Plumbing` it adds the `class_reason:` line" in step8
    readme = flatten_file(REPO_ROOT / "README.md")
    assert "`class: <class name>`, `place: <file>:<named part>` and `class_reason:" in readme
