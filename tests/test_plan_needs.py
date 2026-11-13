# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0281: a plan says who provides each thing the work needs once it runs.
from __future__ import annotations

from pathlib import Path

import pytest
from lib import dispatch_binding, train_state, train_summary
from lib.plan_record import PROVIDES_NONE, Provide, load, loads, provides_missing, validate

from tests.conftest import REPO_ROOT, run_cli
from tests.test_fix_units import PROVIDES
from tests.test_fix_units import _fixture as fix_fixture
from tests.test_plan_record import requirement_sections
from tests.test_records_in_one_call import TRAIN, fixed  # noqa: F401

ONE = "unit: U1 | title: one | files: a.py | base: integration"
TWO = "unit: U2 | title: two | files: b.py | base: integration"
GRAPH = "graph: units=2 critical_path=1 width=2 overlap_only=none"
ROLE = "provide: the bucket write role | kind: permission | provider: U1 | when: before U2 runs"
KEY = "provide: the signing key | kind: secret | provider: user before merge | when: before merge"
HOOK = (
    "provide: the webhook secret | kind: secret | provider: user after deploy | "
    "when: before the first event"
)
SEEN = (
    "provide: the reports bucket | kind: resource | provider: exists | when: before U1 runs | "
    "seen: infra/buckets.tf"
)


def _plan_file(tmp_path: Path, *lines: str) -> Path:
    path = tmp_path / "plan.md"
    block = "\n".join([ONE, TWO, *lines, GRAPH])
    path.write_text(f"# plan\n\n```plan\n{block}\n```\n{requirement_sections(ONE, TWO)}", "utf-8")
    return path


def _defects(tmp_path: Path, *lines: str) -> list[str]:
    return validate(load(_plan_file(tmp_path, *lines)), 5)


def test_provide_lines_load_with_every_field(tmp_path: Path) -> None:
    plan = load(_plan_file(tmp_path, ROLE, SEEN))
    assert plan.provides == (
        Provide("the bucket write role", "permission", "U1", "before U2 runs"),
        Provide("the reports bucket", "resource", "exists", "before U1 runs", "infra/buckets.tf"),
    )
    assert [p.text for p in plan.provides] == [ROLE, SEEN]
    assert validate(plan, 5) == [] and provides_missing(plan) == []


def test_provides_none_alone_validates(tmp_path: Path) -> None:
    plan = load(_plan_file(tmp_path, PROVIDES_NONE))
    assert (plan.provides, plan.provides_none) == ((), 1)
    assert validate(plan, 5) == [] and provides_missing(plan) == []


@pytest.mark.parametrize(
    ("line", "defect"),
    [
        (
            "provide: the role | kind: permission | when: now",
            "provide the role names no provider; name a unit id of this plan, user before merge, "
            "user after deploy or exists.",
        ),
        (
            "provide: the role | kind: permission | provider: U9 | when: now",
            "provide the role names the provider U9, which is no unit of this plan; name a unit "
            "id of this plan, user before merge, user after deploy or exists.",
        ),
        (
            "provide: the role | kind: permission | provider: u1 | when: now",
            "provide the role names the provider u1, which is no unit of this plan; name a unit "
            "id of this plan, user before merge, user after deploy or exists.",
        ),
        (
            "provide: the role | kind: permission | provider: the user | when: now",
            "provide the role names the provider the user, which is no unit of this plan; name a "
            "unit id of this plan, user before merge, user after deploy or exists.",
        ),
        (
            "provide: the bucket | kind: resource | provider: exists | when: now",
            "provide the bucket has the provider exists and names no seen; add seen: <where>.",
        ),
        (
            "provide: the role | kind: role | provider: U1 | when: now",
            "provide the role has kind role; use one of permission, secret, resource, account, "
            "document, other.",
        ),
        (
            "provide: the role | provider: U1 | when: now",
            "provide the role has kind (none); use one of permission, secret, resource, account, "
            "document, other.",
        ),
        (
            "provide: the role | kind: permission | provider: U1",
            "provide the role names no when; say when it must exist.",
        ),
        (
            "provide: the role | kind: permission | provider: U1 | when: now | seen: x.tf",
            "provide the role names seen: with the provider U1; only the provider exists takes "
            "seen.",
        ),
        (
            "provide: the role | kind: permission | provider: U1 | when: now | owner: ops",
            "provide the role has a field it does not know: owner: ops",
        ),
        (
            "provide:  | kind: permission | provider: U1 | when: now",
            "line 3 of the plan block is a provide line that names nothing: "
            "provide:  | kind: permission | provider: U1 | when: now",
        ),
        (
            "provides: some",
            "line 3 of the plan block is not a unit, edge, pin, version, graph, provide or "
            "provides: none line: provides: some",
        ),
    ],
)
def test_each_bad_provide_line_is_one_defect(tmp_path: Path, line: str, defect: str) -> None:
    assert _defects(tmp_path, line) == [defect]


def test_provides_none_beside_a_provide_line_is_refused(tmp_path: Path) -> None:
    assert _defects(tmp_path, ROLE, PROVIDES_NONE) == [
        "the plan block has provides: none beside 1 provide line(s); keep the provide lines "
        "or the one provides: none line, not both."
    ]
    assert _defects(tmp_path, PROVIDES_NONE, PROVIDES_NONE) == [
        "the plan block has 2 provides: none lines; keep one."
    ]


def test_a_separator_or_newline_in_the_text_is_refused_not_misparsed(tmp_path: Path) -> None:
    # A ` | ` inside the text splits into a field the line does not know.
    split = "provide: read | write role | kind: permission | provider: U1 | when: now"
    assert _defects(tmp_path, split) == ["provide read has a field it does not know: write role"]
    # A newline inside the text leaves a second line of no known kind.
    broken = "provide: the role\nfor reports | kind: permission | provider: U1 | when: now"
    assert _defects(tmp_path, broken) == [
        "line 4 of the plan block is not a unit, edge, pin, version, graph, provide or "
        "provides: none line: for reports | kind: permission | provider: U1 | when: now",
        "provide the role has kind (none); use one of permission, secret, resource, account, "
        "document, other.",
        "provide the role names no provider; name a unit id of this plan, user before merge, "
        "user after deploy or exists.",
        "provide the role names no when; say when it must exist.",
    ]


def test_a_plan_recorded_before_still_loads_and_validates(tmp_path: Path) -> None:
    # Item 5: no needs lines loads, and validate() (the dispatch gate's check) passes it.
    plan = load(_plan_file(tmp_path))
    assert plan.provides == () and plan.provides_none == 0
    assert validate(plan, 5) == []
    assert provides_missing(plan) == [
        "the plan block has no provide line and no provides: none line; list each thing the "
        "work needs once it runs as provide: <what> | kind: <kind> | provider: <unit id, user "
        "before merge, user after deploy or exists> | when: <when it must exist>, or write "
        "provides: none."
    ]


def test_the_validator_refuses_a_plan_with_no_needs_table(tmp_path: Path) -> None:
    proc = run_cli("validate_plan.py", str(_plan_file(tmp_path)))
    assert proc.returncode == 1
    lines = proc.stdout.splitlines()
    assert len(lines) == 2 and lines[0].startswith("the plan block has no provide line")
    assert lines[1].startswith("Next: ")


def test_the_validator_prints_the_rows_with_the_users_first(tmp_path: Path) -> None:
    proc = run_cli("validate_plan.py", str(_plan_file(tmp_path, ROLE, HOOK, SEEN, KEY)))
    assert proc.returncode == 0, proc.stdout
    assert proc.stdout.splitlines() == [
        f"OK plan: {GRAPH}",
        f"OK {KEY}",
        f"OK {HOOK}",
        f"OK {ROLE}",
        f"OK {SEEN}",
    ]
    none = run_cli("validate_plan.py", str(_plan_file(tmp_path, PROVIDES_NONE)))
    assert none.returncode == 0 and none.stdout == f"OK plan: {GRAPH}\n"


@pytest.mark.usefixtures("isolated_env", "fixed")
def test_the_gate_and_the_summary_read_a_run_with_needs_lines(tmp_path: Path) -> None:
    # Hunt: the dispatch gate passes, and the summary lists only the user's needs.
    root = fix_fixture(tmp_path / "repo")
    state = train_state.load(root, TRAIN)
    assert dispatch_binding._plan_defect(root, TRAIN, state) is None
    train_summary.write_summary(root, TRAIN, None)
    text = train_summary.summary_path(root, TRAIN).read_text(encoding="utf-8")
    section = text.split(f"\n{train_summary.TO_PROVIDE}\n", 1)[1].split("\n## ", 1)[0]
    assert section.splitlines() == [
        "- After deploy: the deploy key (secret), needed before the first deploy"
    ]
    assert "reports bucket" not in text


@pytest.mark.usefixtures("isolated_env", "fixed")
def test_the_summary_has_no_provide_heading_without_user_needs(tmp_path: Path) -> None:
    root = fix_fixture(tmp_path / "repo")
    path = Path(str(train_state.record(train_state.load(root, TRAIN), train_state.PLAN)["path"]))
    text = path.read_text(encoding="utf-8").replace(PROVIDES, "")
    assert loads(text).provides == ()
    path.write_text(text, encoding="utf-8")
    train_summary.write_summary(root, TRAIN, None)
    summary = train_summary.summary_path(root, TRAIN).read_text(encoding="utf-8")
    assert train_summary.TO_PROVIDE not in summary


def test_the_planner_and_the_plan_skill_state_the_needs_table() -> None:
    planner = " ".join((REPO_ROOT / "agents" / "planner.md").read_text(encoding="utf-8").split())
    block = planner.split("```plan", 1)[1].split("```", 1)[0]
    assert "provide: <what> | kind: <kind> | provider: <unit id" in block
    assert PROVIDES_NONE in planner
    assert "only when no provider is defensible" in planner
    skill = " ".join((REPO_ROOT / "skills" / "plan" / "SKILL.md").read_text("utf-8").split())
    assert "OK provide:" in skill
    assert "| Need | Kind | Who provides it | When it must exist |" in skill
