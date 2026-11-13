# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0267, 0280: the auditor's model from the highest merged class, and the class check first.
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from lib import operator_file, train_runner, train_state, train_summary, work_classes
from lib.audit_proof import findings_path
from lib.train_runner import FixUnit

from tests.conftest import git, run_cli
from tests.test_fix_units import _picked, _plan, _rejected, _reqs
from tests.test_records_in_one_call import (
    PLAN,
    TRAIN,
    _built,
    _cli,
    _ok,
    _verdict,
    fixed,  # noqa: F401
)
from tests.test_records_in_one_call import _fixture as shared_fixture
from tests.test_workspace_train import VERIFIED_REPLY

pytestmark = pytest.mark.usefixtures("isolated_env", "fixed")
VALID = PLAN.replace("1. Refuse x.\n2. Admit y.", "1. Refuse `x`.\n2. Admit `y`.")
REASON = "it proves who calls"
CLASSED = VALID.replace(
    "tests/test_u1.py | base: integration\n",
    "tests/test_u1.py | base: integration | class: Plumbing\n",
).replace(
    "operator_checks: The page shows the title\n",
    "operator_checks: The page shows the title | class: AuthN | place: web/u2.html:login | "
    f"class_reason: {REASON}\n",
)
PLUMBING_LINE = "auditor U1: sonnet | class: Plumbing"
AUTHN_LINE = f"auditor U2: opus | class: AuthN | class_reason: {REASON}"
RAISED_MODEL = (
    "Auditor model: opus, from unit U2 of class Secrets, raised by the class check from Plumbing"
)


def _run(root: Path, plan: str = VALID) -> Path:
    made = shared_fixture(root)
    _plan(made).write_text(plan, encoding="utf-8")
    _ok(train_runner.record_plan(made, _plan(made)))
    return made


def _built_all(root: Path, *uids: str) -> None:
    for uid in uids:
        _ok(train_runner.dispatch_unit(root, uid))
        _verdict(root, _built(root, uid), VERIFIED_REPLY)


def _merged(root: Path, *uids: str) -> Path:
    _built_all(root, *uids)
    for uid in uids:
        _ok(train_runner.finish_unit(root, uid))
    return root


def _model(root: Path, *extra: str) -> tuple[int, list[str]]:
    code, out = _cli(root, "model", "--agent", "auditor", *extra)
    return code, out.splitlines()


def _override(root: Path, body: dict[str, object]) -> None:
    config = root / ".claude" / "daedalus" / "config.json"
    held = json.loads(config.read_text(encoding="utf-8")) if config.is_file() else {}
    held["personal_overrides"] = body
    config.write_text(json.dumps(held), encoding="utf-8")


def _check_file(root: Path, *lines: str) -> Path:
    path = train_runner.class_check_path(root, TRAIN)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(f"{line}\n" for line in lines), encoding="utf-8")
    return path


def test_all_plumbing_answers_the_middle_model_from_the_first_unit(tmp_path: Path) -> None:
    root = _merged(_run(tmp_path / "repo"), "U1", "U2")
    assert _model(root) == (0, ["sonnet", PLUMBING_LINE])
    record = train_state.load(root, TRAIN)[train_state.AUDITOR_MODEL]
    assert record == {"model": "sonnet", "class": "Plumbing", "unit": "U1", "raised_from": None}


def test_a_merged_unit_on_the_top_model_sets_the_auditor(tmp_path: Path) -> None:
    root = _run(tmp_path / "repo", CLASSED)
    _built_all(root, "U1", "U2")
    _ok(train_runner.finish_unit(root, "U1"))
    # Only merged units count: U2 is built and verified, not merged.
    assert _model(root) == (0, ["sonnet", PLUMBING_LINE])
    _ok(train_runner.finish_unit(root, "U2"))
    assert _model(root) == (0, ["opus", AUTHN_LINE])


def test_a_project_setting_that_lowers_the_class_lowers_the_auditor(tmp_path: Path) -> None:
    root = _merged(_run(tmp_path / "repo", CLASSED), "U1", "U2")
    _override(root, {"class_models": {"AuthN": "sonnet"}})
    # A tie keeps the first unit in plan order.
    assert _model(root) == (0, ["sonnet", PLUMBING_LINE])
    _override(root, {"class_models": {"AuthN": "fable"}})
    assert _model(root) == (0, ["fable", AUTHN_LINE.replace("opus", "fable")])


def test_a_fix_unit_with_the_highest_class_sets_the_auditor(tmp_path: Path) -> None:
    root = _merged(_run(tmp_path / "repo"), "U1", "U2")
    _rejected(root, 1, "F1")
    _picked(root, 1, "F1")
    reqs = _reqs(root, "Make `tests/test_u1.py::test_f1` pass.")
    fix = FixUnit(
        "fix1-u1",
        "repair",
        ("tests/test_u1.py",),
        ("U1",),
        ("F1",),
        (),
        reqs,
        "AuthN",
        "tests/test_u1.py:test_f1",
        REASON,
    )
    _ok(train_runner.fix_unit(root, fix))
    assert _model(root) == (0, ["sonnet", PLUMBING_LINE])
    _merged(root, "fix1-u1")
    want = f"auditor fix1-u1: opus | class: AuthN | class_reason: {REASON}"
    assert _model(root) == (0, ["opus", want])


def test_no_merged_unit_and_no_plan_are_refused_with_one_next_line(tmp_path: Path) -> None:
    root = _run(tmp_path / "repo", CLASSED)
    for extra in ((), ("--class-check",)):
        code, lines = _model(root, *extra)
        assert code == 1 and len(lines) == 1, lines
        assert lines[0].startswith(f"no unit of run {TRAIN} is merged into daedalus/{TRAIN}")
        assert lines[0].count("Next:") == 1
    train_state.change(root, TRAIN, lambda state: state.pop(train_state.PLAN))
    code, lines = _model(root)
    assert code == 1 and len(lines) == 1
    assert (
        lines[0].startswith(f"run {TRAIN} records no plan") and "Next: record the plan" in lines[0]
    )
    assert train_state.AUDITOR_MODEL not in train_state.load(root, TRAIN)


def test_outside_a_run_the_auditor_keeps_its_agent_file_model(tmp_path: Path) -> None:
    root = tmp_path / "plain"
    root.mkdir()
    git(root, "init", "-q", "-b", "main")
    done = run_cli(
        "daedalus_train.py", "model", "--repo", str(root), "--agent", "auditor", cwd=root
    )
    assert (done.returncode, done.stdout) == (0, "opus\n"), done.stderr
    refused = run_cli(
        "daedalus_train.py",
        *("model", "--repo", str(root), "--agent", "auditor", "--class-check"),
        cwd=root,
    )
    assert refused.returncode == 1 and "Next:" in refused.stdout


@pytest.mark.parametrize(
    "extra",
    [
        ("--agent", "coder", "--class-check"),
        ("--agent", "auditor", "--class-check", "--unit", "U1"),
    ],
    ids=str,
)
def test_class_check_takes_the_auditor_alone(tmp_path: Path, extra: tuple[str, ...]) -> None:
    root = _merged(_run(tmp_path / "repo"), "U1", "U2")
    code, out = _cli(root, "model", *extra)
    assert code == 1 and "model --class-check names the auditor's class check model" in out


def test_the_class_check_runs_on_the_top_model_in_an_all_plumbing_run(tmp_path: Path) -> None:
    root = _merged(_run(tmp_path / "repo"), "U1", "U2")
    code, lines = _model(root, "--class-check")
    assert code == 0, lines
    assert lines[0] == work_classes.TOP_MODEL == "opus"
    assert (
        lines[1] == "auditor class check: opus | the top coding model, whatever the units' classes"
    )
    assert lines[2] == f"Class check file: {train_runner.class_check_path(root, TRAIN)}"
    assert lines[3] == (
        f"Unit: U1 | class: Plumbing | branch: daedalus-unit/{TRAIN}-u1 | "
        "files: scripts/lib/jail.py, tests/test_u1.py"
    )
    assert (
        lines[4]
        == f"Unit: U2 | class: Plumbing | branch: daedalus-unit/{TRAIN}-u2 | files: web/u2.html"
    )
    classes = operator_file.load(root).work_classes
    assert lines[5:] == [f"Work class: {n} | {d}" for n, d in classes]
    # The audit itself stays on the middle model.
    assert _model(root)[1][0] == "sonnet"


def test_a_raised_unit_raises_the_auditor_and_is_recorded(tmp_path: Path) -> None:
    root = _merged(_run(tmp_path / "repo"), "U1", "U2")
    path = _check_file(
        root, "U1 | Plumbing | class ok", "u2 | Plumbing | AuthN | web/u2.html:login"
    )
    want = (
        "auditor U2: opus | class: AuthN | class check: raised from Plumbing at web/u2.html:login"
    )
    checked = [
        "class check U1: Plumbing | class ok",
        "class check U2: Plumbing -> AuthN (opus) at web/u2.html:login | raised",
        "Class raised: web/u2.html:login work-class | high | work-class",
        "class check: 2 unit(s), 1 raised, round 1",
    ]
    assert _model(root) == (0, ["opus", want, *checked])
    check = train_state.load(root, TRAIN)[train_state.CLASS_CHECK]
    assert check == {
        "round": 1,
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "units": {
            "U1": {"planned": "Plumbing", "class": None, "place": None, "raised": False},
            "U2": {
                "planned": "Plumbing",
                "class": "AuthN",
                "place": "web/u2.html:login",
                "raised": True,
            },
        },
        "raised_keys": {"U2": ["web/u2.html:login work-class"]},
    }
    picked = train_state.load(root, TRAIN)[train_state.AUDITOR_MODEL]
    assert picked == {"model": "opus", "class": "AuthN", "unit": "U2", "raised_from": "Plumbing"}
    # A reread of the same file after round 1 keeps the check bound to round 1.
    _rejected(root, 1, "web/u2.html:login work-class")
    assert _model(root)[1][-1] == "class check: 2 unit(s), 1 raised, round 1"
    assert train_state.load(root, TRAIN)[train_state.CLASS_CHECK]["round"] == 1  # type: ignore[index]


def test_a_lower_or_level_class_is_recorded_and_raises_nothing(tmp_path: Path) -> None:
    root = _merged(_run(tmp_path / "repo", CLASSED), "U1", "U2")
    _check_file(
        root,
        "U1 | Plumbing | Mechanical | scripts/lib/jail.py:rename",
        "U2 | AuthN | AuthZ | web/u2.html:login",
    )
    code, lines = _model(root)
    assert code == 0 and lines[:2] == ["opus", AUTHN_LINE], lines
    assert not any(line.startswith("Class raised:") for line in lines)
    assert lines[-1] == "class check: 2 unit(s), 0 raised, round 1"


@pytest.mark.parametrize(
    ("lines", "says"),
    [
        (("U1 | Plumbing | class ok", "U2 | Plumbing | Wizardry | web/u2.html:x"), "Wizardry"),
        (("U1 | Plumbing | class ok", "U1 | Plumbing | class ok"), "names a unit twice"),
        (("U1 | Plumbing | class ok", "U9 | Plumbing | class ok"), "names no merged unit"),
        (("U1 | AuthN | class ok", "U2 | Plumbing | class ok"), "the planned class AuthN"),
        (("U1 | Plumbing | fine", "U2 | Plumbing | class ok"), "is not `<unit>"),
        (("U1 | Plumbing | AuthN | nowhere", "U2 | Plumbing | class ok"), "<file>:<named part>"),
        (("U1 | Plumbing | Plumbing | a.py:x", "U2 | Plumbing | class ok"), "own planned class"),
        (
            ("U1 | Plumbing | AuthN | a.py:x", "U2 | Plumbing | Secrets | a.py:x"),
            "raises a second unit at a.py:x",
        ),
    ],
    ids=str,
)
def test_a_bad_class_check_file_is_refused_and_records_nothing(
    tmp_path: Path, lines: tuple[str, ...], says: str
) -> None:
    root = _merged(_run(tmp_path / "repo"), "U1", "U2")
    _check_file(root, *lines)
    code, out = _model(root)
    assert code == 1 and len(out) == 1 and says in out[0], out
    assert out[0].count("Next:") == 1 and "rewrite the class check file, then rerun model" in out[0]
    state = train_state.load(root, TRAIN)
    assert train_state.CLASS_CHECK not in state and train_state.AUDITOR_MODEL not in state


def test_a_class_the_settings_do_not_list_is_refused_where_it_is_read(tmp_path: Path) -> None:
    root = _merged(_run(tmp_path / "repo"), "U1", "U2")
    _check_file(root, "U1 | Plumbing | class ok", "U2 | Plumbing | AuthN | web/u2.html:login")
    _ok(train_runner.auditor_model(root))
    # The settings drop AuthN after the check: the reread file is refused, never the middle model.
    path = Path.home() / operator_file.OPERATOR_FILE
    path.parent.mkdir(parents=True, exist_ok=True)
    rows = [{"name": "Plumbing", "definition": "Any other work."}]
    path.write_text(json.dumps({"work_classes": rows, "class_models": {"Plumbing": "sonnet"}}))
    code, lines = _model(root)
    assert code == 1 and len(lines) == 1
    assert "names the class AuthN, which the work classes settings do not list" in lines[0]
    # With the file gone, the recorded raise is held to the settings the same way.
    train_runner.class_check_path(root, TRAIN).unlink()
    code, lines = _model(root)
    assert code == 1 and len(lines) == 1
    assert "raised unit U2 to the class AuthN, which the work classes settings no" in lines[0]


def test_a_class_check_path_that_is_not_a_file_is_refused(tmp_path: Path) -> None:
    root = _merged(_run(tmp_path / "repo"), "U1", "U2")
    train_runner.class_check_path(root, TRAIN).mkdir(parents=True)
    code, lines = _model(root)
    assert code == 1 and "is not a regular file" in lines[0] and "Next:" in lines[0]


def test_the_round_after_a_raise_lists_its_row_before_a_verdict_records(tmp_path: Path) -> None:
    root = _merged(_run(tmp_path / "repo"), "U1", "U2")
    _check_file(root, "U1 | Plumbing | class ok", "U2 | Plumbing | AuthN | web/u2.html:login")
    _ok(train_runner.auditor_model(root))
    path = findings_path(root, TRAIN, 1)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("F1 | high | code\n", encoding="utf-8")
    refused = train_runner.record_verdict(root, "rejected", findings=path)
    assert refused.code == 1
    assert refused.lines[0].startswith(
        "the class check raised unit U2, and round 1 lists no row "
        "`web/u2.html:login work-class | high | work-class`."
    )
    path.write_text("F1 | high | code\nweb/u2.html:login work-class | high | work-class\n")
    passed = train_runner.record_verdict(root, "rejected", findings=path)
    # Past the class row check, the verdict is read from the auditor's own reply.
    assert passed.code == 1 and "class check" not in passed.lines[0], passed.lines


def _findings(root: Path, round_: int, *rows: str) -> Path:
    path = findings_path(root, TRAIN, round_)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(f"{row}\n" for row in rows), encoding="utf-8")
    return path


AGAIN = "--agent auditor --class-check, dispatch the auditor in class-check mode on its line 1"


def test_a_verdict_with_no_class_check_is_refused(tmp_path: Path) -> None:
    root = _merged(_run(tmp_path / "repo"), "U1", "U2")
    refused = train_runner.record_verdict(
        root, "rejected", findings=_findings(root, 1, "F1 | high | code")
    )
    assert refused.code == 1 and len(refused.lines) == 1
    line = refused.lines[0]
    assert line.startswith(
        f"run {TRAIN} records no class check, so no audit verdict can be recorded."
    )
    assert line.count("Next:") == 1
    assert f"Next: run the class check: daedalus_train.py model --repo {root} {AGAIN}" in line
    assert train_state.VERDICT not in train_state.load(root, TRAIN)


def test_a_fix_unit_merged_after_the_check_needs_the_check_again(tmp_path: Path) -> None:
    root = _merged(_run(tmp_path / "repo"), "U1", "U2")
    _check_file(root, "U1 | Plumbing | class ok", "U2 | Plumbing | class ok")
    _ok(train_runner.auditor_model(root))
    _rejected(root, 1, "F1")
    _picked(root, 1, "F1")
    reqs = _reqs(root, "Make `tests/test_u1.py::test_f1` pass.")
    fix = FixUnit("fix1-u1", "repair", ("tests/test_u1.py",), ("U1",), ("F1",), (), reqs)
    _ok(train_runner.fix_unit(root, fix))
    _merged(root, "fix1-u1")
    again = f"Next: run the class check again: daedalus_train.py model --repo {root} {AGAIN}"
    # The model command reads the old file and names the merged unit it lacks.
    code, lines = _model(root)
    assert code == 1 and len(lines) == 1, lines
    assert "names no line for merged unit fix1-u1." in lines[0] and again in lines[0]
    assert lines[0].count("Next:") == 1
    # The verdict reads the recorded check, which names two of the three merged units.
    path = _findings(root, 2, "F2 | high | code")
    refused = train_runner.record_verdict(root, "rejected", findings=path)
    assert refused.code == 1 and len(refused.lines) == 1
    assert refused.lines[0].startswith(
        "the recorded class check names no line for merged unit fix1-u1, so no audit verdict"
    )
    assert again in refused.lines[0] and refused.lines[0].count("Next:") == 1
    # A new check naming all three units lets the verdict go on to the auditor's own reply.
    _check_file(
        root,
        "U1 | Plumbing | class ok",
        "U2 | Plumbing | class ok",
        "fix1-u1 | Plumbing | class ok",
    )
    code, lines = _model(root)
    assert code == 0 and lines[-1] == "class check: 3 unit(s), 0 raised, round 2", lines
    passed = train_runner.record_verdict(root, "rejected", findings=path)
    assert passed.code == 1 and "class check" not in passed.lines[0], passed.lines


def test_the_auditor_on_a_unit_answers_its_class_with_no_unit_merged(tmp_path: Path) -> None:
    # 0280: a compliance question mid-build takes the asking unit's class, merged or not.
    root = _run(tmp_path / "repo", CLASSED)
    assert _model(root, "--unit", "U2") == (0, ["opus", AUTHN_LINE])
    assert _model(root, "--unit", "u1") == (0, ["sonnet", PLUMBING_LINE])
    code, lines = _model(root)
    assert code == 1 and lines[0].startswith(f"no unit of run {TRAIN} is merged")
    state = train_state.load(root, TRAIN)
    assert train_state.AUDITOR_MODEL not in state and train_state.CLASS_CHECK not in state


def test_the_summary_names_the_auditor_model_and_each_raised_unit(tmp_path: Path) -> None:
    root = _merged(_run(tmp_path / "repo"), "U1", "U2")
    state = train_state.load(root, TRAIN)
    assert train_summary._audit_model(state, root, None) == []
    _model(root)
    state = train_state.load(root, TRAIN)
    assert train_summary._audit_model(state, root, None) == [
        "Auditor model: sonnet, from unit U1 of class Plumbing"
    ]
    _check_file(root, "U1 | Plumbing | class ok", "U2 | Plumbing | class ok")
    _ok(train_runner.auditor_model(root))
    state = train_state.load(root, TRAIN)
    assert train_summary._audit_model(state, root, None)[-1] == (
        "Class check: no unit raised (2 checked)"
    )
    _check_file(root, "U1 | Plumbing | class ok", "U2 | Plumbing | Secrets | web/u2.html:key")
    _ok(train_runner.auditor_model(root))
    state = train_state.load(root, TRAIN)
    raised = [RAISED_MODEL, "Class check raised U2 from Plumbing to Secrets"]
    assert train_summary._audit_model(state, root, None) == raised
    notes = train_summary.parse_notes("", "notes")
    section = train_summary._audit(root, state, [], notes)
    assert section[:4] == ["## Audit", "Verdict: pending", *raised]


def test_the_audit_skill_runs_the_class_check_then_the_model_then_round_one() -> None:
    from tests.conftest import REPO_ROOT

    text = (REPO_ROOT / "skills" / "audit" / "SKILL.md").read_text(encoding="utf-8")
    step = text.split("\n5. Choose the auditor's model", 1)[1].split("\n### Short form", 1)[0]
    order = [
        "daedalus_train.py model --repo <repo> --agent auditor --class-check`",
        "first line is `Mode: class-check`",
        "daedalus_train.py model --repo <repo> --agent auditor`",
        "it first reads the class check file, refuses a class the settings do not list",
        "Dispatch `auditor` with `model: <that word>` and: the diff base",
        "in round 1, each `Class raised:` line of the class check",
    ]
    at = [step.index(part) for part in order]
    assert at == sorted(at), at
    assert "opus" not in step
    short = text.split("\n### Short form", 1)[1].split("\n### Table-diff form", 1)[0]
    assert "It keeps the class check of step 5" in short
    auditor = (REPO_ROOT / "agents" / "auditor.md").read_text(encoding="utf-8")
    section = auditor.split("## Class check first (0280)\n", 1)[1].split("\n## ", 1)[0]
    assert section.count(". ") + section.count(".\n") <= 4
    # 349: "function" only beside the section and line range a document or investigation names.
    clause = "the named part is a function, a section or a\nline range, never a sentence"
    assert clause in section and section.count("function") == 1
    assert "opus" not in section
