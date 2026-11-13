# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 349: a fix unit takes the class of the unit it fixes; a class check place is short; a raise
# is answered once.
from __future__ import annotations

import hashlib
import re
from pathlib import Path

import pytest
from lib import operator_file, plan_record, train_runner, train_state
from lib.train_runner import FixUnit

from tests.test_auditor_model import (
    VALID,
    _check_file,
    _findings,
    _merged,
    _model,
    _run,
)
from tests.test_fix_units import _plan, _rejected, _reqs
from tests.test_records_in_one_call import (
    TRAIN,
    _cli,
    _ok,
    fixed,  # noqa: F401
)

pytestmark = pytest.mark.usefixtures("isolated_env", "fixed")
HEX64 = "[0-9a-f]{64}"
SINKS = "it builds the shell guard"
SINKS_FIELDS = f"class: Injection sinks | place: scripts/lib/jail.py:guard | class_reason: {SINKS}"
U1_LINE = "tests/test_u1.py | base: integration\n"
U2_LINE = "operator_checks: The page shows the title\n"
REQ = "Make `tests/test_u1.py::test_f1` pass."


def _classed(u1: str | None, u2: str | None) -> str:
    text = VALID.replace(U1_LINE, f"tests/test_u1.py | base: integration | {u1}\n") if u1 else VALID
    return (
        text.replace(U2_LINE, f"operator_checks: The page shows the title | {u2}\n") if u2 else text
    )


def _fix(
    root: Path,
    uid: str = "fix1-u1",
    fixes: tuple[str, ...] = ("U1",),
    files: tuple[str, ...] = ("scripts/lib/jail.py",),
    finding: str = "F1",
    work_class: str | None = None,
    place: str | None = None,
    reason: str | None = None,
) -> train_runner.Outcome:
    reqs = _reqs(root, REQ)
    given = FixUnit(uid, "repair", files, fixes, (finding,), (), reqs, work_class, place, reason)
    return train_runner.fix_unit(root, given)


def _shot(root: Path) -> tuple[str, object, object]:
    state = train_state.load(root, TRAIN)
    digest = hashlib.sha256(_plan(root).read_bytes()).hexdigest()
    return digest, state.get("plan"), state.get(train_state.FIX_UNITS)


def _sinks_run(tmp_path: Path) -> Path:
    root = _merged(_run(tmp_path / "repo", _classed(SINKS_FIELDS, None)), "U1", "U2")
    _rejected(root, 1, "F1", "F2")
    return root


def _fix_line(root: Path) -> str:
    text = _plan(root).read_text(encoding="utf-8")
    return next(line for line in text.splitlines() if line.startswith("unit: fix1-u1 "))


def test_a_fix_of_an_injection_sinks_unit_takes_its_class_place_and_reason(
    tmp_path: Path,
) -> None:
    root = _sinks_run(tmp_path)
    code, out = _cli(
        root,
        *("fix-unit", "--unit", "fix1-u1", "--title", "repair", "--files", "scripts/lib/jail.py"),
        *("--fixes", "U1", "--finding", "F1", "--requirements", str(_reqs(root, REQ))),
    )
    assert code == 0, out
    want = rf"fix-unit fix1-u1: fixes U1 class=Injection sinks \(from U1\) plan sha256={HEX64}\n"
    assert re.fullmatch(want, out), out
    assert _fix_line(root).endswith(f"| {SINKS_FIELDS}")
    plan = plan_record.load(_plan(root))
    assert plan_record.validate(plan, 5, operator_file.load(root)) == []
    line = _ok(train_runner.dispatch_unit(root, "fix1-u1"))[0]
    assert line.startswith("dispatch fix1-u1: model=opus "), line
    code, out = _cli(root, "model", "--agent", "coder", "--unit", "fix1-u1")
    assert code == 0 and out.splitlines()[0] == "opus", out


def test_a_fix_whose_files_miss_the_place_is_refused_until_class_and_place_are_given(
    tmp_path: Path,
) -> None:
    root = _sinks_run(tmp_path)
    before = _shot(root)
    refused = _fix(root, files=("tests/test_u1.py",))
    assert refused.code == 1 and len(refused.lines) == 1, refused.lines
    assert "does not name scripts/lib/jail.py in --files" in refused.lines[0]
    assert refused.lines[0].count("Next:") == 1 and "--class and --place" in refused.lines[0]
    assert _shot(root) == before
    given = _fix(
        root,
        files=("tests/test_u1.py",),
        work_class="Injection sinks",
        place="tests/test_u1.py:test_f1",
        reason=SINKS,
    )
    assert re.fullmatch(
        rf"fix-unit fix1-u1: fixes U1 class=Injection sinks \(given\) plan sha256={HEX64}",
        _ok(given)[0],
    )


def test_a_smaller_given_class_needs_a_class_reason(tmp_path: Path) -> None:
    root = _sinks_run(tmp_path)
    before = _shot(root)
    refused = _fix(root, work_class="Plumbing")
    assert refused.code == 1 and len(refused.lines) == 1, refused.lines
    assert refused.lines[0].startswith(
        "--class Plumbing runs on sonnet, smaller than opus, which unit U1 of class Injection "
        "sinks runs on."
    )
    assert refused.lines[0].count("Next:") == 1 and "--class-reason" in refused.lines[0]
    assert _shot(root) == before
    done = _ok(_fix(root, work_class="Plumbing", reason="the fix only renames a test"))[0]
    assert re.fullmatch(
        rf"fix-unit fix1-u1: fixes U1 class=Plumbing \(given\) plan sha256={HEX64}", done
    )
    assert _fix_line(root).endswith("| class: Plumbing | class_reason: the fix only renames a test")


@pytest.mark.parametrize(
    ("u1", "u2", "fixes", "files", "want"),
    [
        (
            SINKS_FIELDS,
            "class: Mechanical | class_reason: a rename",
            ("U1", "U2"),
            ("scripts/lib/jail.py",),
            "Injection sinks (from U1)",
        ),
        (
            None,
            f"class: AuthN | place: web/u2.html:login | class_reason: {SINKS}",
            ("U1", "U2"),
            ("web/u2.html",),
            "AuthN (from U2)",
        ),
        (
            f"class: AuthN | place: scripts/lib/jail.py:guard | class_reason: {SINKS}",
            f"class: Injection sinks | place: web/u2.html:login | class_reason: {SINKS}",
            ("U2", "U1"),
            ("web/u2.html",),
            "Injection sinks (from U2)",
        ),
        (
            f"class: AuthN | place: scripts/lib/jail.py:guard | class_reason: {SINKS}",
            f"class: Injection sinks | place: web/u2.html:login | class_reason: {SINKS}",
            ("U1", "U2"),
            ("scripts/lib/jail.py",),
            "AuthN (from U1)",
        ),
    ],
    ids=["highest-first", "highest-second", "tie-keeps-order-u2", "tie-keeps-order-u1"],
)
def test_a_fix_of_several_units_takes_the_highest_class(
    tmp_path: Path,
    u1: str | None,
    u2: str | None,
    fixes: tuple[str, ...],
    files: tuple[str, ...],
    want: str,
) -> None:
    root = _merged(_run(tmp_path / "repo", _classed(u1, u2)), "U1", "U2")
    _rejected(root, 1, "F1", "F2")
    line = _ok(_fix(root, fixes=fixes, files=files))[0]
    assert f"class={want} plan sha256=" in line, line


def test_a_second_fix_takes_the_first_fix_units_class_and_the_check_reads_class_ok(
    tmp_path: Path,
) -> None:
    root = _sinks_run(tmp_path)
    _ok(_fix(root))
    _merged(root, "fix1-u1")
    _check_file(
        root,
        "U1 | Injection sinks | class ok",
        "U2 | Plumbing | class ok",
        "fix1-u1 | Injection sinks | class ok",
    )
    code, lines = _model(root)
    assert code == 0 and "class check fix1-u1: Injection sinks | class ok" in lines, lines
    _rejected(root, 2, "F3")
    second = _ok(_fix(root, "fix2-u1", ("fix1-u1",), finding="F3"))[0]
    assert "fixes fix1-u1 class=Injection sinks (from fix1-u1) plan" in second, second
    line = _ok(train_runner.dispatch_unit(root, "fix2-u1"))[0]
    assert line.startswith("dispatch fix2-u1: model=opus "), line


@pytest.mark.parametrize(
    ("place", "says"),
    [
        ("web/u2.html:" + "x" * 81, "a named part of 81 characters, over 80"),
        ("web/u2.html:login | form", "is not `<unit>"),
    ],
    ids=["81-characters", "pipe"],
)
def test_a_long_or_split_named_part_is_refused_and_records_nothing(
    tmp_path: Path, place: str, says: str
) -> None:
    root = _merged(_run(tmp_path / "repo"), "U1", "U2")
    _check_file(root, "U1 | Plumbing | class ok", f"U2 | Plumbing | AuthN | {place}")
    code, out = _model(root)
    assert code == 1 and len(out) == 1 and says in out[0], out
    assert out[0].count("Next:") == 1 and "rewrite the class check file, then rerun model" in out[0]
    state = train_state.load(root, TRAIN)
    assert train_state.CLASS_CHECK not in state and train_state.AUDITOR_MODEL not in state


def test_an_80_character_named_part_is_read(tmp_path: Path) -> None:
    root = _merged(_run(tmp_path / "repo"), "U1", "U2")
    _check_file(root, "U1 | Plumbing | class ok", "U2 | Plumbing | AuthN | web/u2.html:" + "x" * 80)
    code, out = _model(root)
    assert code == 0 and out[-1] == "class check: 2 unit(s), 1 raised, round 1", out


RAISED = "web/u2.html:login work-class"
RAISED_ROW = f"{RAISED} | high | work-class"


def _raised_round_one(tmp_path: Path) -> Path:
    # Round 1: the check raised U2 from Plumbing to AuthN, and the round was rejected on it.
    root = _merged(_run(tmp_path / "repo"), "U1", "U2")
    _check_file(root, "U1 | Plumbing | class ok", "U2 | Plumbing | AuthN | web/u2.html:login")
    code, lines = _model(root)
    assert code == 0 and f"Class raised: {RAISED_ROW}" in lines, lines
    _rejected(root, 1, RAISED)
    return root


def _fix_u2(root: Path, work_class: str | None) -> None:
    reason = SINKS if work_class else None
    place = "web/u2.html:login" if work_class else None
    _ok(_fix(root, "fix1-u2", ("U2",), ("web/u2.html",), RAISED, work_class, place, reason))
    _merged(root, "fix1-u2")


def _check_round_two(root: Path, fix_class: str, place: str = "web/u2.html:login") -> list[str]:
    _check_file(
        root,
        "U1 | Plumbing | class ok",
        f"U2 | Plumbing | AuthN | {place}",
        f"fix1-u2 | {fix_class} | class ok",
    )
    code, lines = _model(root)
    assert code == 0, lines
    return lines


def _verdict_past_the_class_rows(root: Path, *rows: str) -> train_runner.Outcome:
    return train_runner.record_verdict(root, "rejected", findings=_findings(root, 2, *rows))


def test_a_raise_answered_by_a_fix_of_its_class_owes_no_row(tmp_path: Path) -> None:
    root = _raised_round_one(tmp_path)
    _fix_u2(root, "AuthN")
    lines = _check_round_two(root, "AuthN")
    assert "class check U2: answered by fix1-u2" in lines, lines
    assert not any(line.startswith("Class raised:") for line in lines), lines
    assert lines[-1] == "class check: 3 unit(s), 0 raised, round 2"
    check = train_state.load(root, TRAIN)[train_state.CLASS_CHECK]
    assert check["units"]["U2"]["answered"] == "fix1-u2"  # type: ignore[index]
    passed = _verdict_past_the_class_rows(root, "F2 | high | code")
    # Past the class row check, the verdict is read from the auditor's own reply.
    assert passed.code == 1 and "class check" not in passed.lines[0], passed.lines


def test_a_raise_with_a_lower_fix_and_no_exemption_is_raised_again(tmp_path: Path) -> None:
    root = _raised_round_one(tmp_path)
    _fix_u2(root, None)
    lines = _check_round_two(root, "Plumbing")
    assert f"Class raised: {RAISED_ROW}" in lines, lines
    assert not any("answered by" in line for line in lines)
    refused = _verdict_past_the_class_rows(root, "F2 | high | code")
    assert refused.code == 1 and refused.lines[0].startswith(
        "the class check raised unit U2, and round 2 lists no row"
    )


def test_a_raise_whose_finding_the_operator_exempted_owes_no_row(tmp_path: Path) -> None:
    root = _raised_round_one(tmp_path)
    _fix_u2(root, None)
    exempt = {"1": {RAISED: {"run_id": TRAIN, "reason": "accepted", "tracking": "none"}}}
    train_state.update(root, TRAIN, **{train_state.EXEMPTIONS: exempt})
    # A new check names the place in other words; the earlier key still answers it.
    lines = _check_round_two(root, "Plumbing", "web/u2.html:login form")
    assert "class check U2: answered by exemption" in lines, lines
    assert not any(line.startswith("Class raised:") for line in lines), lines
    keys = train_state.load(root, TRAIN)[train_state.CLASS_CHECK]["raised_keys"]  # type: ignore[index]
    assert keys == {"U2": [RAISED, "web/u2.html:login form work-class"]}
    passed = _verdict_past_the_class_rows(root, "F2 | high | code")
    assert passed.code == 1 and "class check" not in passed.lines[0], passed.lines
