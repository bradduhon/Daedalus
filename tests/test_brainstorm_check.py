# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
"""0243: brainstorm_check.py on canned board, brief, turn log and spec files; one break per rule."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import brainstorm_check
import pytest

from tests.conftest import REPO_ROOT, SCRIPTS_DIR

CANNED = REPO_ROOT / "tests" / "fixtures" / "brainstorm"
SCRIPT = str(SCRIPTS_DIR / "brainstorm_check.py")
FILES = {"board": "board.md", "handoff": "handoff.md", "turns": "turns.md", "risks": "spec.md"}


def _canned(form: str) -> str:
    return (CANNED / FILES[form]).read_text(encoding="utf-8")


def _problems(form: str, text: str) -> list[str]:
    return brainstorm_check.FORMS[form][0](text)


def _run(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, SCRIPT, *args], capture_output=True, text=True, check=False
    )


@pytest.mark.parametrize("form", sorted(FILES))
def test_each_canned_file_passes_its_form(form: str) -> None:
    got = _run(form, str(CANNED / FILES[form]))
    assert (got.returncode, got.stdout, got.stderr) == (0, f"{form} ok\n", "")


# (form, old text, new text, a fragment of the expected problem line)
BREAKS = (
    # board and handoff: the fixed headings present and in order.
    ("board", "## Tensions\n", "## Worries\n", "the heading `## Tensions` is missing"),
    ("board", "## Parked\n", "## Parked\n\n## Extra\n", "`## Extra` is not one of the fixed"),
    ("handoff", "## Receipts owed\n", "## Receipts\n", "`## Receipts owed` is missing"),
    ("board", "## Goal now\n", "## Goal as first stated\n", "appears 2 times"),
    # each rejected framing has a reason.
    ("board", ". Reason: it still", ", it still", "Retired item 1 gives no `Reason:`"),
    (
        "handoff",
        ". Reason: the user wanted",
        ", the user wanted",
        "Why this over the alternatives item 2 gives no `Reason:`",
    ),
    # each confirmed premise or constraint names a turn number.
    ("board", " (turn 4).", ".", "Confirmed premises item 1 names no `turn <n>`"),
    ("handoff", " (turn 4).", ".", "Confirmed constraints item 1 names no `turn <n>`"),
    # both goal lines present.
    (
        "board",
        "## Goal now\nAn agent that shows a confident first draft and lets the user correct it.\n",
        "## Goal now\n",
        "Goal now holds no sentence",
    ),
    (
        "handoff",
        "## Goal as first stated\nA planner agent",
        "## Goal as first stated\nNone.\n\n## Spare\nA planner agent",
        "Goal as first stated holds no sentence",
    ),
    # a checked list holds only `- ` items or None.
    ("board", "- Cap the", "Cap the", "Retired holds a line that is not a `- ` item"),
    # every Receipts owed line carries a receipt or ASSUMED.
    (
        "handoff",
        "faster than answers. ASSUMED",
        "faster than answers.",
        "Receipts owed item 2 carries no URL, no file:line and no ASSUMED",
    ),
    # board: three framings in their fixed shapes, the denied premise quoted and not empty.
    ("board", "## Framings\n", "## Ideas\n", "the heading `## Framings` is missing"),
    ("board", "- Obvious: Keep", "- Plain: Keep", "Framings line 1 is not `- Obvious: <sentence>`"),
    (
        "board",
        "- Stranger: The",
        "- Odd one: The",
        "Framings line 2 is not `- Stranger: <sentence>`",
    ),
    (
        "board",
        'Denies "asks the user design questions":',
        'Denies "":',
        'Framings line 3 is not `- Denies "<premise>": <sentence>`',
    ),
    (
        "board",
        'Denies "asks the user design questions":',
        "Denies asks the user design questions:",
        "Framings line 3 is not",
    ),
    (
        "board",
        "- Stranger: The agent shows",
        "Stranger line gone. The agent shows",
        "holds 2 lines",
    ),
    # turns: the opening holds at most one question, and it is the last sentence.
    (
        "turns",
        "What if the first thing",
        "Who will use it? What if the first thing",
        "turn 2: holds 2 questions",
    ),
    (
        "turns",
        "wrong design?",
        "wrong design? Think about it.",
        "turn 2: the question is not the turn's last sentence",
    ),
    # no session turn holds more than one question.
    (
        "turns",
        "Should the spec be",
        "Is that right? Should the spec be",
        "turn 6: holds 2 questions",
    ),
    # a question is the turn's last sentence and follows at least one other sentence.
    (
        "turns",
        "nothing new written after it?",
        "nothing new written after it? I lean yes.",
        "turn 6: the question is not the turn's last sentence",
    ),
    (
        "turns",
        'Your "keep the spec" holds the finish line still while the start moves. My guess: the '
        "draft becomes the spec once the user stops correcting it. ",
        "",
        "turn 6: the question stands alone",
    ),
    # the session turn after an operator question holds no question.
    (
        "turns",
        "the road not taken.",
        "the road not taken. Want me to sketch one?",
        "turn 4: answers the operator's question at turn 3 and still asks one",
    ),
    # no session turn holds a list of three or more requirement-like items.
    (
        "turns",
        "the road not taken.",
        "the road not taken.\n1. The draft must load fast.\n2. It should mark guesses.\n"
        "3. The user needs to correct inline.",
        "turn 4: holds a list of 3 requirement-like items",
    ),
    # risks: an operator-decided Open risks row cites its question number.
    ("risks", "Decides: the operator, question 4.", "Decides: the operator.", "row 1 is the oper"),
    ("risks", " Decides: later tuning.", "", "Open risks row 2 names no `Decides:`"),
    ("risks", "## 6. Open risks\n", "## 6. Risks\n", "holds no `## 6. Open risks` section"),
)


@pytest.mark.parametrize(("form", "old", "new", "want"), BREAKS)
def test_each_rule_fails_on_its_break(form: str, old: str, new: str, want: str) -> None:
    text = _canned(form)
    assert old in text, old
    problems = _problems(form, text.replace(old, new, 1))
    assert any(want in problem for problem in problems), problems


def test_a_failure_prints_one_line_per_problem_and_a_next_line(tmp_path: Path) -> None:
    path = tmp_path / "board.md"
    path.write_text(_canned("board").replace(" (turn 4).", "."), encoding="utf-8")
    got = _run("board", str(path))
    assert got.returncode == 1 and got.stderr == ""
    lines = got.stdout.splitlines()
    assert lines[0] == (
        "board: Confirmed premises item 1 names no `turn <n>`: The user wants a spec at the end."
    )
    assert lines[-1].startswith("Next: ") and len(lines) == 2


def test_turn_records_count_from_one(tmp_path: Path) -> None:
    text = _canned("turns").replace("### Turn 3: operator", "### Turn 7: operator")
    assert "the record `### Turn 7: operator` should be turn 3" in _problems("turns", text)
    assert _problems("turns", "no records here\n")[:2] == [
        "text before the first turn record: no records here",
        "the log holds no `### Turn <n>: <session|operator>` record",
    ]


def test_quoted_question_marks_are_not_the_sessions_questions() -> None:
    text = "### Turn 1: operator\nAn idea.\n\n### Turn 2: session\n" + (
        'You asked "will it scale?" Three framings: one, a; two, b; three, drop c. I like two.'
    )
    assert _problems("turns", text) == []


@pytest.mark.parametrize(
    "args", [(), ("board",), ("bogus", "x"), ("board", "a", "b"), ("board", "")]
)
def test_usage_errors_exit_two_with_the_usage(args: tuple[str, ...]) -> None:
    got = _run(*args)
    assert got.returncode == 2 and got.stdout == ""
    assert "usage: brainstorm_check.py board <file>" in got.stderr and "Next: " in got.stderr


def test_an_unreadable_file_exits_two_with_a_next_line(tmp_path: Path) -> None:
    missing = _run("handoff", str(tmp_path / "absent.md"))
    assert missing.returncode == 2 and "is not a file. Next: " in missing.stderr
    binary = tmp_path / "board.md"
    binary.write_bytes(b"\xff\xfe\x00")
    bad = _run("board", str(binary))
    assert bad.returncode == 2 and "Next: rewrite the file as UTF-8 text." in bad.stderr
