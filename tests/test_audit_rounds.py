# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0109, spec 3.4: the finding list shape of pin C3 -> C1 and the round number; 0133 retired
# the stall rule, which tests/test_operator_gates.py checks is gone.
from __future__ import annotations

import pytest
from lib.audit_rounds import (
    SEVERITIES,
    Finding,
    FindingsError,
    cell_problems,
    finding_cells,
    next_round,
    parse,
    reply_finding,
)

LOW = "low"


def test_parse_reads_the_pinned_line_shape() -> None:
    text = (
        "audit/round1/test_scope_ledger_write.py::test_refused | high | scope-write\n"
        "\n"
        "scripts/lib/jail.py:12 no-test-class | low | contract\n"
    )
    found = parse(text, "findings.txt")
    assert found == {
        "audit/round1/test_scope_ledger_write.py::test_refused": Finding(
            "audit/round1/test_scope_ledger_write.py::test_refused", "high", "scope-write"
        ),
        "scripts/lib/jail.py:12 no-test-class": Finding(
            "scripts/lib/jail.py:12 no-test-class", LOW, "contract"
        ),
    }
    assert parse("", "findings.txt") == {}
    assert SEVERITIES == ("critical", "high", "medium", "low")


@pytest.mark.parametrize(
    ("text", "why"),
    [
        ("a.py::t | high\n", "is not `<key> | <severity> | <class>`"),
        ("a.py::t |  | c\n", "is not `<key> | <severity> | <class>`"),
        ("a.py::t | severe | c\n", "names severity 'severe'"),
        ("a.py::t | High | c\n", "names severity 'High'"),
        ("a.py::t | high | c\na.py::t | low | d\n", "names a.py::t twice"),
        ("a.py::t\x1b | high | c\n", "is not `<key> | <severity> | <class>`"),
    ],
)
def test_parse_refuses_an_off_shape_list_with_a_next_line(text: str, why: str) -> None:
    with pytest.raises(FindingsError) as info:
        parse(text, "findings.txt")
    assert why in str(info.value) and "Next: " in str(info.value)


@pytest.mark.parametrize(
    ("rounds", "want"),
    [
        ({}, 1),
        ({"1": {}}, 2),
        ({"1": {}, "3": {"a": {}}, "2": {}}, 4),
        # 67: a key that is not a round number never moves the round.
        ({"0": {}, "-2": {}, "x": {}, "01": {}, "²": {}, "1": {}}, 2),
    ],
)
def test_next_round_is_one_more_than_the_highest_recorded(
    rounds: dict[str, object], want: int
) -> None:
    assert next_round(rounds) == want


# 0281: the rule, places and search cells that end every judge finding row.
CELLS = (
    " | rule: every reader keeps the row whole"
    " | places: a.py:3, guide.md:Install | search: git grep -n row"
)


def test_finding_cells_read_each_named_cell() -> None:
    row = "code | claim 2 | MISSING | `a | b` | req 2" + CELLS
    assert finding_cells(row) == {
        "rule": "every reader keeps the row whole",
        "places": "a.py:3, guide.md:Install",
        "search": "git grep -n row",
    }
    assert cell_problems(row) == []


def test_a_search_with_a_pipe_stays_whole() -> None:
    row = "code | c | MISSING | x | y | rule: r | places: a.py:1 | search: git grep -n x | sort"
    assert finding_cells(row)["search"] == "git grep -n x | sort"
    assert cell_problems(row) == []


@pytest.mark.parametrize(
    ("row", "want"),
    [
        ("code | c | MISSING | x | y | rule: r | places: a.py:1 | search: grep -n x a.py", []),
        ("code | c | MISSING | x | y | rule: r | places: a.py:1", ["no search cell"]),
        ("code | c | MISSING | x | y | rule: r | search: grep -n x a.py", ["no places cell"]),
        ("code | c | MISSING | x | y | places: a.py:1 | search: grep -n x", ["no rule cell"]),
        (
            "code | c | MISSING | x | y | rule:  | places:  | search: g",
            ["no rule cell", "no places cell"],
        ),
        ("code | c | MISSING | x | y", ["no rule cell", "no places cell", "no search cell"]),
        (
            "code | c | MISSING | x | y | rule: r | places: a.py, b.py:2 | search: g",
            ["a place that is not `<file>:<line or named part>`"],
        ),
        (
            "code | c | MISSING | x | y | rule: r | places: :4 | search: g",
            ["a place that is not `<file>:<line or named part>`"],
        ),
    ],
)
def test_cell_problems_name_each_missing_cell(row: str, want: list[str]) -> None:
    assert cell_problems(row) == want


@pytest.mark.parametrize(
    ("line", "want"),
    [
        ("audit/round1/test_scope_x.py::test_y high scope: the write lands" + CELLS, True),
        ("- audit/round1/test_scope_x.py::test_y low scope: the write lands", True),
        ("no-test: daedalus/t a.py:3 medium contract: field drift; reason: prose", True),
        ("Fix: guard the write", False),
        ("The high risk is the write.", False),
        ("Table diff: none", False),
        ("", False),
    ],
)
def test_reply_finding_admits_the_two_finding_line_shapes(line: str, want: bool) -> None:
    assert reply_finding(line) is want
