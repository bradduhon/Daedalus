# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0109, spec 3.4 and 3.7: the stall rule table and the finding list shape of pin C3 -> C1.
from __future__ import annotations

import pytest
from lib.audit_rounds import SEVERITIES, Finding, FindingsError, judge, next_round, parse

LOW = "low"


def _set(*keys: str, severity: str = LOW) -> dict[str, str]:
    return dict.fromkeys(keys, severity)


@pytest.mark.parametrize(
    ("previous", "current", "used", "budget", "word"),
    [
        # spec 3.7: (A,B,C) then (A,B) continues.
        (_set("A", "B", "C"), _set("A", "B"), 2, 5, "continue round=3 budget_left=3"),
        # spec 3.7: (A,B) then (A,B) escalates on the recurring finding.
        (_set("A", "B"), _set("A", "B"), 2, 5, "escalate reason=recurring key=A"),
        # spec 3.7: (A,B) then (C high) escalates on the new high.
        (_set("A", "B"), {"C": "high"}, 2, 5, "escalate reason=new-high key=C"),
        # spec 3.7: budget exhaustion escalates, even on a shrinking set.
        (_set("A", "B", "C"), _set("A", "B"), 5, 5, "escalate reason=budget"),
        (_set("A", "B", "C"), _set("A"), 7, 5, "escalate reason=budget"),
        # A first round has nothing to compare: it continues inside the budget.
        (None, {"A": "critical", "B": "high"}, 1, 5, "continue round=2 budget_left=4"),
        (None, _set("A"), 1, 1, "escalate reason=budget"),
        # A key that rises to high counts as a new high; critical over high does not.
        (_set("A", "B"), {"A": "high"}, 2, 5, "escalate reason=new-high key=A"),
        ({"A": "high", "B": LOW}, {"A": "critical"}, 2, 5, "continue round=3 budget_left=3"),
        # A set that grows, or swaps one key while one recurs, does not shrink.
        (_set("A", "B"), _set("A", "B", "C"), 2, 5, "escalate reason=recurring key=A"),
        (_set("A", "B"), _set("B", "D"), 2, 5, "escalate reason=recurring key=B"),
        # The new high wins over the recurring key and the budget.
        (_set("A"), {"A": LOW, "Z": "critical"}, 5, 5, "escalate reason=new-high key=Z"),
        # The recurring key wins over the budget.
        (_set("A"), _set("A"), 5, 5, "escalate reason=recurring key=A"),
        # Every earlier finding fixed and new low ones found: nothing recurs and no new high.
        (_set("A", "B"), _set("C"), 2, 5, "continue round=3 budget_left=3"),
    ],
)
def test_stall_rule_table(
    previous: dict[str, str] | None, current: dict[str, str], used: int, budget: int, word: str
) -> None:
    assert judge(previous, current, used, budget) == word


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
