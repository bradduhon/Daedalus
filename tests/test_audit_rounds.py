# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0109, spec 3.4: the finding list shape of pin C3 -> C1 and the round number; 0133 retired
# the stall rule, which tests/test_operator_gates.py checks is gone.
from __future__ import annotations

import pytest
from lib.audit_rounds import SEVERITIES, Finding, FindingsError, next_round, parse

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
