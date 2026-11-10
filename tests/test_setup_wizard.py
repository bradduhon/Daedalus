# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0242: the settings wizard's tables, overlaps, script forms, examples and skill.
from __future__ import annotations

from collections import Counter

from lib.project_keys import GROUPS, KEY_ROWS, OVERLAPS, reference_keys

from tests.conftest import REPO_ROOT


def test_each_overlap_answer_rests_on_the_line_it_cites() -> None:
    # 0242: a moved or changed line fails here, so the answer is reread before it ships.
    assert [o.id for o in OVERLAPS] == ["ledger", "literacy", "operator"]
    for overlap in OVERLAPS:
        for path, line, words in overlap.sources:
            text = (REPO_ROOT / path).read_text(encoding="utf-8").splitlines()[line - 1]
            assert words in text, (overlap.id, path, line)


def test_overlaps_with_no_deciding_code_say_so_in_future_tense() -> None:
    literacy = next(o for o in OVERLAPS if o.id == "literacy")
    assert "nothing reads it yet" in literacy.text and "will apply" in literacy.text


def test_every_key_sits_in_exactly_one_group_of_its_file() -> None:
    placed = Counter((group.file, key) for group in GROUPS for key in group.keys)
    assert sorted(k for k, n in placed.items() if n > 1) == []
    assert sorted(set(reference_keys()) - set(placed)) == []
    assert sorted(set(placed) - set(reference_keys())) == []


def test_groups_have_unique_ids_orders_and_plain_titles() -> None:
    assert len({g.id for g in GROUPS}) == len(GROUPS)
    assert sorted(g.order for g in GROUPS) == list(range(1, len(GROUPS) + 1))
    for group in GROUPS:
        assert group.title and "\n" not in group.title and not set(group.title) & set("`_/"), group


def test_day_one_keys_are_group_keys_with_readers() -> None:
    for group in GROUPS:
        assert set(group.day_one) <= set(group.keys), group.id
        for key in group.day_one:
            assert KEY_ROWS[(group.file, key)].readers, (group.id, key)
    day_one = [key for group in GROUPS for key in group.day_one]
    assert day_one == [
        "stack.unit_test_cmd",
        "stack.typecheck_cmd",
        "stack.lint_cmd",
        "stack.package_manager",
        "features.secrets_scan",
        "features.ledger",
        "features.terraform_tools",
        "docs.literacy",
    ]
