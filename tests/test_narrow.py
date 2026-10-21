# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# W1.3: the JSON narrowing readers the runner, the definition loader and the gates share.
from __future__ import annotations

import pytest
from lib import narrow

BLOCK: dict[str, object] = {
    "name": "train",
    "count": 3,
    "flag": True,
    "nested": {1: "one", "two": 2},
    "items": [{"a": 1}, "skip", {2: "b"}, 4],
    "words": ["a", 1, "b", None],
}


def test_text_reads_only_strings() -> None:
    assert narrow.text(BLOCK, "name") == "train"
    assert narrow.text(BLOCK, "count") == ""
    assert narrow.text(BLOCK, "absent") == ""


def test_obj_coerces_dict_keys_with_str() -> None:
    assert narrow.obj(BLOCK, "nested") == {"1": "one", "two": 2}
    assert narrow.obj(BLOCK, "name") == {}
    assert narrow.obj(BLOCK, "absent") == {}


def test_objects_keeps_only_dicts_and_coerces_their_keys() -> None:
    assert narrow.objects(BLOCK, "items") == [{"a": 1}, {"2": "b"}]
    assert narrow.objects(BLOCK, "nested") == []
    assert narrow.objects(BLOCK, "absent") == []


def test_strings_keeps_only_strings_of_a_list() -> None:
    assert narrow.strings(BLOCK["words"]) == ["a", "b"]
    assert narrow.strings("ab") == []
    assert narrow.strings(None) == []


@pytest.mark.parametrize(
    ("key", "expected"),
    [("count", 3), ("flag", 7), ("name", 7), ("absent", 7)],
)
def test_integer_refuses_bool_and_non_ints(key: str, expected: int) -> None:
    assert narrow.integer(BLOCK, key, 7) == expected


def test_runner_and_definition_share_the_readers() -> None:
    from lib import dispatch_binding, train_definition, train_runner

    assert train_runner._text is narrow.text and train_runner._int is narrow.integer
    assert train_runner._obj is narrow.obj and train_runner._objects is narrow.objects
    assert train_runner._strings is narrow.strings
    assert train_definition._text is narrow.text and train_definition._obj is narrow.obj
    assert train_definition._objects is narrow.objects
    assert train_definition._texts is narrow.strings
    assert dispatch_binding.integer is narrow.integer
