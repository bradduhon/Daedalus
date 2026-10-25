# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# spec 3.7, issue 76: each bypass class has its module, and each module judges a deny.
from __future__ import annotations

import ast
from pathlib import Path

import pytest

from tests.adversarial.corpus import CLASSES

HERE = Path(__file__).resolve().parent


def test_the_seven_classes_are_named() -> None:
    # issue 76: wrapper_options joined the six classes of spec 3.7.
    assert len(CLASSES) == len(set(CLASSES)) == 7


@pytest.mark.parametrize("name", CLASSES)
def test_each_class_has_a_module_with_denial_tests(name: str) -> None:
    module = HERE / f"test_{name}.py"
    assert module.is_file(), module
    tree = ast.parse(module.read_text(encoding="utf-8"))
    tests = [
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name.startswith("test_")
    ]
    assert tests, module
    calls = {
        node.func.id
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    }
    assert "assert_denied" in calls, module


def test_no_module_outside_the_classes() -> None:
    names = {path.stem.removeprefix("test_") for path in HERE.glob("test_*.py")}
    assert names - {"corpus_classes"} == set(CLASSES)
