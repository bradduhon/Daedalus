# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# spec 3.7, issue 76: each bypass class has its module, and each module judges a deny.
from __future__ import annotations

import ast
from pathlib import Path

import pytest

from tests.adversarial.corpus import CLASSES

HERE = Path(__file__).resolve().parent


def test_each_bypass_class_is_named_once() -> None:
    # issue 76, 204, 116, 121: wrapper_options, operand_grammar, hidden_bodies and chain_state
    # joined spec 3.7's six; 0229 adds the measurement rows.
    assert len(CLASSES) == len(set(CLASSES)) == 11


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
    # 228 S2: admit_corpus runs every class's rows through admit; it is no class of its own.
    # line 70: mutations mutates every class's rows; it is no class of its own either.
    assert names - {"corpus_classes", "admit_corpus", "mutations"} == set(CLASSES)
