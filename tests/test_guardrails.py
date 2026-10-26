# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0047, spec W3.3: every row of docs/guardrails.md names a file, name and test that exist.
from __future__ import annotations

import ast
import re
from functools import cache
from pathlib import Path, PurePosixPath
from typing import NamedTuple

import pytest
from lib.ledger import split_row

from tests.conftest import REPO_ROOT

GUARDRAILS = REPO_ROOT / "docs" / "guardrails.md"
# Plan 6 section 9.2, verbatim.
LEADING_PRINCIPLE = (
    "Daedalus does not let a guarantee rest on someone's word, memory or good behaviour. "
    "Each rule is built so the plugin enforces it and can show that it holds. A limit sits "
    "where it cannot be skipped. Each fact has one owner, and every other copy is computed "
    "from it. A claim waits until a mechanism stands behind it, and a check outranks an "
    "argument. Every change leaves a record. Where a rule is relaxed, the relaxation is "
    "written down with the condition that ends it."
)
HEADER = ["Principle", "Mechanism", "Test"]
_SEPARATOR = re.compile(r"\|(?:\s*:?-+:?\s*\|)+")
_REF = re.compile(r"`([^`]+)`")
# spec W3.3: rows for the controls built after Plan 6 wrote the table.
REQUIRED = frozenset(
    {
        "scripts/lib/locks.py::open_lock",
        'hooks/hooks.json::"onFailure": "block"',
        "scripts/lib/audit_proof.py::summary_anchor",
        "scripts/lib/train_runner.py::reaudit",
        "scripts/daedalus_confine.py::rule_set",
        # 0131: the controls Plan 9 built, each with its row.
        "scripts/handback_check.py::receipts_problem",
        "scripts/lib/plan_record.py::requirement_problem",
        "scripts/daedalus_doctor.py::check_tools",
        "scripts/checks/command_allowlist.py::R_MAP_OUT",
        "scripts/lib/audit_proof.py::exemption_problem",
        "scripts/lib/audit_proof.py::docs_problem",
        "scripts/checks/unit_writes.py::R_DOCS_ONLY",
        "scripts/checks/command_allowlist.py::TERRAFORM_FORMS",
        "scripts/lib/manifest.py::PrioritiesError",
        "scripts/checks/excluded_roots.py::judge",
        "scripts/checks/doc_outputs.py::judge",
    }
)


class Row(NamedTuple):
    line: int
    principle: str
    mechanisms: list[str]
    tests: list[str]


def table_rows(text: str) -> list[Row]:
    lines = text.splitlines()
    starts = [
        i for i, line in enumerate(lines) if line.startswith("|") and split_row(line) == HEADER
    ]
    assert len(starts) == 1, "docs/guardrails.md needs one Principle | Mechanism | Test table"
    start = starts[0]
    assert _SEPARATOR.fullmatch(lines[start + 1].strip()), "the header row lacks its separator"
    rows: list[Row] = []
    for number, line in enumerate(lines[start + 2 :], start + 3):
        if not line.startswith("|"):
            break
        cells = split_row(line)
        assert len(cells) == len(HEADER), f"line {number}: {len(cells)} cells"
        rows.append(Row(number, cells[0], _REF.findall(cells[1]), _REF.findall(cells[2])))
    return rows


@cache
def defined_names(path: Path) -> frozenset[str]:
    # Module and class scope only; a local inside a function is not a mechanism.
    names: set[str] = set()
    pending: list[ast.stmt] = list(ast.parse(path.read_text(encoding="utf-8")).body)
    while pending:
        node = pending.pop()
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            names.add(node.name)
        elif isinstance(node, ast.ClassDef):
            names.add(node.name)
            pending.extend(node.body)
        elif isinstance(node, ast.Assign | ast.AnnAssign):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                elts = target.elts if isinstance(target, ast.Tuple) else [target]
                names.update(e.id for e in elts if isinstance(e, ast.Name))
    return frozenset(names)


def ref_problem(ref: str, test: bool, root: Path = REPO_ROOT) -> str | None:
    rel, sep, name = ref.partition("::")
    pure = PurePosixPath(rel)
    if pure.is_absolute() or ".." in pure.parts or not rel:
        return f"{ref}: not a path relative to the plugin root"
    path = root / rel
    if not path.is_file():
        return f"{ref}: no file {rel}"
    if test:
        if not (sep and pure.parts[0] == "tests" and name.startswith("test_")):
            return f"{ref}: a test reference is tests/<file>.py::test_<name>"
        return None if name in defined_names(path) else f"{ref}: no test {name} in {rel}"
    if not sep:
        return None
    if not name:
        return f"{ref}: empty name after ::"
    if path.suffix == ".py":
        return None if name in defined_names(path) else f"{ref}: no name {name} in {rel}"
    return None if name in path.read_text(encoding="utf-8") else f"{ref}: no text {name} in {rel}"


def row_problems(row: Row, root: Path = REPO_ROOT) -> list[str]:
    where = f"docs/guardrails.md:{row.line}"
    problems = [f"{where}: no mechanism reference"] if not row.mechanisms else []
    if not row.tests:
        problems.append(f"{where}: no test reference")
    for ref, test in [(m, False) for m in row.mechanisms] + [(t, True) for t in row.tests]:
        problem = ref_problem(ref, test, root)
        if problem is not None:
            problems.append(f"{where}: {problem}")
    return problems


def _rows() -> list[Row]:
    return table_rows(GUARDRAILS.read_text(encoding="utf-8"))


def test_the_document_opens_with_the_leading_principle() -> None:
    text = GUARDRAILS.read_text(encoding="utf-8")
    paragraphs = [p.strip() for p in text.split("\n\n") if p.strip()]
    assert paragraphs[0].splitlines()[-1] == "# Guardrails"
    assert paragraphs[1] == LEADING_PRINCIPLE


def test_every_row_names_a_mechanism_and_a_test_that_exist() -> None:
    rows = _rows()
    assert rows, "the guardrails table has no rows"
    assert [problem for row in rows for problem in row_problems(row)] == []


def test_the_controls_built_since_plan_6_have_rows() -> None:
    named = {ref for row in _rows() for ref in row.mechanisms}
    assert sorted(REQUIRED - named) == []


def test_every_principle_is_unique() -> None:
    principles = [row.principle for row in _rows()]
    assert len(principles) == len(set(principles))


def test_a_missing_file_name_or_test_fails_its_row() -> None:
    row = Row(
        7,
        "probe",
        [
            "scripts/no_such_script.py",
            "scripts/lib/locks.py::no_such_name",
            "scripts/lib/locks.py::fd",
            "hooks/hooks.json::no such text",
            "../outside.py",
        ],
        [
            "tests/test_lock_fifo.py::test_no_such_test",
            "tests/test_lock_fifo.py",
            "scripts/lib/locks.py::open_lock",
        ],
    )
    assert row_problems(row) == [
        "docs/guardrails.md:7: scripts/no_such_script.py: no file scripts/no_such_script.py",
        "docs/guardrails.md:7: scripts/lib/locks.py::no_such_name: no name no_such_name in "
        "scripts/lib/locks.py",
        "docs/guardrails.md:7: scripts/lib/locks.py::fd: no name fd in scripts/lib/locks.py",
        "docs/guardrails.md:7: hooks/hooks.json::no such text: no text no such text in "
        "hooks/hooks.json",
        "docs/guardrails.md:7: ../outside.py: not a path relative to the plugin root",
        "docs/guardrails.md:7: tests/test_lock_fifo.py::test_no_such_test: no test "
        "test_no_such_test in tests/test_lock_fifo.py",
        "docs/guardrails.md:7: tests/test_lock_fifo.py: a test reference is "
        "tests/<file>.py::test_<name>",
        "docs/guardrails.md:7: scripts/lib/locks.py::open_lock: a test reference is "
        "tests/<file>.py::test_<name>",
    ]


def test_a_row_without_references_fails() -> None:
    assert row_problems(Row(3, "probe", [], [])) == [
        "docs/guardrails.md:3: no mechanism reference",
        "docs/guardrails.md:3: no test reference",
    ]


def test_the_parser_reads_a_table_and_refuses_a_short_row() -> None:
    lock = "scripts/lib/locks.py::open_lock"
    fifo = "tests/test_lock_fifo.py::test_open_lock_refuses_a_fifo"
    head = "| Principle | Mechanism | Test |\n|---|---|---|\n"
    text = f"{head}| p | words `{lock}` | `{fifo}` |\n\nafter\n"
    assert table_rows(text) == [Row(3, "p", [lock], [fifo])]
    with pytest.raises(AssertionError, match="line 3: 2 cells"):
        table_rows(text.replace("| p | ", "| "))


def test_the_readme_links_the_document() -> None:
    readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    assert "](docs/guardrails.md)" in readme
