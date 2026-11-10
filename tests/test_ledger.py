# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest
from lib.config import Config
from lib.ledger import (
    TABLE_SCHEME,
    LedgerError,
    ResolvedLedger,
    format_entry,
    id_pattern,
    next_id,
    read_sequence,
    resolve_ledger,
    supersedes_problem,
)

from tests.conftest import REPO_ROOT

FIX = REPO_ROOT / "tests" / "fixtures" / "ledgers"


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    subprocess.run(["git", "init", "-q", "-b", "main"], cwd=tmp_path, check=True)
    return tmp_path


def _name(repo: Path, filename: str | None, **docs: object) -> None:
    # 0245, 0247: the manifest's docs group names the decisions file, or names none.
    body = {"docs": {"decisions_filename": filename, **docs}}
    (repo / "service-manifest.json").write_text(json.dumps(body), encoding="utf-8")


def test_a_named_file_in_the_local_docs_folder(repo: Path) -> None:
    # 0245: local_docs_folder wins over the project's own docs folder.
    _name(repo, "decision-log.md")
    led = resolve_ledger(str(repo), Config(charter_root=repo / "charter"))
    assert led is not None and led.path == repo / "charter" / "decision-log.md"
    assert led.origin == "manifest"


def test_a_named_file_in_the_project_docs_folder(repo: Path) -> None:
    _name(repo, "decisions.md", folder="notes")
    led = resolve_ledger(str(repo), Config())
    assert led is not None and led.path == repo / "notes" / "decisions.md"


def test_a_conventional_file_is_never_found_without_a_name(repo: Path) -> None:
    # 0247: no name search; a docs/decisions.md the project never named is never used.
    (repo / "docs").mkdir()
    shutil.copy(FIX / "table.md", repo / "docs" / "decisions.md")
    shutil.copy(FIX / "heading.md", repo / "LEDGER.md")
    assert resolve_ledger(str(repo), Config()) is None
    _name(repo, None)
    assert resolve_ledger(str(repo), Config()) is None


def test_the_layout_is_read_from_a_table_file(repo: Path) -> None:
    (repo / "docs").mkdir()
    shutil.copy(FIX / "table.md", repo / "docs" / "decisions.md")
    _name(repo, "decisions.md")
    led = resolve_ledger(str(repo), Config())
    assert led is not None and led.format == "markdown-table-row"
    assert led.id_scheme == TABLE_SCHEME and led.sequence_source == "last-row-id"
    assert read_sequence(led) == 2


def test_the_layout_is_read_from_a_headings_file_with_frontmatter(repo: Path) -> None:
    (repo / "docs").mkdir()
    shutil.copy(FIX / "heading.md", repo / "docs" / "LEDGER.md")
    _name(repo, "LEDGER.md")
    led = resolve_ledger(str(repo), Config())
    assert led is not None and led.format == "heading-entry"
    assert led.sequence_source == "frontmatter:sequence_id" and read_sequence(led) == 7


def test_a_named_file_not_yet_written_takes_the_default_table(repo: Path) -> None:
    # 0247: the file is created on its first decision, so its sequence starts at 0.
    _name(repo, "decisions.md")
    led = resolve_ledger(str(repo), Config())
    assert led is not None and not led.path.exists()
    assert led.format == "markdown-table-row" and led.id_scheme == TABLE_SCHEME
    assert read_sequence(led) == 0


def test_nothing_named_is_none(repo: Path) -> None:
    assert resolve_ledger(str(repo), Config()) is None


def test_format_entry_table_row_and_heading(repo: Path) -> None:
    table = _led(repo / "t.md", "markdown-table-row", "{seq:04d}-{repo}-{type}", "last-row-id")
    assert next_id(table, 3, "DAE", "PLT") == "0003-DAE-PLT"
    row = format_entry(table, 3, "DAE", "PLT", "2026-10-14", "Ruling text | None | None")
    assert row == "| 0003-DAE-PLT | 2026-10-14 | Ruling text | None | None |\n"
    heading = _led(repo / "h.md", "heading-entry", "{seq}", "last-row-id")
    assert (
        format_entry(heading, 8, "BO", "PLT", "2026-10-14T00:00:00Z", "Eight.")
        == "\n\n## Entry 8 - 2026-10-14T00:00:00Z\n\nEight.\n"
    )


def _led(path: Path, fmt: str, scheme: str, source: str) -> ResolvedLedger:
    return ResolvedLedger(path, fmt, scheme, source, "manifest")


@pytest.mark.parametrize("body,date", [("line1\nline2 | x", "2026-10-14"), ("a", "2026\r-10")])
def test_table_row_rejects_newlines(tmp_path: Path, body: str, date: str) -> None:
    led = _led(tmp_path / "t.md", "markdown-table-row", "{seq}", "last-row-id")
    with pytest.raises(LedgerError, match="Next:"):
        format_entry(led, 1, "BO", "PLT", date, body)


def test_second_table_does_not_change_sequence(tmp_path: Path) -> None:
    text = (FIX / "table.md").read_text(encoding="utf-8")
    text += "\n## Appendix\n\n| Name | Value |\n|---|---|\n| 0099-ZZZ | x |\n"
    (tmp_path / "d.md").write_text(text, encoding="utf-8")
    led = _led(tmp_path / "d.md", "markdown-table-row", "{seq}", "last-row-id")
    assert read_sequence(led) == 2


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("| Id | Date |\n|---|---|\n| 0003-A | d |\n\n| 0099-B | d |\n", 3),
        # issue 186: a short Id index above the main log; the log's highest id is the sequence.
        (
            "| Id | Name |\n|---|---|\n| 0001-A | first |\n\n"
            "| Id | Date |\n|---|---|\n| 0001-A | d |\n| 0002-A | d |\n| 0009-A | d |\n",
            9,
        ),
    ],
)
def test_table_rows_stop_at_first_non_pipe_line(tmp_path: Path, text: str, expected: int) -> None:
    (tmp_path / "d.md").write_text(text, encoding="utf-8")
    led = _led(tmp_path / "d.md", "markdown-table-row", "{seq}", "last-row-id")
    assert read_sequence(led) == expected


@pytest.mark.parametrize("header", ["|Id|Date|", "| ID | Date |"])
def test_compact_and_upper_id_header_inferred_as_table(repo: Path, header: str) -> None:
    (repo / "docs").mkdir()
    (repo / "docs" / "LEDGER.md").write_text(f"{header}\n|---|---|\n|0005-A|d|\n", encoding="utf-8")
    _name(repo, "LEDGER.md")
    led = resolve_ledger(str(repo), Config())
    assert led is not None and led.format == "markdown-table-row"
    assert read_sequence(led) == 5


def test_horizontal_rules_are_not_frontmatter(repo: Path) -> None:
    text = "# Ledger\n\n---\nsequence_id: 99\n---\n\n## Entry 4 - d\n\nFour.\n"
    (repo / "docs").mkdir()
    (repo / "docs" / "LEDGER.md").write_text(text, encoding="utf-8")
    _name(repo, "LEDGER.md")
    led = resolve_ledger(str(repo), Config())
    assert led is not None and led.sequence_source == "last-row-id"
    assert read_sequence(led) == 4
    with pytest.raises(LedgerError, match="Next:"):
        read_sequence(
            _led(repo / "docs" / "LEDGER.md", "heading-entry", "{seq}", "frontmatter:sequence_id")
        )


def test_frontmatter_rejects_non_ascii_digits(tmp_path: Path) -> None:
    (tmp_path / "h.md").write_text("---\nsequence_id: ²\n---\n", encoding="utf-8")
    with pytest.raises(LedgerError, match="Next:"):
        read_sequence(_led(tmp_path / "h.md", "heading-entry", "{seq}", "frontmatter:sequence_id"))


@pytest.mark.parametrize("scheme", ["{seq[0]}", "{nope}", "{seq.real.x}"])
def test_bad_id_scheme_raises_ledger_error(tmp_path: Path, scheme: str) -> None:
    with pytest.raises(LedgerError, match="Next:"):
        next_id(_led(tmp_path / "t.md", "markdown-table-row", scheme, "last-row-id"), 1, "B", "P")


@pytest.mark.parametrize(
    "docs",
    [
        {"decisions_filename": "sub/x.md"},
        {"decisions_filename": ""},
        {"decisions_filename": "x.md", "git_branch": "two words"},
        {"ledger": {"path": "x.md"}},
    ],
)
def test_a_malformed_docs_group_raises(repo: Path, docs: object) -> None:
    (repo / "service-manifest.json").write_text(json.dumps({"docs": docs}), encoding="utf-8")
    with pytest.raises(LedgerError, match="Next:"):
        resolve_ledger(str(repo), Config())


@pytest.mark.parametrize(("extra", "expected"), [({}, None), ({"git_branch": "main"}, "main")])
def test_the_docs_git_branch_is_read(
    repo: Path, extra: dict[str, str], expected: str | None
) -> None:
    # issue 186: the manifest carries the optional branch through to the resolved file.
    _name(repo, "x.md", **extra)
    led = resolve_ledger(str(repo), Config())
    assert led is not None and led.branch == expected


def test_a_branch_pin_beside_a_local_docs_folder_is_refused(repo: Path) -> None:
    # issue 186: a run branches the local docs folder, so the pin could never hold.
    _name(repo, "x.md", git_branch="main")
    with pytest.raises(LedgerError, match="Next: remove docs.git_branch"):
        resolve_ledger(str(repo), Config(charter_root=repo / "charter"))


def test_invalid_manifest_json_raises(repo: Path) -> None:
    (repo / "service-manifest.json").write_text("{ not json", encoding="utf-8")
    with pytest.raises(LedgerError, match="Next:"):
        resolve_ledger(str(repo), Config())


def test_lone_table_with_no_rows_is_sequence_zero(tmp_path: Path) -> None:
    (tmp_path / "t.md").write_text("| Id | Date |\n|---|---|\n", encoding="utf-8")
    led = _led(tmp_path / "t.md", "markdown-table-row", "{seq}", "last-row-id")
    assert read_sequence(led) == 0


def test_empty_table_above_populated_table_raises(tmp_path: Path) -> None:
    # R2-1: an empty Id table above the real one fails closed.
    text = "| Id | Date |\n|---|---|\n\n" + (FIX / "table.md").read_text(encoding="utf-8")
    (tmp_path / "t.md").write_text(text, encoding="utf-8")
    with pytest.raises(LedgerError, match="Next:"):
        read_sequence(_led(tmp_path / "t.md", "markdown-table-row", "{seq}", "last-row-id"))


def test_table_id_without_leading_integer_raises(tmp_path: Path) -> None:
    (tmp_path / "t.md").write_text("| Id | Date |\n|---|---|\n| ABC | d |\n", encoding="utf-8")
    with pytest.raises(LedgerError, match="Next:"):
        read_sequence(_led(tmp_path / "t.md", "markdown-table-row", "{seq}", "last-row-id"))


def test_heading_last_row_id(tmp_path: Path) -> None:
    shutil.copy(FIX / "heading.md", tmp_path / "h.md")
    assert read_sequence(_led(tmp_path / "h.md", "heading-entry", "{seq}", "last-row-id")) == 7
    (tmp_path / "e.md").write_text("# Ledger\n", encoding="utf-8")
    with pytest.raises(LedgerError, match="Next:"):
        read_sequence(_led(tmp_path / "e.md", "heading-entry", "{seq}", "last-row-id"))


def test_read_sequence_unknown_source_raises(tmp_path: Path) -> None:
    shutil.copy(FIX / "heading.md", tmp_path / "h.md")
    with pytest.raises(LedgerError, match="Next:"):
        read_sequence(_led(tmp_path / "h.md", "heading-entry", "{seq}", "max-id"))


@pytest.mark.parametrize(
    "text,expected",
    [
        (
            "| Column | Meaning |\n|---|---|\n| Id | row id |\n| Date | when |\n\n"
            "| Id | Date | Ruling |\n|---|---|---|\n| 0007-DAE-PLT | d | r |\n",
            7,
        ),
        (
            "| Field | Type |\n|---|---|\n| id | int |\n| 2 | example |\n\n"
            "| Id | Date |\n|---|---|\n| 0041-A | d |\n",
            41,
        ),
    ],
)
def test_id_cell_in_body_row_is_not_a_header(repo: Path, text: str, expected: int) -> None:
    (repo / "docs").mkdir()
    (repo / "docs" / "LEDGER.md").write_text(text, encoding="utf-8")
    _name(repo, "LEDGER.md")
    led = resolve_ledger(str(repo), Config())
    assert led is not None and led.format == "markdown-table-row"
    assert read_sequence(led) == expected


@pytest.mark.parametrize("body", ["one two", "one\x85two", "one\x0ctwo", "one\x1etwo"])
def test_table_row_rejects_unicode_line_breaks(tmp_path: Path, body: str) -> None:
    led = _led(tmp_path / "t.md", "markdown-table-row", "{seq}", "last-row-id")
    with pytest.raises(LedgerError, match="Next:"):
        format_entry(led, 1, "BO", "PLT", "2026-10-14", body)
    with pytest.raises(LedgerError, match="Next:"):
        format_entry(led, 1, "BO", "PLT", body, "ok")


def test_table_row_plain_body_still_formats(tmp_path: Path) -> None:
    led = _led(tmp_path / "t.md", "markdown-table-row", "{seq}", "last-row-id")
    assert format_entry(led, 1, "BO", "PLT", "d", "plain") == "| 1 | d | plain |\n"


def test_sequence_reads_the_id_column(tmp_path: Path) -> None:
    text = "| Date | Id |\n|---|---|\n| d | 0003-A |\n| d | 0004-A |\n"
    (tmp_path / "t.md").write_text(text, encoding="utf-8")
    assert read_sequence(_led(tmp_path / "t.md", "markdown-table-row", "{seq}", "last-row-id")) == 4


def test_bom_does_not_hide_frontmatter(repo: Path) -> None:
    (repo / "docs").mkdir()
    (repo / "docs" / "LEDGER.md").write_text("﻿---\nsequence_id: 12\n---\n", encoding="utf-8")
    _name(repo, "LEDGER.md")
    led = resolve_ledger(str(repo), Config())
    assert led is not None and led.sequence_source == "frontmatter:sequence_id"
    assert read_sequence(led) == 12


def test_separator_row_below_the_first_is_not_an_entry(tmp_path: Path) -> None:
    text = "| Id | Date |\n|---|---|\n| 0003-A | d |\n|---|---|\n"
    (tmp_path / "d.md").write_text(text, encoding="utf-8")
    assert read_sequence(_led(tmp_path / "d.md", "markdown-table-row", "{seq}", "last-row-id")) == 3


def test_table_row_rejects_line_break_in_entry_id(tmp_path: Path) -> None:
    led = _led(tmp_path / "t.md", "markdown-table-row", "{seq}-{repo}", "last-row-id")
    with pytest.raises(LedgerError, match="Next:"):
        format_entry(led, 1, "A\nB", "PLT", "2026-10-14", "body")


def test_supersedes_ids_follow_the_declared_scheme() -> None:
    # 0090: an id matches the ledger's own scheme, not a fixed shape.
    assert supersedes_problem("Supersedes: 0012.", "{seq:04d}") is None
    assert supersedes_problem("Supersedes: 0012-DAE-PLT.", "{seq:04d}") is not None
    with pytest.raises(LedgerError, match="Next:"):
        id_pattern("{seq}-{owner}")


def test_last_row_id_keeps_an_escaped_pipe_in_its_cell(tmp_path: Path) -> None:
    # W1.3: the sequence reader and table_cells share split_row, escaped pipes included.
    text = "| Note \\| x | Id |\n|---|---|\n| a \\| b | 0007-A |\n"
    (tmp_path / "t.md").write_text(text, encoding="utf-8")
    assert read_sequence(_led(tmp_path / "t.md", "markdown-table-row", "{seq}", "last-row-id")) == 7


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("---\nsequence_id: 9\nnot a pair\n---\n", 9),
        ("---\n  sequence_id: 3\nsequence_id: 9\n---\n", 9),
        ("---\n# comment\n- item\nsequence_id: 9\n---\n", 9),
    ],
)
def test_frontmatter_sequence_uses_the_shared_lenient_reader(
    tmp_path: Path, text: str, expected: int
) -> None:
    # W1.3: malformed, nested, comment and list lines are skipped, never raised.
    (tmp_path / "h.md").write_text(text, encoding="utf-8")
    led = _led(tmp_path / "h.md", "heading-entry", "{seq}", "frontmatter:sequence_id")
    assert read_sequence(led) == expected


def test_unclosed_frontmatter_reads_as_absent(tmp_path: Path) -> None:
    (tmp_path / "h.md").write_text("---\nsequence_id: 9\n", encoding="utf-8")
    led = _led(tmp_path / "h.md", "heading-entry", "{seq}", "frontmatter:sequence_id")
    with pytest.raises(LedgerError, match="missing or not an integer"):
        read_sequence(led)
