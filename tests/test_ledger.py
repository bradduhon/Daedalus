# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest
from lib.config import Config, LedgerDecl
from lib.ledger import (
    LedgerError,
    ResolvedLedger,
    format_entry,
    next_id,
    read_sequence,
    resolve_ledger,
)

from tests.conftest import REPO_ROOT

FIX = REPO_ROOT / "tests" / "fixtures" / "ledgers"


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    subprocess.run(["git", "init", "-q", "-b", "main"], cwd=tmp_path, check=True)
    return tmp_path


def test_config_block_resolves_placeholders(repo: Path) -> None:
    cfg = Config(
        charter_root=repo / "charter",
        ledger=LedgerDecl(
            Path("<charter_root>/decision-log.md"),
            "markdown-table-row",
            "{seq:04d}-{repo}-{type}",
            "last-row-id",
        ),
    )
    led = resolve_ledger(str(repo), cfg)
    assert (
        led is not None
        and led.path == repo / "charter" / "decision-log.md"
        and led.origin == "config"
    )


def test_manifest_override_wins(repo: Path) -> None:
    shutil.copy(FIX / "manifest-override.json", repo / "service-manifest.json")
    cfg = Config(ledger=LedgerDecl(Path("/elsewhere.md"), "heading-entry", "{seq}", "last-row-id"))
    led = resolve_ledger(str(repo), cfg)
    assert (
        led is not None and led.origin == "manifest" and led.path == repo / "docs" / "decisions.md"
    )
    assert led.id_scheme == "{seq:04d}-X-{type}"


def test_probe_finds_docs_decisions_table(repo: Path) -> None:
    (repo / "docs").mkdir()
    shutil.copy(FIX / "table.md", repo / "docs" / "decisions.md")
    led = resolve_ledger(str(repo), Config())
    assert led is not None and led.origin == "probe" and led.format == "markdown-table-row"
    assert led.sequence_source == "last-row-id"


def test_probe_infers_heading_frontmatter(repo: Path) -> None:
    shutil.copy(FIX / "heading.md", repo / "LEDGER.md")
    led = resolve_ledger(str(repo), Config())
    assert (
        led is not None
        and led.format == "heading-entry"
        and led.sequence_source == "frontmatter:sequence_id"
    )


def test_nothing_declared_nothing_found_is_none(repo: Path) -> None:
    assert resolve_ledger(str(repo), Config()) is None


def test_read_sequence_table_and_heading(repo: Path) -> None:
    (repo / "docs").mkdir()
    shutil.copy(FIX / "table.md", repo / "docs" / "decisions.md")
    shutil.copy(FIX / "heading.md", repo / "LEDGER.md")
    table = resolve_ledger(str(repo), Config())
    assert table is not None and read_sequence(table) == 2
    heading = resolve_ledger(
        str(repo),
        Config(
            ledger=LedgerDecl(
                repo / "LEDGER.md", "heading-entry", "{seq}", "frontmatter:sequence_id"
            )
        ),
    )
    assert heading is not None and read_sequence(heading) == 7


def test_read_sequence_errors_carry_next(repo: Path) -> None:
    led = resolve_ledger(
        str(repo),
        Config(
            ledger=LedgerDecl(repo / "missing.md", "markdown-table-row", "{seq}", "last-row-id")
        ),
    )
    assert led is not None
    with pytest.raises(LedgerError) as info:
        read_sequence(led)
    assert "Next:" in str(info.value)


def test_format_entry_table_row_and_heading(repo: Path) -> None:
    table = resolve_ledger(
        str(repo),
        Config(
            ledger=LedgerDecl(
                repo / "t.md", "markdown-table-row", "{seq:04d}-{repo}-{type}", "last-row-id"
            )
        ),
    )
    assert table is not None
    assert next_id(table, 3, "DAE", "PLT") == "0003-DAE-PLT"
    row = format_entry(table, 3, "DAE", "PLT", "2026-10-14", "Ruling text | None | None")
    assert row == "| 0003-DAE-PLT | 2026-10-14 | Ruling text | None | None |\n"
    heading = resolve_ledger(
        str(repo), Config(ledger=LedgerDecl(repo / "h.md", "heading-entry", "{seq}", "last-row-id"))
    )
    assert heading is not None
    assert (
        format_entry(heading, 8, "BO", "PLT", "2026-10-14T00:00:00Z", "Eight.")
        == "\n\n## Entry 8 - 2026-10-14T00:00:00Z\n\nEight.\n"
    )


def _led(path: Path, fmt: str, scheme: str, source: str) -> ResolvedLedger:
    return ResolvedLedger(path, fmt, scheme, source, "config")


def _write_manifest(repo: Path, ledger: object) -> None:
    payload = {"manifest_version": 1, "service_name": "x", "ledger": ledger}
    (repo / "service-manifest.json").write_text(json.dumps(payload), encoding="utf-8")


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


def test_table_rows_stop_at_first_non_pipe_line(tmp_path: Path) -> None:
    text = "| Id | Date |\n|---|---|\n| 0003-A | d |\n\n| 0099-B | d |\n"
    (tmp_path / "d.md").write_text(text, encoding="utf-8")
    assert read_sequence(_led(tmp_path / "d.md", "markdown-table-row", "{seq}", "last-row-id")) == 3


@pytest.mark.parametrize("header", ["|Id|Date|", "| ID | Date |"])
def test_compact_and_upper_id_header_inferred_as_table(repo: Path, header: str) -> None:
    (repo / "LEDGER.md").write_text(f"{header}\n|---|---|\n|0005-A|d|\n", encoding="utf-8")
    led = resolve_ledger(str(repo), Config())
    assert led is not None and led.format == "markdown-table-row"
    assert read_sequence(led) == 5


def test_horizontal_rules_are_not_frontmatter(repo: Path) -> None:
    text = "# Ledger\n\n---\nsequence_id: 99\n---\n\n## Entry 4 - d\n\nFour.\n"
    (repo / "LEDGER.md").write_text(text, encoding="utf-8")
    led = resolve_ledger(str(repo), Config())
    assert led is not None and led.sequence_source == "last-row-id"
    assert read_sequence(led) == 4
    with pytest.raises(LedgerError, match="Next:"):
        read_sequence(_led(repo / "LEDGER.md", "heading-entry", "{seq}", "frontmatter:sequence_id"))


def test_frontmatter_rejects_non_ascii_digits(tmp_path: Path) -> None:
    (tmp_path / "h.md").write_text("---\nsequence_id: ²\n---\n", encoding="utf-8")
    with pytest.raises(LedgerError, match="Next:"):
        read_sequence(_led(tmp_path / "h.md", "heading-entry", "{seq}", "frontmatter:sequence_id"))


@pytest.mark.parametrize("scheme", ["{seq[0]}", "{nope}", "{seq.real.x}"])
def test_bad_id_scheme_raises_ledger_error(tmp_path: Path, scheme: str) -> None:
    with pytest.raises(LedgerError, match="Next:"):
        next_id(_led(tmp_path / "t.md", "markdown-table-row", scheme, "last-row-id"), 1, "B", "P")


@pytest.mark.parametrize(
    "ledger",
    [
        "not-an-object",
        {"path": "x.md", "format": "markdown-table-row", "id_scheme": "{seq}"},
        {"path": "", "format": "markdown-table-row", "id_scheme": "{seq}", "sequence_source": "x"},
        {"path": "x.md", "format": "csv", "id_scheme": "{seq}", "sequence_source": "last-row-id"},
        {"path": "x.md", "format": "heading-entry", "id_scheme": "{seq}", "sequence_source": "max"},
        {
            "path": "x.md",
            "format": "heading-entry",
            "id_scheme": "{seq}",
            "sequence_source": "frontmatter:",
        },
    ],
)
def test_malformed_manifest_block_raises(repo: Path, ledger: object) -> None:
    _write_manifest(repo, ledger)
    with pytest.raises(LedgerError, match="Next:"):
        resolve_ledger(str(repo), Config())


def test_invalid_manifest_json_raises(repo: Path) -> None:
    (repo / "service-manifest.json").write_text("{ not json", encoding="utf-8")
    with pytest.raises(LedgerError, match="Next:"):
        resolve_ledger(str(repo), Config())


def test_config_unknown_sequence_source_raises(repo: Path) -> None:
    cfg = Config(ledger=LedgerDecl(repo / "t.md", "markdown-table-row", "{seq}", "max-id"))
    with pytest.raises(LedgerError, match="Next:"):
        resolve_ledger(str(repo), cfg)


def test_missing_charter_root_raises(repo: Path) -> None:
    decl = LedgerDecl(
        Path("<charter_root>/decision-log.md"), "markdown-table-row", "{seq}", "last-row-id"
    )
    with pytest.raises(LedgerError, match="Next:"):
        resolve_ledger(str(repo), Config(ledger=decl))


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
    (repo / "LEDGER.md").write_text(text, encoding="utf-8")
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
    (repo / "LEDGER.md").write_text("﻿---\nsequence_id: 12\n---\n", encoding="utf-8")
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
