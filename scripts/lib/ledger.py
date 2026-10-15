# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from lib.audit import project_root
from lib.config import LEDGER_FIELDS, LEDGER_FORMATS, Config, LedgerDecl

# 0004: convention probe order, tried under repo_root then charter_root.
PROBE_NAMES = ("decision-log.md", "docs/decisions.md", "LEDGER.md")
TABLE_SCHEME = "{seq:04d}-{repo}-{type}"
HEADING_SCHEME = "{seq}"
_SEPARATOR = re.compile(r"^\|(\s*:?-+:?\s*\|)+\s*$")
_ENTRY_HEADING = re.compile(r"^## Entry ([0-9]+)\b")
_LEADING_INT = re.compile(r"[0-9]+")
_DIGITS = re.compile(r"[0-9]+")
_FRONTMATTER_SOURCE = re.compile(r"frontmatter:\S+")


class LedgerError(ValueError):
    pass


@dataclass(frozen=True)
class ResolvedLedger:
    path: Path
    format: str
    id_scheme: str
    sequence_source: str
    origin: str


def _resolve_path(raw: str, repo_root: Path, charter_root: Path | None) -> Path:
    if "<charter_root>" in raw:
        if charter_root is None:
            raise LedgerError(
                f"ledger path {raw} uses <charter_root> but no charter_root is set. "
                "Next: set charter_root in .claude/daedalus/config.json."
            )
        raw = raw.replace("<charter_root>", str(charter_root))
    path = Path(raw.replace("<repo_root>", str(repo_root)))
    # 0004: a relative ledger path is read against repo_root, never the process cwd.
    return path if path.is_absolute() else repo_root / path


def _manifest_decl(repo_root: Path) -> LedgerDecl | None:
    target = repo_root / "service-manifest.json"
    if not target.is_file():
        return None
    try:
        raw: Any = json.loads(target.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise LedgerError(
            f"{target} could not be read as JSON ({exc}). Next: fix the manifest syntax."
        ) from exc
    if not isinstance(raw, dict) or "ledger" not in raw:
        return None
    block = raw["ledger"]
    if not isinstance(block, dict) or not all(
        isinstance(block.get(k), str) and block.get(k) for k in LEDGER_FIELDS
    ):
        raise LedgerError(
            f"{target} ledger block needs non-empty string fields {', '.join(LEDGER_FIELDS)}. "
            "Next: declare all four ledger fields in the manifest."
        )
    return LedgerDecl(
        Path(block["path"]), block["format"], block["id_scheme"], block["sequence_source"]
    )


def _validate(decl: LedgerDecl, where: str) -> None:
    if decl.format not in LEDGER_FORMATS:
        raise LedgerError(
            f"{where} ledger.format must be one of {LEDGER_FORMATS}. "
            "Next: pick the one matching your ledger file."
        )
    source = decl.sequence_source
    if source != "last-row-id" and not _FRONTMATTER_SOURCE.fullmatch(source):
        raise LedgerError(
            f"{where} ledger.sequence_source {source!r} is not supported. "
            "Next: use last-row-id or frontmatter:<key>."
        )


# 0004: a heading ledger must start with a `---` line to use a frontmatter sequence.
def _frontmatter(text: str) -> dict[str, str]:
    lines = text.splitlines()
    if not lines or lines[0] != "---":
        return {}
    out: dict[str, str] = {}
    for line in lines[1:]:
        if line.strip() == "---":
            return out
        key, sep, value = line.partition(":")
        if sep and key.strip():
            out[key.strip()] = value.strip()
    return {}


def _cells(line: str) -> list[str]:
    return [cell.strip() for cell in line.strip().strip("|").split("|")]


def _id_column(lines: list[str], i: int) -> int | None:
    # 0004: a header is a pipe line with an Id cell AND a separator row directly under it.
    line = lines[i]
    if not line.startswith("|") or i + 1 >= len(lines) or not _SEPARATOR.match(lines[i + 1]):
        return None
    cells = [cell.lower() for cell in _cells(line)]
    return cells.index("id") if "id" in cells else None


def id_table_span(lines: list[str]) -> tuple[int, int, int] | None:
    # 0004: (header index, Id column, index past the table's last pipe line).
    for i in range(len(lines)):
        column = _id_column(lines, i)
        if column is None:
            continue
        end = i + 2
        while end < len(lines) and lines[end].startswith("|"):
            end += 1
        return i, column, end
    return None


def _id_table_rows(lines: list[str]) -> list[list[str]]:
    out: list[list[str]] = []
    for i in range(len(lines)):
        if _id_column(lines, i) is None:
            continue
        end = i + 2
        while end < len(lines) and lines[end].startswith("|"):
            end += 1
        out.append([row for row in lines[i + 2 : end] if not _SEPARATOR.match(row)])
    return out


def _id_table(lines: list[str]) -> tuple[int, list[str]] | None:
    span = id_table_span(lines)
    if span is None:
        return None
    start, column, end = span
    return column, [row for row in lines[start + 2 : end] if not _SEPARATOR.match(row)]


def _infer(path: Path) -> ResolvedLedger | None:
    try:
        text = path.read_text(encoding="utf-8-sig")
    except (OSError, UnicodeDecodeError):
        return None
    if _id_table(text.splitlines()) is not None:
        return ResolvedLedger(path, "markdown-table-row", TABLE_SCHEME, "last-row-id", "probe")
    if "sequence_id" in _frontmatter(text):
        return ResolvedLedger(
            path, "heading-entry", HEADING_SCHEME, "frontmatter:sequence_id", "probe"
        )
    return ResolvedLedger(path, "heading-entry", HEADING_SCHEME, "last-row-id", "probe")


def resolve_ledger(cwd: str, config: Config) -> ResolvedLedger | None:
    repo_root = project_root(cwd)
    charter_root = config.charter_root
    # 0004: manifest wins, then config, then the convention probe.
    declared = (
        (_manifest_decl(repo_root), "manifest", f"{repo_root / 'service-manifest.json'}"),
        (config.ledger, "config", "config.json"),
    )
    for decl, origin, where in declared:
        if decl is not None:
            _validate(decl, where)
            path = _resolve_path(str(decl.path), repo_root, charter_root)
            return ResolvedLedger(path, decl.format, decl.id_scheme, decl.sequence_source, origin)
    roots = [repo_root] + ([charter_root] if charter_root is not None else [])
    for root in roots:
        for name in PROBE_NAMES:
            candidate = root / name
            if candidate.is_file():
                found = _infer(candidate)
                if found is not None:
                    return found
    return None


def _leading_int(token: str, ledger: ResolvedLedger) -> int:
    match = _LEADING_INT.match(token.strip())
    if match is None:
        raise LedgerError(
            f"{ledger.path} last id {token!r} has no leading integer. "
            "Next: fix the last entry id or declare a frontmatter sequence_source."
        )
    return int(match.group())


def _last_table_id(lines: list[str], ledger: ResolvedLedger) -> int:
    table = _id_table(lines)
    # C1: a lone empty Id table is a new ledger (seq 0); one above another table is R2-1.
    if table is not None and not table[1]:
        tables = _id_table_rows(lines)
        if len(tables) == 1:
            return 0
        if any(tables[1:]):
            raise LedgerError(
                f"{ledger.path}: the first Id table has a header but no rows and another Id "
                "table follows it. Next: keep one ledger table."
            )
        raise LedgerError(f"{ledger.path} has two or more empty Id tables. Next: keep one.")
    if table is None or not table[1]:
        raise LedgerError(
            f"{ledger.path} has no table rows. Next: add a header, separator and first row."
        )
    column, rows = table
    cells = _cells(rows[-1])
    return _leading_int(cells[column] if column < len(cells) else "", ledger)


def _last_heading_id(lines: list[str], ledger: ResolvedLedger) -> int:
    ids = [int(m.group(1)) for line in lines if (m := _ENTRY_HEADING.match(line))]
    if not ids:
        raise LedgerError(
            f"{ledger.path} has no '## Entry N' headings. Next: add the first entry heading."
        )
    return ids[-1]


def read_sequence(ledger: ResolvedLedger) -> int:
    try:
        text = ledger.path.read_text(encoding="utf-8-sig")
    except FileNotFoundError as exc:
        raise LedgerError(
            f"ledger {ledger.path} does not exist. Next: create it or fix the declared path."
        ) from exc
    except (OSError, UnicodeDecodeError) as exc:
        raise LedgerError(
            f"ledger {ledger.path} could not be read ({exc}). Next: make it a readable UTF-8 file."
        ) from exc
    source = ledger.sequence_source
    if source == "last-row-id":
        lines = text.splitlines()
        if ledger.format == "markdown-table-row":
            return _last_table_id(lines, ledger)
        return _last_heading_id(lines, ledger)
    if source.startswith("frontmatter:"):
        key = source.removeprefix("frontmatter:")
        value = _frontmatter(text).get(key)
        if value is None or not _DIGITS.fullmatch(value):
            raise LedgerError(
                f"{ledger.path} frontmatter key {key!r} is missing or not an integer. "
                f"Next: set '{key}: <n>' between the leading --- lines."
            )
        return int(value)
    raise LedgerError(
        f"ledger sequence_source {source!r} is not supported. "
        "Next: use last-row-id or frontmatter:<key>."
    )


def next_id(ledger: ResolvedLedger, seq: int, repo: str, type_: str) -> str:
    try:
        return ledger.id_scheme.format(seq=seq, repo=repo, type=type_)
    except (KeyError, IndexError, ValueError, TypeError, AttributeError) as exc:
        raise LedgerError(
            f"ledger id_scheme {ledger.id_scheme!r} could not be formatted ({exc}). "
            "Next: use only {seq}, {repo} and {type} placeholders."
        ) from exc


def format_entry(
    ledger: ResolvedLedger, seq: int, repo: str, type_: str, date: str, body: str
) -> str:
    entry_id = next_id(ledger, seq, repo, type_)
    if ledger.format == "markdown-table-row":
        # 0004: splitlines matches read_sequence, so every break it honors is rejected here.
        if any(text and text.splitlines() != [text] for text in (body, date, entry_id)):
            raise LedgerError(
                "table rows are one line; the entry id, body or date contains a newline. "
                "Next: join the text onto one line or escape it as a heading-entry ledger."
            )
        return f"| {entry_id} | {date} | {body} |\n"
    return f"\n\n## Entry {entry_id} - {date}\n\n{body}\n"
