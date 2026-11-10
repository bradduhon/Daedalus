# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import os
import re
import string
from dataclasses import dataclass, replace
from pathlib import Path

from lib.agent_files import parse_frontmatter
from lib.audit import project_root
from lib.config import Config
from lib.manifest import Docs, ManifestError
from lib.manifest import load as load_manifest

TABLE_SCHEME = "{seq:04d}-{repo}-{type}"
# 0247: an empty table or a new file numbers its rows as plain four-digit numbers.
PLAIN_SCHEME = "{seq:04d}"
HEADING_SCHEME = "{seq}"
_PLAIN_ID = re.compile(r"[0-9]+")
_THREE_PART_ID = re.compile(r"[0-9]+-[A-Za-z0-9_]+-[A-Za-z0-9_]+")
_SEPARATOR = re.compile(r"^\|(\s*:?-+:?\s*\|)+\s*$")
_ENTRY_HEADING = re.compile(r"^## Entry ([0-9]+)\b")
_LEADING_INT = re.compile(r"[0-9]+")
_DIGITS = re.compile(r"[0-9]+")
_UNESCAPED_PIPE = re.compile(r"(?<!\\)\|")
_CODE_CLASS = "[A-Za-z0-9_-]+"
_SCHEME_FIELDS = {"seq": "[0-9]+", "repo": _CODE_CLASS, "type": _CODE_CLASS}
_FIRST_SENTENCE = re.compile(r"(.+?)\.(?=\s|$)")
_NAME_WORD = re.compile(r"[^\s.]+")
NAME_WORDS = (2, 5)
SUPERSEDES_NEXT = (
    "Next: write `None.`, or `Supersedes: <ids>.` and `Amends: <ids>.` naming ledger ids, "
    "optionally followed by `Applies: <text>.`"
)
RULING_NEXT = (
    "Next: begin the cell with the ruling's short name and a period, e.g. `Open composition.`"
)


class LedgerError(ValueError):
    pass


@dataclass(frozen=True)
class ResolvedLedger:
    path: Path
    format: str
    id_scheme: str
    sequence_source: str
    origin: str
    branch: str | None = None


def _docs(repo_root: Path) -> Docs | None:
    try:
        loaded = load_manifest(repo_root)
    except ManifestError as exc:
        raise LedgerError(str(exc)) from exc
    return loaded.docs if loaded is not None else None


def decisions_folder(repo_root: Path, config: Config, docs: Docs) -> Path:
    # 0245: the docs folder kept elsewhere on this machine wins over the project's own.
    return config.charter_root if config.charter_root is not None else repo_root / docs.folder


# 0247: the summary of decisions in force, read beside the decisions file when it exists.
RULES_SUMMARY_NAME = "standing-rules.md"


def rules_summary(ledger: ResolvedLedger) -> Path | None:
    path = ledger.path.parent / RULES_SUMMARY_NAME
    return path if path.is_file() else None


# 0004, W1.3: a heading ledger must start with a `---` line to use a frontmatter sequence.
def _frontmatter(text: str, path: Path) -> dict[str, str]:
    return parse_frontmatter(text.splitlines(), path, lenient=True)


def _id_column(lines: list[str], i: int) -> int | None:
    # 0004: a header is a pipe line with an Id cell AND a separator row directly under it.
    line = lines[i]
    if not line.startswith("|") or i + 1 >= len(lines) or not _SEPARATOR.match(lines[i + 1]):
        return None
    cells = [cell.lower() for cell in split_row(line)]
    return cells.index("id") if "id" in cells else None


Span = tuple[int, int, int]


def id_table_spans(lines: list[str]) -> list[Span]:
    # 0004, issue 186: per Id table, (header index, Id column, index past its last pipe line).
    out: list[Span] = []
    i = 0
    while i < len(lines):
        column = _id_column(lines, i)
        if column is None:
            i += 1
            continue
        end = i + 2
        while end < len(lines) and lines[end].startswith("|"):
            end += 1
        out.append((i, column, end))
        i = end
    return out


def id_table_span(lines: list[str]) -> Span | None:
    spans = id_table_spans(lines)
    return spans[0] if spans else None


def _span_rows(lines: list[str], span: Span) -> list[str]:
    start, _column, end = span
    return [row for row in lines[start + 2 : end] if not _SEPARATOR.match(row)]


def _id_table_rows(lines: list[str]) -> list[list[str]]:
    return [_span_rows(lines, span) for span in id_table_spans(lines)]


def _id_table(lines: list[str]) -> tuple[int, list[str]] | None:
    span = id_table_span(lines)
    return None if span is None else (span[1], _span_rows(lines, span))


def _span_ids(lines: list[str], span: Span) -> list[int]:
    column = span[1]
    out: list[int] = []
    for row in _span_rows(lines, span):
        cells = split_row(row)
        match = _LEADING_INT.match(cells[column].strip()) if column < len(cells) else None
        if match is not None:
            out.append(int(match.group()))
    return out


def highest_id_table(lines: list[str]) -> tuple[Span, int] | None:
    # issue 186: the Id table holding the highest id and that id; more rows wins a tie.
    best: tuple[Span, int] | None = None
    rank = (-1, -1)
    for span in id_table_spans(lines):
        ids = _span_ids(lines, span)
        if ids and (max(ids), len(_span_rows(lines, span))) > rank:
            rank = (max(ids), len(_span_rows(lines, span)))
            best = (span, rank[0])
    return best


def table_scheme(lines: list[str], path: Path) -> str:
    # 0247: the id pattern follows the shape of the main table's last id, else plain numbers.
    found = highest_id_table(lines)
    filled = [span for span in id_table_spans(lines) if _span_rows(lines, span)]
    if found is None and not filled:
        return PLAIN_SCHEME
    span = found[0] if found is not None else filled[0]
    rows = _span_rows(lines, span)
    cells = split_row(rows[-1])
    last = cells[span[1]].strip() if span[1] < len(cells) else ""
    if _PLAIN_ID.fullmatch(last):
        return f"{{seq:0{len(last)}d}}"
    if _THREE_PART_ID.fullmatch(last):
        return TABLE_SCHEME
    raise LedgerError(
        f"decisions file {path}: the last id {last!r} is neither a plain number such as 0007 nor "
        "a number, a repository code and a type such as 0007-SVC-PLT, so the next id cannot be "
        "worked out. Next: renumber that row in one of those two shapes."
    )


def _infer(path: Path) -> ResolvedLedger | None:
    try:
        text = path.read_text(encoding="utf-8-sig")
    except (OSError, UnicodeDecodeError):
        return None
    lines = text.splitlines()
    if _id_table(lines) is not None:
        scheme = table_scheme(lines, path)
        return ResolvedLedger(path, "markdown-table-row", scheme, "last-row-id", "probe")
    if "sequence_id" in _frontmatter(text, path):
        return ResolvedLedger(
            path, "heading-entry", HEADING_SCHEME, "frontmatter:sequence_id", "probe"
        )
    return ResolvedLedger(path, "heading-entry", HEADING_SCHEME, "last-row-id", "probe")


def resolve_ledger(cwd: str, config: Config) -> ResolvedLedger | None:
    # 0247: only a named file; no name means no decisions, and nothing is searched for.
    repo_root = project_root(cwd)
    docs = _docs(repo_root)
    if docs is None or docs.decisions_filename is None:
        return None
    if docs.git_branch is not None and config.charter_root is not None:
        raise LedgerError(
            "docs.git_branch is set while local_docs_folder names a docs folder a run branches "
            "as daedalus/<run id>, so every decision write would be refused. Next: remove "
            "docs.git_branch from the service manifest, or set local_docs_folder to null."
        )
    path = decisions_folder(repo_root, config, docs) / docs.decisions_filename
    found = _infer(path) if os.path.lexists(path) else None
    if found is None and os.path.lexists(path):
        raise LedgerError(
            f"decisions file {path} could not be read. Next: make it a readable UTF-8 file."
        )
    # 0247: a named file not yet written takes the default table layout on its first decision.
    layout = found or ResolvedLedger(path, "markdown-table-row", PLAIN_SCHEME, "last-row-id", "")
    return replace(layout, origin="manifest", branch=docs.git_branch)


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
        raise LedgerError(
            f"{ledger.path} has two or more empty Id tables. "
            "Next: keep one ledger table and delete the others."
        )
    if table is None or not table[1]:
        raise LedgerError(
            f"{ledger.path} has no table rows. Next: add a header, separator and first row."
        )
    found = highest_id_table(lines)
    if found is None:
        raise LedgerError(
            f"{ledger.path} has no Id cell with a leading integer. "
            "Next: fix the entry ids or declare a frontmatter sequence_source."
        )
    return found[1]


def _last_heading_id(lines: list[str], ledger: ResolvedLedger) -> int:
    ids = [int(m.group(1)) for line in lines if (m := _ENTRY_HEADING.match(line))]
    if not ids:
        raise LedgerError(
            f"{ledger.path} has no '## Entry N' headings. Next: add the first entry heading."
        )
    return ids[-1]


def read_sequence(ledger: ResolvedLedger) -> int:
    # 0247: a named file not yet written holds no decisions, so its sequence is 0.
    if not os.path.lexists(ledger.path):
        return 0
    try:
        text = ledger.path.read_text(encoding="utf-8-sig")
    except FileNotFoundError:
        return 0
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
        value = _frontmatter(text, ledger.path).get(key)
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


def uses_codes(ledger: ResolvedLedger) -> bool:
    # 0247: only a file whose ids carry a repository code and a type takes --repo and --type.
    return "{repo}" in ledger.id_scheme or "{type}" in ledger.id_scheme


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


def split_row(line: str) -> list[str]:
    # 0004: an escaped \| stays inside its cell.
    text = line.strip().removeprefix("|")
    if text.endswith("|") and not text.endswith("\\|"):
        text = text[:-1]
    return [cell.strip() for cell in _UNESCAPED_PIPE.split(text)]


def table_cells(lines: list[str]) -> tuple[list[str], list[list[str]]] | None:
    # 0090: the first Id table's header cells and row cells, separator rows dropped.
    span = id_table_span(lines)
    if span is None:
        return None
    start, _column, end = span
    rows = [split_row(row) for row in lines[start + 2 : end] if not _SEPARATOR.match(row)]
    return split_row(lines[start]), rows


def id_pattern(scheme: str) -> str:
    # 0090: the regex an id written by this scheme matches; the seq width is not enforced.
    parts: list[str] = []
    try:
        parsed = list(string.Formatter().parse(scheme))
    except ValueError as exc:
        raise LedgerError(f"ledger id_scheme {scheme!r} is malformed ({exc}).") from exc
    for literal, field, _spec, _conversion in parsed:
        parts.append(re.escape(literal))
        if field is None:
            continue
        if field not in _SCHEME_FIELDS:
            raise LedgerError(
                f"ledger id_scheme {scheme!r} has field {field!r}. "
                "Next: use only {seq}, {repo} and {type} placeholders."
            )
        parts.append(_SCHEME_FIELDS[field])
    return "".join(parts)


def ruling_name(cell: str) -> str | None:
    # 0094: the name is the cell's first sentence.
    match = _FIRST_SENTENCE.match(cell.strip())
    return match.group(1).strip() if match else None


def supersedes_problem(cell: str, id_scheme: str) -> str | None:
    ident = id_pattern(id_scheme)
    ids = f"{ident}(?:, {ident})*"
    relation = f"(?:Supersedes|Amends): {ids}\\."
    grammar = f"(?:None\\.|{relation}(?: {relation})*)(?: Applies: \\S.*\\.)?"
    if re.fullmatch(grammar, cell):
        return None
    return (
        f"the Supersedes cell {cell!r} is not in the machine-readable form (0090). "
        f"{SUPERSEDES_NEXT}"
    )


def ruling_problem(cell: str) -> str | None:
    name = ruling_name(cell)
    words = name.split() if name else []
    low, high = NAME_WORDS
    if low <= len(words) <= high and all(_NAME_WORD.fullmatch(word) for word in words):
        return None
    return (
        f"the Ruling cell must begin with a name of {low} to {high} words and a period (0094); "
        f"it begins {(name or cell)[:60]!r}. {RULING_NEXT}"
    )


def body_cell_problem(columns: list[str], cells: list[str], id_scheme: str) -> str | None:
    # 0090, 0094: each check runs only when the ledger header carries its column.
    named = dict(zip((column.lower() for column in columns), cells, strict=False))
    if "supersedes" in named:
        problem = supersedes_problem(named["supersedes"], id_scheme)
        if problem:
            return problem
    if "ruling" in named:
        return ruling_problem(named["ruling"])
    return None
