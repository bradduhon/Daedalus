#!/usr/bin/env python3
# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from lib.ledger import (  # noqa: E402
    NAME_WORDS,
    TABLE_SCHEME,
    LedgerError,
    id_pattern,
    ruling_name,
    ruling_problem,
    table_cells,
)

# 22: the --help text, kept below the future import as a plain string.
DESCRIPTION = (
    "Derive the standing-rules file from a markdown-table ledger (0090, 0094). "
    "Areas, quoted from 0090-DAE-PLT: composition and phases; planning and dispatch; the jail and "
    "grammars; the audit log and proofs; the ledger and charter; GitHub and release; the project "
    "files; operator interaction. The backfill JSON maps every in-force id to one area, carries "
    "the Supersedes and Amends ids of every row before its relations_from id, and names the first "
    "row (names_from) whose Ruling cell starts with its name. An optional names object gives a row "
    "before names_from a hand-written name of two to five words (0181); a row it leaves out is "
    "named by the first clause of its Ruling cell. --check exits 1 when --out differs from what "
    "this script would write; every refusal exits 1."
)
AREAS = (
    "composition and phases",
    "planning and dispatch",
    "the jail and grammars",
    "the audit log and proofs",
    "the ledger and charter",
    "GitHub and release",
    "the project files",
    "operator interaction",
)
COLUMNS = ("id", "date", "ruling", "supersedes")
BACKFILL_KEYS = frozenset({"relations_from", "names_from", "areas", "relations"})
OPTIONAL_BACKFILL_KEYS = frozenset({"names"})
RELATION_KEYS = frozenset({"supersedes", "amends"})
_SENTENCE_BREAK = re.compile(r"(?<=\.)\s+")
_CLAUSE_END = ",;:"
_ID_EDGE = "A-Za-z0-9_-"


class StandingRulesError(Exception):
    pass


@dataclass(frozen=True)
class Relations:
    supersedes: tuple[str, ...]
    amends: tuple[str, ...]


@dataclass(frozen=True)
class Backfill:
    relations_from: str
    names_from: str
    areas: dict[str, str]
    relations: dict[str, Relations]
    names: dict[str, str]


@dataclass(frozen=True)
class Row:
    id: str
    date: str
    ruling: str
    name: str
    relations: Relations


def _id_list(value: object, where: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise StandingRulesError(f"{where} must be a list of ids. Next: write a JSON list.")
    return tuple(str(item) for item in value)


def _load_backfill(path: Path) -> Backfill:
    try:
        data: object = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        raise StandingRulesError(
            f"backfill {path} is not readable JSON ({exc}). Next: fix the backfill file."
        ) from exc
    if not isinstance(data, dict) or not BACKFILL_KEYS <= set(data) <= (
        BACKFILL_KEYS | OPTIONAL_BACKFILL_KEYS
    ):
        raise StandingRulesError(
            f"backfill {path} is not an object with exactly {', '.join(sorted(BACKFILL_KEYS))} "
            "and an optional names. Next: keep those keys and no others."
        )
    relations_from, names_from = data["relations_from"], data["names_from"]
    areas, relations = data["areas"], data["relations"]
    if not isinstance(relations_from, str) or not isinstance(names_from, str):
        raise StandingRulesError(
            f"backfill {path} relations_from and names_from are not strings. "
            "Next: set each to a ledger id."
        )
    if not isinstance(areas, dict) or not isinstance(relations, dict):
        raise StandingRulesError(
            f"backfill {path} areas and relations are not objects. Next: key each by row id."
        )
    area_map: dict[str, str] = {}
    for row_id, area in areas.items():
        if area not in AREAS:
            raise StandingRulesError(
                f"backfill {path} gives {row_id} the area {area!r} (0090). "
                "Next: use one of the eight area names in standing_rules.AREAS."
            )
        area_map[str(row_id)] = str(area)
    relation_map: dict[str, Relations] = {}
    for row_id, record in relations.items():
        where = f"backfill {path} relations for {row_id}"
        if not isinstance(record, dict) or set(record) != RELATION_KEYS:
            raise StandingRulesError(
                f"{where} are not an object of supersedes and amends. "
                "Next: write an object holding a supersedes list and an amends list of ids."
            )
        relation_map[str(row_id)] = Relations(
            _id_list(record["supersedes"], where), _id_list(record["amends"], where)
        )
    names = data.get("names", {})
    if not isinstance(names, dict) or not all(isinstance(v, str) for v in names.values()):
        raise StandingRulesError(
            f"backfill {path} names is not an object of names. "
            "Next: key each name by its row id, each value a string."
        )
    name_map = {str(row_id): str(name) for row_id, name in names.items()}
    return Backfill(relations_from, names_from, area_map, relation_map, name_map)


def _first_clause(text: str) -> str:
    # 0094: rows before names_from are named by their first clause, outside parens and code.
    depth, code = 0, False
    for i, char in enumerate(text):
        if char == "`":
            code = not code
        elif code:
            continue
        elif char in "([":
            depth += 1
        elif char in ")]":
            depth = max(0, depth - 1)
        elif depth == 0 and (
            char in _CLAUSE_END or (char == "." and (i + 1 == len(text) or text[i + 1].isspace()))
        ):
            return text[:i].strip()
    return text.strip().rstrip(".")


def _cell_relations(cell: str, ident: re.Pattern[str]) -> Relations:
    # 0090: only the Supersedes and Amends sentences count; Applies and free text never do.
    found: dict[str, list[str]] = {"Supersedes": [], "Amends": []}
    for sentence in _SENTENCE_BREAK.split(cell):
        key, sep, rest = sentence.partition(": ")
        if sep and key in found:
            found[key].extend(ident.findall(rest))
    return Relations(tuple(found["Supersedes"]), tuple(found["Amends"]))


def _read_ledger(path: Path) -> tuple[str | None, list[dict[str, str]]]:
    try:
        text = path.read_text(encoding="utf-8-sig")
    except (OSError, UnicodeDecodeError) as exc:
        raise StandingRulesError(
            f"ledger {path} could not be read ({exc}). Next: pass a readable UTF-8 ledger."
        ) from exc
    lines = text.splitlines()
    table = table_cells(lines)
    if table is None:
        raise StandingRulesError(
            f"ledger {path} has no Id table. Next: pass the file that holds the decisions table."
        )
    header = [cell.lower() for cell in table[0]]
    missing = [column for column in COLUMNS if column not in header]
    if missing:
        raise StandingRulesError(
            f"ledger {path} header lacks {', '.join(missing)}. "
            "Next: the table needs Id, Date, Ruling and Supersedes columns."
        )
    rows: list[dict[str, str]] = []
    for cells in table[1]:
        if len(cells) != len(header):
            raise StandingRulesError(
                f"ledger {path} row {cells[0]!r} has {len(cells)} cells, the header "
                f"{len(header)}. Next: escape pipes as \\| inside a cell."
            )
        rows.append(dict(zip(header, cells, strict=True)))
    first = lines[0].strip() if lines else ""
    leading = first if first.startswith("<!--") and first.endswith("-->") else None
    return leading, rows


def _index(ids: list[str], wanted: str, key: str) -> int:
    if wanted not in ids:
        raise StandingRulesError(
            f"backfill {key} {wanted} is not a row of the ledger. Next: set it to a ledger id."
        )
    return ids.index(wanted)


def _relations(
    cells: dict[str, str], before: bool, backfill: Backfill, ident: re.Pattern[str]
) -> Relations:
    row_id = cells["id"]
    if before:
        relations = backfill.relations.get(row_id)
        if relations is None:
            raise StandingRulesError(
                f"row {row_id} is before {backfill.relations_from} and has no backfill "
                "relations (0090). Next: add its supersedes and amends ids to the backfill."
            )
        return relations
    if row_id in backfill.relations:
        raise StandingRulesError(
            f"backfill carries relations for {row_id}, which reads its own Supersedes cell. "
            "Next: remove it from the backfill relations."
        )
    return _cell_relations(cells["supersedes"], ident)


def _rows(raw: list[dict[str, str]], backfill: Backfill, scheme: str) -> list[Row]:
    ids = [cells["id"] for cells in raw]
    duplicate = next((row_id for row_id in ids if ids.count(row_id) > 1), None)
    if duplicate is not None:
        raise StandingRulesError(
            f"ledger id {duplicate} appears more than once. Next: fix the duplicate row."
        )
    relations_at = _index(ids, backfill.relations_from, "relations_from")
    names_at = _index(ids, backfill.names_from, "names_from")
    _check_names(ids, names_at, backfill)
    ident = re.compile(rf"(?<![{_ID_EDGE}])(?:{id_pattern(scheme)})(?![{_ID_EDGE}])")
    rows: list[Row] = []
    for i, cells in enumerate(raw):
        row_id, ruling = cells["id"], cells["ruling"]
        if i >= names_at:
            name = ruling_name(ruling)
        else:
            name = backfill.names.get(row_id) or _first_clause(ruling)
        if not name:
            raise StandingRulesError(
                f"row {row_id} has no name in its Ruling cell (0094). "
                "Next: begin the cell with its name and a period."
            )
        relations = _relations(cells, i < relations_at, backfill, ident)
        for target in relations.supersedes + relations.amends:
            if target not in ids[:i]:
                raise StandingRulesError(
                    f"row {row_id} supersedes or amends {target}, which is not an earlier row. "
                    "Next: fix the id in its Supersedes cell or in the backfill."
                )
        rows.append(Row(row_id, cells["date"], ruling, name, relations))
    return rows


def _check_names(ids: list[str], names_at: int, backfill: Backfill) -> None:
    # 0181: hand-written names only for rows before names_from, each of two to five words.
    low, high = NAME_WORDS
    for row_id, name in backfill.names.items():
        if row_id not in ids[:names_at]:
            raise StandingRulesError(
                f"backfill names {row_id}, which is not a row before {backfill.names_from} "
                f"(0181). Next: remove it; from {backfill.names_from} on the Ruling cell names it."
            )
        if ruling_problem(f"{name}.") is not None:
            raise StandingRulesError(
                f"backfill name {name!r} for {row_id} is not {low} to {high} plain words (0181). "
                "Next: write a name of two to five words with no period."
            )


def _check_unique(in_force: list[Row], backfill: Backfill) -> None:
    # 0094: a name is unique within its ledger, compared case-insensitively over in-force rows.
    seen: dict[str, Row] = {}
    for row in in_force:
        first = seen.setdefault(row.name.casefold(), row)
        if first is row:
            continue
        if first.id in backfill.names or row.id in backfill.names:
            fix = "rename one of them in the backfill names"
        else:
            fix = f"rename {row.id} in the ledger, the later of the two rows"
        raise StandingRulesError(
            f"rows {first.id} and {row.id} share the name {row.name!r} (0094). Next: {fix}."
        )


def _check_areas(rows: list[Row], in_force: list[Row], backfill: Backfill) -> None:
    stale = sorted(set(backfill.areas) - {row.id for row in rows})
    if stale:
        raise StandingRulesError(
            f"backfill areas name ids not in the ledger: {', '.join(stale)}. "
            "Next: remove them from the backfill areas."
        )
    for row in in_force:
        if row.id not in backfill.areas:
            raise StandingRulesError(
                f"row {row.id} is in force but has no area (0090). "
                f'Next: add "{row.id}": "<one of the eight areas>" to the backfill areas.'
            )


def render(ledger: Path, backfill_path: Path, scheme: str = TABLE_SCHEME) -> str:
    backfill = _load_backfill(backfill_path)
    leading, raw = _read_ledger(ledger)
    try:
        rows = _rows(raw, backfill, scheme)
    except LedgerError as exc:
        raise StandingRulesError(str(exc)) from exc
    names = {row.id: row.name for row in rows}
    superseded_by: dict[str, list[str]] = {row.id: [] for row in rows}
    amended_by: dict[str, list[str]] = {row.id: [] for row in rows}
    for row in rows:
        for target in row.relations.supersedes:
            superseded_by[target].append(row.id)
        for target in row.relations.amends:
            amended_by[target].append(row.id)
    in_force = [row for row in rows if not superseded_by[row.id]]
    for row_id in backfill.names:
        if superseded_by[row_id]:
            raise StandingRulesError(
                f"backfill names {row_id}, which is superseded by "
                f"{', '.join(superseded_by[row_id])} (0181). "
                "Next: remove the name of this superseded row."
            )
    _check_areas(rows, in_force, backfill)
    _check_unique(in_force, backfill)
    out = [leading] if leading else []
    out += [
        f"<!-- Generated by scripts/standing_rules.py from {ledger.name}; do not edit. -->",
        "",
        "# Standing rules",
        "",
    ]
    for area in AREAS:
        members = [row for row in in_force if backfill.areas[row.id] == area]
        if not members:
            continue
        out += [f"## {area[0].upper()}{area[1:]}", ""]
        for row in members:
            out += [f"### {row.name} ({row.id}, {row.date})", "", row.ruling, ""]
            if amended_by[row.id]:
                later = ", ".join(
                    f"{later_id} ({names[later_id]})" for later_id in amended_by[row.id]
                )
                out += [f"Amended by {later}.", ""]
    gone = [row for row in rows if superseded_by[row.id]]
    if gone:
        out += ["## Superseded", ""]
        out += [
            f"- {row.name} ({row.id}), superseded by {', '.join(superseded_by[row.id])}."
            for row in gone
        ]
    return "\n".join(out).rstrip("\n") + "\n"


def _parse(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="standing_rules.py", description=DESCRIPTION, allow_abbrev=False
    )
    parser.add_argument("--ledger", required=True, type=Path)
    parser.add_argument("--backfill", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--id-scheme", default=TABLE_SCHEME)
    parser.add_argument("--check", action="store_true")
    return parser.parse_args(argv)


def _check(out: Path, ledger: Path, text: str) -> int:
    try:
        current: str | None = out.read_text(encoding="utf-8")
    except FileNotFoundError:
        current = None
    if current != text:
        print(
            f"standing_rules: {out} differs from {ledger} (0090). "
            "Next: rerun without --check to regenerate it.",
            file=sys.stderr,
        )
        return 1
    print(f"standing_rules: {out} matches {ledger}")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = _parse(sys.argv[1:] if argv is None else argv)
    try:
        text = render(args.ledger, args.backfill, args.id_scheme)
        if args.check:
            return _check(args.out, args.ledger, text)
        args.out.write_text(text, encoding="utf-8")
    except StandingRulesError as exc:
        print(f"standing_rules: {exc}", file=sys.stderr)
        return 1
    except (OSError, UnicodeDecodeError) as exc:
        print(f"standing_rules: {exc}. Next: check the paths and permissions.", file=sys.stderr)
        return 1
    print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
