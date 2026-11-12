# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0109, spec 3.4: the auditor's finding list and the round number; pure, so the table test owns it.
# 0133: no stall rule and no budget; the operator decides each finding.
from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass

SEVERITIES = ("critical", "high", "medium", "low")
_SEP = " | "
_ROUND_KEY = re.compile(r"[1-9][0-9]{0,5}")
# 0281: the three cells ending every judge finding row, ` | <name>: <text>`, in this order.
FIELDS = ("rule", "places", "search")
PLACE_SEP = ", "
NO_TEST = "no-test:"
CELLS = (
    "` | rule: <the rule broken, in one sentence> | places: <file>:<line or named part>[, ...]"
    " | search: <the command that found every place>`"
)


class FindingsError(ValueError):
    pass


@dataclass(frozen=True)
class Finding:
    key: str
    severity: str
    kind: str


def parse(text: str, where: str) -> dict[str, Finding]:
    # pin C3 -> C1: one `<key> | <severity> | <class>` line per blocking finding.
    found: dict[str, Finding] = {}
    for number, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line:
            continue
        parts = [part.strip() for part in line.rsplit(_SEP, 2)]
        if len(parts) != 3 or not all(parts) or not line.isprintable():
            raise FindingsError(
                f"{where} line {number} is not `<key> | <severity> | <class>`. "
                "Next: have the auditor rewrite the finding list in that form."
            )
        key, severity, kind = parts
        if severity not in SEVERITIES:
            raise FindingsError(
                f"{where} line {number} names severity {severity!r}. "
                f"Next: have the auditor use one of {', '.join(SEVERITIES)}."
            )
        if key in found:
            raise FindingsError(
                f"{where} names {key} twice. Next: have the auditor list each finding once."
            )
        found[key] = Finding(key, severity, kind)
    return found


def finding_cells(row: str) -> dict[str, str]:
    # 0281: each named cell runs from its last ` | <name>: ` marker to the next marker or the end.
    marks = sorted((row.rfind(f"{_SEP}{name}: "), name) for name in FIELDS)
    found = [(at, name) for at, name in marks if at >= 0]
    cells: dict[str, str] = {}
    for index, (at, name) in enumerate(found):
        end = found[index + 1][0] if index + 1 < len(found) else len(row)
        cells[name] = row[at + len(_SEP) + len(name) + 2 : end].strip()
    return cells


def _place(place: str) -> bool:
    # 0281: a place is `<file>:<line>` or `<file>:<named part>`, both sides non-empty.
    file, colon, part = place.partition(":")
    return bool(colon and file.strip() and part.strip())


def cell_problems(row: str) -> list[str]:
    # 0281: what a finding row lacks; a rule with one place still carries its search.
    cells = finding_cells(row)
    out = [f"no {name} cell" for name in FIELDS if not cells.get(name)]
    places = cells.get("places")
    if places and not all(_place(p) for p in places.split(PLACE_SEP)):
        out.append("a place that is not `<file>:<line or named part>`")
    return out


def reply_finding(line: str) -> bool:
    # 0281, agents/auditor.md Finding format: `<node id> <severity> <class>: ...` or `no-test: ...`.
    words = line.removeprefix("- ").split()
    if words[:1] == [NO_TEST]:
        return True
    return len(words) >= 3 and words[1] in SEVERITIES and words[2].endswith(":")


def next_round(rounds: Mapping[str, object]) -> int:
    # 67: one more than the highest round key the train recorded, else 1; other keys are skipped.
    return max((int(key) for key in rounds if _ROUND_KEY.fullmatch(key)), default=0) + 1
