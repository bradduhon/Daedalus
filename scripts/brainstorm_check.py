#!/usr/bin/env python3
# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0243: the brainstorm's file checks; brainstorm_check.py <board|handoff|turns|risks> <file>.
# Exit 0 prints `<form> ok`, 1 prints one `<form>: <problem>` line each and a Next line, 2 usage.
from __future__ import annotations

import re
import sys
from collections.abc import Callable
from pathlib import Path

USAGE = (
    "usage: brainstorm_check.py board <file>\n"
    "       brainstorm_check.py handoff <file>\n"
    "       brainstorm_check.py turns <file>\n"
    "       brainstorm_check.py risks <file>"
)
USAGE_NEXT = "Next: pass one form word and one file path, in that order."
MAX_BYTES = 1_048_576

BOARD = (
    "Goal as first stated",
    "Goal now",
    "Framings",
    "Live",
    "Parked",
    "Retired",
    "Tensions",
    "Confirmed premises",
    "Soft premises",
)
HANDOFF = (
    "Goal as first stated",
    "Goal now",
    "Chosen direction",
    "Fixed words",
    "Why this over the alternatives",
    "Confirmed constraints",
    "Soft constraints",
    "Open tensions",
    "Parked ideas",
    "Worth building because",
    "Receipts owed",
)
GOALS = ("Goal as first stated", "Goal now")
NONE = "None."

_HEADING = re.compile(r"## (.+?)\s*")
_ITEM = re.compile(r"- (.*)")
_REASON = re.compile(r"\bReason:\s*\S")
_TURN_REF = re.compile(r"\bturn \d+\b", re.IGNORECASE)
_URL = re.compile(r"https?://\S")
_FILE_LINE = re.compile(r"[\w.-]*[/.][\w./-]*:\d+")
_ASSUMED = re.compile(r"\bASSUMED\b")
_RECORD = re.compile(r"### Turn (\d+): (session|operator)\s*")
_SENTENCE = re.compile(r"[^.!?]*[.!?]+[\"'”’)\]]*|[^.!?]+$")
_QUOTED = re.compile(r"\"[^\"\n]*\"|“[^”\n]*”")
_TRAILING = "\"'”’)] \t"
# 0243: the three framing lines of the board, in order; the denied premise is quoted, never empty.
_FRAMINGS = (
    ("Obvious", re.compile(r"Obvious: \S.*")),
    ("Stranger", re.compile(r"Stranger: \S.*")),
    ("Denies", re.compile(r"Denies [\"“]\s*[^\"”\s][^\"”]*[\"”]: \S.*")),
)
_FRAMING_SHAPES = (
    "- Obvious: <sentence>",
    "- Stranger: <sentence>",
    '- Denies "<premise>": <sentence>',
)
_LIST_ITEM = re.compile(r"\s*(?:\d+[.)]|[-*•])\s+(.*)")
_REQUIREMENT = re.compile(
    r"\b(must|shall|should|needs? to|has to|required|requirements?|acceptance)\b", re.IGNORECASE
)
_OPEN_RISKS = re.compile(r"##\s+(?:\d+\.\s*)?Open risks\s*")
_DECIDES = re.compile(r"\bDecides:\s*(.*)")
_OPERATOR = re.compile(r"\boperator\b", re.IGNORECASE)
_QUESTION_REF = re.compile(r"\bquestion \d+\b", re.IGNORECASE)
# 0250: one fixed word or phrase, then its meaning.
_FIXED_WORD = re.compile(r"[^:\s][^:]*: \S.*")


class CheckError(Exception):
    pass


def _sections(text: str) -> list[tuple[str, list[str]]]:
    # 0243: each `## ` heading and its body lines; text above the first heading is the title.
    out: list[tuple[str, list[str]]] = []
    for line in text.splitlines():
        head = _HEADING.fullmatch(line)
        if head is not None:
            out.append((head[1], []))
        elif out:
            out[-1][1].append(line)
    return out


def _heading_problems(found: list[str], fixed: tuple[str, ...]) -> list[str]:
    problems = [f"the heading `## {name}` is missing" for name in fixed if name not in found]
    problems += [
        f"the heading `## {name}` is not one of the fixed headings"
        for name in found
        if name not in fixed
    ]
    for name in fixed:
        if found.count(name) > 1:
            problems.append(f"the heading `## {name}` appears {found.count(name)} times")
    known = [name for name in found if name in fixed]
    if not problems and known != list(fixed):
        problems.append("the headings are out of order; the order is: " + ", ".join(fixed))
    return problems


def _items(name: str, body: list[str]) -> tuple[list[str], list[str]]:
    # 0243: `- ` items; an indented line continues the item above; `None.` is an empty list.
    items: list[str] = []
    problems: list[str] = []
    for line in body:
        item = _ITEM.fullmatch(line)
        if item is not None:
            items.append(item[1].strip())
        elif not line.strip() or line.strip() == NONE:
            continue
        elif line[:1].isspace() and items:
            items[-1] += " " + line.strip()
        else:
            problems.append(f"{name} holds a line that is not a `- ` item: {line.strip()}")
    return items, problems


def _goal_problems(sections: dict[str, list[str]]) -> list[str]:
    problems: list[str] = []
    for name in GOALS:
        text = " ".join(line.strip() for line in sections.get(name, [])).strip()
        if name in sections and (not text or text == NONE):
            problems.append(f"{name} holds no sentence")
    return problems


def _per_item(
    sections: dict[str, list[str]], name: str, ok: Callable[[str], bool], need: str
) -> list[str]:
    if name not in sections:
        return []
    items, problems = _items(name, sections[name])
    problems += [
        f"{name} item {n} {need}: {item}" for n, item in enumerate(items, 1) if not ok(item)
    ]
    return problems


def _has_reason(item: str) -> bool:
    return _REASON.search(item) is not None


def _has_turn(item: str) -> bool:
    return _TURN_REF.search(item) is not None


def _has_receipt(item: str) -> bool:
    return any(p.search(item) for p in (_URL, _FILE_LINE, _ASSUMED))


def board_problems(text: str) -> list[str]:
    # 0243: spec 3 rules 4 and 10, the board's headings, framings, reasons and tested turns.
    parsed = _sections(text)
    problems = _heading_problems([name for name, _ in parsed], BOARD)
    sections = dict(parsed)
    problems += _goal_problems(sections)
    problems += _framing_problems(sections)
    problems += _per_item(sections, "Retired", _has_reason, "gives no `Reason:`")
    problems += _per_item(sections, "Confirmed premises", _has_turn, "names no `turn <n>`")
    return problems


def _fixed_word_problems(sections: dict[str, list[str]]) -> list[str]:
    # 0250: at least one `- <word or phrase>: <its meaning>` line; the planner keeps them as given.
    name = "Fixed words"
    if name not in sections:
        return []
    items, problems = _items(name, sections[name])
    if not items:
        problems.append(f"{name} holds no `- <word or phrase>: <its meaning>` line")
    problems += [
        f"{name} item {n} is not `- <word or phrase>: <its meaning>`: {item}"
        for n, item in enumerate(items, 1)
        if _FIXED_WORD.fullmatch(item) is None
    ]
    return problems


def handoff_problems(text: str) -> list[str]:
    # 0243: spec 4 and 7, the brief's fixed headings, reasons, tested turns and receipts.
    parsed = _sections(text)
    problems = _heading_problems([name for name, _ in parsed], HANDOFF)
    sections = dict(parsed)
    problems += _goal_problems(sections)
    problems += _fixed_word_problems(sections)
    why = "Why this over the alternatives"
    problems += _per_item(sections, why, _has_reason, "gives no `Reason:`")
    problems += _per_item(sections, "Confirmed constraints", _has_turn, "names no `turn <n>`")
    problems += _per_item(
        sections, "Receipts owed", _has_receipt, "carries no URL, no file:line and no ASSUMED"
    )
    return problems


def _records(text: str) -> tuple[list[tuple[str, str]], list[str]]:
    records: list[tuple[str, list[str]]] = []
    problems: list[str] = []
    for line in text.splitlines():
        record = _RECORD.fullmatch(line)
        if record is not None:
            want = len(records) + 1
            if int(record[1]) != want:
                problems.append(f"the record `{line.strip()}` should be turn {want}")
            records.append((record[2], []))
        elif records:
            records[-1][1].append(line)
        elif line.strip() and not line.startswith(("# ", "<!--")):
            problems.append(f"text before the first turn record: {line.strip()}")
    if not records:
        problems.append("the log holds no `### Turn <n>: <session|operator>` record")
    return [(who, "\n".join(body).strip()) for who, body in records], problems


def _sentences(text: str) -> list[str]:
    flat = " ".join(text.split())
    return [s.strip() for s in _SENTENCE.findall(flat) if s.strip()]


def _is_question(sentence: str) -> bool:
    return _QUOTED.sub("", sentence).rstrip(_TRAILING).endswith("?")


def _framing_problems(sections: dict[str, list[str]]) -> list[str]:
    # 0243: the opening's framings live on the board, in their fixed line shapes.
    if "Framings" not in sections:
        return []
    items, problems = _items("Framings", sections["Framings"])
    if len(items) != len(_FRAMINGS):
        problems.append(f"Framings holds {len(items)} lines; it holds exactly three")
    for n, ((name, shape), item, want) in enumerate(
        zip(_FRAMINGS, items, _FRAMING_SHAPES, strict=False), 1
    ):
        if not shape.fullmatch(item):
            problems.append(f"Framings line {n} is not `{want}` ({name}): {item}")
    return problems


def _turn_problems(n: int, text: str, after_question: bool) -> list[str]:
    problems: list[str] = []
    sentences = _sentences(text)
    asked = [i for i, sentence in enumerate(sentences) if _is_question(sentence)]
    if len(asked) > 1:
        problems.append(f"turn {n}: holds {len(asked)} questions; a turn holds at most one")
    if asked and asked[-1] != len(sentences) - 1:
        problems.append(f"turn {n}: the question is not the turn's last sentence")
    if asked and len(sentences) < 2:
        problems.append(f"turn {n}: the question stands alone; it follows a sentence of your own")
    if asked and after_question:
        problems.append(
            f"turn {n}: answers the operator's question at turn {n - 1} and still asks one"
        )
    listed = [m[1] for line in text.splitlines() if (m := _LIST_ITEM.fullmatch(line))]
    wants = [item for item in listed if _REQUIREMENT.search(item)]
    if len(wants) >= 3:
        problems.append(
            f"turn {n}: holds a list of {len(wants)} requirement-like items; "
            "requirements belong to shaping"
        )
    return problems


def turns_problems(text: str) -> list[str]:
    # 0243: spec 7, the per-turn checks of the exploring transcript.
    records, problems = _records(text)
    opened = False
    for n, (who, body) in enumerate(records, 1):
        if who != "session":
            continue
        previous = records[n - 2] if n > 1 else ("", "")
        after = previous[0] == "operator" and previous[1].rstrip(_TRAILING).endswith("?")
        opened = True
        problems += _turn_problems(n, body, after)
    if records and not opened:
        problems.append("the log holds no session turn")
    return problems


def risks_problems(text: str) -> list[str]:
    # 0243: rule B5, an operator-decided Open risks row cites the question that left it open.
    lines = text.splitlines()
    start = next((i for i, line in enumerate(lines) if _OPEN_RISKS.fullmatch(line)), None)
    if start is None:
        return ["the spec holds no `## 6. Open risks` section"]
    body: list[str] = []
    for line in lines[start + 1 :]:
        if line.startswith("## "):
            break
        body.append(line)
    items, problems = _items("Open risks", body)
    for n, item in enumerate(items, 1):
        decides = _DECIDES.search(item)
        if decides is None:
            problems.append(f"Open risks row {n} names no `Decides:`: {item}")
        elif _OPERATOR.search(decides[1]) and not _QUESTION_REF.search(decides[1]):
            problems.append(
                f"Open risks row {n} is the operator's to decide but cites no `question <n>`: "
                f"{item}"
            )
    return problems


FORMS: dict[str, tuple[Callable[[str], list[str]], str]] = {
    "board": (board_problems, "Next: fix each named line of the board, then run board again."),
    "handoff": (
        handoff_problems,
        "Next: fix each named line of the brief, then run handoff again.",
    ),
    "turns": (turns_problems, "Next: read each named turn against the rule its line names."),
    "risks": (
        risks_problems,
        "Next: ask each named item as a question, or cite the question that left it open.",
    ),
}


def read_text(path: str) -> str:
    target = Path(path)
    if not target.is_file():
        raise CheckError(f"{path} is not a file. Next: write the file, then run the check again.")
    if target.stat().st_size > MAX_BYTES:
        raise CheckError(
            f"{path} is over {MAX_BYTES} bytes. Next: pass the brainstorm file itself, not a log."
        )
    try:
        return target.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise CheckError(
            f"{path} could not be read ({exc}). Next: rewrite the file as UTF-8 text."
        ) from exc


def main(argv: list[str]) -> int:
    if len(argv) != 2 or argv[0] not in FORMS or not argv[1]:
        print(f"{USAGE}\n{USAGE_NEXT}", file=sys.stderr)
        return 2
    form, path = argv
    check, next_line = FORMS[form]
    try:
        problems = check(read_text(path))
    except CheckError as exc:
        print(f"brainstorm_check.py: {exc}", file=sys.stderr)
        return 2
    if not problems:
        print(f"{form} ok")
        return 0
    print("\n".join(f"{form}: {problem}" for problem in problems))
    print(next_line)
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
