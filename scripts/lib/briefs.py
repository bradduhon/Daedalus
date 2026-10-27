# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0153, 0157 (12.5): a decision brief's operator text is checked at the manifest literacy level.
# brief_problems reads the Question:, Context: and option label text of a brief file's sections;
# brief_file_problems resolves docs.literacy and reads one brief under the repo's scratch root.
from __future__ import annotations

import os
import re
from pathlib import Path

from lib.manifest import load
from lib.train_scope import KNOWN_AGENTS

PLAIN, STANDARD, EXPERT = "plain", "standard", "expert"
# 0153: words per sentence; expert has no limit.
SENTENCE_LIMITS: dict[str, int | None] = {PLAIN: 15, STANDARD: 22, EXPERT: None}
FIELDS = ("Question:", "Context:")
OPTIONS = "Options:"
# 0153: a brief file is a few short sections; a larger file is refused, not read.
MAX_BRIEF_BYTES = 64 * 1024
SCRATCH = Path("docs") / ".tmp" / "daedalus"
# 0031: "main" names the main session, not an agent file, and is an everyday word.
AGENT_NAMES = KNOWN_AGENTS - {"main"}
_LABEL = re.compile(r"[A-Z][A-Za-z ]*:(\s|$)")
# 0153: an ellipsis never ends a sentence, so a quoted "..." cannot split one in two.
_SENTENCE_END = re.compile(r"(?<=[^.][.?!])\s+")
# 0153: every name-shaped run in a word, so a possessive or a daedalus: prefix still matches.
_NAME_RUN = re.compile(r"[a-z]+(?:-[a-z]+)*")
_SNAKE = re.compile(r"[A-Za-z][A-Za-z0-9]*_[A-Za-z0-9_]+")
_RULING_ID = re.compile(r"[0-9]{4}-[A-Z]{3}")
_ISSUE = re.compile(r"#[0-9]+")
_EDGE = ".,;:!?\"'()[]"


class BriefError(ValueError):
    pass


def level_of(literacy: str | None) -> str:
    # 0153: absent, a profile: value and any unknown word read as plain, the strictest level.
    if literacy in (STANDARD, EXPERT):
        return literacy
    return PLAIN


def _fields(text: str) -> list[tuple[str, str]]:
    # 0153: one (where, text) pair per Question:, Context: and option label; no descriptions.
    out: list[tuple[str, list[str]]] = []
    mode = ""
    for raw in text.splitlines():
        line = raw.strip()
        field = next((name for name in FIELDS if line.startswith(name)), None)
        if field is not None:
            out.append((field.rstrip(":"), [line[len(field) :].strip()]))
            mode = "field"
        elif line.startswith(OPTIONS):
            mode = "options"
        elif mode == "options" and line.startswith("- "):
            # 0153: ids may trail in the description after the label's first colon.
            out.append(("Option label", [line[2:].split(":", 1)[0].strip()]))
        elif (
            mode == "field" and line and not line.startswith(("#", "- ")) and not _LABEL.match(line)
        ):
            out[-1][1].append(line)
        else:
            mode = ""
    return [(where, " ".join(part for part in parts if part)) for where, parts in out]


def _token_problems(where: str, text: str) -> list[str]:
    found: list[str] = []
    if "`" in text:
        found.append(f"{where} carries a backtick: {text}")
    for word in text.split():
        bare = word.strip(_EDGE)
        if _SNAKE.search(bare):
            found.append(f"{where} carries the snake_case token {bare}")
        if "/" in bare:
            found.append(f"{where} carries the word {bare} with a slash")
        if _RULING_ID.search(bare):
            found.append(f"{where} carries the ruling id {bare}")
        if _ISSUE.search(bare):
            found.append(f"{where} carries the issue number {bare}")
        runs = _NAME_RUN.findall(bare.lower())
        if AGENT_NAMES & {*runs, *(part for run in runs for part in run.split("-"))}:
            found.append(f"{where} carries the agent name {bare}")
    return found


def brief_problems(text: str, level: str) -> list[str]:
    # 0153: one problem line per breach; an empty list means the brief passes at that level.
    level = level_of(level)
    limit = SENTENCE_LIMITS[level]
    fields = _fields(text)
    problems: list[str] = []
    if not any(where == "Question" for where, _ in fields):
        problems.append("the brief holds no Question: line")
    for where, value in fields:
        if not value:
            problems.append(f"{where} is empty")
            continue
        if limit is not None:
            for sentence in _SENTENCE_END.split(value):
                count = len(sentence.split())
                if count > limit:
                    problems.append(
                        f"{where} sentence has {count} words, over {limit} at {level}: {sentence}"
                    )
        if level != EXPERT:
            problems.extend(_token_problems(where, value))
    return problems


def brief_file_problems(repo: Path, brief: Path) -> tuple[str, list[str]]:
    # 0153: the level from docs.literacy (absent reads plain) and the brief's problem lines.
    root = os.path.realpath(repo / SCRATCH)
    real = os.path.realpath(brief)
    if os.path.commonpath([root, real]) != root or not os.path.isfile(real):
        raise BriefError(
            f"brief {brief} is not a file under {root}. Next: write the decision brief under "
            f"{root} and run brief-check on that file."
        )
    if os.path.getsize(real) > MAX_BRIEF_BYTES:
        raise BriefError(
            f"brief {brief} is over {MAX_BRIEF_BYTES} bytes. Next: write at most four short "
            "questions per brief file."
        )
    try:
        text = Path(real).read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise BriefError(
            f"brief {brief} could not be read ({exc}). Next: rewrite the brief file as UTF-8 text."
        ) from exc
    manifest = load(repo)
    level = level_of(manifest.docs.literacy if manifest is not None else None)
    return level, brief_problems(text, level)
