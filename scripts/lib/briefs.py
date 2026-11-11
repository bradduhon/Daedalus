# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0157 (12.5), 0211: brief_problems reads a decision brief's Question:, Context: and option labels;
# brief_file_problems reads one brief under the scratch root and names docs.reading_level.
# 0199, 0251: ask_problems reads one question's reader text and any lettered choice lines.
# 0254, 0255: both refuse an id at every level; the level changes no refusal and is only printed.
# 0164: both refuse a web address other than the local site, at every level.
# The project's own names (backticks, underscores, slashes, agent names) and sentence length pass.
from __future__ import annotations

import os
import re
from pathlib import Path

from lib.manifest import load

STANDARD, EXPERT = "standard", "expert"
FIELDS = ("Question:", "Context:")
OPTIONS = "Options:"
# 0211: one Ref: line directly under an option holds its ids and paths, never checked.
REF = "Ref:"
# 0211: a security or infrastructure question carries these lines, checked for presence only.
SAFETY_LINES = ("Access impact:", "Change nature:", "Rollback:")
# 0211: a Question or Context naming any of these is a security or infrastructure question.
SECURITY_WORDS = (
    *("policy", "policies", "key policy", "key policies", "trust policy", "trust policies"),
    *("permission", "permissions", "role", "roles", "grant", "grants", "granted", "granting"),
    *("access", "accesses", "accessed", "access boundary", "access boundaries"),
    *("boundary", "boundaries", "apply", "applies", "applied", "applying", "apply order"),
    *("IAM", "ACL", "ACLs", "firewall", "firewalls", "security group", "security groups"),
    *("network rule", "network rules", "encryption key", "encryption keys", "KMS"),
    *("secret", "secrets", "credential", "credentials"),
)
# 0211: longest first, so a phrase wins over the word it starts with.
_SECURITY = re.compile(
    r"\b(?:" + "|".join(map(re.escape, sorted(SECURITY_WORDS, key=len, reverse=True))) + r")\b",
    re.IGNORECASE,
)
# 0153: a brief file is a few short sections; a larger file is refused, not read.
MAX_BRIEF_BYTES = 64 * 1024
SCRATCH = Path("docs") / ".tmp" / "daedalus"
_LABEL = re.compile(r"[A-Z][A-Za-z ]*:(\s|$)")
_LABEL_END = re.compile(r":(?:\s|$)")
_RULING_ID = re.compile(r"[0-9]{4}-[A-Z]{3}")
_ISSUE = re.compile(r"#[0-9]+")
# 0164: an allow list; a word holding :// must be the local site. Its rest holds no :// or @,
# and no query value shaped like a host and path, such as ?u=evil.com/x.
_LOCAL_URL = re.compile(
    r"https?://(?:localhost|127\.0\.0\.1)(?::[0-9]{1,5})?"
    r"(?:[/?#](?:(?!://|=[^\s=&#/]*\.[^\s=&#/]*/)[^\s`@])*)?"
)
_EDGE = ".,;:!?\"'()[]"
# 0255: the plain-words sentence an id refusal carries.
ID_HELP = "Give its label or a short excerpt of what it is about instead."
# 0164: the plain-words sentence a web address refusal carries.
SITE_HELP = "A question may only ask the operator to open a site on this machine."
# 0251: the reader text of one brainstorm or setup question, then its lettered Choices lines.
ASK_FIELDS = (
    "What I take you to want:",
    "Anchor:",
    "Topic:",
    "Sides:",
    "Case:",
    "Question:",
)
ASK_CHOICES = "Choices:"
# 0200: only these end a field; any other label-shaped line is reader text and is checked.
ASK_ENDS = ("Rests on:", "[STATUS:")
_LETTERED = re.compile(r"([A-Z])[.)]\s+(.*)")
# 0250: the handoff brief's section of words the operator settled on.
FIXED_WORDS = "## Fixed words"


class BriefError(ValueError):
    pass


def level_of(literacy: str | None) -> str:
    # 0255: two levels; absent, plain, a profile: value and any other word read standard.
    return EXPERT if literacy == EXPERT else STANDARD


def _fields(text: str) -> list[tuple[str, str]]:
    # 0153: one (where, text) pair per Question:, Context: and option label; no descriptions.
    # 0211: a Ref: line is skipped; a second one under one option yields ("Ref", label).
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
        elif mode in ("options", "option", "ref") and line.startswith("- "):
            # 0153: ids may trail in the description; 0164: a label ends at a colon and a space,
            # so a web address in the label is read whole.
            out.append(("Option label", [_LABEL_END.split(line[2:], 1)[0].strip()]))
            mode = "option"
        elif mode == "option" and line.startswith(REF):
            mode = "ref"
        elif mode == "ref" and line.startswith(REF):
            out.append(("Ref", [out[-1][1][0]]))
        elif (
            mode == "field" and line and not line.startswith(("#", "- ")) and not _LABEL.match(line)
        ):
            out[-1][1].append(line)
        else:
            mode = ""
    return [(where, " ".join(part for part in parts if part)) for where, parts in out]


def _value_problems(where: str, value: str) -> list[str]:
    # 0255: no ruling id or issue number in text the operator reads, at any level.
    # 0164: a web address is the local site or refused; a path with no :// passes.
    if not value:
        return [f"{where} is empty"]
    found: list[str] = []
    for word in value.split():
        bare = word.strip(_EDGE)
        address = bare.strip("`" + _EDGE)
        if "://" in address and not _LOCAL_URL.fullmatch(address):
            found.append(f"{where} carries the web address {address}. {SITE_HELP}")
        if _RULING_ID.search(bare):
            found.append(f"{where} carries the ruling id {bare}. {ID_HELP}")
        if _ISSUE.search(bare):
            found.append(f"{where} carries the issue number {bare}. {ID_HELP}")
    return found


def brief_problems(text: str) -> list[str]:
    # 0153: one problem line per breach; an empty list means the brief passes.
    fields = _fields(text)
    problems: list[str] = []
    if not any(where == "Question" for where, _ in fields):
        problems.append("the brief holds no Question: line")
    for where, value in fields:
        if where == "Ref":
            problems.append(f"Option label {value} has a second Ref: line; keep one per option")
            continue
        problems.extend(_value_problems(where, value))
    problems.extend(_safety_problems(text))
    return problems


def _sections(text: str) -> list[list[str]]:
    # 0211: one line list per ## section; text above the first heading is its own section.
    sections: list[list[str]] = [[]]
    for raw in text.splitlines():
        if raw.strip().startswith("## "):
            sections.append([])
        sections[-1].append(raw.strip())
    return sections


def _safety_problems(text: str) -> list[str]:
    # 0211: a question naming access or apply order says what breaks and how to undo it.
    problems: list[str] = []
    for lines in _sections(text):
        named = (
            _SECURITY.search(value)
            for where, value in _fields("\n".join(lines))
            if where in ("Question", "Context")
        )
        hit = next((match for match in named if match is not None), None)
        if hit is None:
            continue
        missing = [
            label
            for label in SAFETY_LINES
            if not any(line.startswith(label) and line[len(label) :].strip() for line in lines)
        ]
        if missing:
            head = lines[0][3:].strip() if lines[0].startswith("## ") else "The brief"
            problems.append(f"{head} names {hit[0]} and lacks {', '.join(missing)}")
    return problems


def _ask_fields(text: str) -> list[tuple[str, str]]:
    # 0251: one (where, text) pair per reader field and per lettered Choices line.
    out: list[tuple[str, list[str]]] = []
    mode = ""
    for raw in text.splitlines():
        line = raw.strip()
        field = next((name for name in ASK_FIELDS if line.startswith(name)), None)
        if line.startswith(ASK_CHOICES):
            mode, line = "choices", line[len(ASK_CHOICES) :].strip()
        lettered = _LETTERED.fullmatch(line) if mode == "choices" else None
        if field is not None:
            out.append((field.rstrip(":"), [line[len(field) :].strip()]))
            mode = "field"
        elif lettered is not None:
            out.append((f"Choice {lettered[1]}", [lettered[2]]))
        elif line.startswith(ASK_ENDS):
            mode = ""
        elif line and out and mode:
            out[-1][1].append(line)
    return [(where, " ".join(" ".join(parts).split())) for where, parts in out]


def _uses(phrase: str, text: str) -> bool:
    # 0250: whole words, any case, a plural ending allowed.
    pattern = r"(?<![\w-])" + re.escape(phrase) + r"(?:s|es)?(?![\w-])"
    return re.search(pattern, text, re.IGNORECASE) is not None


def ask_problems(text: str, fixed_words: tuple[str, ...] | None = None) -> list[str]:
    # 0199, 0255: a Question: line, no id anywhere; empty means it passes; choices are optional.
    # 0250: fixed_words, when read from a handoff brief, must appear.
    fields = _ask_fields(text)
    problems: list[str] = []
    if not any(where == "Question" for where, _ in fields):
        problems.append("the question holds no Question: line")
    for where, value in fields:
        problems.extend(_value_problems(where, value))
    if fixed_words and not any(
        _uses(phrase, value) for phrase in fixed_words for _, value in fields
    ):
        problems.append("the question uses none of the fixed words: " + "; ".join(fixed_words))
    return problems


def fixed_words(text: str) -> tuple[str, ...] | None:
    # 0250: the `- <word or phrase>: <meaning>` lines of a handoff brief; None when it lists none.
    words: list[str] = []
    inside = False
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("## "):
            inside = line == FIXED_WORDS
        elif inside and line.startswith("- ") and ": " in line:
            words.append(line[2:].split(": ", 1)[0].strip())
    return tuple(word for word in words if word) or None


def _read(label: str, real: str, next_step: str) -> str:
    if os.path.getsize(real) > MAX_BRIEF_BYTES:
        raise BriefError(f"{label} is over {MAX_BRIEF_BYTES} bytes. Next: {next_step}")
    try:
        return Path(real).read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise BriefError(
            f"{label} could not be read ({exc}). Next: rewrite the file as UTF-8 text."
        ) from exc


def ask_file_problems(question: Path, brief: Path | None = None) -> list[str]:
    # 0199: a folder run's brainstorm folder may sit outside the repo, so no root check here.
    real = os.path.realpath(question)
    if not os.path.isfile(real):
        raise BriefError(
            f"question file {question} is not a file. Next: write the question's reader text "
            "to the file and run ask-check again."
        )
    words = None
    if brief is not None:
        # 0250: the handoff brief's Fixed words; a named brief that is missing is a stop.
        brief_real = os.path.realpath(brief)
        if not os.path.isfile(brief_real):
            raise BriefError(
                f"handoff brief {brief} is not a file. Next: pass the brainstorm folder's "
                "handoff.md, or run ask-check without --brief."
            )
        words = fixed_words(_read(f"handoff brief {brief}", brief_real, "pass the brief itself."))
    text = _read(f"question file {question}", real, "write one question per file.")
    return ask_problems(text, words)


def brief_file_problems(repo: Path, brief: Path) -> tuple[str, list[str]]:
    # 0255: the level from docs.reading_level (absent reads standard), printed, never judged.
    root = os.path.realpath(repo / SCRATCH)
    real = os.path.realpath(brief)
    if os.path.commonpath([root, real]) != root or not os.path.isfile(real):
        raise BriefError(
            f"brief {brief} is not a file under {root}. Next: write the decision brief under "
            f"{root} and run brief-check on that file."
        )
    text = _read(f"brief {brief}", real, "write at most four short questions per brief file.")
    manifest = load(repo)
    level = level_of(manifest.docs.literacy if manifest is not None else None)
    return level, brief_problems(text)
