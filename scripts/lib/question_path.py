# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0252, question-path spec 4 and 5: stores a conversation's path of questions under lib.storage
# and judges it with three checks. It holds no model text and calls no model.
# 0221: every list of allowed values below is a fixed tuple; anything else is refused by name.
from __future__ import annotations

import argparse
import contextlib
import io
import json
import os
import stat
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, NoReturn

from lib import atomic, ledger, storage
from lib.project_keys import reference_keys

FEATURE = "question-path"
HANDOVER = "handover.json"
LOG = "log.jsonl"
MAX_HANDOVER_BYTES = 64 * 1024
MAX_BRIEF_BYTES = 1024 * 1024
MAX_LINE = 300
MAX_RESPONSE = 4000
MIN_STATED_WORDS = 4
MIN_STATED_CHARS = 20

KINDS: tuple[str, ...] = (
    "storage",
    "naming",
    "permission",
    "who",
    "scope",
    "behaviour",
    "format",
    "proceed",
    "confirm",
    "other",
)
SOURCES: tuple[str, ...] = ("setting", "stated", "rule", "profile", "default", "none")
STATUSES: tuple[str, ...] = ("decide", "rule", "folded", "ask")
OUTCOMES: tuple[str, ...] = ("hit", "miss", "typed")
FACT_KINDS: tuple[str, ...] = ("web", "refuted", "changed-answer")
ROW_KEYS: tuple[str, ...] = (
    "id",
    "kind",
    "gap",
    "predicted",
    "source",
    "source_ref",
    "depends_on",
    "folds_into",
    "is_rule",
)
# Kinds that stay asked unless a setting or the user's own words answer them.
ASKED_KINDS: tuple[str, ...] = ("who", "scope", "behaviour")
CONFIDENCE: dict[str, str] = {
    "setting": "high",
    "stated": "high",
    "rule": "medium",
    "profile": "medium",
    "default": "low",
    "none": "none",
}
SOURCE_WORDS: dict[str, str] = {
    "setting": "a setting you set",
    "stated": "something you said",
    "rule": "a project rule",
    "profile": "your profile",
    "default": "a shipped default",
    "none": "no source",
}
STAMP_FORMAT = "%Y%m%dT%H%M%SZ"
SCRIPT = "daedalus_path.py"


class Refusal(Exception):
    def __init__(self, problems: list[str], next_step: str) -> None:
        super().__init__("; ".join(problems))
        self.problems = problems
        self.next_step = next_step


@dataclass(frozen=True)
class Row:
    id: int
    kind: str
    gap: str
    predicted: str
    source: str
    source_ref: str
    depends_on: tuple[int, ...]
    folds_into: int | None
    is_rule: bool
    confidence: str = ""
    status: str = ""

    def to_json(self) -> dict[str, Any]:
        out = {key: getattr(self, key) for key in ROW_KEYS}
        out["depends_on"] = list(self.depends_on)
        out["confidence"] = self.confidence
        out["status"] = self.status
        return out


@dataclass(frozen=True)
class Ctx:
    repo: str
    conv: str
    folder: Path

    def cmd(self, name: str, extra: str = "") -> str:
        return f"{SCRIPT} {name} --repo {self.repo} --conv {self.conv}{extra}"


def _norm(text: str) -> str:
    return " ".join(text.split())


def _same(a: str, b: str) -> bool:
    return _norm(a).casefold() == _norm(b).casefold()


# ---------------------------------------------------------------- folders and files


def _stamp_ok(conv: str) -> bool:
    try:
        return datetime.strptime(conv, STAMP_FORMAT).strftime(STAMP_FORMAT) == conv
    except ValueError:
        return False


def _conv_folder(repo: str, conv: str) -> Path:
    return storage.tmp_dir(FEATURE, repo) / conv


def make_conv(repo: str, conv: str) -> Path:
    base = storage.make_tmp_dir(FEATURE, repo)
    folder = base / conv
    os.mkdir(folder, 0o700)
    os.chmod(folder, 0o700)
    return folder


def _open_ctx(repo: str, conv: str) -> Ctx:
    if not _stamp_ok(conv):
        raise Refusal(
            [f"path: conversation {conv!r} is not a stamp like YYYYMMDDTHHMMSSZ"],
            f"Next: run `{SCRIPT} open --repo {repo}` to start a conversation.",
        )
    reason = storage.check_tmp_dirs(FEATURE, repo)
    if reason is not None:
        raise Refusal(
            [f"path: {reason}"], "Next: remove that item from your own shell, then rerun."
        )
    folder = _conv_folder(repo, conv)
    try:
        info = folder.lstat()
    except OSError:
        info = None
    if info is None or not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid():
        raise Refusal(
            [f"path: there is no conversation {conv}"],
            f"Next: run `{SCRIPT} open --repo {repo}` to start one.",
        )
    return Ctx(repo, conv, folder)


def _take_handover(folder: Path) -> tuple[Any, str | None]:
    # Read once, then delete whatever the outcome; a link or a non-file is never read.
    path = folder / HANDOVER
    try:
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        except FileNotFoundError:
            return None, "path: there is no handover file"
        except OSError:
            return None, "path: the handover file is a link or cannot be read"
        with os.fdopen(fd, "rb") as fh:
            if not stat.S_ISREG(os.fstat(fh.fileno()).st_mode):
                return None, "path: the handover is not a plain file"
            raw = fh.read(MAX_HANDOVER_BYTES + 1)
        if len(raw) > MAX_HANDOVER_BYTES:
            return None, f"path: the handover is over {MAX_HANDOVER_BYTES} bytes"
        return json.loads(raw.decode("utf-8")), None
    except ValueError as exc:
        return None, f"path: the handover is not valid JSON ({exc})"
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def _write_version(folder: Path, number: int, rows: list[Row]) -> None:
    body = {"v": number, "rows": [row.to_json() for row in rows]}
    try:
        atomic.create_once(
            folder / f"path-v{number}.json", json.dumps(body, indent=1) + "\n", 0o600
        )
    except FileExistsError as exc:
        raise Refusal(
            [f"path: version {number} already exists"],
            "Next: run the status command to read the newest version.",
        ) from exc


def _append_log(folder: Path, event: dict[str, Any]) -> None:
    line = json.dumps(event, ensure_ascii=False) + "\n"
    fd = os.open(folder / LOG, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "a", encoding="utf-8", newline="") as fh:
        fh.write(line)


def _damaged(name: str) -> Refusal:
    return Refusal([f"path: {name} is damaged"], "Next: start a new conversation with open.")


def _events(folder: Path) -> list[dict[str, Any]]:
    path = folder / LOG
    if not path.exists():
        return []
    out: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        try:
            event = json.loads(line)
        except ValueError:
            raise _damaged(LOG) from None
        if not isinstance(event, dict) or not isinstance(event.get("ev"), str):
            raise _damaged(LOG)
        out.append(event)
    return out


def _versions(folder: Path) -> list[int]:
    out: list[int] = []
    for entry in folder.iterdir():
        name = entry.name
        if name.startswith("path-v") and name.endswith(".json"):
            digits = name[len("path-v") : -len(".json")]
            if digits.isdecimal():
                out.append(int(digits))
    return sorted(out)


def _load_version(folder: Path, number: int) -> list[Row]:
    name = f"path-v{number}.json"
    try:
        body = json.loads((folder / name).read_text(encoding="utf-8"))
        return [
            Row(
                **{key: raw[key] for key in ROW_KEYS if key not in ("depends_on",)},
                depends_on=tuple(raw["depends_on"]),
                confidence=raw["confidence"],
                status=raw["status"],
            )
            for raw in body["rows"]
        ]
    except (OSError, ValueError, KeyError, TypeError):
        raise _damaged(name) from None


# ---------------------------------------------------------------- log views


def _responses(events: list[dict[str, Any]]) -> dict[int, dict[str, Any]]:
    return {e["id"]: e for e in events if e["ev"] == "response"}


def _shift_pending(events: list[dict[str, Any]]) -> bool:
    pending = False
    for event in events:
        if event["ev"] == "regenerate":
            pending = False
        elif event["ev"] == "fact" or (event["ev"] == "response" and event.get("shift") is True):
            pending = True
    return pending


def _ratified(events: list[dict[str, Any]]) -> set[int]:
    return {e["v"] for e in events if e["ev"] == "ratify"}


def _last_handout(events: list[dict[str, Any]]) -> int | None:
    last = [e["id"] for e in events if e["ev"] == "handout"]
    return last[-1] if last else None


# ---------------------------------------------------------------- the three checks


def _text_problem(value: object, label: str, low: int, high: int) -> str | None:
    if not isinstance(value, str):
        return f"{label} must be text, not {value!r}"
    if "\n" in value or "\r" in value:
        return f"{label} must be one line"
    if not value.isprintable():
        return f"{label} holds a control character"
    if not low <= len(value) <= high:
        return f"{label} must be {low} to {high} characters, not {len(value)}"
    return None


def _response_problem(value: object) -> str | None:
    # Line breaks stay; every line must be printable (a bare CR is not a line break here).
    if not isinstance(value, str):
        return f"response must be text, not {value!r}"
    lines = value.replace("\r\n", "\n").split("\n")
    if not all(line.isprintable() for line in lines):
        return "response holds a control character"
    if not 1 <= len(value) <= MAX_RESPONSE:
        return f"response must be 1 to {MAX_RESPONSE} characters, not {len(value)}"
    return None


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _parse_row(raw: object, pos: int) -> tuple[Row | None, list[str]]:
    if not isinstance(raw, dict):
        return None, [f"path: row at position {pos} is not an object"]
    ident = raw.get("id")
    who = f"row {ident}" if _is_int(ident) else f"row at position {pos}"
    missing = [k for k in ROW_KEYS if k not in raw]
    extra = [str(k) for k in raw if k not in ROW_KEYS]
    if missing or extra:
        parts = []
        if missing:
            parts.append("missing " + ", ".join(missing))
        if extra:
            parts.append("unexpected " + ", ".join(extra))
        return None, [f"path: {who}: keys differ ({'; '.join(parts)})"]
    problems: list[str] = []
    if not isinstance(ident, int) or isinstance(ident, bool) or ident < 1:
        problems.append(f"path: {who}: id must be an integer from 1, not {ident!r}")
    if raw["kind"] not in KINDS:
        problems.append(f"path: {who}: kind {raw['kind']!r} is not one of {', '.join(KINDS)}")
    if raw["source"] not in SOURCES:
        problems.append(f"path: {who}: source {raw['source']!r} is not one of {', '.join(SOURCES)}")
    for key, low in (("gap", 1), ("predicted", 0), ("source_ref", 0)):
        found = _text_problem(raw[key], key, low, MAX_LINE)
        if found:
            problems.append(f"path: {who}: {found}")
    deps = raw["depends_on"]
    if not isinstance(deps, list) or not all(_is_int(d) for d in deps):
        problems.append(f"path: {who}: depends_on must be a list of row ids")
    fold = raw["folds_into"]
    if fold is not None and not _is_int(fold):
        problems.append(f"path: {who}: folds_into must be a row id or null, not {fold!r}")
    if not isinstance(raw["is_rule"], bool):
        problems.append(f"path: {who}: is_rule must be true or false, not {raw['is_rule']!r}")
    if problems:
        return None, problems
    row = Row(
        ident if isinstance(ident, int) else 0,
        raw["kind"],
        raw["gap"],
        raw["predicted"],
        raw["source"],
        raw["source_ref"],
        tuple(deps),
        fold,
        raw["is_rule"],
    )
    return row, []


def _cycle(rows: list[Row]) -> list[int]:
    # Kahn: whatever cannot be placed sits on or behind a cycle.
    left = {r.id: set(r.depends_on) & {x.id for x in rows} for r in rows}
    while True:
        ready = [i for i, deps in left.items() if not deps]
        if not ready:
            return sorted(left)
        for i in ready:
            del left[i]
        for deps in left.values():
            deps.difference_update(ready)


def _structure(rows: list[Row]) -> list[str]:
    problems: list[str] = []
    seen: set[int] = set()
    for row in rows:
        if row.id in seen:
            problems.append(f"path: row id {row.id} appears more than once")
        seen.add(row.id)
    by_id = {r.id: r for r in rows}
    for row in rows:
        for dep in row.depends_on:
            if dep not in by_id:
                problems.append(
                    f"path: row {row.id}: depends_on names row {dep}, which does not exist"
                )
        if row.folds_into is not None:
            target = by_id.get(row.folds_into)
            if row.is_rule:
                problems.append(f"path: row {row.id}: a rule row must have folds_into null")
            elif target is None:
                problems.append(
                    f"path: row {row.id}: folds_into names a missing row {row.folds_into}"
                )
            elif not target.is_rule or target.kind != row.kind:
                problems.append(
                    f"path: row {row.id}: folds_into must name a rule row of kind {row.kind}"
                )
    if not problems:
        loop = _cycle(rows)
        if loop:
            problems.append(f"path: depends_on has a cycle among rows {', '.join(map(str, loop))}")
    return problems


def _shape(rows: list[Row]) -> list[str]:
    counts: dict[str, int] = {}
    for row in rows:
        if not row.is_rule and row.folds_into is None and row.kind != "other":
            counts[row.kind] = counts.get(row.kind, 0) + 1
    return [
        f"path: kind {kind} has {n} rows and no rule; fold them into one rule row"
        for kind, n in counts.items()
        if n >= 2
    ]


def _read_text(path: Path, label: str) -> str:
    try:
        if path.stat().st_size > MAX_BRIEF_BYTES:
            raise Refusal(
                [f"path: {label} file is over {MAX_BRIEF_BYTES} bytes"],
                "Next: pass a smaller file.",
            )
        return path.read_text(encoding="utf-8")
    except (OSError, ValueError):
        raise Refusal(
            [f"path: the {label} file {str(path)!r} cannot be read"], "Next: pass a readable file."
        ) from None


def _rule_ids(path: Path) -> set[str]:
    lines = _read_text(path, "rules").splitlines()
    out: set[str] = set()
    for start, column, end in ledger.id_table_spans(lines):
        for line in lines[start + 2 : end]:
            cells = ledger.split_row(line)
            if column < len(cells):
                out.add(cells[column].strip())
    return out


def _set_keys(repo: str) -> set[str]:
    # Reuses daedalus_setup.describe, the settings wizard's reader of all three files; a key
    # counts as set when its entry is set or default and holds a value other than null.
    import daedalus_setup

    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        daedalus_setup.describe(Path(repo))
    keys = json.loads(buf.getvalue())["keys"]
    return {
        k["key"]
        for k in keys
        if k.get("state") in ("set", "default") and not ("value" in k and k["value"] is None)
    }


def _sources(
    rows: list[Row], brief: Path | None, rules: Path | None, answers: list[str], repo: str
) -> list[str]:
    problems: list[str] = []
    keys = {key for _file, key in reference_keys()}
    set_keys = _set_keys(repo) if any(r.source == "setting" for r in rows) else set()
    heard = [_norm(a) for a in answers]
    if brief is not None:
        heard.append(_norm(_read_text(brief, "brief")))
    rule_ids = _rule_ids(rules) if rules is not None else None
    for row in rows:
        ref = row.source_ref
        if row.source == "setting" and ref not in keys:
            problems.append(f"path: row {row.id}: {ref!r} is not a settings key")
        elif row.source == "setting" and ref not in set_keys:
            problems.append(f"path: row {row.id}: the key {ref!r} has no value set in any file")
        elif row.source == "stated" and (
            len(_norm(ref)) < MIN_STATED_CHARS or len(_norm(ref).split()) < MIN_STATED_WORDS
        ):
            problems.append(
                f"path: row {row.id}: a stated sentence needs at least {MIN_STATED_WORDS} words "
                f"and {MIN_STATED_CHARS} characters"
            )
        elif row.source == "stated" and not any(_norm(ref) in h for h in heard):
            problems.append(
                f"path: row {row.id}: the sentence {ref!r} is not in the brief or an answer"
            )
        elif row.source == "rule" and (rule_ids is None or ref not in rule_ids):
            where = "no rules file was given" if rule_ids is None else "it is not in the rules file"
            problems.append(f"path: row {row.id}: rule {ref!r} not found ({where})")
        elif row.source == "profile":
            problems.append(f"path: row {row.id}: the profile source is not available yet")
        elif row.source == "default" and not ref:
            problems.append(f"path: row {row.id}: a default needs a source_ref")
        elif row.source == "none" and (row.predicted or ref or row.is_rule):
            problems.append(
                f"path: row {row.id}: source none needs empty predicted, source_ref and is_rule"
            )
        elif row.source != "none" and not (row.predicted and ref):
            problems.append(
                f"path: row {row.id}: predicted and source_ref are empty only when source is none"
            )
    return problems


def _status(row: Row, confidence: str) -> str:
    if row.is_rule:
        return "rule"
    if row.folds_into is not None:
        return "folded"
    if row.source == "none" or row.kind == "other":
        return "ask"
    if row.kind in ASKED_KINDS and confidence != "high":
        return "ask"
    return "decide"


def judge(
    handover: object, brief: Path | None, rules: Path | None, answers: list[str], repo: str
) -> tuple[list[Row], list[str]]:
    if (
        not isinstance(handover, dict)
        or set(handover) != {"rows"}
        or not isinstance(handover["rows"], list)
    ):
        return [], ['path: the handover must be {"rows": [...]} and nothing else']
    if not handover["rows"]:
        return [], ["path: rows is empty"]
    rows: list[Row] = []
    problems: list[str] = []
    for pos, raw in enumerate(handover["rows"], start=1):
        row, found = _parse_row(raw, pos)
        problems.extend(found)
        if row is not None:
            rows.append(row)
    if problems:
        return [], problems
    problems = _structure(rows)
    if problems:
        return [], problems
    problems = _shape(rows) + _sources(rows, brief, rules, answers, repo)
    done = [
        replace(r, confidence=CONFIDENCE[r.source], status=_status(r, CONFIDENCE[r.source]))
        for r in sorted(rows, key=lambda r: r.id)
    ]
    return done, problems


# ---------------------------------------------------------------- counts and order


def counts(rows: list[Row], answered: set[int]) -> dict[str, int]:
    ask = [r for r in rows if r.status == "ask"]
    return {
        "gaps": len(rows),
        "decided": sum(r.status == "decide" for r in rows),
        "rules": sum(r.status == "rule" for r in rows),
        "ask": len(ask),
        "to_ask": sum(r.id not in answered for r in ask),
        "answered": sum(r.id in answered for r in ask),
    }


def _counts_line(c: dict[str, int]) -> str:
    return (
        f"{c['gaps']} gaps: {c['decided']} decided, {c['rules']} rules, "
        f"{c['to_ask']} to ask, {c['answered']} answered"
    )


def _order(rows: list[Row]) -> list[Row]:
    by_id = {r.id: r for r in rows}
    done: set[int] = set()
    out: list[Row] = []
    while len(out) < len(rows):
        ready = sorted(r.id for r in rows if r.id not in done and set(r.depends_on) <= done)
        if not ready:
            break
        done.add(ready[0])
        out.append(by_id[ready[0]])
    return out


# ---------------------------------------------------------------- state and commands


@dataclass(frozen=True)
class State:
    versions: list[int]
    rows: list[Row]
    events: list[dict[str, Any]]

    @property
    def newest(self) -> int:
        return self.versions[-1]


def _state(ctx: Ctx) -> State:
    versions = _versions(ctx.folder)
    if not versions:
        raise Refusal(
            ["path: this conversation has no path yet"],
            f"Next: write the handover, then run `{ctx.cmd('check')}`.",
        )
    return State(versions, _load_version(ctx.folder, versions[-1]), _events(ctx.folder))


def _bad_handover(ctx: Ctx, problem: str | None, name: str) -> None:
    if problem is not None:
        raise Refusal([problem], f"Next: write {HANDOVER} again, then run `{ctx.cmd(name)}`.")


def _pass_line(number: int, rows: list[Row], extra: str = "") -> str:
    c = counts(rows, set())
    head = f"path ok v={number} gaps={c['gaps']} rules={c['rules']}"
    return f"{head} decided={c['decided']} ask={c['ask']}{extra}"


def _cmd_check(ctx: Ctx, args: argparse.Namespace) -> list[str]:
    data, problem = _take_handover(ctx.folder)
    if _versions(ctx.folder):
        raise Refusal(
            ["path: a path already exists for this conversation"],
            f"Next: run `{ctx.cmd('regenerate')}` after a shift, or open a new conversation.",
        )
    _bad_handover(ctx, problem, "check")
    answers = [e["response"] for e in _events(ctx.folder) if e["ev"] == "response"]
    rows, problems = judge(data, args.brief, args.rules, answers, ctx.repo)
    if problems:
        raise Refusal(
            problems,
            f"Next: write {HANDOVER} again with the rows fixed, then run `{ctx.cmd('check')}`.",
        )
    _write_version(ctx.folder, 1, rows)
    return [_pass_line(1, rows)]


def _cmd_propose(ctx: Ctx, args: argparse.Namespace) -> list[str]:
    state = _state(ctx)
    answered = set(_responses(state.events))
    c = counts(state.rows, answered)
    out = [_counts_line(c)]
    rules = [r for r in state.rows if r.status == "rule"]
    if rules:
        out.append("Rules:")
    for rule in rules:
        out.append(f"- Row {rule.id}: {rule.gap} -> {rule.predicted} ({SOURCE_WORDS[rule.source]})")
        out.extend(f"    covers row {r.id}: {r.gap}" for r in state.rows if r.folds_into == rule.id)
    decided = [r for r in state.rows if r.status == "decide"]
    if decided:
        out.append("Decided:")
    out.extend(
        f"- Row {r.id}: {r.gap} -> {r.predicted} ({SOURCE_WORDS[r.source]})" for r in decided
    )
    asks = [r for r in state.rows if r.status == "ask" and r.id not in answered]
    if asks:
        out.append("To ask:")
    out.extend(f"- Row {r.id}: {r.gap}" for r in asks)
    return out


def _cmd_ratify(ctx: Ctx, args: argparse.Namespace) -> list[str]:
    state = _state(ctx)
    if state.newest in _ratified(state.events):
        raise Refusal(
            ["path: this version is already ratified"],
            f"Next: run `{ctx.cmd('next')}` to get the next question to ask.",
        )
    if _shift_pending(state.events):
        raise Refusal(
            ["path: a shift is pending, so this list is out of date"],
            f"Next: write the handover, then run `{ctx.cmd('regenerate')}`.",
        )
    _append_log(ctx.folder, {"ev": "ratify", "v": state.newest})
    return [f"ratified v={state.newest}"]


def _cmd_next(ctx: Ctx, args: argparse.Namespace) -> list[str]:
    state = _state(ctx)
    if state.newest not in _ratified(state.events):
        raise Refusal(
            ["path: the newest version is not ratified"],
            f"Next: run `{ctx.cmd('propose')}`, then `{ctx.cmd('ratify')}` once the user agrees.",
        )
    if _shift_pending(state.events):
        raise Refusal(
            ["path: a shift is pending"],
            f"Next: write the handover, then run `{ctx.cmd('regenerate')}`.",
        )
    done = _responses(state.events)
    last = _last_handout(state.events)
    if last is not None and last not in done:
        raise Refusal(
            [f"path: row {last} was handed out and has no response recorded"],
            f"Next: write the handover, then run `{ctx.cmd('record')}`.",
        )
    for row in _order(state.rows):
        if row.status == "ask" and row.id not in done:
            _append_log(ctx.folder, {"ev": "handout", "id": row.id})
            return [f"next: {row.id}"]
    return ["next: none"]


def _record_problems(data: object, state: State) -> list[str]:
    keys = {"id", "response", "chosen", "typed", "touches"}
    if not isinstance(data, dict) or set(data) != keys:
        return [f"path: the handover must hold exactly {', '.join(sorted(keys))}"]
    out: list[str] = []
    if not _is_int(data["id"]):
        out.append(f"path: id must be a row id, not {data['id']!r}")
    found = _response_problem(data["response"])
    if found:
        out.append(f"path: {found}")
    found = _text_problem(data["chosen"], "chosen", 0, MAX_LINE)
    if found:
        out.append(f"path: {found}")
    if not isinstance(data["typed"], bool):
        out.append(f"path: typed must be true or false, not {data['typed']!r}")
    ids = {r.id for r in state.rows}
    touches = data["touches"]
    if not isinstance(touches, list) or not all(_is_int(t) and t in ids for t in touches):
        out.append("path: touches must be a list of existing row ids")
    return out


def _cmd_record(ctx: Ctx, args: argparse.Namespace) -> list[str]:
    data, problem = _take_handover(ctx.folder)
    state = _state(ctx)
    _bad_handover(ctx, problem, "record")
    problems = _record_problems(data, state)
    if problems:
        raise Refusal(problems, f"Next: write {HANDOVER} again, then run `{ctx.cmd('record')}`.")
    last = _last_handout(state.events)
    if last is None or data["id"] != last or last in _responses(state.events):
        raise Refusal(
            [f"path: row {data['id']} is not the row last handed out"],
            f"Next: run `{ctx.cmd('next')}` and record the row it names.",
        )
    row = next(r for r in state.rows if r.id == last)
    if data["typed"]:
        outcome = "typed"
    elif not row.predicted or _same(data["chosen"], row.predicted):
        outcome = "hit"
    else:
        outcome = "miss"
    shift = outcome == "typed" or (outcome == "miss" and row.confidence in ("high", "medium"))
    _append_log(
        ctx.folder,
        {
            "ev": "response", "id": row.id, "response": data["response"], "chosen": data["chosen"],
            "typed": data["typed"], "touches": data["touches"], "outcome": outcome, "shift": shift,
        },
    )  # fmt: skip
    return [f"recorded id={row.id} outcome={outcome} shift={'yes' if shift else 'no'}"]


def _cmd_fact(ctx: Ctx, args: argparse.Namespace) -> list[str]:
    data, problem = _take_handover(ctx.folder)
    state = _state(ctx)
    _bad_handover(ctx, problem, "fact")
    problems: list[str] = []
    if not isinstance(data, dict) or set(data) != {"fact", "kind"}:
        problems.append("path: the handover must hold exactly fact, kind")
    else:
        found = _text_problem(data["fact"], "fact", 1, MAX_LINE)
        if found:
            problems.append(f"path: {found}")
        if data["kind"] not in FACT_KINDS:
            problems.append(f"path: kind {data['kind']!r} is not one of {', '.join(FACT_KINDS)}")
    if problems:
        raise Refusal(problems, f"Next: write {HANDOVER} again, then run `{ctx.cmd('fact')}`.")
    _append_log(ctx.folder, {"ev": "fact", "kind": data["kind"], "fact": data["fact"]})
    del state
    return ["fact recorded shift=yes"]


def _answered_ok(row: Row, response: str) -> bool:
    # An answered row stays asked, or is decided only by a sentence its own answer holds.
    if row.status == "ask":
        return True
    return (
        row.status == "decide"
        and row.source == "stated"
        and _norm(row.source_ref) in _norm(response)
    )


def _regen_problems(rows: list[Row], state: State) -> list[str]:
    new = {r.id: r for r in rows}
    out: list[str] = []
    replies = _responses(state.events)
    for ident in sorted(replies):
        old = next((r for r in state.rows if r.id == ident), None)
        if old is None:
            continue
        got = new.get(ident)
        if got is None:
            out.append(f"path: row {ident} was answered and cannot be dropped")
        elif (got.kind, got.gap) != (old.kind, old.gap):
            out.append(f"path: row {ident} was answered; its kind and gap must stay as they were")
        elif not _answered_ok(got, replies[ident]["response"]):
            out.append(
                f"path: row {ident} has a recorded answer; it stays asked, or is decided only "
                "from a stated sentence found in that answer"
            )
    return out


def _moved(rows: list[Row], base: list[Row]) -> list[str]:
    old = {r.id: r for r in base}
    out: list[str] = []
    for row in rows:
        if row.status not in ("decide", "rule"):
            continue
        before = old.get(row.id)
        if before is None:
            out.append(f"moved: row {row.id}: (new row) -> {row.predicted}")
        elif before.status not in ("decide", "rule"):
            out.append(f"moved: row {row.id}: (asked) -> {row.predicted}")
        elif before.predicted != row.predicted:
            out.append(f"moved: row {row.id}: {before.predicted} -> {row.predicted}")
    return out


def _cmd_regenerate(ctx: Ctx, args: argparse.Namespace) -> list[str]:
    data, problem = _take_handover(ctx.folder)
    state = _state(ctx)
    if not _shift_pending(state.events):
        raise Refusal(
            ["path: no shift is pending"],
            f"Next: run `{ctx.cmd('next')}` to get the next question to ask.",
        )
    _bad_handover(ctx, problem, "regenerate")
    answers = [e["response"] for e in state.events if e["ev"] == "response"]
    rows, problems = judge(data, args.brief, args.rules, answers, ctx.repo)
    if not problems:
        problems = _regen_problems(rows, state)
    if problems:
        raise Refusal(
            problems,
            f"Next: rewrite {HANDOVER} with the rows fixed, then run `{ctx.cmd('regenerate')}`.",
        )
    ratified = [v for v in state.versions if v in _ratified(state.events)]
    base = _load_version(ctx.folder, ratified[-1]) if ratified else state.rows
    moved = _moved(rows, base)
    number = state.newest + 1
    _write_version(ctx.folder, number, rows)
    _append_log(ctx.folder, {"ev": "regenerate", "v": number, "moved": len(moved)})
    if not moved and ratified:
        _append_log(ctx.folder, {"ev": "ratify", "v": number, "inherited": True})
    return [*moved, _pass_line(number, rows, f" moved={len(moved)}")]


def _cmd_status(ctx: Ctx, args: argparse.Namespace) -> list[str]:
    state = _state(ctx)
    c = counts(state.rows, set(_responses(state.events)))
    shift = "yes" if _shift_pending(state.events) else "no"
    ratified = "yes" if state.newest in _ratified(state.events) else "no"
    return [_counts_line(c), f"shift={shift} ratified={ratified} v={state.newest}"]


# ---------------------------------------------------------------- entry


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> NoReturn:
        raise Refusal(
            [f"path: {message}"],
            f"Next: run `{SCRIPT} --help` to read the commands and their flags.",
        )


COMMANDS = {
    "check": _cmd_check,
    "propose": _cmd_propose,
    "ratify": _cmd_ratify,
    "next": _cmd_next,
    "record": _cmd_record,
    "fact": _cmd_fact,
    "regenerate": _cmd_regenerate,
    "status": _cmd_status,
}
WITH_FILES = ("check", "regenerate")


def _parser() -> argparse.ArgumentParser:
    parser = _Parser(prog=SCRIPT)
    sub = parser.add_subparsers(dest="command", required=True)
    opener = sub.add_parser("open")
    opener.add_argument("--repo", required=True)
    for name in COMMANDS:
        one = sub.add_parser(name)
        one.add_argument("--repo", required=True)
        one.add_argument("--conv", required=True)
        if name in WITH_FILES:
            one.add_argument("--brief", type=Path)
            one.add_argument("--rules", type=Path)
    return parser


def _open(repo: str) -> list[str]:
    conv = datetime.now(UTC).strftime(STAMP_FORMAT)
    try:
        folder = make_conv(repo, conv)
    except FileExistsError:
        raise Refusal(
            [f"path: conversation {conv} already exists"],
            f"Next: run `{SCRIPT} open --repo {repo}` again in a second.",
        ) from None
    return [f"path: open conv={conv} handover={folder / HANDOVER}"]


def run(argv: list[str]) -> list[str]:
    args = _parser().parse_args(argv)
    if args.command == "open":
        return _open(args.repo)
    return COMMANDS[args.command](_open_ctx(args.repo, args.conv), args)


def main(argv: list[str] | None = None) -> int:
    import sys

    try:
        lines = run(sys.argv[1:] if argv is None else argv)
    except Refusal as refusal:
        print("\n".join([*refusal.problems, refusal.next_step]))
        return 1
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"path: {exc}\nNext: fix that, then rerun the command.")
        return 1
    print("\n".join(lines))
    return 0
