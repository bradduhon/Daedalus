# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# W3.2 (0046): the train summary in the shape of agents/orchestrator.md step 6, rendered from the
# train state, the audit logs and one orchestrator-written notes file; it is a public PR body.
from __future__ import annotations

import html
import json
import os
import re
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path

from lib import train_state
from lib.audit_proof import (
    _SESSION_LINE,
    AUDIT_DIR,
    AUDITOR,
    HANDBACK,
    SUMMARY_DIR,
    TIP,
    VERDICT_APPROVED,
    VERDICT_REJECTED,
    handback_message,
)
from lib.jail import normalize_agent
from lib.narrow import integer as _int
from lib.narrow import obj as _obj
from lib.narrow import strings as _strings
from lib.narrow import text as _text
from lib.plan_record import Version

NOTES_FILE = "summary-notes.md"
# pin D1 -> E4: the ledger record `daedalus_train.py ledger` writes, and the pending line.
LEDGER = "ledger"
LEDGER_PENDING = "Ledger ids: pending"
_SESSION_ID = re.compile(r"[A-Za-z0-9_-]+")
NO_NOTES = "not recorded (no summary notes file)"
NOT_RUN = "not run (no IAM, KMS, mTLS, key custody or infrastructure change)"
NOTE_FIELDS = ("Task", "Codes", "Migration")
NOTE_SECTIONS = ("Rulings", "Blocks", "Waived")
_CODES = re.compile(r"--repo [A-Za-z0-9]{1,16} --type [A-Za-z0-9]{1,16}")
# W3.2 allow-list: a token is a run between whitespace and the marks that can wrap a path; it
# is path-like when it holds `/`, `\` or a percent-encoded slash, and passes only as a plain
# relative path under the repo or the Charter.
_TOKEN = re.compile(r"[^\s\"'`()<>\[\]{},;|=*]+")
_PATH_LIKE = re.compile(r"[/\\]|%2f|%5c", re.IGNORECASE)
_COMPONENT = re.compile(r"[A-Za-z0-9_.][A-Za-z0-9_.+-]*")
_NODE = re.compile(r"[A-Za-z0-9_.:-]+")
_LINE_SUFFIX = re.compile(r"(?::[0-9]+)+$")
# W3.2: the one marker a refused path from the audit log or train state prints as.
WITHHELD = "[path withheld]"
_TRAILING = ".,:;!?"
_MD_ESCAPED = re.compile(r"\\(.)")
_COMPLETE = re.compile(
    r"\[STATUS: COMPLETE\] branch=(\S+) packet_version=(\S+) files=(.*?) tests=(.*?) ledger_notes="
)
_YIELD = re.compile(r"\[STATUS: (YIELD_[A-Z]+)\]\s*(.*)")
_COMPLIANCE = re.compile(r"\[STATUS: COMPLIANCE\]\s*(.*)")
_VERIFIER = re.compile(r"\[VERDICT: (VERIFIED|REFUTED)\]\s*(.*)")
# 0127: agents/verifier.md status contract, the line directly above the closing verdict.
_CORRECTED = re.compile(r"corrected=([0-9]+)")
_UNIT_WORKTREE = re.compile(r"Unit worktree: (\S+)")
_LEDGER_PATH = re.compile(r"ledger: (.+?) \(")
_DISPATCH_TOOLS = ("Agent", "Task", "SendMessage")
_REFUSALS = ("block", "ask")
_ANSWERERS: dict[str, tuple[str, ...]] = {
    "YIELD_WEB": ("web-researcher",),
    "YIELD_CONTRACT": ("contract-spec",),
    "YIELD_COMPLIANCE": ("nist-specialist", "cis-specialist"),
    "YIELD_STANDARDS": ("standards-rules-specialist",),
}
# 0132: the two diff-content judges list into Compliance too, never into the audit gate.
_COMPLIANCE_AGENTS = (
    "nist-specialist",
    "cis-specialist",
    "dependency-auditor",
    "terraform-reviewer",
)
_CELL_CHARS = 300
_PARAGRAPH_CHARS = 600

Record = Mapping[str, object]


class SummaryError(RuntimeError):
    pass


@dataclass(frozen=True)
class Notes:
    found: bool = False
    fields: dict[str, str] = field(default_factory=dict)
    sections: dict[str, list[str]] = field(default_factory=dict)


@dataclass(frozen=True)
class SessionLog:
    session: str
    path: Path
    records: Sequence[Record]


@dataclass(frozen=True)
class Reply:
    seq: int
    agent: str
    agent_id: str
    text: str

    @property
    def rows(self) -> list[str]:
        return [ln.strip() for ln in self.text.splitlines() if ln.strip()]

    @property
    def last(self) -> str:
        rows = self.rows
        return rows[-1] if rows else ""

    @property
    def corrected(self) -> int | None:
        # 0127: None when no `corrected=<k>` line sits above the closing line, never a zero.
        rows = self.rows
        found = _CORRECTED.fullmatch(rows[-2]) if len(rows) > 1 else None
        return int(found.group(1)) if found else None


def summary_path(repo: Path, train_id: str) -> Path:
    return repo / SUMMARY_DIR / f"{train_id}-summary.md"


def notes_path(repo: Path, train_id: str) -> Path:
    return repo / SUMMARY_DIR / train_id / NOTES_FILE


def parse_notes(text: str, where: str) -> Notes:
    # W3.2: `Field: value` lines, then `## <section>` blocks; a Session line could spoof the proof.
    fields: dict[str, str] = {}
    sections: dict[str, list[str]] = {}
    current: list[str] | None = None
    for number, raw in enumerate(text.splitlines(), start=1):
        # Every row is judged with its leading whitespace stripped, as the summary prints it.
        line = raw.strip()
        if _SESSION_LINE.match(line):
            raise SummaryError(
                f"line {number} of {where} starts with `Session <id>:`, the audit log line the "
                "push proof reads. Next: reword that line, then rerun summary."
            )
        if line.startswith("#"):
            name = line[3:].strip() if line.startswith("## ") else line
            if not line.startswith("## ") or name not in NOTE_SECTIONS or name in sections:
                raise SummaryError(
                    f"line {number} of {where} opens section {name!r}; the notes hold each of "
                    f"{', '.join(NOTE_SECTIONS)} at most once. Next: fix the notes, then rerun "
                    "summary."
                )
            current = sections.setdefault(name, [])
            continue
        if current is not None:
            if line:
                current.append(line)
            continue
        if not line:
            continue
        key, sep, value = line.partition(": ")
        if not sep or key not in NOTE_FIELDS or key in fields or not value.strip():
            raise SummaryError(
                f"line {number} of {where} is not one of the lines {', '.join(NOTE_FIELDS)} "
                "(`<name>: <value>`, each once) before the first section. Next: fix the notes, "
                "then rerun summary."
            )
        fields[key] = value.strip()
    codes = fields.get("Codes")
    if codes is not None and not _CODES.fullmatch(codes):
        raise SummaryError(
            f"the Codes line of {where} is not `--repo <R> --type <T>`. Next: fix it, then rerun "
            "summary."
        )
    return Notes(True, fields, sections)


LOG_NEXT = "Next: report it to the operator; an audit log record is never edited."
NOTES_NEXT = f"Next: remove that path from {NOTES_FILE}, then rerun summary."


def _under(path: Path, root: Path) -> bool:
    real, base = os.path.realpath(path), os.path.realpath(root)
    return real == base or real.startswith(base + os.sep)


def plain_path(token: str, repo: Path, charter: Path | None) -> bool:
    # W3.2: every component a plain ASCII name, so no scheme, leading or doubled slash, drive,
    # backslash, `~`, `%`, `$`, `@`, `..` or glued prefix, and the path resolves inside.
    path = _LINE_SUFFIX.sub("", token.rstrip(_TRAILING))
    path, _, node = path.partition("::")
    if node and not _NODE.fullmatch(node):
        return False
    path = path.removesuffix("/")
    parts = path.split("/")
    if not path or ".." in parts or not all(_COMPONENT.fullmatch(part) for part in parts):
        return False
    if charter is not None and parts[0] == charter.name and _under(charter.parent / path, charter):
        return True
    return _under(repo / path, repo)


def _relative(text: str, root: Path, label: str) -> str:
    text = text.replace(f"{root}/", f"{label}/" if label else "")
    return re.sub(re.escape(str(root)) + r"(?![\w./-])", label or ".", text)


def public(
    text: str,
    repo: Path,
    charter: Path | None,
    where: str,
    fix: str = LOG_NEXT,
    withhold: bool = False,
) -> str:
    # W3.2: a public PR body; repo and Charter paths go relative. Any other path refuses, or,
    # for text from the audit log or train state, which nobody can edit, becomes the marker.
    if charter is not None:
        text = _relative(text, charter, charter.name)
    text = _relative(text, repo, "")
    kept: list[str] = []
    start = 0
    for match in _TOKEN.finditer(text):
        token = match.group(0)
        # A lone `/` is a prose separator ("pass / fail"), not a path; `//` and longer are paths.
        if token == "/" or not _PATH_LIKE.search(token) or plain_path(token, repo, charter):
            continue
        if not withhold:
            raise SummaryError(
                f"{where} carries the path {token!r}, which is not a plain relative path under "
                f"this repository or the Charter, so no summary was written. {fix}"
            )
        kept += [text[start : match.start()], WITHHELD]
        start = match.end()
    return "".join([*kept, text[start:]])


def _seq(record: Record) -> int:
    value = record.get("seq")
    return value if isinstance(value, int) and not isinstance(value, bool) else 0


def _agent(record: Record) -> str:
    raw = record.get("agent_type")
    return normalize_agent(raw) if isinstance(raw, str) else ""


def replies(records: Sequence[Record]) -> list[Reply]:
    # issue 57: a reply is a hand-back call or a stop's tail; a stop relaying the same line is one.
    found: list[Reply] = []
    last: dict[str, str] = {}
    for record in records:
        event, tool = record.get("event"), record.get("tool_name")
        if event == "PostToolUse" and tool == HANDBACK:
            raw = handback_message(record)
        elif event == "SubagentStop":
            raw = record.get("last_message_tail") or record.get("last_message_head")
        else:
            continue
        if not isinstance(raw, str) or not raw.strip():
            continue
        agent_id = _text(record, "agent_id")
        reply = Reply(_seq(record), _agent(record), agent_id, raw)
        if agent_id and last.get(agent_id) == reply.last:
            continue
        last[agent_id] = reply.last
        found.append(reply)
    return found


def _input_text(record: Record) -> str:
    value = record.get("tool_input")
    return value if isinstance(value, str) else json.dumps(value, ensure_ascii=False)


def _unit_paths(units: Sequence[dict[str, object]]) -> list[tuple[str, re.Pattern[str]]]:
    named = [(_text(u, "name"), _text(u, "path")) for u in units if _text(u, "path")]
    named.sort(key=lambda pair: len(pair[1]), reverse=True)
    return [(name, re.compile(re.escape(path) + r"(?=/|\s|$|[\"'])")) for name, path in named]


def _unit_in(text: str, paths: list[tuple[str, re.Pattern[str]]]) -> str | None:
    return next((name for name, pattern in paths if pattern.search(text)), None)


def _cell(
    value: str, repo: Path, charter: Path | None, where: str, limit: int = _CELL_CHARS
) -> str:
    from audit_report import md_escape

    return md_escape(public(value, repo, charter, where, withhold=True), limit) or "-"


def _source(reply: Reply, log: SessionLog) -> str:
    return f"the {reply.agent or 'unnamed agent'} reply at seq {reply.seq} of session {log.session}"


@dataclass
class _Facts:
    complete: dict[str, tuple[str, str, str, str]] = field(default_factory=dict)
    verified: dict[str, tuple[str, str, int | None]] = field(default_factory=dict)
    yields: list[tuple[str, str, str, str, str]] = field(default_factory=list)
    compliance: list[tuple[str, str, str]] = field(default_factory=list)
    blocks: Counter[tuple[str, str]] = field(default_factory=Counter)


def _gather(logs: Sequence[SessionLog], units: Sequence[dict[str, object]]) -> _Facts:
    from audit_report import _hook_of

    facts = _Facts()
    paths = _unit_paths(units)
    for log in logs:
        records = list(log.records)
        found = replies(records)
        for reply in found:
            line, where = reply.last, _source(reply, log)
            done = _COMPLETE.search(line)
            if reply.agent == "repo-coder" and done:
                packet, files, tests = done.group(2), done.group(3), done.group(4)
                facts.complete[done.group(1)] = (packet, files, tests, where)
            asked = _YIELD.match(line)
            if reply.agent == "repo-coder" and asked:
                facts.yields.append((*_yield_row(records, found, reply, asked, paths), where))
            listed = _COMPLIANCE.match(line)
            if reply.agent in _COMPLIANCE_AGENTS and listed:
                facts.compliance.append((reply.agent, listed.group(1), where))
            judged = _VERIFIER.match(line)
            if reply.agent == "verifier" and judged:
                unit = _verified_unit(records, reply.seq, paths)
                if unit is not None:
                    facts.verified[unit] = (line, where, reply.corrected)
        for record in records:
            if record.get("event") == "PreToolUse" and record.get("decision") in _REFUSALS:
                facts.blocks[(_hook_of(dict(record)), _agent(record) or "main")] += 1
    return facts


def _yield_row(
    records: list[Record],
    found: list[Reply],
    reply: Reply,
    asked: re.Match[str],
    paths: list[tuple[str, re.Pattern[str]]],
) -> tuple[str, str, str, str]:
    # 0083: a coder commits WIP in its worktree before it yields, so its last call names the unit.
    unit = None
    for record in reversed(records):
        if _seq(record) >= reply.seq or record.get("event") != "PreToolUse":
            continue
        if _text(record, "agent_id") != reply.agent_id:
            continue
        unit = _unit_in(_input_text(record), paths)
        if unit is not None:
            break
    kind = asked.group(1)
    want = _ANSWERERS.get(kind, ())
    answer = next((r.agent for r in found if r.seq > reply.seq and r.agent in want), None)
    return unit or "", kind, asked.group(2), answer or "no answer recorded"


def _verified_unit(
    records: list[Record], seq: int, paths: list[tuple[str, re.Pattern[str]]]
) -> str | None:
    # spec 5: the verifier's brief names its unit on a `Unit worktree:` line.
    for record in reversed(records):
        if _seq(record) >= seq or record.get("event") != "PreToolUse":
            continue
        if record.get("tool_name") not in _DISPATCH_TOOLS or record.get("decision") in _REFUSALS:
            continue
        named = _UNIT_WORKTREE.search(_input_text(record).replace("\\n", "\n"))
        if named is not None:
            return _unit_in(named.group(1), paths)
    return None


def _located(path: str, repo: Path, charter: Path | None, prefix_repo: bool) -> str:
    target = Path(path)
    if charter is not None and target.is_relative_to(charter):
        return f"{charter.name}/{target.relative_to(charter).as_posix()}"
    if target.is_relative_to(repo):
        rel = target.relative_to(repo).as_posix()
        return f"{repo.name}/{rel}" if prefix_repo else rel
    return target.name


def _ledger_lines(state: dict[str, object], notes: Notes) -> str:
    ledger = train_state.record(state, LEDGER)
    if not ledger:
        codes = notes.fields.get("Codes")
        return f"{LEDGER_PENDING}." + (f" Codes: {codes}." if codes else "")
    sha, ids = ledger.get("sha"), _strings(ledger.get("ids"))
    if not isinstance(sha, str) or not TIP.fullmatch(sha) or not ids:
        raise SummaryError(
            "the train's ledger record names no commit sha or no ids. Next: rerun "
            "daedalus_train.py ledger with the sha and ids of charter-docs' COMMITTED line, then "
            "rerun summary."
        )
    return f"Ledger ids: {','.join(ids)} in commit {sha}."


def _header(
    repo: Path,
    train_id: str,
    state: dict[str, object],
    notes: Notes,
    policy_declared: bool,
    version: Version | None,
) -> list[str]:
    charter_raw = _text(state, "charter_root")
    charter = Path(charter_raw) if charter_raw else None
    ledger_match = _LEDGER_PATH.match(_text(state, "ledger_line"))
    ledger = ledger_match.group(1) if ledger_match else ""
    under = charter is not None and bool(ledger) and Path(ledger).is_relative_to(charter)
    base = f"{_text(state, 'base_branch') or 'unknown'} @ {_text(state, 'base_sha') or 'unknown'}"
    lines = [
        f"# Build Train {train_id}",
        f"Task: {_note(notes.fields.get('Task', NO_NOTES), repo, charter, 'Task line')}",
        f"Base: {base}. Integration branch: daedalus/{train_id}.",
    ]
    if charter is None:
        lines.append("charter: none (repo-local ledger)")
    else:
        where = "ledger under charter_root" if under else "ledger repo-local"
        lines.append(
            f"charter: {charter.name}, branch daedalus/{train_id}, charter base: "
            f"{_text(state, 'charter_base') or 'none'} ({where})"
        )
    packet = _int(state, "packet_version", 0)
    shown = _located(ledger, repo, charter, True) if ledger else "not recorded"
    lines.append(f"Packet: {f'v{packet}' if packet else 'not locked'}. Ledger: {shown}.")
    contract = _text(state, "contract_path")
    if contract:
        lines.append(f"Contract: {_located(contract, repo, charter, False)} v{packet}")
    else:
        lines.append("Contract: not locked")
    lines.append(_ledger_lines(state, notes))
    # W3.2: the train state lines above withhold a path; the Task line already passed the check.
    lines = [public(line, repo, charter, "the train state", withhold=True) for line in lines]
    lines.append(
        f"[POLICY: {'declared, gate not yet shipped' if policy_declared else 'none declared'}]"
    )
    if version is not None:
        lines.append(
            public(
                version.summary_line,
                repo,
                charter,
                "the recorded plan's version line",
                "Next: reword the plan's version reason, record the plan, then rerun summary.",
            )
        )
        if version.change_class == "X":
            migration = notes.fields.get("Migration")
            if migration is None:
                raise SummaryError(
                    "the plan's version line is class X, and the summary notes carry no "
                    "`Migration: <what an operator edits>` line. Next: add it to the notes, then "
                    "rerun summary."
                )
            lines.append(f"Migration: {_note(migration, repo, charter, 'Migration line')}")
    return lines


def _note(text: str, repo: Path, charter: Path | None, row: str) -> str:
    return public(text, repo, charter, f"the {row} of {NOTES_FILE}", NOTES_NEXT)


def _noted(notes: Notes, name: str, empty: str, repo: Path, charter: Path | None) -> list[str]:
    if name not in notes.sections:
        return [NO_NOTES if not notes.found else f"not recorded in the summary notes ({name})"]
    rows = notes.sections[name]
    found = [_note(r, repo, charter, f"{name} row {n}") for n, r in enumerate(rows, start=1)]
    return found or [empty]


def _units(
    repo: Path, train_id: str, units: Sequence[dict[str, object]], facts: _Facts
) -> list[str]:
    lines = ["## Units", "| Unit | Branch | Packet | Files | Tests |", "|---|---|---|---|---|"]
    for unit in units:
        branch = _text(unit, "branch")
        packet, files, tests, where = facts.complete.get(branch, ("", "", "", ""))
        state = f"the train state unit {_text(unit, 'name')}"
        cells = [
            _cell(_text(unit, "name").removeprefix(f"{train_id}-"), repo, None, state),
            _cell(branch, repo, None, state),
            _cell(f"v{packet}" if packet else "", repo, None, where),
            _cell(files, repo, None, where),
            _cell(tests, repo, None, where),
        ]
        lines.append(f"| {' | '.join(cells)} |")
    return lines


def _exempted(exempt: dict[str, object], repo: Path, charter: Path | None) -> list[str]:
    # 0133, 0139: each exempted finding with its ledger id and tracking; 0142: untracked ones
    # carry a Deviation: line naming the finding and its exemption row.
    lines: list[str] = []
    for key in sorted(exempt):
        entry = _obj(exempt, key)
        where = f"the train state exemption of {key}"
        finding = _cell(key, repo, charter, "a train state finding key")
        ledger = _cell(_text(entry, "ledger_id"), repo, charter, where)
        tracking = _text(entry, "tracking")
        label = train_state.TRACKING.get(tracking, "not recorded")
        if tracking == "other":
            label = f"{label}: {_cell(_text(entry, 'other'), repo, charter, where)}"
        lines.append(f"- Exempted {finding} ({ledger}), tracking: {label}")
        if tracking in train_state.UNTRACKED:
            lines.append(
                f"Deviation: finding {finding} exempted with no tracked issue ({label}), "
                f"exemption row {ledger}."
            )
    return lines


def _audit(
    repo: Path, state: dict[str, object], logs: Sequence[SessionLog], notes: Notes
) -> list[str]:
    charter_raw = _text(state, "charter_root")
    charter = Path(charter_raw) if charter_raw else None
    verdict = train_state.record(state, train_state.VERDICT)
    rounds = train_state.record(state, train_state.AUDIT_ROUNDS)
    status, tip = _text(verdict, "status"), _text(verdict, "tip")
    last = _int(verdict, "round", 0)
    keys = [int(k) for k in rounds if k.isdigit()]
    top = max([last, *keys], default=0)
    exempt = train_state.record(train_state.record(state, train_state.EXEMPTIONS), str(last))
    lines = ["## Audit"]
    if status == train_state.REJECTED and exempt:
        lines.append(
            f"{VERDICT_REJECTED} tip={tip} after {last} round(s); the operator exempted "
            f"{len(exempt)} of the {len(_obj(rounds, str(last)))} finding(s) of round {last}."
        )
        lines += _exempted(exempt, repo, charter)
        if "Waived" in notes.sections:
            lines += _noted(notes, "Waived", "none", repo, charter)
    elif status == train_state.APPROVED:
        lines.append(
            f"{VERDICT_APPROVED} tip={tip} on the merged integration tip after {last} round(s)."
        )
        paragraph, where = _paragraph(logs, _int(verdict, "seq", 0), _text(state, "audit_session"))
        if paragraph:
            lines.append(f"Auditor: {_cell(paragraph, repo, charter, where, _PARAGRAPH_CHARS)}")
    elif status == train_state.REJECTED:
        lines.append(f"{VERDICT_REJECTED} tip={tip} after {last} round(s).")
    else:
        lines.append("Verdict: pending")
    for number in range(1, top + 1):
        entry = rounds.get(str(number))
        if isinstance(entry, dict) and entry:
            levels = Counter(
                _text(v, "severity") or "unrated" for v in entry.values() if isinstance(v, dict)
            )
            counts = ", ".join(f"{n} {level}" for level, n in sorted(levels.items()))
            lines.append(f"Round {number}: rejected, {len(entry)} finding(s) ({counts})")
        elif number == last and status:
            lines.append(f"Round {number}: {status}")
        elif isinstance(entry, dict):
            lines.append(f"Round {number}: no findings recorded")
        else:
            lines.append(f"Round {number}: not recorded in train state")
    return lines + _docs(state, repo, charter)


def _docs(state: dict[str, object], repo: Path, charter: Path | None) -> list[str]:
    # 0131, 0134: the docs verdict beside the security verdict; no record reads as not run.
    docs = train_state.record(state, train_state.DOCS_VERDICT)
    status, tip = _text(docs, "status"), _text(docs, "tip")
    if status == train_state.VERIFIED:
        return [f"Docs: verified on tip {tip}"]
    if status != train_state.REFUTED:
        return ["Docs: not run"]
    claims, exempt = _obj(docs, "findings"), _obj(docs, "exemptions")
    head = f"Docs: refuted on tip {tip}; the operator exempted {len(exempt)} of the "
    return [f"{head}{len(claims)} claim(s)", *_exempted(exempt, repo, charter)]


def _paragraph(logs: Sequence[SessionLog], seq: int, session: str) -> tuple[str, str]:
    # 0089: the auditor reply the verdict record names, minus its verdict lines.
    if seq < 1:
        return "", ""
    ordered = sorted(logs, key=lambda log: log.session != session)
    for log in ordered:
        for record in log.records:
            if _seq(record) != seq or record.get("agent_type") != AUDITOR:
                continue
            raw = (
                handback_message(record)
                if record.get("tool_name") == HANDBACK
                else record.get("last_message_head")
            )
            if not isinstance(raw, str):
                return "", ""
            kept = [ln for ln in raw.splitlines() if not ln.strip().startswith("[VERDICT:")]
            paragraphs = "\n".join(kept).split("\n\n")
            body = next((" ".join(p.split()) for p in paragraphs if p.strip()), "")
            return body, f"the security-auditor reply at seq {seq} of session {log.session}"
    return "", ""


def render(
    repo: Path,
    train_id: str,
    state: dict[str, object],
    logs: Sequence[SessionLog],
    notes: Notes,
    policy_declared: bool,
    version: Version | None,
) -> str:
    # W3.2: logs[0] is the session that runs the command; the proof reads its Session line first.
    from audit_report import ReportError, _totals, md_escape

    charter_raw = _text(state, "charter_root")
    charter = Path(charter_raw) if charter_raw else None
    units = [u for u in train_state.units(state) if not train_state.is_audit_unit(u)]
    # The other sessions came first in time; the running session is the newest.
    facts = _gather([*logs[1:], *logs[:1]], units)
    labels = {_text(u, "name"): _text(u, "name").removeprefix(f"{train_id}-") for u in units}
    lines = _header(repo, train_id, state, notes, policy_declared, version)
    lines += ["## Rulings", *_noted(notes, "Rulings", "none", repo, charter)]
    lines += _units(repo, train_id, units, facts)
    lines.append("## Verification")
    verified = [
        f"- {labels[n]}: {_cell(line, repo, charter, where)}"
        + ("" if corrected is None else f" corrected={corrected}")
        for n, (line, where, corrected) in facts.verified.items()
        if n in labels
    ]
    lines += verified or ["none"]
    lines.append("## Yields")
    lines += [
        f"- {labels.get(unit, 'unknown unit')}: {kind} {_cell(question, repo, charter, where)} "
        f"(answered by {who})"
        for unit, kind, question, who, where in facts.yields
    ] or ["none"]
    lines.append("## Compliance")
    lines += [
        f"- {agent}: {_cell(listed, repo, charter, where)}"
        for agent, listed, where in facts.compliance
    ] or [NOT_RUN]
    lines += _audit(repo, state, logs, notes)
    lines.append("## Blocks")
    if "Blocks" in notes.sections:
        lines += _noted(notes, "Blocks", "Friction: none", repo, charter)
    else:
        lines += [f"Friction: {NO_NOTES}", f"Habit: {NO_NOTES}"]
    lines.append("Recorded blocks per hook:")
    lines += [
        f"- {md_escape(hook)}, {_cell(agent, repo, charter, 'an audit record agent type')}: {n}"
        for (hook, agent), n in sorted(facts.blocks.items())
    ] or ["- none"]
    lines.append("## Audit log")
    lines += [
        f"Session {log.session}: {(AUDIT_DIR / f'{log.session}.jsonl').as_posix()}" for log in logs
    ]
    if not logs:
        lines.append("none")
    for log in logs:
        try:
            totals = _totals([dict(r) for r in log.records], log.path)
        except ReportError as exc:
            raise SummaryError(f"{exc}. Next: keep the audit log, report it.") from exc
        lines += [f"### Audit totals, session {log.session}", *totals[2:]]
    text = "\n".join(lines) + "\n"
    # W3.2: a last pass over the whole body, with the Markdown escapes taken back out.
    # The pass reads the body as it stood before md_escape: its backslashes come out first,
    # then its HTML entities, so escaping never makes a token the checked fields lacked.
    unescaped = html.unescape(_MD_ESCAPED.sub(r"\1", text))
    public(unescaped, repo, charter, "the rendered summary (train state)")
    # W3.2: the proof reads the first Session line, so only the Audit log section carries any.
    found = list(_SESSION_LINE.finditer(text))
    section = text.find("\n## Audit log\n")
    named = [m.group(1) for m in found]
    if named != [log.session for log in logs] or any(m.start() < section for m in found):
        raise SummaryError(
            "the rendered summary carries a `Session <id>:` line outside its audit log section. "
            "Next: report it; the summary was not written."
        )
    return text


def load_logs(repo: Path, state: dict[str, object], first: str | None) -> list[SessionLog]:
    # W3.2: the running session first, then every session the train bound; missing logs skip.
    from lib.audit_proof import ProofError, read_chain

    named = [first, *_obj(state, train_state.AUDIT_BOUNDS), _text(state, train_state.AUDIT_SESSION)]
    order: list[str] = []
    for session in named:
        if session and _SESSION_ID.fullmatch(session) and session not in order:
            order.append(session)
    logs: list[SessionLog] = []
    for session in order:
        path = repo / AUDIT_DIR / f"{session}.jsonl"
        if not path.is_file():
            continue
        try:
            logs.append(SessionLog(session, path, read_chain(path)))
        except ProofError as exc:
            raise SummaryError(str(exc)) from exc
    # Train state stores its bounds with sorted keys, so the other sessions go oldest first.
    head = [log for log in logs if log.session == first]
    rest = sorted((log for log in logs if log.session != first), key=_mtime)
    if not head and rest:
        head = [rest.pop()]
    return head + rest


def _mtime(log: SessionLog) -> int:
    try:
        return log.path.stat().st_mtime_ns
    except OSError:
        return 0


def read_notes(repo: Path, train_id: str) -> Notes:
    path = notes_path(repo, train_id)
    where = path.relative_to(repo).as_posix()
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return Notes()
    except (OSError, UnicodeDecodeError) as exc:
        raise SummaryError(
            f"cannot read {where} ({exc}). Next: save the notes as UTF-8 text, then rerun."
        ) from exc
    return parse_notes(text, where)


def plan_version(state: dict[str, object]) -> Version | None:
    # pin D4 -> D5: the recorded plan's optional version line.
    from lib.plan_record import PlanError, load

    raw = _text(train_state.record(state, train_state.PLAN), "path")
    if not raw:
        return None
    try:
        return load(Path(raw)).version
    except PlanError as exc:
        raise SummaryError(f"{exc} Next: restore the recorded plan, then rerun summary.") from exc


def first_session(repo: Path, train_id: str) -> str | None:
    # W3.2: a rewrite keeps the session the summary already names first, the one the proof reads.
    try:
        text = summary_path(repo, train_id).read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return None
    match = _SESSION_LINE.search(text)
    return match.group(1) if match else None


def write_summary(repo: Path, train_id: str, session: str | None) -> str:
    from lib import atomic
    from lib.config import ConfigError, load_config

    state = train_state.load(repo, train_id)
    notes = read_notes(repo, train_id)
    try:
        declared = load_config(cwd=str(repo)).policy is not None
    except ConfigError as exc:
        raise SummaryError(str(exc)) from exc
    text = render(
        repo, train_id, state, load_logs(repo, state, session), notes, declared, plan_version(state)
    )
    path = summary_path(repo, train_id)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        atomic.write_atomic(path, text)
    except OSError as exc:
        raise SummaryError(
            f"cannot write {path.name} ({exc}). Next: fix the folder, rerun."
        ) from exc
    ledger = "recorded" if train_state.record(state, LEDGER) else "pending"
    return (
        f"summary written train={train_id} path={path.relative_to(repo).as_posix()} ledger={ledger}"
    )
