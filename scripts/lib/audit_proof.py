# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import json
import re
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

from lib.audit import GENESIS, record_hash

AUDIT_DIR = Path(".claude") / "daedalus" / "audit"
SUMMARY_DIR = Path("docs") / ".tmp" / "daedalus"
NOT_UTF8 = "BROKEN: {path} is not valid UTF-8. Next: keep the file, report it, do not edit it."
DOCTOR_NEXT = "Next: run the Daedalus health check (/daedalus:doctor)."
APPROVED_NEXT = "Next: run /daedalus:build-train; this train has no approved audit in its log."
AUDITOR = "daedalus:security-auditor"
VERDICT_APPROVED = "[VERDICT: APPROVED]"
VERDICT_REJECTED = "[VERDICT: REJECTED]"
_VERDICT_FIELDS = ("last_message_head", "last_message_tail")
_TRAIN_ID = re.compile(r"[0-9]{8}-[0-9]{6}")
_SESSION_LINE = re.compile(r"^Session ([A-Za-z0-9_-]+):", re.MULTILINE)


class ProofError(RuntimeError):
    pass


def verify_lines(lines: Iterable[str]) -> tuple[bool, str]:
    prev, expect_seq, count = GENESIS, 1, 0
    for lineno, raw in enumerate(lines, start=1):
        raw = raw.strip()
        if not raw:
            continue
        try:
            rec = json.loads(raw)
        except json.JSONDecodeError as exc:
            return False, f"BROKEN line {lineno}: not JSON ({exc.msg})"
        if not isinstance(rec, dict):
            return False, f"BROKEN line {lineno}: not a JSON object"
        if rec.get("seq") != expect_seq:
            return False, f"BROKEN line {lineno}: seq {rec.get('seq')} != {expect_seq}"
        if rec.get("prev_hash") != prev:
            return False, f"BROKEN line {lineno}: prev_hash mismatch"
        if record_hash(rec) != rec.get("hash"):
            return False, f"BROKEN line {lineno}: hash mismatch"
        prev, expect_seq, count = rec["hash"], expect_seq + 1, count + 1
    return True, f"OK: {count} records, chain intact, head={prev}"


def read_chain(path: Path) -> list[dict[str, Any]]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except UnicodeDecodeError:
        raise ProofError(NOT_UTF8.format(path=path)) from None
    except OSError as exc:
        raise ProofError(f"BROKEN: cannot read {path} ({exc}). {DOCTOR_NEXT}") from exc
    ok, message = verify_lines(lines)
    if not ok:
        raise ProofError(
            f"{message} in {path.name}. Next: keep the file, report it, do not edit it."
        )
    return [json.loads(raw) for raw in lines if raw.strip()]


def newest_log(repo: Path) -> Path:
    logs = sorted((repo / AUDIT_DIR).glob("*.jsonl"), key=lambda p: p.stat().st_mtime_ns)
    if not logs:
        raise ProofError(f"NOT LIVE: no audit log under {repo / AUDIT_DIR}. {DOCTOR_NEXT}")
    return logs[-1]


def live_log(repo: Path, needle: str) -> tuple[Path, int]:
    # 0024: the jail appends PreToolUse before the command runs, so this call is the newest
    # Bash record.
    log = newest_log(repo)
    records = read_chain(log)
    bash = [r for r in records if r.get("event") == "PreToolUse" and r.get("tool_name") == "Bash"]
    tool_input = bash[-1].get("tool_input") if bash else None
    command = str(tool_input.get("command") or "") if isinstance(tool_input, dict) else ""
    if needle not in command:
        raise ProofError(
            f"NOT LIVE: the newest Bash record in {log.name} is not this command, so this "
            f"session's hooks are not writing the audit log. {DOCTOR_NEXT}"
        )
    return log, len(records)


def hooks_live(repo: Path, needle: str) -> str:
    log, count = live_log(repo, needle)
    return f"OK hooks live: session {log.stem}, chain intact ({count} records)"


def _not_approved(check: str) -> ProofError:
    return ProofError(f"NOT APPROVED: {check}. {APPROVED_NEXT}")


def _summary_session(repo: Path, train_id: str) -> str:
    summary = repo / SUMMARY_DIR / f"{train_id}-summary.md"
    try:
        text = summary.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise _not_approved(f"cannot read the summary {summary} ({exc})") from exc
    match = _SESSION_LINE.search(text)
    if match is None:
        raise _not_approved(f"{summary.name} has no Session <id>: line")
    return match.group(1)


def _file_name(record: Mapping[str, object]) -> str:
    tool_input = record.get("tool_input")
    raw = tool_input.get("file_path") if isinstance(tool_input, dict) else None
    return Path(raw).name if isinstance(raw, str) else ""


def _verdict_refusal(stop: Mapping[str, object]) -> str | None:
    # 41: every field is untrusted; head first line or tail last line approves, any reject refuses.
    seq = stop.get("seq")
    shown = seq if isinstance(seq, int) and not isinstance(seq, bool) else "?"
    where = f"the {AUDITOR} final round (record seq {shown})"
    lines: dict[str, list[str]] = {}
    for field in _VERDICT_FIELDS:
        value = stop.get(field)
        if value is not None and not isinstance(value, str):
            return f"{where} has a {field} that is not text"
        lines[field] = [ln.strip() for ln in (value or "").splitlines() if ln.strip()]
    head, tail = lines["last_message_head"], lines["last_message_tail"]
    if any(ln.startswith(VERDICT_REJECTED) for ln in head + tail):
        return f"{where} carries a {VERDICT_REJECTED} line"
    if (head and head[0].startswith(VERDICT_APPROVED)) or (
        tail and tail[-1].startswith(VERDICT_APPROVED)
    ):
        return None
    return f"{where} is not {VERDICT_APPROVED}"


def approved(repo: Path, train_id: str) -> str:
    if not _TRAIN_ID.fullmatch(train_id):
        raise ProofError(
            f"NOT APPROVED: train id {train_id} is not YYYYMMDD-HHMMSS. "
            "Next: pass the id from a summary file name in docs/.tmp/daedalus/."
        )
    session = _summary_session(repo, train_id)
    log = repo / AUDIT_DIR / f"{session}.jsonl"
    if not log.is_file():
        raise _not_approved(f"no audit log {log.name} for session {session}")
    records = read_chain(log)
    name = f"{train_id}-summary.md"
    writes = [
        i for i, r in enumerate(records) if r.get("tool_name") == "Write" and _file_name(r) == name
    ]
    if not writes:
        raise _not_approved(f"session {session} has no Write record of {name}")
    # 0024: the auditor's final round for this train is its last stop before the summary Write.
    stops = [
        r
        for r in records[: writes[0]]
        if r.get("event") == "SubagentStop" and r.get("agent_type") == AUDITOR
    ]
    if not stops:
        raise _not_approved(f"no {AUDITOR} SubagentStop record before the summary Write")
    refusal = _verdict_refusal(stops[-1])
    if refusal is not None:
        raise _not_approved(refusal)
    return (
        f"OK approved: train {train_id}, session {session}, auditor record seq {stops[-1]['seq']}"
    )
