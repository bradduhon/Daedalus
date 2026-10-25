# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import json
import re
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

from lib import git, train_state
from lib.audit import GENESIS, AuditLockError, read_log, record_hash
from lib.train_state import TRAIN_ID as _TRAIN_ID

AUDIT_DIR = Path(".claude") / "daedalus" / "audit"
SUMMARY_DIR = Path("docs") / ".tmp" / "daedalus"
NOT_UTF8 = "BROKEN: {path} is not valid UTF-8. Next: keep the file, report it, do not edit it."
DOCTOR_NEXT = "Next: run the Daedalus health check (/daedalus:doctor)."
APPROVED_NEXT = "Next: run /daedalus:build-train; this train has no approved audit in its log."
AUDITOR = "daedalus:security-auditor"
VERDICT_APPROVED = "[VERDICT: APPROVED]"
VERDICT_REJECTED = "[VERDICT: REJECTED]"
HANDBACK = "SubagentHandback"
_VERDICT_FIELDS = ("last_message_head", "last_message_tail")
_HANDBACK_FIELD = "tool_input.message"
TIP = re.compile(r"[0-9a-f]{40}")
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
    # issue 10: the runner's hooks-live and check-reply reads wait on the writer's lock too.
    try:
        lines = read_log(path).splitlines()
    except UnicodeDecodeError:
        raise ProofError(NOT_UTF8.format(path=path)) from None
    except AuditLockError as exc:
        raise ProofError(f"BUSY: {exc}") from exc
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


def hooks_live(repo: Path, needle: str, mark: bool = False) -> str:
    log, count = live_log(repo, needle)
    train = train_state.active_train(repo) if mark else None
    # issue 57: the train's start_seq; no state file yet leaves it unset, and verdicts refuse.
    if train is not None and train_state.state_path(repo, train).is_file():
        try:
            train_state.mark_start(repo, train, count, log.stem)
        except train_state.TrainStateError as exc:
            raise ProofError(f"BROKEN: {exc}") from exc
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


def handback_message(record: Mapping[str, object]) -> object:
    # issue 57: the reply text of a hand-back call record, read from tool_input.message.
    tool_input = record.get("tool_input")
    return tool_input.get("message") if isinstance(tool_input, dict) else tool_input


def _verdict_fields(record: Mapping[str, object]) -> dict[str, object]:
    # issue 57: the auditor's reply lands in its hand-back call; its stop record holds a relay.
    if record.get("tool_name") == HANDBACK:
        return {_HANDBACK_FIELD: handback_message(record)}
    return {field: record.get(field) for field in _VERDICT_FIELDS}


def stop_verdict(stop: Mapping[str, object]) -> str | None:
    # 41: every field is untrusted; a first or closing line approves, any reject refuses.
    lines: dict[str, list[str]] = {}
    for field, value in _verdict_fields(stop).items():
        if value is not None and not isinstance(value, str):
            return None
        lines[field] = [ln.strip() for ln in (value or "").splitlines() if ln.strip()]
    if any(ln.startswith(VERDICT_REJECTED) for rows in lines.values() for ln in rows):
        return VERDICT_REJECTED
    firsts = [rows[0] for f, rows in lines.items() if rows and f != "last_message_tail"]
    closing = [rows[-1] for f, rows in lines.items() if rows and f != "last_message_head"]
    if any(ln.startswith(VERDICT_APPROVED) for ln in firsts + closing):
        return VERDICT_APPROVED
    return None


def _seq(record: Mapping[str, object]) -> int:
    value = record.get("seq")
    return value if isinstance(value, int) and not isinstance(value, bool) else 0


def _auditor_reply(record: Mapping[str, object]) -> bool:
    if record.get("agent_type") != AUDITOR:
        return False
    event = record.get("event")
    return event == "SubagentStop" or (
        event == "PostToolUse" and record.get("tool_name") == HANDBACK
    )


def auditor_round(
    records: Iterable[Mapping[str, object]], start: int
) -> list[Mapping[str, object]]:
    # issue 57: the newest auditor turn after start_seq, its hand-back calls and the stop ending it.
    replies = [r for r in records if _seq(r) > start and _auditor_reply(r)]
    end = len(replies) - 1
    if end >= 0 and replies[end].get("event") == "SubagentStop":
        end -= 1
    while end >= 0 and replies[end].get("event") != "SubagentStop":
        end -= 1
    return replies[end + 1 :]


def round_verdict(turn: list[Mapping[str, object]]) -> tuple[str | None, int]:
    # 0089: a rejection anywhere in the turn wins; the seq is the record that carries the verdict.
    found = [(stop_verdict(r), _seq(r)) for r in turn]
    for want in (VERDICT_REJECTED, VERDICT_APPROVED):
        hits = [seq for verdict, seq in found if verdict == want]
        if hits:
            return want, hits[-1]
    return None, _seq(turn[-1]) if turn else 0


def _verdict_refusal(turn: list[Mapping[str, object]]) -> str | None:
    for record in turn:
        bad = [f for f, v in _verdict_fields(record).items() if not isinstance(v, str | None)]
        if bad:
            where = f"the {AUDITOR} final round (record seq {_seq(record)})"
            return f"{where} has a {bad[0]} that is not text"
    verdict, seq = round_verdict(turn)
    where = f"the {AUDITOR} final round (record seq {seq or '?'})"
    if verdict == VERDICT_REJECTED:
        return f"{where} carries a {VERDICT_REJECTED} line"
    return None if verdict == VERDICT_APPROVED else f"{where} is not {VERDICT_APPROVED}"


def verdict_tip(turn: list[Mapping[str, object]], seq: int) -> str | None:
    # pin C1 -> C3: the tip= token after the marker on the verdict record; none or two is no tip.
    record = next((r for r in turn if _seq(r) == seq), None)
    if record is None:
        return None
    tips: set[str] = set()
    for value in _verdict_fields(record).values():
        for line in value.splitlines() if isinstance(value, str) else ():
            words = line.strip().split()
            if " ".join(words[:2]) not in (VERDICT_APPROVED, VERDICT_REJECTED):
                continue
            named = [w.removeprefix("tip=") for w in words[2:] if w.startswith("tip=")]
            tips.update(named or [""])
    return tips.pop() if len(tips) == 1 and TIP.fullmatch(next(iter(tips))) else None


def _git(repo: Path, *args: str) -> str | None:
    try:
        found = git.run(args, repo, 120)
    except (OSError, git.GitTimeout):
        return None
    return found.stdout if found.returncode == 0 else None


def integration_tip(repo: Path, train_id: str) -> str | None:
    out = _git(
        repo, "rev-parse", "--verify", "--quiet", f"refs/heads/daedalus/{train_id}^{{commit}}"
    )
    tip = (out or "").strip()
    return tip if TIP.fullmatch(tip) else None


def _ledger_rel(repo: Path) -> str | None:
    # spec 3.5: the train's own ledger, resolved as append_ledger resolves it; outside repo is none.
    from lib.config import ConfigError, load_config
    from lib.ledger import LedgerError, resolve_ledger

    try:
        ledger = resolve_ledger(str(repo), load_config(cwd=str(repo)))
        if ledger is None:
            return None
        return ledger.path.resolve().relative_to(repo.resolve()).as_posix()
    except (ConfigError, LedgerError, OSError, RuntimeError, ValueError):
        return None


def tip_problem(repo: Path, judged: object, current: str) -> str | None:
    # 59, spec 3.5: the tip is the judged tip, or one non-merge child that changes only the ledger.
    if not isinstance(judged, str) or not TIP.fullmatch(judged):
        return "the recorded verdict names no judged tip"
    if judged == current:
        return None
    moved = f"the tip {current[:12]} moved past the judged tip {judged[:12]}"
    parents = (_git(repo, "rev-list", "--parents", "-n", "1", current) or "").split()
    if parents[1:] != [judged]:
        return f"{moved}, and the tip is not one plain commit on top of it"
    changed = (
        _git(repo, "diff-tree", "--no-commit-id", "--name-only", "-r", "-z", judged, current) or ""
    ).split("\0")
    ledger = _ledger_rel(repo)
    if ledger is None or [path for path in changed if path] != [ledger]:
        return f"{moved} with a commit that changes more than the ledger"
    return None


def _state(repo: Path, train_id: str) -> dict[str, object]:
    try:
        return train_state.load(repo, train_id)
    except train_state.TrainStateError as exc:
        raise _not_approved(f"the state of train {train_id} is not readable ({exc})") from exc


def _judged(repo: Path, train_id: str, state: dict[str, object], named: str | None) -> str:
    # 59: the recorded approval, the auditor's tip= and the integration tip agree.
    verdict = train_state.record(state, train_state.VERDICT)
    if verdict.get("status") != train_state.APPROVED:
        raise _not_approved(f"the state of train {train_id} records no approved verdict")
    judged = verdict.get("tip")
    if named is None or named != judged:
        shown = judged[:12] if isinstance(judged, str) else "no tip"
        raise _not_approved(
            f"the {AUDITOR} verdict names tip {named or 'none'}, not the recorded tip {shown}"
        )
    current = integration_tip(repo, train_id)
    if current is None:
        raise _not_approved(f"daedalus/{train_id} does not resolve to a commit")
    problem = tip_problem(repo, judged, current)
    if problem is not None:
        raise _not_approved(problem)
    return named


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
    state = _state(repo, train_id)
    # issue 60: the bound hooks-live recorded for the session the summary names.
    start = train_state.session_bound(state, session)
    if start is None:
        raise _not_approved(
            f"the state of train {train_id} records no start_seq for session {session} "
            "to bound the search"
        )
    records = read_chain(log)
    name = f"{train_id}-summary.md"
    writes = [
        i
        for i, r in enumerate(records)
        if _seq(r) > start and r.get("tool_name") == "Write" and _file_name(r) == name
    ]
    if not writes:
        raise _not_approved(f"session {session} has no Write record of {name}")
    # 0024: the auditor's final round for this train is its last turn before the summary Write.
    turn = auditor_round(records[: writes[0]], start)
    if not turn:
        raise _not_approved(f"no {AUDITOR} reply after seq {start} before the summary Write")
    refusal = _verdict_refusal(turn)
    if refusal is not None:
        raise _not_approved(refusal)
    _, seq = round_verdict(turn)
    tip = _judged(repo, train_id, state, verdict_tip(turn, seq))
    return (
        f"OK approved: approved verdict, train {train_id}, session {session}, "
        f"auditor record seq {seq}, judged tip {tip[:12]}"
    )


def push_proof(repo: Path, train_id: str) -> str:
    # 62: the approved verdict, else an exception ruling bound to the current integration tip.
    try:
        return approved(repo, train_id)
    except ProofError as refused:
        try:
            exception = train_state.record(train_state.load(repo, train_id), train_state.EXCEPTION)
        except train_state.TrainStateError:
            raise refused from None
        ledger_id, tip = exception.get("ledger_id"), exception.get("tip")
        bound = isinstance(ledger_id, str) and ledger_id and isinstance(tip, str)
        if not bound or tip != integration_tip(repo, train_id):
            raise refused from None
        return f"OK approved: exception {ledger_id}, train {train_id}, integration tip {tip[:12]}"
