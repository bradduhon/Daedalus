# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import json
import os
import re
import shlex
from collections.abc import Iterable, Mapping, Sequence
from datetime import datetime
from pathlib import Path

from lib import audit_rounds, git, train_state
from lib.audit import GENESIS, AuditLockError, read_log, record_hash
from lib.train_state import TRAIN_ID as _TRAIN_ID

AUDIT_DIR = Path(".claude") / "daedalus" / "audit"
SUMMARY_DIR = Path("docs") / ".tmp" / "daedalus"
NOT_UTF8 = "BROKEN: {path} is not valid UTF-8. Next: keep the file, report it, do not edit it."
DOCTOR_NEXT = "Next: run the Daedalus health check (/daedalus:doctor)."
APPROVED_NEXT = "Next: run /daedalus:run; this train has no approved audit in its log."
AUDITOR = "daedalus:security-auditor"
VERDICT_APPROVED = "[VERDICT: APPROVED]"
VERDICT_REJECTED = "[VERDICT: REJECTED]"
HANDBACK = "SubagentHandback"
_VERDICT_FIELDS = ("last_message_head", "last_message_tail")
_HANDBACK_FIELD = "tool_input.message"
TIP = re.compile(r"[0-9a-f]{40}")
# 0131, 0134: the one list of the four public docs; dispatch_binding imports it.
PUBLIC_DOCS = (
    "README.md",
    "docs/howto/README.md",
    "docs/guardrails.md",
    "docs/project-requirements.md",
)
# 0131: a public doc stays a regular non-executable file; 000000 marks a path that is new.
DOC_MODE, NO_MODE = "100644", "000000"
_SESSION_LINE = re.compile(r"^Session ([A-Za-z0-9_-]+):", re.MULTILINE)
# pin D3 -> D1: the stop record's full-reply verdict lines; absent on a record written before D3.
VERDICT_LINES = "verdict_lines"
_VERDICT_TAG = "[VERDICT:"
_VERDICT_KIND = re.compile(r"\[VERDICT:\s*([A-Za-z_]+)\s*\]")
VERDICT_BOTH = "both verdicts"
# W3.2: the summary command the proof anchors on: the plugin's own script, run by the
# orchestrator or the main session, unrefused, whose PostToolUse record shows its written line.
SUMMARY_SCRIPT, SUMMARY_ACTION = "daedalus_train.py", "summary"
PLUGIN_SCRIPT = Path(__file__).resolve().parents[1] / SUMMARY_SCRIPT
_PLUGIN_VARS = ("${CLAUDE_PLUGIN_ROOT}", "$CLAUDE_PLUGIN_ROOT")
_SUMMARY_AGENTS = ("main", "daedalus:orchestrator")
_REFUSED = ("block", "ask")
_PYTHONS = ("python3", "python")
# pin D1 -> E4: the D1 refusal texts; only their Next: action names the summary command.
R_NO_SUMMARY_WRITE = (
    "no summary Write after the recorded verdict at seq {seq}. "
    "Next: rewrite the summary with daedalus_train.py summary --repo <repo>, then rerun the proof."
)
R_GRADED_NOT_RECORDED = (
    "the graded auditor turn at seq {graded} is not the recorded verdict at seq {recorded}. "
    "Next: rerun the audit round."
)
R_BOTH_VERDICTS = "auditor reply at seq {seq} carries both verdicts. Next: rerun the audit round."
# 0149: the gate labels the operator picks from, verbatim.
UNEXEMPTED_NEXT = (
    "Next: put each finding to the operator through the per-finding step of the Build Train "
    "with the choices `Fix it now`, `Skip, track or exempt it` and `Stop the train`, then record "
    "each exemption with daedalus_train.py exception."
)


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


def read_chain(path: Path) -> list[dict[str, object]]:
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


def _newest_bash(repo: Path) -> tuple[Path, list[dict[str, object]], dict[str, object] | None]:
    # 0024: the jail appends PreToolUse before the command runs, so this call is the newest
    # Bash record.
    log = newest_log(repo)
    records = read_chain(log)
    bash = [r for r in records if r.get("event") == "PreToolUse" and r.get("tool_name") == "Bash"]
    return log, records, bash[-1] if bash else None


def live_log(repo: Path, needle: str) -> tuple[Path, int]:
    log, records, newest = _newest_bash(repo)
    tool_input = newest.get("tool_input") if newest else None
    command = str(tool_input.get("command") or "") if isinstance(tool_input, dict) else ""
    if needle not in command:
        raise ProofError(
            f"NOT LIVE: the newest Bash record in {log.name} is not this command, so this "
            f"session's hooks are not writing the audit log. {DOCTOR_NEXT}"
        )
    return log, len(records)


def live_summary(repo: Path) -> Path:
    # W3.2: the summary command checks its own record with the predicate the proof anchors on.
    log, _, newest = _newest_bash(repo)
    if newest is None or not summary_call(newest, repo):
        raise ProofError(
            f"NOT LIVE: the newest Bash record in {log.name} is not the summary command the "
            f"push proof anchors on. Next: run `python3 {PLUGIN_SCRIPT} summary --repo {repo}` "
            "exactly, single-spaced, from the orchestrator or the main session."
        )
    return log


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


def stale_agents(log: Path, agents: Path) -> list[str]:
    # spec 6: agent files load at session start; one changed after the first record is stale.
    records = read_chain(log)
    raw = records[0].get("ts") if records else None
    try:
        first = datetime.fromisoformat(raw).timestamp() if isinstance(raw, str) else None
    except ValueError:
        first = None
    if first is None:
        return []
    found: list[str] = []
    for path in sorted(agents.glob("*.md")):
        try:
            changed = path.stat().st_mtime
        except OSError:
            continue
        if changed > first:
            found.append(path.stem)
    return found


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


def handback_message(record: Mapping[str, object]) -> object:
    # issue 57: the reply text of a hand-back call record, read from tool_input.message.
    tool_input = record.get("tool_input")
    return tool_input.get("message") if isinstance(tool_input, dict) else tool_input


def _verdict_fields(record: Mapping[str, object]) -> dict[str, object]:
    # issue 57: the auditor's reply lands in its hand-back call; its stop record holds a relay.
    if record.get("tool_name") == HANDBACK:
        return {_HANDBACK_FIELD: handback_message(record)}
    return {field: record.get(field) for field in _VERDICT_FIELDS}


def verdict_lines(record: Mapping[str, object]) -> list[str] | None:
    # pin D3 -> D1: a hand-back's verdict lines come from its whole message; None is no field.
    if record.get("tool_name") == HANDBACK:
        message = handback_message(record)
        if not isinstance(message, str):
            return None
        return [ln.strip() for ln in message.splitlines() if ln.strip().startswith(_VERDICT_TAG)]
    raw = record.get(VERDICT_LINES)
    if raw is None:
        return None
    if not isinstance(raw, list) or not all(isinstance(ln, str) for ln in raw):
        raise ValueError(VERDICT_LINES)
    return [ln.strip() for ln in raw]


def stop_verdict(stop: Mapping[str, object]) -> str | None:
    # 41: every field is untrusted; a first or closing line approves, any reject refuses.
    lines: dict[str, list[str]] = {}
    for field, value in _verdict_fields(stop).items():
        if value is not None and not isinstance(value, str):
            return None
        lines[field] = [ln.strip() for ln in (value or "").splitlines() if ln.strip()]
    try:
        listed = verdict_lines(stop) or []
    except ValueError:
        return None
    # spec 3.6: one verdict kind per reply; the full-reply lines also catch a mid-reply reject.
    if len({m.group(1).upper() for ln in listed if (m := _VERDICT_KIND.match(ln))}) > 1:
        return VERDICT_BOTH
    if any(ln.startswith(VERDICT_REJECTED) for ln in listed):
        return VERDICT_REJECTED
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
    for want in (VERDICT_BOTH, VERDICT_REJECTED, VERDICT_APPROVED):
        hits = [seq for verdict, seq in found if verdict == want]
        if hits:
            return want, hits[-1]
    return None, _seq(turn[-1]) if turn else 0


def _verdict_refusal(turn: list[Mapping[str, object]]) -> str | None:
    for record in turn:
        bad = [f for f, v in _verdict_fields(record).items() if not isinstance(v, str | None)]
        try:
            verdict_lines(record)
        except ValueError:
            bad.append(VERDICT_LINES)
        if bad:
            where = f"the {AUDITOR} final round (record seq {_seq(record)})"
            return f"{where} has a {bad[0]} that is not text"
    verdict, seq = round_verdict(turn)
    if verdict == VERDICT_BOTH:
        # pin D1 -> D5: this refusal carries its own Next line.
        raise ProofError(f"NOT APPROVED: {R_BOTH_VERDICTS.format(seq=seq)}")
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
    if not _ledger_only(_raw(repo, judged, current), _ledger_rel(repo)):
        return f"{moved} with a commit that changes more than the ledger, or its file mode"
    return None


def _state(repo: Path, train_id: str) -> dict[str, object]:
    try:
        return train_state.load(repo, train_id)
    except train_state.TrainStateError as exc:
        raise _not_approved(f"the state of train {train_id} is not readable ({exc})") from exc


def _judged(
    repo: Path, train_id: str, state: dict[str, object], named: str | None
) -> tuple[str, str]:
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
    problem = tip_admits(repo, train_id, state, judged, current)
    if problem is not None:
        raise _not_approved(problem)
    return named, current


def _same_path(given: str, want: Path) -> bool:
    return os.path.realpath(given) == os.path.realpath(want)


def summary_call(record: Mapping[str, object], repo: Path | None = None) -> bool:
    # W3.2: exactly `python3 <plugin>/scripts/daedalus_train.py summary --repo <repo>`, one space
    # between words, as the jail allowed it; a coder, a copied script or --help never counts.
    if record.get("event") != "PreToolUse" or record.get("tool_name") != "Bash":
        return False
    if record.get("decision") in _REFUSED or record.get("agent_type") not in _SUMMARY_AGENTS:
        return False
    tool_input = record.get("tool_input")
    command = tool_input.get("command") if isinstance(tool_input, dict) else None
    if not isinstance(command, str):
        return False
    try:
        argv = shlex.split(command)
    except ValueError:
        return False
    # Single spaces only, plain or shlex-quoted; the live check and the anchor share this form.
    if command != " ".join(argv) and command != " ".join(shlex.quote(a) for a in argv):
        return False
    if len(argv) == 4 and argv[3].startswith("--repo="):
        argv = [*argv[:3], "--repo", argv[3].removeprefix("--repo=")]
    if (
        len(argv) != 5
        or Path(argv[0]).name not in _PYTHONS
        or argv[2:4] != [SUMMARY_ACTION, "--repo"]
    ):
        return False
    script = argv[1]
    for var in _PLUGIN_VARS:
        if script.startswith(f"{var}/"):
            script = f"{PLUGIN_SCRIPT.parents[1]}{script.removeprefix(var)}"
    if not Path(script).is_absolute() or not _same_path(script, PLUGIN_SCRIPT):
        return False
    if repo is None:
        return True
    target = Path(argv[4])
    cwd = record.get("cwd")
    if not target.is_absolute():
        if not isinstance(cwd, str):
            return False
        target = Path(cwd) / target
    return _same_path(str(target), repo)


def _wrote(later: Sequence[Mapping[str, object]], call: Mapping[str, object], train: str) -> bool:
    # W3.2: the call's own PostToolUse record, by tool_use_id, holds the line a written file prints.
    use = call.get("tool_use_id")
    if not isinstance(use, str) or not use:
        return False
    line = f"summary written train={train}"
    if train:
        line += f" path={SUMMARY_DIR.as_posix()}/{train}-summary.md "
    for record in later:
        if record.get("tool_use_id") != use or record.get("agent_id") != call.get("agent_id"):
            continue
        if record.get("event") not in ("PostToolUse", "PostToolUseFailure"):
            continue
        head = record.get("result_head")
        return record.get("event") == "PostToolUse" and isinstance(head, str) and line in head
    return False


def summary_anchor(
    records: Sequence[Mapping[str, object]],
    verdict_seq: int,
    *,
    repo: Path | None = None,
    train_id: str = "",
) -> int | None:
    # pin D1 -> E4: the seq of the first summary command record after the recorded verdict seq;
    # W3.2: the proof also binds the record to its repo and to the train the written line names.
    for index, record in enumerate(records):
        if _seq(record) <= verdict_seq or not summary_call(record, repo):
            continue
        if _wrote(records[index + 1 :], record, train_id):
            return _seq(record)
    return None


def _recorded_seq(train_id: str, state: dict[str, object]) -> int:
    # 73: the proof grades the verdict the train recorded, so an approval names its audit seq.
    verdict = train_state.record(state, train_state.VERDICT)
    if verdict.get("status") != train_state.APPROVED:
        raise _not_approved(f"the state of train {train_id} records no approved verdict")
    seq = verdict.get("seq")
    if not isinstance(seq, int) or isinstance(seq, bool) or seq < 1:
        raise _not_approved(f"the recorded verdict of train {train_id} names no audit seq")
    return seq


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
    recorded = _recorded_seq(train_id, state)
    # W3.2: a Write of the summary file never anchors; only the summary command's record does.
    anchor = summary_anchor(records, recorded, repo=repo, train_id=train_id)
    if anchor is None:
        raise ProofError(f"NOT APPROVED: {R_NO_SUMMARY_WRITE.format(seq=recorded)}")
    # 73: the graded turn is the last auditor turn before that command, and it is the recorded one.
    turn = auditor_round([r for r in records if _seq(r) < anchor], start)
    if not turn:
        raise _not_approved(f"no {AUDITOR} reply after seq {start} before the summary command")
    refusal = _verdict_refusal(turn)
    if refusal is not None:
        raise _not_approved(refusal)
    _, seq = round_verdict(turn)
    if seq != recorded:
        raise ProofError(
            f"NOT APPROVED: {R_GRADED_NOT_RECORDED.format(graded=seq, recorded=recorded)}"
        )
    tip, current = _judged(repo, train_id, state, verdict_tip(turn, seq))
    return (
        f"OK approved: approved verdict, train {train_id}, session {session}, "
        f"auditor record seq {seq}, judged tip {tip[:12]}"
        f"{_docs_note(repo, train_id, state, current)}"
    )


def findings_path(repo: Path, train_id: str, round_: int) -> Path:
    # pin C3 -> C1: the one path of a round's finding list.
    return repo / SUMMARY_DIR / train_id / "audit" / f"round{round_}" / "findings.txt"


def read_findings(path: Path) -> dict[str, audit_rounds.Finding]:
    if path.is_symlink() or not path.is_file():
        raise ProofError(
            f"{path} is not a regular file. Next: have the auditor write the round's finding list."
        )
    try:
        return audit_rounds.parse(path.read_text(encoding="utf-8"), str(path))
    except (OSError, UnicodeDecodeError) as exc:
        raise ProofError(f"cannot read {path} ({exc}). Next: make it a UTF-8 file.") from exc
    except audit_rounds.FindingsError as exc:
        raise ProofError(str(exc)) from exc


def docs_findings_path(repo: Path, train_id: str) -> Path:
    # 0131: the one path of the refuted docs claim list, in the round list's line shape.
    return repo / SUMMARY_DIR / train_id / "docs" / "findings.txt"


def _exempt(entry: object, judged: str) -> bool:
    if not isinstance(entry, dict):
        return False
    ledger_id, tracking, other = entry.get("ledger_id"), entry.get("tracking"), entry.get("other")
    # 0139: `other` holds the operator's own words, as the exception recorder requires.
    worded = tracking != "other" or (isinstance(other, str) and bool(other.strip()))
    return (
        isinstance(ledger_id, str)
        and bool(ledger_id)
        and entry.get("tip") == judged
        and tracking in train_state.TRACKING
        and worded
    )


def round_keys(repo: Path, train_id: str, state: dict[str, object], round_: int) -> list[str]:
    # 0133: the findings file and the round recorded at verdict time; a key in either counts.
    listed = read_findings(findings_path(repo, train_id, round_))
    recorded = train_state.record(train_state.record(state, train_state.AUDIT_ROUNDS), str(round_))
    return sorted(set(listed) | set(recorded))


def docs_keys(repo: Path, train_id: str, state: dict[str, object]) -> list[str]:
    # 0131: the refuted claim file and the claims the docs record holds; a key in either counts.
    listed = read_findings(docs_findings_path(repo, train_id))
    docs = train_state.record(state, train_state.DOCS_VERDICT)
    return sorted(set(listed) | set(train_state.record(docs, "findings")))


def _unexempted(keys: list[str], exempt: dict[str, object], tip: str) -> list[str]:
    # 0133: the one exemption check, shared by the security round and the docs record.
    return [key for key in keys if not _exempt(exempt.get(key), tip)]


def docs_problem(repo: Path, train_id: str, state: dict[str, object], current: str) -> str | None:
    # 0131, 0134: the docs record names the current tip verified, or every refuted claim exempted.
    docs = train_state.record(state, train_state.DOCS_VERDICT)
    tip, status = docs.get("tip"), docs.get("status")
    if tip != current:
        shown = tip[:12] if isinstance(tip, str) else "no tip"
        return f"the docs record names tip {shown}, not the current tip {current[:12]}"
    if status == train_state.VERIFIED:
        return None
    if status != train_state.REFUTED:
        return "the docs record holds no verified or refuted verdict"
    try:
        keys = docs_keys(repo, train_id, state)
    except ProofError as exc:
        return f"the refuted docs claim list is unreadable ({exc})"
    if not keys:
        return "the refuted docs record lists no claims"
    missing = _unexempted(keys, train_state.record(docs, "exemptions"), current)
    if missing:
        return (
            f"refuted docs claim {missing[0]} has no exemption, "
            f"{len(missing)} of {len(keys)} claims have none"
        )
    return None


def _parents(repo: Path, commit: str) -> list[str]:
    return (_git(repo, "rev-list", "--parents", "-n", "1", commit) or "").split()[1:]


def _raw(repo: Path, parent: str, commit: str) -> list[tuple[str, str, str]] | None:
    # 0131: (old mode, new mode, path) per changed path; None when git or the format fails.
    out = _git(
        repo, "diff-tree", "--no-commit-id", "--no-renames", "--raw", "-r", "-z", parent, commit
    )
    if out is None:
        return None
    fields, entries = out.split("\0"), []
    for meta, path in zip(fields[0:-1:2], fields[1::2], strict=False):
        modes = meta.removeprefix(":").split()
        if not meta.startswith(":") or len(modes) != 5 or not path:
            return None
        entries.append((modes[0], modes[1], path))
    return entries


def _regular(entries: list[tuple[str, str, str]]) -> bool:
    # 0131: each changed path is a regular non-executable file before and after.
    return all(new == DOC_MODE and old in (DOC_MODE, NO_MODE) for old, new, _ in entries)


def _docs_only(entries: list[tuple[str, str, str]]) -> bool:
    # 0131: only the four docs, each a regular non-executable file before and after.
    return _regular(entries) and all(path in PUBLIC_DOCS for _, _, path in entries)


def _ledger_only(entries: list[tuple[str, str, str]] | None, ledger: str | None) -> bool:
    # 59: only the declared ledger changes, and it passes the _docs_only mode test.
    return (
        bool(entries)
        and ledger is not None
        and {path for _, _, path in entries or ()} == {ledger}
        and _regular(entries or [])
    )


def ledger_parent(repo: Path, commit: str) -> str | None:
    # 59, 0131: the parent of a one-parent commit that changes only the declared ledger, else None.
    ledger, parents = _ledger_rel(repo), _parents(repo, commit)
    if ledger is None or len(parents) != 1:
        return None
    return parents[0] if _ledger_only(_raw(repo, parents[0], commit), ledger) else None


def _docs_end(repo: Path, judged: str, current: str) -> str:
    # 0131: the tip the docs-only commits end at; one ledger commit on top of them is admitted.
    parent = ledger_parent(repo, current) if current != judged else None
    return parent if parent is not None and parent != judged else current


def _docs_moves(repo: Path, judged: str, end: str) -> str | None:
    # 0131: each commit past the judged tip changes only the four public docs, or is issue 59's
    # one ledger commit on the judged tip; a merge is judged against its first parent.
    if _git(repo, "merge-base", "--is-ancestor", judged, end) is None:
        return f"the tip {end[:12]} does not descend from the judged tip {judged[:12]}"
    ledger = _ledger_rel(repo)
    for commit in (_git(repo, "rev-list", f"{judged}..{end}") or "").split():
        parents = _parents(repo, commit)
        entries = _raw(repo, parents[0], commit) if parents else None
        paths = {path for _, _, path in entries or ()}
        if entries is not None and _docs_only(entries):
            continue
        if parents == [judged] and _ledger_only(entries, ledger):
            continue
        if entries is not None and paths <= set(PUBLIC_DOCS):
            return (
                f"the commit {commit[:12]} past the judged tip {judged[:12]} changes the type or "
                "mode of a public doc"
            )
        return (
            f"the commit {commit[:12]} past the judged tip {judged[:12]} changes more than the "
            "four public docs"
        )
    return None


def tip_admits(
    repo: Path, train_id: str, state: dict[str, object], judged: object, current: str
) -> str | None:
    # 59, 0131: the judged-tip rule, extended to docs-only commits the docs record covers.
    problem = tip_problem(repo, judged, current)
    if problem is None or not train_state.record(state, train_state.DOCS_VERDICT):
        return problem
    if not isinstance(judged, str) or not TIP.fullmatch(judged):
        return problem
    end = _docs_end(repo, judged, current)
    return (
        _docs_moves(repo, judged, end)
        or _tree_problem(repo, judged, end)
        or docs_problem(repo, train_id, state, end)
    )


def _tree_problem(repo: Path, judged: str, end: str) -> str | None:
    # 0131, audit round 1: the end tree is the judged tree but for the four docs and the ledger,
    # whatever parents a merge names.
    entries = _raw(repo, judged, end)
    ledger = _ledger_rel(repo)
    allowed = set(PUBLIC_DOCS) | ({ledger} if ledger else set())
    if entries is not None and {path for _, _, path in entries} <= allowed:
        # 0131: each public doc in the end tree stays a regular non-executable file.
        if _docs_only([e for e in entries if e[2] in PUBLIC_DOCS]):
            return None
        return (
            f"the tree of {end[:12]} holds a public doc whose type or mode differs from a "
            f"regular file, or drops one, against the judged tip {judged[:12]}"
        )
    return (
        f"the tree of {end[:12]} differs from the judged tip {judged[:12]} outside the four "
        "public docs and the ledger"
    )


def _docs_note(repo: Path, train_id: str, state: dict[str, object], current: str) -> str:
    # 0131: the proof line names the docs path when a docs record covers the docs tip.
    docs = train_state.record(state, train_state.DOCS_VERDICT)
    end = current if docs.get("tip") == current else ledger_parent(repo, current) or current
    if not docs or docs_problem(repo, train_id, state, end) is not None:
        return ""
    if docs.get("status") == train_state.VERIFIED:
        return f", docs verified on tip {end[:12]}"
    return f", docs refuted with every claim exempted on tip {end[:12]}"


def exemption_problem(
    repo: Path, train_id: str, state: dict[str, object], current: str
) -> str | None:
    # 0133: a rejected verdict passes when each of its round's findings carries an exemption.
    verdict = train_state.record(state, train_state.VERDICT)
    round_ = verdict.get("round")
    rejected = verdict.get("status") == train_state.REJECTED
    if not rejected or not isinstance(round_, int) or isinstance(round_, bool):
        return "the recorded verdict is not a rejected round"
    judged = verdict.get("tip")
    problem = tip_admits(repo, train_id, state, judged, current)
    if problem is not None:
        return problem
    try:
        keys = round_keys(repo, train_id, state, round_)
    except ProofError as exc:
        return f"the rejected round {round_} finding list is unreadable ({exc})"
    if not keys:
        return f"the rejected round {round_} lists no findings"
    exempt = train_state.record(train_state.record(state, train_state.EXEMPTIONS), str(round_))
    missing = _unexempted(keys, exempt, str(judged))
    if missing:
        return (
            f"finding {missing[0]} of the rejected round {round_} has no exemption, "
            f"{len(missing)} of {len(keys)} findings have none"
        )
    return None


def push_proof(repo: Path, train_id: str) -> str:
    # 0133: the approved verdict, else a rejected round whose every finding the operator exempted.
    try:
        return approved(repo, train_id)
    except ProofError as refused:
        try:
            state = train_state.load(repo, train_id)
        except train_state.TrainStateError:
            raise refused from None
        verdict = train_state.record(state, train_state.VERDICT)
        current = integration_tip(repo, train_id)
        if verdict.get("status") != train_state.REJECTED or current is None:
            raise refused from None
        problem = exemption_problem(repo, train_id, state, current)
        if problem is not None:
            raise ProofError(f"NOT APPROVED: {problem}. {UNEXEMPTED_NEXT}") from None
        return (
            f"OK approved: every finding exempted, train {train_id}, round {verdict['round']}, "
            f"integration tip {current[:12]}{_docs_note(repo, train_id, state, current)}"
        )
