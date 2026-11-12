#!/usr/bin/env python3
# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# RCP, 0128: the check on a coder's COMPLETE reply, before any verifier runs. It reads the
# SubagentStop reply and, by the operator's pick 4 of train 20261026-002310, the message of a
# PreToolUse SubagentHandback call. Pin RCP -> VER: the receipts block sits directly above the
# COMPLETE line. 0281: a verifier's REFUTED or an auditor's REJECTED reply carries the rule,
# places and search cells on every finding. A yield, another agent's reply and an empty reply
# pass; a check that cannot run never blocks.
from __future__ import annotations

import hashlib
import hmac
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

CODER = "coder"
RECEIPTS = "## Receipts"
# Pin RCP -> VER: the only six line shapes the block holds, by kind.
SHAPES: dict[str, re.Pattern[str]] = {
    "commit": re.compile(r"- commit [0-9a-f]{40} .*\S"),
    "test": re.compile(r"- test \S.* => .*\S"),
    "typecheck": re.compile(r"- typecheck \S.* => .*\S"),
    "yield": re.compile(r"- yield \S+ \S.* => .*\S"),
    "deviation": re.compile(r"- deviation \S.* \| .*\S"),
    # 227: a self-hunt receipt; the outcome is refused or a fix commit of 7 to 40 hex.
    "hunt": re.compile(r"- hunt \S.* => (?:refused|admitted, fixed in [0-9a-f]{7,40})"),
}
REQUIRED = ("commit", "test")
# 227: a ` hunt=<n>` field sits directly before the closing ` turns=<n>`.
_HUNT_FIELD = re.compile(r"(?<!\S)hunt=")
_HUNT_TAIL = re.compile(r" hunt=([0-9]+) turns=[0-9]+\Z")
SHAPE = (
    "a line `## Receipts`, then only lines `- commit <40 hex> <subject>`, "
    "`- test <command> => <last output line>`, `- typecheck <command> => <last output line>`, "
    "`- yield <kind> <question> => <who answered>`, "
    "`- deviation <file or behaviour> | <reason>` and "
    "`- hunt <form> => refused` or `- hunt <form> => admitted, fixed in <7 to 40 hex>`, "
    "with at least one commit line and one test line, and the COMPLETE line unchanged "
    "but for ` hunt=<n>` directly before its closing ` turns=<n>`"
)
SHOWN_CHARS = 120
# 209: a files= refusal leads with this text and takes FILES_NEXT as its one Next line.
FILES_LEAD = "the COMPLETE line's `files=` entry"
FILES_NEXT = (
    "list every file in `files=` relative to the unit worktree root, as `scripts/lib/jail.py`, "
    "with no leading `/` or `~`, no `..` part and no link out of the worktree"
)


def _kind(line: str) -> str | None:
    return next((kind for kind, shape in SHAPES.items() if shape.fullmatch(line)), None)


def files_problem(status: str, root: Path) -> str | None:
    # 209: the summary's own files= reader and path judge; a line it cannot read is not judged.
    from lib.train_summary import _COMPLETE, _PATH_LIKE, _TOKEN, plain_path

    done = _COMPLETE.search(status)
    if done is None:
        return None
    for match in _TOKEN.finditer(done.group(3)):
        token = match.group(0)
        if (_PATH_LIKE.search(token) or token == "..") and not plain_path(token, root, None):
            shown = token if len(token) <= SHOWN_CHARS else token[:SHOWN_CHARS] + "..."
            return (
                f"{FILES_LEAD} {shown!r} is absolute, has a `..` part or leaves the unit "
                "worktree; files= paths are relative to the worktree root"
            )
    return None


def receipts_problem(reply: str, root: Path | None = None) -> str | None:
    # Pin RCP -> VER: None when the reply's last line is no COMPLETE line or its block is whole.
    # 209: root is the unit worktree files= is judged under; None judges under the process cwd.
    from lib.train_runner import COMPLETE_LINE

    lines = [line.rstrip() for line in reply.rstrip().splitlines()]
    if not lines or not lines[-1].strip().startswith(COMPLETE_LINE):
        return None
    body, status = lines[:-1], lines[-1].strip()
    tail = _HUNT_TAIL.search(status)
    hunts = _HUNT_FIELD.findall(status)
    if hunts and (len(hunts) > 1 or tail is None):
        return "the COMPLETE line carries `hunt=` other than as ` hunt=<n>` before ` turns=<n>`"
    if RECEIPTS not in body:
        return f"the COMPLETE reply has no `{RECEIPTS}` line above its status line"
    block = body[len(body) - body[::-1].index(RECEIPTS) :]
    kinds: list[str] = []
    for line in block:
        kind = _kind(line)
        if kind is None:
            shown = line if len(line) <= SHOWN_CHARS else line[:SHOWN_CHARS] + "..."
            return f"the receipts block holds a line of another shape: {shown!r}"
        kinds.append(kind)
    missing = [kind for kind in REQUIRED if kind not in kinds]
    if missing:
        return "the receipts block has no " + " and no ".join(missing) + " line"
    # 227: a hunt count equals the hunt receipts; no field leaves the count to the build skill.
    if tail is not None and int(tail.group(1)) != kinds.count("hunt"):
        return (
            f"the COMPLETE line carries hunt={int(tail.group(1))} "
            f"but the receipts block holds {kinds.count('hunt')} hunt lines"
        )
    return files_problem(status, root if root is not None else Path.cwd())


VERIFIER, AUDITOR = "verifier", "auditor"
COMPLIANCE = "## Compliance"


def _judge_next(agent: str) -> str:
    from lib.audit_rounds import CELLS

    if agent == VERIFIER:
        return (
            f"end each row of the REFUTED line with {CELLS}, rows joined by `; ` and no other `;`"
        )
    return (
        "write one line per finding, `<node id> <severity> <class>: <one line>` or "
        f"`no-test: <branch> <file>:<line> <severity> <class>: <what is wrong>`, each ending with "
        f"{CELLS}"
    )


def findings_problem(agent: str, reply: str, listed: tuple[int, int] | None = None) -> str | None:
    # 0281: a failing verdict whose finding lacks its rule, a place or its search is refused;
    # listed is the (round, count) of the round's findings file, None when it cannot be read.
    from lib.audit_proof import VERDICT_REJECTED
    from lib.audit_rounds import cell_problems, reply_finding
    from lib.coder_model import REFUTED_PREFIX
    from lib.workspace import refuted_rows

    lines = [line.strip() for line in reply.splitlines() if line.strip()]
    last = lines[-1] if lines else ""
    if agent == VERIFIER and last.startswith(REFUTED_PREFIX):
        rows = refuted_rows(last)
        if not rows:
            return "the REFUTED line holds no row, or a row with a `;` of its own"
        named = [(f"row {n}", row) for n, row in enumerate(rows, start=1)]
    elif agent == AUDITOR and last.startswith(VERDICT_REJECTED):
        body = lines[1:-1]
        body = body[: body.index(COMPLIANCE)] if COMPLIANCE in body else body
        found = [line.removeprefix("- ") for line in body if reply_finding(line)]
        if not found:
            return "the REJECTED reply lists no finding line"
        named = [(f"finding {n}", line) for n, line in enumerate(found, start=1)]
    else:
        return None
    problems: list[str] = []
    # 0281: the count binds only a reply whose own node ids name the file's round.
    tied = listed is not None and any(_names_round(row, listed[0]) for _, row in named)
    if agent == AUDITOR and listed is not None and tied and len(named) < listed[1]:
        problems.append(
            f"the REJECTED reply lists {len(named)} finding lines but the round {listed[0]} "
            f"findings file lists {listed[1]}"
        )
    for name, row in named:
        lacks = cell_problems(row)
        if lacks:
            shown = row if len(row) <= SHOWN_CHARS else row[:SHOWN_CHARS] + "..."
            problems.append(f"{name} {shown!r} has {' and '.join(lacks)}")
    return "; ".join(problems) or None


def _names_round(line: str, round_: int) -> bool:
    # 0281: a test finding's node id holds the parts `audit`, `round<n>` of its round folder.
    parts = Path(line.split(maxsplit=1)[0].split("::", 1)[0]).parts
    want = ("audit", f"round{round_}")
    return any(parts[i : i + 2] == want for i in range(len(parts) - 1))


def round_findings(cwd: object) -> tuple[int, int] | None:
    # 0281: the round and count of the round's findings file, by the verdict command's readers.
    from lib import train_state
    from lib.audit_proof import ProofError, findings_path, read_findings
    from lib.project_root import project_root
    from lib.train_runner import derived_round

    if not isinstance(cwd, str) or not Path(cwd).is_absolute():
        return None
    try:
        repo = project_root(Path(cwd))
        train = train_state.active_train(repo)
        if train is None:
            return None
        round_ = derived_round(train_state.load(repo, train))
        return round_, len(read_findings(findings_path(repo, train, round_)))
    except (OSError, ValueError, ProofError, train_state.TrainStateError):
        return None


PASS_FEATURE = "handback-pass"
MAX_ID = 64


def _marker_id(agent_id: object) -> str | None:
    # 0281: the tree has no agent id shape; ASCII letters, digits and hyphen, 1 to 64 long.
    if not isinstance(agent_id, str) or not 1 <= len(agent_id) <= MAX_ID:
        return None
    ok = all(ch.isascii() and (ch.isalnum() or ch == "-") for ch in agent_id)
    return agent_id if ok else None


def _last_line_sha(reply: str) -> str:
    lines = [line.strip() for line in reply.splitlines() if line.strip()]
    last = lines[-1] if lines else ""
    return hashlib.sha256(last.encode("utf-8", "surrogatepass")).hexdigest()


def write_pass(hook_input: dict[str, object], reply: str) -> None:
    # 0281: the marker is evidence of a pass by this same check only; nothing else reads it.
    from lib import atomic, storage

    agent, cwd = _marker_id(hook_input.get("agent_id")), hook_input.get("cwd")
    if agent is None or not isinstance(cwd, str) or not Path(cwd).is_absolute():
        return
    try:
        folder = storage.make_tmp_dir(PASS_FEATURE, cwd)
        atomic.write_atomic(folder / agent, _last_line_sha(reply) + "\n", 0o600)
    except (OSError, RuntimeError, ValueError):
        return


def relayed(hook_input: dict[str, object], reply: str) -> bool:
    # 0281: a stop whose last line hashes to this agent's pass marker relays a judged reply.
    from lib import storage

    agent, cwd = _marker_id(hook_input.get("agent_id")), hook_input.get("cwd")
    if agent is None or not isinstance(cwd, str) or not Path(cwd).is_absolute():
        return False
    try:
        if storage.check_tmp_dirs(PASS_FEATURE, cwd) is not None:
            return False
        path = storage.tmp_dir(PASS_FEATURE, cwd) / agent
        if path.is_symlink() or not path.is_file():
            return False
        marker = path.read_text(encoding="utf-8").strip()
    except (OSError, UnicodeDecodeError, ValueError):
        return False
    return hmac.compare_digest(marker, _last_line_sha(reply))


def _agent(hook_input: dict[str, object]) -> str:
    # 6.1: a stop without agent_type takes the newest SubagentStart type for its agent_id.
    from lib import audit, hook_io

    raw = hook_input.get("agent_type")
    agent_id, cwd = hook_input.get("agent_id"), hook_input.get("cwd")
    if not raw and isinstance(agent_id, str) and agent_id and isinstance(cwd, str):
        try:
            raw = audit._started_type(
                audit.log_path(str(hook_input.get("session_id")), cwd), agent_id
            )
        except (OSError, ValueError):
            raw = None
    return hook_io.agent({"agent_type": raw}) if raw else ""


def _reply(hook_input: dict[str, object]) -> object:
    # RCP: the stop's reply, or the hand-back tool's message; any other event has none.
    from lib.audit_proof import HANDBACK

    event = hook_input.get("hook_event_name")
    if event == "SubagentStop":
        return hook_input.get("last_assistant_message")
    fields = hook_input.get("tool_input")
    if event == "PreToolUse" and hook_input.get("tool_name") == HANDBACK:
        return fields.get("message") if isinstance(fields, dict) else None
    return None


def _unit_root(hook_input: dict[str, object]) -> Path | None:
    # 209: the worktree of the unit this coder is bound to (issue 29), else the hook cwd.
    from lib import train_state, unit_binding
    from lib.project_root import project_root

    cwd = hook_input.get("cwd")
    if not isinstance(cwd, str) or not cwd:
        return None
    agent_id, session = hook_input.get("agent_id"), hook_input.get("session_id")
    coder = agent_id if isinstance(agent_id, str) and agent_id else f"session:{session}"
    try:
        repo = project_root(Path(cwd))
        train = train_state.active_train(repo) if Path(cwd).is_absolute() else None
        unit = unit_binding.bound_units(repo, train).get(coder) if train else None
        units = train_state.units(train_state.load(repo, train)) if train and unit else []
    except (OSError, train_state.TrainStateError):
        units, unit = [], None
    path = next((u.get("path") for u in units if u.get("name") == unit), None)
    return Path(path) if isinstance(path, str) and Path(path).is_absolute() else Path(cwd)


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
_HANDOFF_HOLDS = (
    "what is done, what is left, the files read or touched, the next step and any open question"
)


def handoff_problem(hook_input: dict[str, object], agent: str, reply: str) -> str | None:
    # 0284: an agent with Write names its own hand-off file; one without carries it inline.
    from lib import handoff

    lines = [line.strip() for line in reply.splitlines() if line.strip()]
    if handoff.holds_write(agent, PLUGIN_ROOT):
        path = handoff.handoff_path(hook_input)
        if path is None:
            return (
                "the hand-off path cannot be built from this agent's id and working folder. "
                "Next: hand back with the hand-off inline and tell the operator."
            )
        want = f"{handoff.STATUS} path={path}"
        fix = f"Next: write the hand-off to {path} with the Write tool, then end with `{want}`."
        if lines[-1] != want:
            return f"the HANDOFF line is not `{want}`. {fix}"
        if not handoff.written(path):
            return f"the hand-off file {path} is missing, empty, a link or not a file. {fix}"
        return None
    want = f"{handoff.STATUS} {handoff.INLINE}"
    fix = (
        f"Next: end the reply with a `{handoff.HEADING}` section holding {_HANDOFF_HOLDS}, "
        f"then the line `{want}`."
    )
    if lines[-1] != want:
        return f"the HANDOFF line is not `{want}`. {fix}"
    if not any(line == handoff.HEADING for line in lines[:-2]):
        return f"the reply has no `{handoff.HEADING}` heading with a line under it. {fix}"
    return None


def judge(hook_input: dict[str, object]) -> str | None:
    from lib import handoff
    from lib.train_scope import KNOWN_AGENTS

    reply = _reply(hook_input)
    agent = _agent(hook_input) if isinstance(reply, str) and reply else ""
    last = [line.strip() for line in str(reply).splitlines() if line.strip()][-1:]
    if agent in KNOWN_AGENTS - {"main"} and last and last[0].startswith(handoff.STATUS):
        # 0284: judged before the judges' checks, so a HANDOFF reply leaves no pass marker.
        found = handoff_problem(hook_input, agent, str(reply))
        return None if found is None else f"Daedalus hand-back check: {found}"
    if agent in (VERIFIER, AUDITOR):
        stop = hook_input.get("hook_event_name") == "SubagentStop"
        if stop and relayed(hook_input, str(reply)):
            return None
        listed = round_findings(hook_input.get("cwd")) if agent == AUDITOR else None
        found = findings_problem(agent, str(reply), listed)
        if found is None:
            if not stop:
                write_pass(hook_input, str(reply))
            return None
        return f"Daedalus hand-back check: {found}. Next: {_judge_next(agent)}."
    if not isinstance(reply, str) or not reply or agent != CODER:
        return None
    problem = receipts_problem(reply, _unit_root(hook_input))
    if problem is None:
        return None
    fix = FILES_NEXT if problem.startswith(FILES_LEAD) else f"end the reply with {SHAPE}"
    return f"Daedalus hand-back check: {problem}. Next: {fix}."


def digest_output(hook_input: dict[str, object]) -> dict[str, object] | None:
    # 0205: a passing hand-back of a listed agent goes out as its digest; the report stays on disk.
    from lib import reply_digest
    from lib.audit import project_root
    from lib.train_state import active_train

    message, cwd = _reply(hook_input), hook_input.get("cwd")
    fields = hook_input.get("tool_input")
    if hook_input.get("hook_event_name") != "PreToolUse" or not isinstance(fields, dict):
        return None
    if not isinstance(message, str) or not isinstance(cwd, str) or not Path(cwd).is_absolute():
        return None
    repo = project_root(cwd)
    train = active_train(repo)
    agent_id = hook_input.get("agent_id")
    if train is None:
        return None
    short = reply_digest.digest(
        _agent(hook_input), message, repo, train, agent_id if isinstance(agent_id, str) else ""
    )
    if short is None:
        return None
    # 0205: allow only carries updatedInput; a deny from any other hook still wins.
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "allow",
            "permissionDecisionReason": "Daedalus reply digest (0205)",
            "updatedInput": {**fields, "message": short},
        }
    }


def _emit_digest(hook_input: dict[str, object]) -> None:
    out = digest_output(hook_input)
    if out is not None:
        print(json.dumps(out))


def main() -> int:
    try:
        from lib.project_root import train_marked

        payload = json.loads(sys.stdin.read() or "{}")
        if not isinstance(payload, dict) or not train_marked(payload.get("cwd")):
            return 0  # 0035: no train marker, no check.
        reason = judge(payload)
        if reason is not None and payload.get("hook_event_name") == "PreToolUse":
            from lib import hook_io

            hook_io.emit(reason)  # RCP: the PreToolUse deny shape the checks share.
        elif reason is not None:
            print(json.dumps({"decision": "block", "reason": reason}))
        else:
            _emit_digest(payload)
    except Exception as exc:  # noqa: BLE001
        # RCP: a broken check never stalls a train; the verifier still judges the unit.
        print(f"daedalus-handback-check: {exc}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
