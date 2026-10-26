#!/usr/bin/env python3
# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# RCP, 0128: the check on a repo-coder's COMPLETE reply, before any verifier runs. It reads the
# SubagentStop reply and, by the operator's pick 4 of train 20261026-002310, the message of a
# PreToolUse SubagentHandback call. Pin RCP -> VER: the receipts block sits directly above the
# COMPLETE line. A yield, another agent's reply and an empty reply pass; a check that cannot run
# never blocks.
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

CODER = "repo-coder"
RECEIPTS = "## Receipts"
# Pin RCP -> VER: the only five line shapes the block holds, by kind.
SHAPES: dict[str, re.Pattern[str]] = {
    "commit": re.compile(r"- commit [0-9a-f]{40} .*\S"),
    "test": re.compile(r"- test \S.* => .*\S"),
    "typecheck": re.compile(r"- typecheck \S.* => .*\S"),
    "yield": re.compile(r"- yield \S+ \S.* => .*\S"),
    "deviation": re.compile(r"- deviation \S.* \| .*\S"),
}
REQUIRED = ("commit", "test")
SHAPE = (
    "a line `## Receipts`, then only lines `- commit <40 hex> <subject>`, "
    "`- test <command> => <last output line>`, `- typecheck <command> => <last output line>`, "
    "`- yield <kind> <question> => <who answered>` and "
    "`- deviation <file or behaviour> | <reason>`, "
    "with at least one commit line and one test line, and the COMPLETE line unchanged"
)
SHOWN_CHARS = 120


def _kind(line: str) -> str | None:
    return next((kind for kind, shape in SHAPES.items() if shape.fullmatch(line)), None)


def receipts_problem(reply: str) -> str | None:
    # Pin RCP -> VER: None when the reply's last line is no COMPLETE line or its block is whole.
    from lib.train_runner import COMPLETE_LINE

    lines = [line.rstrip() for line in reply.rstrip().splitlines()]
    if not lines or not lines[-1].strip().startswith(COMPLETE_LINE):
        return None
    body = lines[:-1]
    if RECEIPTS not in body:
        return f"the COMPLETE reply has no `{RECEIPTS}` line above its status line"
    block = body[len(body) - body[::-1].index(RECEIPTS) :]
    kinds: set[str] = set()
    for line in block:
        kind = _kind(line)
        if kind is None:
            shown = line if len(line) <= SHOWN_CHARS else line[:SHOWN_CHARS] + "..."
            return f"the receipts block holds a line of another shape: {shown!r}"
        kinds.add(kind)
    missing = [kind for kind in REQUIRED if kind not in kinds]
    if missing:
        return "the receipts block has no " + " and no ".join(missing) + " line"
    return None


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


def judge(hook_input: dict[str, object]) -> str | None:
    reply = _reply(hook_input)
    if not isinstance(reply, str) or not reply or _agent(hook_input) != CODER:
        return None
    problem = receipts_problem(reply)
    if problem is None:
        return None
    return f"Daedalus hand-back check: {problem}. Next: end the reply with {SHAPE}."


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
    except Exception as exc:  # noqa: BLE001
        # RCP: a broken check never stalls a train; the verifier still judges the unit.
        print(f"daedalus-handback-check: {exc}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
