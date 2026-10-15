#!/usr/bin/env python3
# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

# Exit 1 is non-blocking for a PreToolUse hook, so an import failure must exit 2.
try:
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from lib.audit import audit_append, root_info
    from lib.config import Config, load_config
    from lib.jail import CREDENTIAL_TOOLS, Decision, decide
except Exception as _exc:  # noqa: BLE001
    print(
        f"daedalus-jail[?]: hook could not load its libraries ({_exc}). "
        "Next: run the plugin with Python 3.12 and an intact scripts/lib directory.",
        file=sys.stderr,
    )
    sys.exit(2)

_CONFIG_NEXT = " Next: fix <repo>/.claude/daedalus/config.json and retry."
_REPORT_NEXT = " Next: report this hook failure to the operator."


def _block(agent: str, message: str, next_step: str = _REPORT_NEXT) -> int:
    if "Next:" not in message:
        message += next_step
    try:
        print(f"daedalus-jail[{agent}]: {message}", file=sys.stderr)
    except OSError:
        pass  # m5: a closed stderr must not turn the block into exit 1.
    return 2


def _note(agent: str, message: str) -> None:
    try:
        print(f"daedalus-jail[{agent}]: {message}", file=sys.stderr)
    except OSError:
        pass  # m5: a closed stderr must not turn an allow into exit 1.


def _warn_fallback(cwd: str) -> None:
    try:
        print(
            f"daedalus-audit: project root fell back to cwd ({root_info(cwd)[2]})", file=sys.stderr
        )
    except OSError:
        pass  # m5: a closed stderr must not turn an allow into exit 1.


def _record_and_block(
    payload: dict[str, Any], agent: str, message: str, next_step: str = _REPORT_NEXT
) -> int:
    if "Next:" not in message:
        message += next_step
    try:
        audit_append(payload, "block", message)
    except Exception:  # noqa: BLE001, S110
        pass  # 8.5: best effort; the block stands whether or not the record lands.
    return _block(agent, message)


def _judge(payload: dict[str, Any], agent: str) -> int:
    cwd = payload.get("cwd")
    # 0023: reads carry only the credential deny, so a broken data dir never closes them.
    read = payload.get("tool_name") in CREDENTIAL_TOOLS and isinstance(cwd, str)
    read = read and Path(cwd).is_absolute()
    try:
        config = load_config(cwd)
    except Exception as exc:  # noqa: BLE001
        if not read:
            return _record_and_block(payload, agent, str(exc), _CONFIG_NEXT)
        config = Config()
    decision: Decision = decide(payload, config)
    agent = decision.agent or agent
    try:
        record = audit_append(payload, "allow" if decision.allow else "block", decision.reason)
    except Exception as exc:  # noqa: BLE001
        if read and decision.allow:
            # spec 8: an allowed read is non-blocking on a failed record, as audit_log.py is.
            _note(agent, f"audit log unavailable ({exc}); the read proceeds unrecorded.")
            return 0
        # 8.5: no record, no action. The jail fails closed when the chain cannot be written.
        detail = f"audit log unavailable ({exc})."
        if "Next:" not in detail:
            detail += " Next: fix the project data dir (<repo>/.claude/daedalus) and retry."
        return _block(agent, detail)
    if record.get("root_source") == "cwd-fallback":
        _warn_fallback(str(payload.get("cwd")))
    if decision.allow:
        return 0
    return _block(agent, str(decision.reason))


def main() -> int:
    # Every path but a clean allow exits 2.
    try:
        text = sys.stdin.read()
        if not text.strip():
            return _block("?", "hook input is empty.")
        payload = json.loads(text)
    except Exception as exc:  # noqa: BLE001
        return _block("?", f"hook input could not be parsed ({exc}).")
    if not isinstance(payload, dict):
        return _block("?", "hook input is not a JSON object.")
    agent = str(payload.get("agent_type") or "main")
    tool_name = payload.get("tool_name")
    if not isinstance(tool_name, str) or not tool_name:
        return _block(agent, "hook input has no tool_name string.")
    if "tool_input" in payload and not isinstance(payload["tool_input"], dict):
        return _block(agent, "hook input tool_input is not an object.")
    try:
        return _judge(payload, agent)
    except Exception as exc:  # noqa: BLE001
        return _record_and_block(payload, agent, str(exc))


if __name__ == "__main__":
    sys.exit(main())
