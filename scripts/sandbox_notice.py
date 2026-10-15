#!/usr/bin/env python3
# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
from lib.audit import project_root  # noqa: E402
from lib.sandbox_state import sandbox_check  # noqa: E402


def _payload(raw: str) -> dict[str, Any]:
    # spec 5: empty or non-JSON input falls back to the current directory.
    try:
        data = json.loads(raw)
    except ValueError:
        return {}
    return data if isinstance(data, dict) else {}


def notice(payload: dict[str, Any]) -> str | None:
    cwd = payload.get("cwd")
    ok, line = sandbox_check(project_root(cwd if isinstance(cwd, str) and cwd else os.getcwd()))
    return None if ok else line


def main() -> int:
    # 0020: SessionStart never blocks; it names the sandbox state only when it is not on.
    try:
        line = notice(_payload(sys.stdin.read()))
    except Exception as exc:  # noqa: BLE001
        print(f"daedalus-sandbox: {exc}", file=sys.stderr)
        return 0
    if line:
        context = {"hookEventName": "SessionStart", "additionalContext": line}
        print(json.dumps({"systemMessage": line, "hookSpecificOutput": context}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
