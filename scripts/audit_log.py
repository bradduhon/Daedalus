#!/usr/bin/env python3
# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))


def main() -> int:
    try:
        from lib.project_root import train_marked

        payload = json.loads(sys.stdin.read() or "{}")
        cwd = payload.get("cwd") if isinstance(payload, dict) else None
        # 0035: no train marker, no record; the audit modules are not even imported.
        if not train_marked(cwd):
            return 0
        from lib.audit import audit_append, root_info

        record = audit_append(payload)
        if record is not None and record.get("root_source") == "cwd-fallback":
            reason = root_info(payload["cwd"])[2]
            print(f"daedalus-audit: project root fell back to cwd ({reason})", file=sys.stderr)
    except Exception as exc:  # noqa: BLE001
        # 8.4: logging failures never block a non-mutating event; the jail blocks.
        print(f"daedalus-audit: {exc}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
