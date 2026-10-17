# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import json
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from lib.audit import GENESIS, record_hash

AUDIT_DIR = Path(".claude") / "daedalus" / "audit"
SUMMARY_DIR = Path("docs") / ".tmp" / "daedalus"
NOT_UTF8 = "BROKEN: {path} is not valid UTF-8. Next: keep the file, report it, do not edit it."
DOCTOR_NEXT = "Next: run /daedalus:doctor."


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


def hooks_live(repo: Path, needle: str) -> str:
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
    return f"OK hooks live: session {log.stem}, chain intact ({len(records)} records)"
