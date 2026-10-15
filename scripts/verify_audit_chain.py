#!/usr/bin/env python3
# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import json
import sys
from collections.abc import Iterable
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from lib.audit import GENESIS, record_hash  # noqa: E402

NOT_UTF8 = "BROKEN: {path} is not valid UTF-8. Next: keep the file, report it, do not edit it."


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


def verify(path: Path) -> tuple[bool, str]:
    with open(path, encoding="utf-8") as fh:
        return verify_lines(fh)


USAGE = "usage: verify_audit_chain.py <session.jsonl>"
USAGE_NEXT = "Next: pass the path of a session log under .claude/daedalus/audit/."
MISSING = (
    "BROKEN: {path} does not exist. Next: list .claude/daedalus/audit/ and pass an existing log."
)

NOT_FILE = (
    "BROKEN: {path} is not a regular file. Next: pass a session log (.jsonl) under "
    ".claude/daedalus/audit/."
)


def main(argv: list[str]) -> int:
    if len(argv) == 2 and argv[1] in ("-h", "--help"):
        print(f"{USAGE}\n{USAGE_NEXT}")
        return 0
    if len(argv) != 2:
        print(f"{USAGE}\n{USAGE_NEXT}", file=sys.stderr)
        return 1
    if not Path(argv[1]).exists():
        print(MISSING.format(path=argv[1]))
        return 1
    if not Path(argv[1]).is_file():
        print(NOT_FILE.format(path=argv[1]))
        return 1
    try:
        ok, message = verify(Path(argv[1]))
    except UnicodeDecodeError:
        ok, message = False, NOT_UTF8.format(path=argv[1])
    print(message)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
