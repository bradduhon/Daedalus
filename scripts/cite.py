#!/usr/bin/env python3
# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# RCP, 0128: cite.py <file> <pattern> prints <file>:<line> for each line holding the fixed string.
# Exit 0 printed at least one citation, 1 no line holds it, 2 a usage or read error.
from __future__ import annotations

import sys
from pathlib import Path

USAGE = "usage: cite.py <file> <pattern>"
USAGE_NEXT = "Next: pass one file path and one non-empty fixed string, in that order."


def citations(path: str, pattern: str) -> list[str]:
    # RCP: a fixed string, case-sensitive, one citation per matching line, numbered from 1.
    text = Path(path).read_text(encoding="utf-8", errors="surrogateescape")
    return [f"{path}:{n}" for n, line in enumerate(text.splitlines(), start=1) if pattern in line]


def main(argv: list[str]) -> int:
    if len(argv) != 2 or not argv[1]:
        print(f"{USAGE}\n{USAGE_NEXT}", file=sys.stderr)
        return 2
    path, pattern = argv
    try:
        found = citations(path, pattern)
    except OSError as exc:
        print(f"cite.py cannot read {path} ({exc.strerror or exc}).", file=sys.stderr)
        print("Next: check the path from your unit worktree, then rerun cite.py.", file=sys.stderr)
        return 2
    if not found:
        print(f"no line of {path} holds {pattern!r}.", file=sys.stderr)
        print("Next: copy the pattern from the file itself, then rerun cite.py.", file=sys.stderr)
        return 1
    print("\n".join(found))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
