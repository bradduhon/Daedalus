#!/usr/bin/env python3
# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# A2, 0252: start, save and show for Self-Assessment findings; the logic is in lib/findings.py.
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from lib import findings  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="daedalus_findings.py")
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("start", "save", "show"):
        one = sub.add_parser(name)
        one.add_argument("--repo", required=True)
        if name != "start":
            one.add_argument("--since", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "start":
            code, lines = findings.start(args.repo)
        elif args.command == "save":
            code, lines = findings.save(args.repo, args.since)
        else:
            code, lines = findings.show(args.repo, args.since)
    except Exception as exc:  # 0221: a one-line refusal, never a traceback
        code, lines = 1, [f"refused: {type(exc).__name__}: {exc}".splitlines()[0]]
    print("\n".join(lines))
    return code


if __name__ == "__main__":
    sys.exit(main())
