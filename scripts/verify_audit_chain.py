#!/usr/bin/env python3
# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import NoReturn

sys.path.insert(0, str(Path(__file__).resolve().parent))
from lib.audit_proof import NOT_UTF8, ProofError, approved, hooks_live, verify_lines  # noqa: E402

__all__ = ["NOT_UTF8", "verify", "verify_lines"]
HOOKS_LIVE_NEEDLE = "verify_audit_chain.py --hooks-live"


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
MODE_USAGE = "usage: verify_audit_chain.py (--hooks-live | --approved <train-id>) --repo <repo>"
MODE_NEXT = (
    "Next: pass --hooks-live or --approved <train-id>, and --repo with the repository's path."
)


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> NoReturn:
        # 3.3: usage errors keep exit 1, as the legacy mode does.
        print(f"{MODE_USAGE}\nverify_audit_chain.py: {message}\n{MODE_NEXT}", file=sys.stderr)
        sys.exit(1)


def _mode(argv: list[str]) -> int:
    parser = _Parser(prog="verify_audit_chain.py", usage=MODE_USAGE)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--hooks-live", action="store_true")
    mode.add_argument("--approved", metavar="TRAIN_ID")
    parser.add_argument("--repo", type=Path, required=True)
    args = parser.parse_args(argv)
    repo = args.repo.resolve()
    try:
        if args.approved is None:
            print(hooks_live(repo, HOOKS_LIVE_NEEDLE))
        else:
            print(approved(repo, args.approved))
    except ProofError as exc:
        print(exc)
        return 1
    return 0


def main(argv: list[str]) -> int:
    if {"--hooks-live", "--approved"} & set(argv[1:]):
        return _mode(argv[1:])
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
