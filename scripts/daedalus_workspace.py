#!/usr/bin/env python3
# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from lib.workspace import (  # noqa: E402
    LedgerQuestion,
    WorkspaceError,
    begin,
    clear_train,
    create,
    lock,
    mark_train,
    remove,
    worktree_path,
)


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        description="Create or remove a Daedalus worktree; mark or unmark the active train."
    )
    sub = parser.add_subparsers(dest="action", required=True)
    make = sub.add_parser("create")
    make.add_argument("--repo", type=Path, required=True)
    make.add_argument("--name", required=True)
    make.add_argument("--base", required=True)
    drop = sub.add_parser("remove")
    drop.add_argument("--repo", type=Path, required=True)
    drop.add_argument("--name", required=True)
    mark = sub.add_parser("mark")
    mark.add_argument("--repo", type=Path, required=True)
    mark.add_argument("--train", required=True)
    unmark = sub.add_parser("unmark")
    unmark.add_argument("--repo", type=Path, required=True)
    start = sub.add_parser("begin")
    start.add_argument("--repo", type=Path, required=True)
    locking = sub.add_parser("lock")
    locking.add_argument("--repo", type=Path, required=True)
    locking.add_argument("--contract", required=True)
    locking.add_argument("--version", type=int, required=True)
    args = parser.parse_args(argv)
    repo = args.repo.resolve()
    try:
        if args.action == "create":
            print(create(repo, args.name, args.base))
        elif args.action == "remove":
            remove(repo, args.name)
            print(f"removed {worktree_path(repo, args.name)}")
        elif args.action == "mark":
            print(mark_train(repo, args.train))
        elif args.action == "unmark":
            print(f"cleared {clear_train(repo)}")
        elif args.action == "begin":
            print("\n".join(begin(repo)))
        elif args.action == "lock":
            print("\n".join(lock(repo, args.contract, args.version)))
    except LedgerQuestion as exc:
        # 0004: exit 3 hands the ledger question to the operator; nothing was written.
        print(exc)
        return 3
    except WorkspaceError as exc:
        print(f"daedalus-workspace: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
