#!/usr/bin/env python3
# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from lib.project_root import repo_refusal  # noqa: E402
from lib.workspace import (  # noqa: E402
    LedgerQuestion,
    WorkspaceError,
    begin,
    clear_train,
    create,
    finish,
    lock,
    mark_train,
    merge,
    refresh,
    release,
    remove,
    resume,
    stop,
    worktree_path,
)


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        description="Daedalus worktrees and train state: create, remove, refresh, mark, unmark, "
        "begin, lock, stop, finish, merge, resume, release. Exit 0 done, 1 stopped with a Next "
        "line, 3 ledger question."
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
    halt = sub.add_parser("stop")
    halt.add_argument("--repo", type=Path, required=True)
    halt.add_argument("--reason", required=True)
    halt.add_argument("--next", dest="next_action")
    for action in ("finish", "resume"):
        sub.add_parser(action).add_argument("--repo", type=Path, required=True)
    # 0121: one wave of units into the integration branch, the train left open.
    wave = sub.add_parser("merge")
    wave.add_argument("--repo", type=Path, required=True)
    wave.add_argument("--units", required=True)
    publish = sub.add_parser("release")
    publish.add_argument("--repo", type=Path, required=True)
    publish.add_argument("--merge-sha", dest="merge_sha", required=True)
    again = sub.add_parser("refresh")
    again.add_argument("--repo", type=Path, required=True)
    again.add_argument("--name", required=True)
    args = parser.parse_args(argv)
    repo = args.repo.resolve()
    # pin C3 -> C4, issue 63: --repo is the project root of the working directory, or nothing runs.
    refusal = repo_refusal(args.repo, Path.cwd())
    if refusal is not None:
        print(f"daedalus-workspace: {refusal}", file=sys.stderr)
        return 1
    try:
        if args.action == "create":
            print(create(repo, args.name, args.base))
        elif args.action == "refresh":
            print(refresh(repo, args.name))
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
        elif args.action == "stop":
            lines, ok = stop(repo, args.reason, args.next_action)
            print("\n".join(lines))
            return 0 if ok else 1
        elif args.action == "finish":
            print("\n".join(finish(repo)))
        elif args.action == "merge":
            ids = [part.strip() for part in args.units.split(",") if part.strip()]
            print("\n".join(merge(repo, ids)))
        elif args.action == "resume":
            print("\n".join(resume(repo)))
        elif args.action == "release":
            print("\n".join(release(repo, args.merge_sha)))
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
