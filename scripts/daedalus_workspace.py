#!/usr/bin/env python3
# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from lib.workspace import WorkspaceError, create, remove, worktree_path  # noqa: E402


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Create or remove a Daedalus worktree.")
    sub = parser.add_subparsers(dest="action", required=True)
    make = sub.add_parser("create")
    make.add_argument("--repo", type=Path, required=True)
    make.add_argument("--name", required=True)
    make.add_argument("--base", required=True)
    drop = sub.add_parser("remove")
    drop.add_argument("--repo", type=Path, required=True)
    drop.add_argument("--name", required=True)
    args = parser.parse_args(argv)
    repo = args.repo.resolve()
    try:
        if args.action == "create":
            print(create(repo, args.name, args.base))
        else:
            remove(repo, args.name)
            print(f"removed {worktree_path(repo, args.name)}")
    except WorkspaceError as exc:
        print(f"daedalus-workspace: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
