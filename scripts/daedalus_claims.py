#!/usr/bin/env python3
# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0230: daedalus_claims.py --worktree <path> --branch <b> --ranges <file>:<first>-<last>[,...]
# prints every named range as `git -C <path> show <b>:<file>` holds it, each headed
# `== <file>:<first>-<last> ==`, in one output. Exit 0 printed every range, 1 a file is not on
# the branch (its header and one `!!` line are printed), 2 a usage error.
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from lib.shell import claims_ok, claims_ranges  # noqa: E402

USAGE = (
    "usage: daedalus_claims.py --worktree <absolute path> --branch <branch> "
    "--ranges <file>:<first>-<last>[,...]"
)
USAGE_NEXT = (
    "Next: pass the three options once each in that order, an absolute worktree, a branch name "
    "and comma-joined ranges of relative files with lines from 1."
)


def _show(worktree: str, branch: str, file: str) -> tuple[list[str] | None, str]:
    # 0230: the verifier's own read, git show <branch>:<file>, run once per file.
    got = subprocess.run(
        ["git", "-C", worktree, "show", f"{branch}:{file}"],
        capture_output=True,
        check=False,
    )
    if got.returncode != 0:
        lines = got.stderr.decode("utf-8", "replace").strip().splitlines()
        return None, lines[-1] if lines else f"git exited {got.returncode}"
    text = got.stdout.decode("utf-8", "surrogateescape")
    return text.splitlines(), ""


def render(worktree: str, branch: str, ranges: list[tuple[str, int, int]]) -> tuple[str, int]:
    out: list[str] = []
    code = 0
    shown: dict[str, tuple[list[str] | None, str]] = {}
    for file, first, last in ranges:
        if file not in shown:
            shown[file] = _show(worktree, branch, file)
        lines, error = shown[file]
        out.append(f"== {file}:{first}-{last} ==")
        if lines is None:
            out.append(f"!! {file} is not readable on {branch}: {error}")
            code = 1
            continue
        out.extend(lines[first - 1 : last])
    return "\n".join(out) + "\n", code


def _parse(argv: list[str]) -> tuple[str, str, list[tuple[str, int, int]]] | None:
    # 0230: the jail's own reader judges the arguments, so the script admits what the jail does.
    if not claims_ok(["python3", str(Path(__file__).resolve()), *argv]):
        return None
    worktree, branch, value = argv[1::2]
    ranges = claims_ranges(value)
    if ranges is None or not os.path.isdir(worktree):
        return None
    return worktree, branch, ranges


def main(argv: list[str]) -> int:
    parsed = _parse(argv)
    if parsed is None:
        print(f"{USAGE}\n{USAGE_NEXT}", file=sys.stderr)
        return 2
    text, code = render(*parsed)
    sys.stdout.write(text)
    return code


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
