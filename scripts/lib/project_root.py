# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0077, 0035: the one project root finder; filesystem only, no subprocess, so a plain folder
# runs no git. Standard library plus lib.repo_root, because the hooks import it before any lib.
from __future__ import annotations

from pathlib import Path

from lib.repo_root import git_root

MANIFEST = "service-manifest.json"
DATA_DIR = Path(".claude") / "daedalus"


def project_root(cwd: Path) -> Path:
    # 0077: nearest manifest or data-folder ancestor, else the git root, else cwd itself.
    start = Path(cwd)
    for folder in (start, *start.parents):
        if (folder / MANIFEST).is_file() or (folder / DATA_DIR).is_dir():
            # 0010: a linked worktree carries the manifest too; its main tree owns the data.
            main = git_root(str(folder)) if (folder / ".git").is_file() else None
            return main if main is not None and (main / ".git").is_dir() else folder
    return git_root(str(start)) or start


def in_git_work_tree(path: Path) -> bool:
    # 0074: repository scope is detected from the filesystem, never by running git.
    return git_root(str(path)) is not None
