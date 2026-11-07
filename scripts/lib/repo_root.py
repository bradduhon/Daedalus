# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0035: standard library only; the hooks find a train marker before loading any other lib module.
from __future__ import annotations

import os
from pathlib import Path

TRAIN_MARKER = Path(".claude") / "daedalus" / "train.active"


def checkout_git_dir(path: str) -> tuple[Path, Path | None] | None:
    # issue 186: the nearest checkout and its own git dir holding HEAD; None for a bad .git.
    start = Path(path)
    for folder in (start, *start.parents):
        dot = folder / ".git"
        if dot.is_dir():
            return folder, dot
        if not dot.is_file():
            continue
        try:
            text = dot.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            return folder, None
        if not text.startswith("gitdir:"):
            return folder, None
        return folder, folder / text[len("gitdir:") :].strip()
    return None


def git_root(path: str) -> Path | None:
    # 0035: filesystem mirror of git's common dir; the main working tree, None outside git.
    found = checkout_git_dir(path)
    if found is None:
        return None
    folder, gitdir = found
    if gitdir is None or (folder / ".git").is_dir():
        return folder
    try:
        common = gitdir / (gitdir / "commondir").read_text(encoding="utf-8").strip()
    except (OSError, UnicodeDecodeError):
        common = gitdir
    return Path(os.path.normpath(common)).parent
