# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 21, W1.1: the one atomic writer and create-once writer; a link at the target is never followed.
from __future__ import annotations

import os
import secrets
from pathlib import Path

R_LINK = (
    "{path} is a symlink, and the plugin never writes through a link. "
    "Next: delete it from your own shell, then rerun."
)


class LinkRefused(OSError):
    def __init__(self, path: Path) -> None:
        super().__init__(R_LINK.format(path=path))
        self.path = path


def refuse_links(path: Path) -> None:
    # 0010: a link is refused, dangling or not; the caller walks each folder it relies on.
    if os.path.islink(path):
        raise LinkRefused(path)


def _temp(path: Path, mode: int) -> tuple[int, Path]:
    # 21: O_EXCL and O_NOFOLLOW on a random name in the target folder, so os.replace stays atomic.
    tmp = path.parent / f".{path.name}.{secrets.token_hex(8)}.tmp"
    return os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode), tmp


def _fill(fd: int, text: str) -> None:
    with os.fdopen(fd, "w", encoding="utf-8", newline="") as fh:
        fh.write(text)
        fh.flush()
        os.fsync(fh.fileno())


def write_atomic(path: Path, text: str, mode: int | None = None) -> None:
    # W1.1: os.replace onto the unresolved name replaces a link planted after the check, never its
    # target; mode None keeps the old file's mode, else a new file is 0600.
    refuse_links(path)
    try:
        old: int | None = os.lstat(path).st_mode & 0o7777
    except FileNotFoundError:
        old = None
    keep = mode if mode is not None else old if old is not None else 0o600
    fd, tmp = _temp(path, 0o600)
    try:
        os.fchmod(fd, keep)
        _fill(fd, text)
        os.replace(tmp, path)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise


def create_once(path: Path, text: str, mode: int) -> None:
    # W1.1: written whole, then linked in; link() never follows a link at path and raises
    # FileExistsError for anything there, so a reader never sees a partial file.
    fd, tmp = _temp(path, 0o600)
    try:
        os.fchmod(fd, mode)
        _fill(fd, text)
        os.link(tmp, path)
    finally:
        tmp.unlink(missing_ok=True)
