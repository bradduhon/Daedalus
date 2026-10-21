# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 75, W1.1: the one lock opener and the one bounded lock; every lock in the tree goes through them.
from __future__ import annotations

import fcntl
import os
import stat
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import IO, Any

R_LOCK_NOT_REGULAR = "lock {path} is not a regular file. Next: remove it and retry."


class LockRefused(OSError):
    def __init__(self, path: Path) -> None:
        super().__init__(R_LOCK_NOT_REGULAR.format(path=path))
        self.path = path


class LockHeld(RuntimeError):
    pass


def bounded_flock(
    fh: Any, timeout_s: float = 5.0, poll_s: float = 0.05, label: str = "lock"
) -> None:
    # I6: bounded wait; a hung holder must not stall every later caller.
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fcntl.flock(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return
        except BlockingIOError:
            if time.monotonic() >= deadline:
                raise LockHeld(
                    f"{label} held for {timeout_s:g} s ({fh.name}). "
                    "Next: find and stop the stuck hook process; do not delete the .lock file."
                ) from None
            time.sleep(poll_s)


def open_lock(path: Path) -> int:
    # 75: O_NONBLOCK so a planted FIFO cannot hang the open; only a regular file is a lock.
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    try:
        regular = stat.S_ISREG(os.fstat(fd).st_mode)
    except BaseException:
        os.close(fd)
        raise
    if not regular:
        os.close(fd)
        raise LockRefused(path)
    return fd


@contextmanager
def locked(path: Path, timeout_s: float = 5.0, label: str = "lock") -> Iterator[IO[str]]:
    # OSError (LockRefused included) when the open fails; LockHeld when the wait runs out.
    with open(path, "r+", opener=lambda name, _flags: open_lock(Path(name))) as handle:
        bounded_flock(handle, timeout_s, label=label)
        yield handle
