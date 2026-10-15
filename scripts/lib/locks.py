# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import fcntl
import time
from typing import Any


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
                raise RuntimeError(
                    f"{label} held for {timeout_s:g} s ({fh.name}). "
                    "Next: find and stop the stuck hook process; do not delete the .lock file."
                ) from None
            time.sleep(poll_s)
