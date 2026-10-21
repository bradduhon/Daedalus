# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# W1.1: the one git runner; every call has a timeout and runs against -C <cwd>, never a redirect.
from __future__ import annotations

import os
import subprocess
from collections.abc import Sequence
from pathlib import Path

# 0010: env vars that would point git at another repository than the one -C names.
REDIRECT_ENV = frozenset(
    {
        "GIT_DIR",
        "GIT_COMMON_DIR",
        "GIT_WORK_TREE",
        "GIT_INDEX_FILE",
        "GIT_OBJECT_DIRECTORY",
        "GIT_ALTERNATE_OBJECT_DIRECTORIES",
        "GIT_NAMESPACE",
    }
)


class GitTimeout(subprocess.TimeoutExpired):
    pass


def env() -> dict[str, str]:
    return {k: v for k, v in os.environ.items() if k not in REDIRECT_ENV}


def run(
    args: Sequence[str], cwd: Path | str, timeout: float = 30.0
) -> subprocess.CompletedProcess[str]:
    # W1.1: a non-zero exit is returned for the caller to read; OSError (git missing) propagates.
    cmd = ["git", "-C", str(cwd), *args]
    try:
        return subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=env(),
            stdin=subprocess.DEVNULL,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise GitTimeout(exc.cmd, exc.timeout, exc.output, exc.stderr) from None
