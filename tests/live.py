# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# W1.4: the shared runner for the live tests that drive the real claude CLI.
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest


class LiveRun:
    def __init__(self, result: subprocess.CompletedProcess[str], session: str, repo: Path) -> None:
        self.result = result
        self.session = session
        self.repo = repo


def require_claude() -> None:
    if shutil.which("claude") is None:
        pytest.skip("claude CLI not on PATH")


def run_claude(
    args: list[str], session: str, cwd: Path, env: dict[str, str], label: str = ""
) -> LiveRun:
    # W1.4: one claude -p run with a five-minute cap; the transcript prints for the receipt.
    result = subprocess.run(
        ["claude", "-p", *args],
        capture_output=True,
        text=True,
        env=env,
        cwd=cwd,
        check=False,
        timeout=300,
    )
    print(f"{label}session={session} exit={result.returncode}")
    print(f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}")
    return LiveRun(result, session, cwd)
