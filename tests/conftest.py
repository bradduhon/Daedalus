# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import json
import os
import subprocess
import sys
from collections.abc import Callable, Iterable, Iterator
from pathlib import Path
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS_DIR = REPO_ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS_DIR))


def fake_bin(
    tmp_path: Path, names: Iterable[str], exit_codes: dict[str, int] | None = None
) -> Path:
    # 0020: shared stub-tool directory for PATH; each stub exits with its mapped code or 0.
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    codes = exit_codes or {}
    for name in names:
        tool = bin_dir / name
        tool.write_text(f"#!/bin/sh\nexit {codes.get(name, 0)}\n")
        tool.chmod(0o755)
    return bin_dir


@pytest.fixture
def plugin_data(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    root = tmp_path / "plugin-data"
    root.mkdir()
    monkeypatch.setenv("CLAUDE_PLUGIN_DATA", str(root))
    return root


@pytest.fixture(autouse=True)
def _fresh_project_root() -> Iterator[None]:
    # 0010: root_info and the tracked-file check are cached per process; tests need them cold.
    from lib import audit

    audit.root_info.cache_clear()
    audit._TRACKED.clear()
    yield
    audit.root_info.cache_clear()
    audit._TRACKED.clear()


@pytest.fixture
def repo_cwd(tmp_path: Path) -> Path:
    root = tmp_path.resolve() / "repo"
    root.mkdir()
    subprocess.run(["git", "init", "-q", "-b", "main", str(root)], check=True)
    return root


@pytest.fixture
def project_data(repo_cwd: Path) -> Path:
    data = repo_cwd / ".claude" / "daedalus"
    data.mkdir(parents=True)
    return data


@pytest.fixture
def hook_input(repo_cwd: Path) -> Callable[..., dict[str, Any]]:
    def _make(**overrides: Any) -> dict[str, Any]:
        base: dict[str, Any] = {
            "session_id": "sess-test",
            "hook_event_name": "PreToolUse",
            "cwd": str(repo_cwd),
            "tool_name": "Bash",
            "tool_input": {"command": "ls"},
            "tool_use_id": "toolu_1",
        }
        base.update(overrides)
        return base

    return _make


@pytest.fixture
def run_script(
    plugin_data: Path,
) -> Callable[[str, dict[str, Any]], subprocess.CompletedProcess[str]]:
    def _run(script: str, payload: dict[str, Any]) -> subprocess.CompletedProcess[str]:
        env = dict(os.environ)
        env["CLAUDE_PLUGIN_DATA"] = str(plugin_data)
        return subprocess.run(
            [sys.executable, str(SCRIPTS_DIR / script)],
            input=json.dumps(payload),
            capture_output=True,
            text=True,
            env=env,
            check=False,
        )

    return _run
