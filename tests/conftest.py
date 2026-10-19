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

from lib.config import Config, LedgerDecl  # noqa: E402

# 0044: the fake repo the jail and hook-script cases share; it is not a real git repo.
CWD = "/work/repo"
CFG = Config(
    charter_root=Path("/work/Charter"),
    ledger=LedgerDecl(
        Path("/work/Charter/decision-log.md"), "markdown-table-row", "{seq:04d}", "last-row-id"
    ),
)
WT = f"{CWD}/.claude/worktrees/20261015-120000-u1"
FAKE_UNITS = frozenset({f"{CWD}/.claude/worktrees/u1", WT})
# issue 11: the integration branch of the train CWD stands in for.
TRAIN_BRANCH = "daedalus/20261015-120000"


@pytest.fixture
def jail_fakes(monkeypatch: pytest.MonkeyPatch) -> None:
    # 0022: CWD is not a real repo; register its fake unit worktrees, real repos query git.
    from lib import dispatch_binding, gh_policy, hook_io, jail

    real = getattr(jail, "_registered_worktrees", None)

    def fake(repo: str) -> frozenset[str]:
        if repo == CWD:
            return FAKE_UNITS
        return real(repo) if real is not None else frozenset()

    monkeypatch.setattr(jail, "_registered_worktrees", fake, raising=False)
    # issue 29: CWD has no train state; binding is proven in tests/test_unit_binding.py.
    real_binding = dispatch_binding._binding_reason

    def no_binding(hook_input: dict[str, object], cwd: str, units: set[str]) -> str | None:
        return None if cwd == CWD else real_binding(hook_input, cwd, units)

    monkeypatch.setattr(dispatch_binding, "_binding_reason", no_binding)
    # 0035: CWD stands for a repo a train runs in; real repos below resolve their own marker.
    real_scoped = jail._train_scoped

    def scoped(cwd: str, tool: str, tool_input: dict[str, object]) -> bool:
        return cwd.startswith(CWD) or real_scoped(cwd, tool, tool_input)

    monkeypatch.setattr(jail, "_train_scoped", scoped)
    # issue 11: CWD has no marker; real repos read the branch from their own marker.
    real_branch = jail._train_branch

    def branch(cwd: str) -> str | None:
        return TRAIN_BRANCH if cwd.startswith(CWD) else real_branch(cwd)

    monkeypatch.setattr(jail, "_train_branch", branch)
    # spec 4.2: CWD has no train state; the verdict gate is proven in tests/test_checks_git_push.py.
    real_verdict = gh_policy.verdict_reason

    def verdict(cwd: str, what: str) -> str | None:
        return None if cwd.startswith(CWD) else real_verdict(cwd, what)

    monkeypatch.setattr(gh_policy, "verdict_reason", verdict)
    # 0044: hook scripts read the project config through this one name.
    monkeypatch.setattr(hook_io, "hook_config", lambda cwd: CFG)


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


def write_train_marker(repo: Path) -> Path:
    # 0035: the audit log records only while this marker exists.
    marker = repo / ".claude" / "daedalus" / "train.active"
    marker.parent.mkdir(parents=True, exist_ok=True)
    marker.write_text("20261017-120000\n", encoding="utf-8")
    return marker


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
