# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
from lib import audit, train_state, workspace
from lib.sandbox_state import SettingsError
from lib.workspace import WorkspaceError, begin, train_marker

from tests.conftest import SCRIPTS_DIR

NEEDLE_COMMAND = "python3 /p/scripts/daedalus_workspace.py begin --repo ."
LEDGER = "| Id | Date | Ruling | Supersedes | Follow-ups |\n|---|---|---|---|---|\n"


def _git(repo: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", "-C", str(repo), *args], capture_output=True, text=True, check=False
    )


def _ok(repo: Path, *args: str) -> str:
    result = _git(repo, *args)
    assert result.returncode == 0, result.stderr
    return result.stdout.strip()


def _commit_all(repo: Path, message: str) -> None:
    _ok(repo, "add", "-A")
    _ok(repo, "commit", "-q", "-m", message)


def _head(repo: Path) -> str:
    return _ok(repo, "rev-parse", "--abbrev-ref", "HEAD")


def _cli(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPTS_DIR / "daedalus_workspace.py"), *args],
        capture_output=True,
        text=True,
        check=False,
    )


@pytest.fixture(autouse=True)
def _isolated_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # 0020: a temp HOME keeps the operator's sandbox and plugin cache out of these tests.
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.delenv("CLAUDE_PLUGIN_DATA", raising=False)
    for key in ("AUTHOR", "COMMITTER"):
        monkeypatch.setenv(f"GIT_{key}_NAME", "t")
        monkeypatch.setenv(f"GIT_{key}_EMAIL", "t@example.invalid")
    monkeypatch.setenv("GIT_CONFIG_COUNT", "1")
    monkeypatch.setenv("GIT_CONFIG_KEY_0", "commit.gpgsign")
    monkeypatch.setenv("GIT_CONFIG_VALUE_0", "false")


@pytest.fixture
def repo(project_data: Path) -> Path:
    root = project_data.parent.parent
    (project_data / ".gitignore").write_text("*\n")
    (root / "docs").mkdir()
    (root / "docs" / "decisions.md").write_text(LEDGER)
    _commit_all(root, "init")
    return root


@pytest.fixture
def live(hook_input: Any, repo: Path) -> None:
    audit.audit_append(hook_input(tool_input={"command": NEEDLE_COMMAND}))


@pytest.fixture
def charter(tmp_path: Path, repo: Path) -> Path:
    root = tmp_path.resolve() / "charter"
    root.mkdir()
    _ok(root, "init", "-q", "-b", "main")
    (root / "README.md").write_text("charter\n")
    _commit_all(root, "init")
    config = repo / ".claude" / "daedalus" / "config.json"
    config.write_text(json.dumps({"charter_root": str(root)}))
    return root


def _nothing_written(repo: Path) -> None:
    assert not train_marker(repo).exists()
    assert not (repo / train_state.STATE_DIR).exists()


def test_begin_prints_the_state_block_seed(repo: Path, live: None) -> None:
    lines = begin(repo)
    prefixes = ["train: ", "ledger: ", "charter_root: ", "policy: ", "cache: ", "sandbox: "]
    assert [line.split(" ")[0] + " " for line in lines] == prefixes
    train = lines[0].split()[1]
    sha = _ok(repo, "rev-parse", "HEAD")
    assert lines[0] == f"train: {train}  base: main @ {sha}  audit session: sess-test"
    assert (
        lines[1] == f"ledger: {repo / 'docs' / 'decisions.md'} (probe, markdown-table-row, seq=0)"
    )
    assert lines[2] == "charter_root: none  charter base: none"
    assert lines[3] == "policy: none declared  standards: 0 sources"
    assert lines[4] == "cache: unresolved"
    assert lines[5] == "sandbox: off"
    state = train_state.load(repo, train)
    assert state["base_branch"] == "main" and state["base_sha"] == sha
    assert state["audit_session"] == "sess-test" and state["units"] == []
    assert train_marker(repo).read_text() == f"{train}\n"
    assert (repo / "docs" / ".tmp" / "daedalus" / ".gitignore").read_text() == "*\n"
    assert _git(repo, "status", "--porcelain").stdout == ""


def test_begin_cli_prints_six_lines(repo: Path, live: None) -> None:
    result = _cli("begin", "--repo", str(repo))
    assert result.returncode == 0, result.stderr
    assert len(result.stdout.splitlines()) == 6


def test_begin_stops_on_a_dirty_tree(repo: Path, live: None) -> None:
    (repo / "stray.txt").write_text("x\n")
    with pytest.raises(WorkspaceError) as info:
        begin(repo)
    assert "stray.txt" in str(info.value) and "Next: commit or stash" in str(info.value)
    _nothing_written(repo)


def test_begin_refuses_a_detached_head(repo: Path, live: None) -> None:
    _ok(repo, "switch", "-q", "--detach")
    with pytest.raises(WorkspaceError, match="Next:"):
        begin(repo)
    _nothing_written(repo)


def test_begin_asks_the_ledger_question_with_exit_three(repo: Path, live: None) -> None:
    _ok(repo, "rm", "-q", "docs/decisions.md")
    _ok(repo, "commit", "-q", "-m", "drop ledger")
    result = _cli("begin", "--repo", str(repo))
    assert result.returncode == 3, result.stderr
    assert result.stdout.splitlines() == [
        "ledger: none declared and none found.",
        "This repo has no decision ledger. Options: name an existing file, or let Daedalus "
        "create docs/decisions.md as a table. Which?",
        "| Id | Date | Ruling | Supersedes | Follow-ups |",
        "|---|---|---|---|---|",
    ]
    _nothing_written(repo)
    assert not (repo / "docs" / ".tmp").exists()


def test_begin_refuses_dead_hooks(repo: Path, hook_input: Any) -> None:
    audit.audit_append(hook_input(tool_input={"command": "ls"}))
    with pytest.raises(WorkspaceError) as info:
        begin(repo)
    assert str(info.value).startswith("NOT LIVE:")
    _nothing_written(repo)


def test_begin_branches_a_clean_charter(repo: Path, charter: Path, live: None) -> None:
    lines = begin(repo)
    train = lines[0].split()[1]
    assert lines[2] == f"charter_root: {charter}  charter base: main"
    assert _head(charter) == f"daedalus/{train}"
    state = train_state.load(repo, train)
    assert state["charter_base"] == "main" and state["charter_branch_created"] is True


def test_begin_stops_on_a_dirty_charter(repo: Path, charter: Path, live: None) -> None:
    (charter / "draft.md").write_text("x\n")
    with pytest.raises(WorkspaceError) as info:
        begin(repo)
    assert "draft.md" in str(info.value) and "Next:" in str(info.value)
    assert _head(charter) == "main"
    _nothing_written(repo)


def test_begin_switches_the_charter_back_when_a_later_step_fails(
    repo: Path, charter: Path, live: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    def _bad(repo: Path) -> str:
        raise SettingsError("settings.json is not valid JSON. Next: fix settings.json")

    monkeypatch.setattr(workspace, "sandbox_state", _bad)
    with pytest.raises(WorkspaceError, match="Next: fix settings.json"):
        begin(repo)
    assert _head(charter) == "main"
    _nothing_written(repo)


def test_begin_invalid_config_stops_with_its_next(repo: Path, live: None) -> None:
    (repo / ".claude" / "daedalus" / "config.json").write_text("{")
    with pytest.raises(WorkspaceError) as info:
        begin(repo)
    assert "not valid JSON" in str(info.value) and "Next:" in str(info.value)
    _nothing_written(repo)


def test_begin_reports_policy_and_cache(
    repo: Path, live: None, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cache = tmp_path / "cache"
    cache.mkdir()
    monkeypatch.setenv("CLAUDE_PLUGIN_DATA", str(cache))
    config = {
        "policy": {"engine": "conftest", "path": "policy/"},
        "standards_sources": [{"kind": "file", "path": "STANDARDS.md"}],
    }
    (repo / ".claude" / "daedalus" / "config.json").write_text(json.dumps(config))
    lines = begin(repo)
    assert lines[3] == "policy: conftest policy  standards: 1 sources"
    assert lines[4] == f"cache: {cache.resolve()}/frameworks"
    assert os.path.isabs(lines[4].split()[1])
