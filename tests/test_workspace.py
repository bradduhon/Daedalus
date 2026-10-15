# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

import pytest
from lib.workspace import WorkspaceError, branch_name, create, remove, worktree_path

from tests.conftest import SCRIPTS_DIR

BASE = "daedalus/20261015-120000"
NAME = "20261015-120000-u1"


def _git(repo: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", "-C", str(repo), *args], capture_output=True, text=True, check=False
    )


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    root = tmp_path.resolve() / "repo"
    root.mkdir()
    assert _git(root, "init", "-q", "-b", "main").returncode == 0
    commit = ["-c", "user.name=t", "-c", "user.email=t@example.invalid"]
    commit += ["-c", "commit.gpgsign=false", "commit", "-q", "--allow-empty", "-m", "init"]
    assert _git(root, *commit).returncode == 0
    assert _git(root, "branch", BASE).returncode == 0
    return root


def test_create_branches_from_the_base_ref(repo: Path) -> None:
    path = create(repo, NAME, BASE)
    assert path == repo / ".claude" / "worktrees" / NAME == worktree_path(repo, NAME)
    assert (path / ".git").is_file()
    head = _git(path, "rev-parse", "--abbrev-ref", "HEAD").stdout.strip()
    assert head == branch_name(NAME) == f"daedalus-unit/{NAME}"
    assert _git(repo, "merge-base", "--is-ancestor", BASE, head).returncode == 0
    assert (repo / ".claude" / "worktrees" / ".gitignore").read_text() == "*\n"
    assert _git(repo, "status", "--porcelain").stdout == ""


def test_create_keeps_an_existing_marker(repo: Path) -> None:
    marker = repo / ".claude" / "worktrees" / ".gitignore"
    marker.parent.mkdir(parents=True)
    marker.write_text("*")
    create(repo, NAME, BASE)
    assert marker.read_text() == "*"


@pytest.mark.parametrize("name", ["../x", "U1", "", "a/b", "-x"])
def test_create_rejects_a_bad_name(repo: Path, name: str) -> None:
    with pytest.raises(WorkspaceError) as info:
        create(repo, name, BASE)
    assert "Next:" in str(info.value)


def test_create_reports_a_missing_base_ref(repo: Path) -> None:
    with pytest.raises(WorkspaceError) as info:
        create(repo, NAME, "daedalus/nope")
    assert "git worktree add failed" in str(info.value) and "Next:" in str(info.value)


def test_create_refuses_an_existing_path(repo: Path) -> None:
    worktree_path(repo, NAME).mkdir(parents=True)
    with pytest.raises(WorkspaceError) as info:
        create(repo, NAME, BASE)
    message = str(info.value)
    assert "already exists" in message and "Next:" in message and "remove" in message


def test_create_refuses_an_existing_branch(repo: Path) -> None:
    assert _git(repo, "branch", branch_name(NAME), BASE).returncode == 0
    with pytest.raises(WorkspaceError) as info:
        create(repo, NAME, BASE)
    message = str(info.value)
    assert "already exists" in message and "Next:" in message and "remove" in message
    assert not worktree_path(repo, NAME).exists()


def test_remove_deletes_the_worktree_and_keeps_the_branch(repo: Path) -> None:
    path = create(repo, NAME, BASE)
    (path / "scratch.txt").write_text("uncommitted")
    remove(repo, NAME)
    assert not path.exists()
    assert str(path) not in _git(repo, "worktree", "list", "--porcelain").stdout
    assert _git(repo, "rev-parse", "--verify", branch_name(NAME)).returncode == 0


def test_remove_prunes_a_worktree_already_gone(repo: Path) -> None:
    path = create(repo, NAME, BASE)
    shutil.rmtree(path)
    remove(repo, NAME)
    remove(repo, NAME)
    assert str(path) not in _git(repo, "worktree", "list", "--porcelain").stdout


@pytest.mark.parametrize("name", ["a/b", "../x"])
def test_remove_refuses_a_name_that_escapes(repo: Path, name: str) -> None:
    with pytest.raises(WorkspaceError) as info:
        remove(repo, name)
    assert "Next:" in str(info.value)


def test_remove_refuses_a_symlinked_worktrees_dir(repo: Path, tmp_path: Path) -> None:
    outside = tmp_path / "outside" / NAME
    outside.mkdir(parents=True)
    (repo / ".claude").mkdir()
    (repo / ".claude" / "worktrees").symlink_to(outside.parent)
    with pytest.raises(WorkspaceError) as info:
        remove(repo, NAME)
    assert "Next:" in str(info.value)
    assert outside.is_dir()


def _cli(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPTS_DIR / "daedalus_workspace.py"), *args],
        capture_output=True,
        text=True,
        check=False,
    )


def test_cli_create_prints_the_path_and_remove_names_it(repo: Path) -> None:
    made = _cli("create", "--repo", str(repo), "--name", NAME, "--base", BASE)
    assert made.returncode == 0, made.stderr
    assert made.stdout == f"{worktree_path(repo, NAME)}\n"
    gone = _cli("remove", "--repo", str(repo), "--name", NAME)
    assert gone.returncode == 0, gone.stderr
    assert gone.stdout == f"removed {worktree_path(repo, NAME)}\n"


def test_cli_error_exits_one_with_next(repo: Path) -> None:
    result = _cli("create", "--repo", str(repo), "--name", NAME, "--base", "daedalus/nope")
    assert result.returncode == 1
    assert result.stderr.startswith("daedalus-workspace: ") and "Next:" in result.stderr
