# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

import pytest
from lib import workspace
from lib.workspace import (
    WorkspaceError,
    branch_name,
    clear_train,
    create,
    mark_train,
    remove,
    train_marker,
    worktree_path,
)

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


def test_create_and_remove_resolve_a_relative_repo(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(repo.parent)
    path = create(Path(repo.name), NAME, BASE)
    assert path == worktree_path(repo, NAME) and path.is_absolute() and path.is_dir()
    assert not (repo / repo.name).exists()
    remove(Path(repo.name), NAME)
    assert not path.exists()


def test_create_timeout_names_unlock(repo: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def hang(cmd: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        if "add" in cmd:
            raise subprocess.TimeoutExpired(cmd, 1)
        return subprocess.CompletedProcess(cmd, 1, "", "")

    monkeypatch.setattr(workspace.subprocess, "run", hang)
    with pytest.raises(WorkspaceError) as info:
        create(repo, NAME, BASE)
    message = str(info.value)
    assert "timed out" in message and "Next:" in message
    assert f"worktree unlock {worktree_path(repo, NAME)}" in message


def test_create_reports_an_unwritable_marker(repo: Path) -> None:
    (repo / ".claude").write_text("not a directory")
    with pytest.raises(WorkspaceError) as info:
        create(repo, NAME, BASE)
    assert "cannot write" in str(info.value) and "Next:" in str(info.value)


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


TRAIN = "20261015-120000"


@pytest.fixture
def data_repo(repo: Path) -> Path:
    (repo / ".claude" / "daedalus").mkdir(parents=True)
    return repo


def test_mark_train_writes_the_train_id_first(data_repo: Path) -> None:
    # 0023: the jail reads the train id from the first line.
    path = mark_train(data_repo, TRAIN)
    assert path == data_repo / ".claude" / "daedalus" / "train.active" == train_marker(data_repo)
    assert path.read_text(encoding="utf-8") == f"{TRAIN}\n"


@pytest.mark.parametrize("train", ["", "2026-10-15", "20261015-1200001", "../x", "x\ny"])
def test_mark_train_rejects_a_bad_train_id(data_repo: Path, train: str) -> None:
    with pytest.raises(WorkspaceError, match="Next:"):
        mark_train(data_repo, train)
    assert not train_marker(data_repo).exists()


def test_mark_train_leaves_no_temp_file(data_repo: Path) -> None:
    mark_train(data_repo, TRAIN)
    assert sorted(p.name for p in train_marker(data_repo).parent.iterdir()) == ["train.active"]


def test_mark_train_refuses_a_symlinked_marker(data_repo: Path, tmp_path: Path) -> None:
    # Fix round 1, finding 1: never write through a link planted at the marker path.
    target = tmp_path / "elsewhere"
    target.write_text("keep\n", encoding="utf-8")
    train_marker(data_repo).symlink_to(target)
    with pytest.raises(WorkspaceError, match="is a symlink"):
        mark_train(data_repo, TRAIN)
    assert target.read_text(encoding="utf-8") == "keep\n"
    assert train_marker(data_repo).is_symlink()


def test_mark_train_needs_the_data_dir(repo: Path) -> None:
    with pytest.raises(WorkspaceError, match="Next: run /daedalus:doctor"):
        mark_train(repo, TRAIN)
    assert not (repo / ".claude" / "daedalus").exists()


def test_clear_train_removes_the_marker_and_tolerates_its_absence(data_repo: Path) -> None:
    mark_train(data_repo, TRAIN)
    assert clear_train(data_repo) == train_marker(data_repo)
    assert not train_marker(data_repo).exists()
    clear_train(data_repo)


def test_cli_mark_prints_the_marker_and_unmark_names_it(data_repo: Path) -> None:
    made = _cli("mark", "--repo", str(data_repo), "--train", TRAIN)
    assert made.returncode == 0, made.stderr
    assert made.stdout == f"{train_marker(data_repo)}\n"
    gone = _cli("unmark", "--repo", str(data_repo))
    assert gone.returncode == 0, gone.stderr
    assert gone.stdout == f"cleared {train_marker(data_repo)}\n"
    assert not train_marker(data_repo).exists()
