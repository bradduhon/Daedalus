# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# W1.1: the one git runner.
from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

import pytest
from lib import git


def test_run_reads_the_repo_named_by_cwd(repo_cwd: Path) -> None:
    done = git.run(["rev-parse", "--show-toplevel"], repo_cwd)
    assert done.returncode == 0 and done.stdout.strip() == str(repo_cwd)
    assert done.args[:3] == ["git", "-C", str(repo_cwd)]


def test_run_returns_a_non_zero_exit(repo_cwd: Path) -> None:
    done = git.run(["rev-parse", "--verify", "--quiet", "refs/heads/missing"], repo_cwd)
    assert done.returncode != 0 and isinstance(done.stderr, str)


def test_run_scrubs_the_redirect_environment(
    repo_cwd: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    other = tmp_path / "other"
    subprocess.run(["git", "init", "-q", str(other)], check=True)
    for name in sorted(git.REDIRECT_ENV):
        monkeypatch.setenv(name, str(other / ".git"))
    monkeypatch.setenv("GIT_AUTHOR_NAME", "kept")
    env = git.env()
    assert not git.REDIRECT_ENV & set(env) and env["GIT_AUTHOR_NAME"] == "kept"
    done = git.run(["rev-parse", "--show-toplevel"], repo_cwd)
    assert done.stdout.strip() == str(repo_cwd)


def test_run_raises_git_timeout(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    seen: dict[str, Any] = {}

    def hang(cmd: list[str], **kwargs: Any) -> Any:
        seen.update(kwargs)
        raise subprocess.TimeoutExpired(cmd, kwargs["timeout"])

    monkeypatch.setattr(git.subprocess, "run", hang)
    with pytest.raises(git.GitTimeout) as info:
        git.run(["status"], tmp_path, 1.5)
    assert isinstance(info.value, subprocess.TimeoutExpired) and info.value.timeout == 1.5
    assert seen["text"] is True and seen["check"] is False and seen["stdin"] == subprocess.DEVNULL


def test_run_uses_a_thirty_second_default(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    seen: dict[str, Any] = {}

    def spy(cmd: list[str], **kwargs: Any) -> Any:
        seen.update(kwargs)
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(git.subprocess, "run", spy)
    git.run(["status"], str(tmp_path))
    assert seen["timeout"] == 30.0


def test_run_lets_a_missing_git_raise(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("PATH", str(tmp_path))
    with pytest.raises(FileNotFoundError):
        git.run(["status"], tmp_path)
