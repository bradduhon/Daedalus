# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0230: daedalus_claims.py prints every named range of a branch in one output.
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from tests.conftest import SCRIPTS_DIR

CLAIMS = str(SCRIPTS_DIR / "daedalus_claims.py")
BRANCH = "daedalus-unit/u1"


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True)


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    # 0230: the branch holds a.py and docs/b.md; the working tree holds an edit never committed.
    _git(tmp_path, "init", "-q", "-b", "main")
    _git(tmp_path, "config", "user.email", "t@example.com")
    _git(tmp_path, "config", "user.name", "t")
    (tmp_path / "a.py").write_text("".join(f"a{n}\n" for n in range(1, 11)), encoding="utf-8")
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "b.md").write_text("b1\nb2\nb3\n", encoding="utf-8")
    _git(tmp_path, "switch", "-q", "-c", BRANCH)
    _git(tmp_path, "add", "a.py", "docs/b.md")
    _git(tmp_path, "commit", "-q", "-m", "Add the fixture")
    (tmp_path / "a.py").write_text("edited\n", encoding="utf-8")
    return tmp_path


def _run(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, CLAIMS, *args], capture_output=True, text=True, check=False
    )


def test_every_range_prints_under_its_header_in_one_output(repo: Path) -> None:
    ranges = "a.py:2-4,docs/b.md:3-3,a.py:9-12"
    got = _run("--worktree", str(repo), "--branch", BRANCH, "--ranges", ranges)
    want = "== a.py:2-4 ==\na2\na3\na4\n== docs/b.md:3-3 ==\nb3\n== a.py:9-12 ==\na9\na10\n"
    assert (got.returncode, got.stdout, got.stderr) == (0, want, "")


def test_each_range_matches_the_git_show_sed_read(repo: Path) -> None:
    # 0230: the same read the verifier ran per claim, git show <branch>:<file> | sed -n.
    show = subprocess.run(
        ["git", "-C", str(repo), "show", f"{BRANCH}:a.py"],
        capture_output=True,
        text=True,
        check=True,
    )
    sed = subprocess.run(
        ["sed", "-n", "5,7p"], input=show.stdout, capture_output=True, text=True, check=True
    )
    got = _run("--worktree", str(repo), "--branch", BRANCH, "--ranges", "a.py:5-7")
    assert got.stdout == "== a.py:5-7 ==\n" + sed.stdout


def test_a_file_off_the_branch_prints_its_header_and_exits_1(repo: Path) -> None:
    got = _run("--worktree", str(repo), "--branch", BRANCH, "--ranges", "gone.py:1-2,a.py:1-1")
    lines = got.stdout.splitlines()
    assert got.returncode == 1
    assert lines[0] == "== gone.py:1-2 =="
    assert lines[1].startswith(f"!! gone.py is not readable on {BRANCH}: ")
    assert lines[2:] == ["== a.py:1-1 ==", "a1"]


@pytest.mark.parametrize(
    "args",
    [
        (),
        ("--worktree", "{repo}", "--branch", BRANCH),
        ("--branch", BRANCH, "--worktree", "{repo}", "--ranges", "a.py:1-2"),
        ("--worktree", "{repo}", "--branch", BRANCH, "--ranges", "a.py:1-2", "--out", "x"),
        ("--worktree", "relative", "--branch", BRANCH, "--ranges", "a.py:1-2"),
        ("--worktree", "{repo}/missing", "--branch", BRANCH, "--ranges", "a.py:1-2"),
        ("--worktree", "{repo}", "--branch", "--output", "--ranges", "a.py:1-2"),
        ("--worktree", "{repo}", "--branch", f"{BRANCH}:a.py", "--ranges", "a.py:1-2"),
        ("--worktree", "{repo}", "--branch", "main..b", "--ranges", "a.py:1-2"),
        ("--worktree", "{repo}", "--branch", BRANCH, "--ranges", "a.py:3-2"),
        ("--worktree", "{repo}", "--branch", BRANCH, "--ranges", "a.py:0-2"),
        ("--worktree", "{repo}", "--branch", BRANCH, "--ranges", "a.py:1"),
        ("--worktree", "{repo}", "--branch", BRANCH, "--ranges", "/etc/passwd:1-2"),
        ("--worktree", "{repo}", "--branch", BRANCH, "--ranges", "../a.py:1-2"),
        ("--worktree", "{repo}", "--branch", BRANCH, "--ranges", "a.py:1-2,"),
    ],
)
def test_usage_errors_exit_2_and_print_nothing(repo: Path, args: tuple[str, ...]) -> None:
    got = _run(*(a.format(repo=repo) for a in args))
    assert (got.returncode, got.stdout) == (2, "")
    assert got.stderr.splitlines()[-1].startswith("Next: ")
