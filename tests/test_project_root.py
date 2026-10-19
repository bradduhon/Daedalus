# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

import pytest
from lib import audit

from tests.conftest import write_train_marker

_GIT_ID = ["-c", "user.name=t", "-c", "user.email=t@example.invalid", "-c", "commit.gpgsign=false"]
# 0035: a record that only names the begin command creates nothing.
BEGIN = {"command": "python3 /p/scripts/daedalus_workspace.py begin --repo /r"}


@pytest.fixture
def project_data(project_data: Path, repo_cwd: Path) -> Path:
    write_train_marker(repo_cwd)
    return project_data


def _git(repo: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", "-C", str(repo), *_GIT_ID, *args], capture_output=True, text=True, check=False
    )


def test_main_tree_and_linked_worktree_resolve_to_main_root(repo_cwd: Path, tmp_path: Path) -> None:
    assert _git(repo_cwd, "commit", "-q", "--allow-empty", "-m", "init").returncode == 0
    worktree = tmp_path.resolve() / "wt"
    assert _git(repo_cwd, "worktree", "add", "-q", str(worktree)).returncode == 0
    (repo_cwd / "sub").mkdir()
    assert audit.project_root(str(repo_cwd)) == repo_cwd
    assert audit.project_root(str(repo_cwd / "sub")) == repo_cwd
    assert audit.project_root(str(worktree)) == repo_cwd
    assert audit.project_data_dir(str(worktree)) == repo_cwd / ".claude" / "daedalus"


def test_non_git_dir_falls_back_to_itself(tmp_path: Path) -> None:
    plain = tmp_path.resolve() / "plain"
    plain.mkdir()
    assert audit.project_root(str(plain)) == plain


def test_git_missing_from_path_falls_back(
    repo_cwd: Path, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # 0077: the root comes from the filesystem; git only labels the source.
    monkeypatch.setenv("PATH", str(tmp_path / "empty-bin"))
    root, source, detail = audit.root_info(str(repo_cwd / "nested"))
    assert (root, source) == (repo_cwd, "cwd-fallback") and detail
    assert audit.project_root(str(repo_cwd / "nested")) == repo_cwd


def test_plain_folder_root_info_runs_no_git(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # CM-7, AC-6: outside a work tree neither root_info nor the data-dir check calls git.
    plain = tmp_path.resolve() / "plain"
    plain.mkdir()
    _no_subprocess(monkeypatch)
    assert audit.root_info(str(plain)) == (plain, "cwd-fallback", "no git work tree at this folder")
    assert audit.check_project_data_dir(str(plain)) == plain / ".claude" / "daedalus"


def test_git_timeout_falls_back(monkeypatch: pytest.MonkeyPatch, repo_cwd: Path) -> None:
    def _hang(*_args: Any, **_kwargs: Any) -> Any:
        raise subprocess.TimeoutExpired("git", 2)

    monkeypatch.setattr(audit.subprocess, "run", _hang)
    assert audit.project_root(str(repo_cwd)) == repo_cwd


def test_git_dir_env_does_not_redirect(
    repo_cwd: Path, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    other = tmp_path.resolve() / "other"
    other.mkdir()
    assert _git(other, "init", "-q").returncode == 0
    monkeypatch.setenv("GIT_DIR", str(other / ".git"))
    assert audit.project_root(str(repo_cwd)) == repo_cwd


def test_data_dir_writes_star_marker_and_repo_stays_clean(repo_cwd: Path, hook_input: Any) -> None:
    audit.ensure_project_data_dir(str(repo_cwd))
    write_train_marker(repo_cwd)
    audit.audit_append(hook_input())
    data = repo_cwd / ".claude" / "daedalus"
    assert (data / ".gitignore").read_text() == "*\n"
    assert (data.stat().st_mode & 0o777) == 0o700
    assert _git(repo_cwd, "status", "--porcelain").stdout == ""
    probe = data / "audit" / "sess-test.jsonl"
    assert probe.exists()
    assert _git(repo_cwd, "check-ignore", "-q", str(probe)).returncode == 0


@pytest.mark.parametrize(
    "overrides",
    [
        {},
        {"tool_name": "Read", "tool_input": {"file_path": "/etc/hosts"}},
        {"hook_event_name": "SessionStart"},
        {"tool_input": BEGIN},
        {"hook_event_name": "PostToolUse", "tool_input": BEGIN},
    ],
)
def test_no_data_dir_writes_nothing(
    repo_cwd: Path, hook_input: Any, overrides: dict[str, Any]
) -> None:
    # 0035: outside a train's repo every hook record is skipped and nothing is created.
    assert audit.audit_append(hook_input(**overrides)) is None
    assert not (repo_cwd / ".claude").exists()


@pytest.mark.parametrize(
    "overrides",
    [{}, {"tool_name": "Read", "tool_input": {"file_path": "/etc/hosts"}}, {"tool_input": BEGIN}],
)
def test_data_dir_without_train_marker_writes_nothing(
    repo_cwd: Path, hook_input: Any, overrides: dict[str, Any]
) -> None:
    # 0035: a repo that once ran a train is not logged again until a train marks it.
    data = audit.ensure_project_data_dir(str(repo_cwd))
    before = sorted(data.rglob("*"))
    assert audit.audit_append(hook_input(hook_event_name="SessionStart", **overrides)) is None
    assert audit.audit_append(hook_input(**overrides)) is None
    assert sorted(data.rglob("*")) == before


def test_train_marker_turns_the_log_on_and_its_removal_off(repo_cwd: Path, hook_input: Any) -> None:
    audit.ensure_project_data_dir(str(repo_cwd))
    marker = write_train_marker(repo_cwd)
    assert audit.audit_append(hook_input())["seq"] == 1
    marker.unlink()
    assert audit.audit_append(hook_input()) is None
    log = repo_cwd / ".claude" / "daedalus" / "audit" / "sess-test.jsonl"
    assert len(log.read_text().splitlines()) == 1


def test_existing_marker_is_left_alone(repo_cwd: Path, hook_input: Any) -> None:
    data = repo_cwd / ".claude" / "daedalus"
    data.mkdir(parents=True)
    (data / ".gitignore").write_text("*\n")
    write_train_marker(repo_cwd)
    assert audit.audit_append(hook_input()) is not None
    assert (data / ".gitignore").read_text() == "*\n"


def test_worktree_append_lands_in_main_repo(
    repo_cwd: Path, tmp_path: Path, hook_input: Any
) -> None:
    assert _git(repo_cwd, "commit", "-q", "--allow-empty", "-m", "init").returncode == 0
    worktree = tmp_path.resolve() / "wt"
    assert _git(repo_cwd, "worktree", "add", "-q", str(worktree)).returncode == 0
    audit.ensure_project_data_dir(str(repo_cwd))
    write_train_marker(repo_cwd)
    audit.audit_append(hook_input(cwd=str(worktree)))
    assert (repo_cwd / ".claude" / "daedalus" / "audit" / "sess-test.jsonl").exists()
    assert not (worktree / ".claude").exists()
    assert _git(worktree, "status", "--porcelain").stdout == ""


@pytest.mark.parametrize("cwd", [None, "", "relative/dir", 5])
def test_missing_or_relative_cwd_raises_with_next(hook_input: Any, cwd: Any) -> None:
    with pytest.raises(ValueError, match="Next:"):
        audit.audit_append(hook_input(cwd=cwd))


def _commit(repo: Path) -> None:
    assert _git(repo, "add", "-A", "-f").returncode == 0
    assert _git(repo, "commit", "-q", "-m", "c").returncode == 0


def _tracked_config(repo: Path) -> None:
    data = repo / ".claude" / "daedalus"
    data.mkdir(parents=True)
    (data / "config.json").write_text('{"charter_root": "/attacker"}')
    _commit(repo)


def _symlinked_data_dir(repo: Path, tmp_path: Path) -> Path:
    elsewhere = tmp_path.resolve() / "elsewhere"
    elsewhere.mkdir()
    (repo / ".claude").mkdir()
    (repo / ".claude" / "daedalus").symlink_to(elsewhere)
    _commit(repo)
    return elsewhere


def _empty_marker(repo: Path) -> None:
    data = repo / ".claude" / "daedalus"
    data.mkdir(parents=True)
    (data / ".gitignore").write_text("")
    _commit(repo)


def test_tracked_config_refuses_load_config(repo_cwd: Path) -> None:
    from lib.config import load_config

    _tracked_config(repo_cwd)
    with pytest.raises(audit.DataDirError, match="a tracked plugin config is not trusted"):
        load_config(str(repo_cwd))


def test_symlinked_data_dir_refuses_before_writing(
    repo_cwd: Path, tmp_path: Path, hook_input: Any
) -> None:
    elsewhere = _symlinked_data_dir(repo_cwd, tmp_path)
    marker = write_train_marker(repo_cwd)
    with pytest.raises(audit.DataDirError, match="must be a real directory inside the repo"):
        audit.audit_append(hook_input())
    assert list(elsewhere.iterdir()) == [elsewhere / marker.name]


def test_symlinked_claude_dir_refuses(repo_cwd: Path, tmp_path: Path, hook_input: Any) -> None:
    elsewhere = tmp_path.resolve() / "elsewhere"
    elsewhere.mkdir()
    (repo_cwd / ".claude").symlink_to(elsewhere)
    assert audit.audit_append(hook_input()) is None
    assert audit.audit_append(hook_input(tool_input=BEGIN)) is None
    with pytest.raises(audit.DataDirError, match="is a symlink"):
        audit.ensure_project_data_dir(str(repo_cwd))
    assert list(elsewhere.iterdir()) == []


def test_committed_empty_marker_refuses(repo_cwd: Path, hook_input: Any) -> None:
    _empty_marker(repo_cwd)
    write_train_marker(repo_cwd)
    with pytest.raises(audit.DataDirError):
        audit.audit_append(hook_input())


@pytest.mark.parametrize("content", ["", "audit/\n", "*\n!config.json\n", "* \n"])
def test_untracked_marker_with_other_content_refuses(
    repo_cwd: Path, hook_input: Any, content: str
) -> None:
    data = repo_cwd / ".claude" / "daedalus"
    data.mkdir(parents=True)
    (data / ".gitignore").write_text(content)
    write_train_marker(repo_cwd)
    with pytest.raises(audit.DataDirError, match="restore the `\\*` marker"):
        audit.audit_append(hook_input())


@pytest.mark.parametrize("content", ["*", "*\n"])
def test_exact_marker_is_accepted(repo_cwd: Path, hook_input: Any, content: str) -> None:
    data = repo_cwd / ".claude" / "daedalus"
    data.mkdir(parents=True)
    (data / ".gitignore").write_text(content)
    write_train_marker(repo_cwd)
    assert audit.audit_append(hook_input())["seq"] == 1


def test_tracked_check_runs_once_per_process(
    project_data: Path, hook_input: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[list[str]] = []
    real = subprocess.run

    def _spy(cmd: list[str], **kwargs: Any) -> Any:
        calls.append(cmd)
        return real(cmd, **kwargs)

    monkeypatch.setattr(audit.subprocess, "run", _spy)
    for i in range(3):
        audit.audit_append(hook_input(tool_use_id=f"t{i}"))
    assert sum("ls-files" in c for c in calls) == 1


def test_record_carries_project_root_and_git_source(
    repo_cwd: Path, project_data: Path, hook_input: Any
) -> None:
    rec = audit.audit_append(hook_input())
    assert rec is not None
    assert rec["project_root"] == str(repo_cwd) and rec["root_source"] == "git"


def test_record_marks_cwd_fallback(tmp_path: Path, hook_input: Any) -> None:
    plain = tmp_path.resolve() / "plain"
    plain.mkdir()
    audit.ensure_project_data_dir(str(plain))
    write_train_marker(plain)
    rec = audit.audit_append(hook_input(cwd=str(plain)))
    assert rec is not None
    assert rec["project_root"] == str(plain) and rec["root_source"] == "cwd-fallback"
    assert (plain / ".claude" / "daedalus" / "audit" / "sess-test.jsonl").exists()


def test_root_fields_are_hashed(project_data: Path, hook_input: Any) -> None:
    rec = audit.audit_append(hook_input())
    assert rec is not None
    assert audit.record_hash(rec) == rec["hash"]
    assert audit.record_hash({**rec, "project_root": "/elsewhere"}) != rec["hash"]
    assert audit.record_hash({**rec, "root_source": "cwd-fallback"}) != rec["hash"]


def test_ls_files_failure_names_the_layout_not_history(
    repo_cwd: Path, project_data: Path, hook_input: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    real = subprocess.run

    def _fail_ls_files(cmd: list[str], **kwargs: Any) -> Any:
        if "ls-files" in cmd:
            return subprocess.CompletedProcess(cmd, 128, "", "fatal: not a git repository\nmore")
        return real(cmd, **kwargs)

    monkeypatch.setattr(audit.subprocess, "run", _fail_ls_files)
    with pytest.raises(audit.DataDirError) as info:
        audit.audit_append(hook_input())
    text = str(info.value)
    assert f"git could not list files under {repo_cwd} (fatal: not a git repository);" in text
    assert "(separate-git-dir, bare, submodule). Next: run the plugin from a standard clone" in text
    assert "git history" not in text and info.value.kind == "layout"


def _no_subprocess(monkeypatch: pytest.MonkeyPatch) -> None:
    def _refuse(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError(f"0077: project_root ran a subprocess {args!r}")

    monkeypatch.setattr(subprocess, "run", _refuse)
    monkeypatch.setattr(subprocess, "Popen", _refuse)


def test_project_root_is_the_nearest_manifest_ancestor(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from lib.project_root import project_root

    proj = tmp_path.resolve() / "proj"
    (proj / "a" / "b").mkdir(parents=True)
    (proj / "service-manifest.json").write_text("{}")
    data_only = tmp_path.resolve() / "data-only"
    (data_only / ".claude" / "daedalus").mkdir(parents=True)
    (data_only / "x").mkdir()
    inner = proj / "a" / "inner"
    inner.mkdir()
    (inner / "service-manifest.json").write_text("{}")
    _no_subprocess(monkeypatch)
    assert project_root(proj / "a" / "b") == proj
    assert project_root(proj / "a" / "missing" / "file") == proj
    assert project_root(data_only / "x") == data_only
    assert project_root(inner) == inner


def test_project_root_falls_back_to_the_git_root(
    repo_cwd: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from lib.project_root import in_git_work_tree, project_root

    assert _git(repo_cwd, "commit", "-q", "--allow-empty", "-m", "init").returncode == 0
    worktree = tmp_path.resolve() / "wt"
    assert _git(repo_cwd, "worktree", "add", "-q", str(worktree)).returncode == 0
    (repo_cwd / "sub").mkdir()
    plain = tmp_path.resolve() / "plain"
    plain.mkdir()
    _no_subprocess(monkeypatch)
    assert project_root(repo_cwd / "sub") == repo_cwd
    assert project_root(worktree) == repo_cwd
    assert project_root(plain) == plain
    assert project_root(plain / "missing") == plain / "missing"
    assert in_git_work_tree(repo_cwd / "sub") and not in_git_work_tree(plain)


def test_nested_clone_resolves_to_the_enclosing_project(
    repo_cwd: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from lib.project_root import project_root

    (repo_cwd / "service-manifest.json").write_text("{}")
    nested = repo_cwd / "docs" / "private"
    nested.mkdir(parents=True)
    assert _git(nested, "init", "-q").returncode == 0
    (nested / "specs").mkdir()
    assert _git(repo_cwd, "add", "service-manifest.json").returncode == 0
    assert _git(repo_cwd, "commit", "-q", "-m", "init").returncode == 0
    linked = repo_cwd / ".claude" / "worktrees" / "u1"
    assert _git(repo_cwd, "worktree", "add", "-q", str(linked)).returncode == 0
    assert (linked / "service-manifest.json").is_file()
    _no_subprocess(monkeypatch)
    assert project_root(nested / "specs") == repo_cwd
    assert project_root(linked) == repo_cwd
    assert audit.project_root(str(nested)) == repo_cwd


def test_tracked_file_message_keeps_history_next(repo_cwd: Path, hook_input: Any) -> None:
    _tracked_config(repo_cwd)
    write_train_marker(repo_cwd)
    with pytest.raises(audit.DataDirError, match="remove .claude/daedalus from git history"):
        audit.audit_append(hook_input())
