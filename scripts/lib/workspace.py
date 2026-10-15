# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import re
import subprocess
from pathlib import Path

# 0022: pipeline-neutral; every caller names its own base ref.
WORKTREES_DIR = Path(".claude") / "worktrees"
BRANCH_PREFIX = "daedalus-unit/"
_NAME = re.compile(r"[a-z0-9][a-z0-9-]*")
_GIT_TIMEOUT_S = 120


class WorkspaceError(RuntimeError):
    pass


def _check_name(name: str) -> None:
    if not _NAME.fullmatch(name):
        raise WorkspaceError(
            f"workspace name {name!r} must be lowercase letters, digits and hyphens. "
            "Next: pass a name such as 20261015-120000-u1."
        )


def worktree_path(repo: Path, name: str) -> Path:
    _check_name(name)
    return repo / WORKTREES_DIR / name


def branch_name(name: str) -> str:
    _check_name(name)
    return BRANCH_PREFIX + name


def _confined(repo: Path, name: str) -> Path:
    # spec 7: never act on a path that resolves outside <repo>/.claude/worktrees/.
    path = worktree_path(repo, name)
    root = repo.resolve() / WORKTREES_DIR
    if path.resolve().parent != root:
        raise WorkspaceError(
            f"{path} resolves outside {root}. "
            f"Next: replace any symlink at {root} with a plain directory, then rerun."
        )
    return path


def _run(repo: Path, *args: str, path: Path | None = None) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            ["git", "-C", str(repo), *args],
            capture_output=True,
            text=True,
            timeout=_GIT_TIMEOUT_S,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        # spec 7: a killed worktree add can leave a lock that a single --force will not clear.
        target = path or repo / WORKTREES_DIR / "<name>"
        raise WorkspaceError(
            f"git {args[0]} {args[1]} timed out after {_GIT_TIMEOUT_S} s. "
            f"Next: run git -C {repo} worktree unlock {target} (or worktree remove -f -f "
            f"{target}), then run daedalus_workspace.py remove and rerun."
        ) from exc
    except OSError as exc:
        raise WorkspaceError(
            f"git {args[0]} {args[1]} did not run ({exc}). Next: check git is on PATH, then rerun."
        ) from exc


def _git(repo: Path, *args: str, path: Path | None = None) -> None:
    result = _run(repo, *args, path=path)
    if result.returncode != 0:
        detail = " ".join(result.stderr.split()) or "no stderr"
        raise WorkspaceError(
            f"git {args[0]} {args[1]} failed ({detail}). Next: fix the cause git names, then rerun."
        )


def _ensure_marker(repo: Path) -> None:
    # 0022: a single * keeps every worktree here out of the main checkout's status.
    marker = repo / WORKTREES_DIR / ".gitignore"
    if marker.exists():
        return
    try:
        marker.parent.mkdir(parents=True, exist_ok=True)
        marker.write_text("*\n", encoding="utf-8")
    except OSError as exc:
        raise WorkspaceError(
            f"cannot write {marker} ({exc}). Next: make {marker.parent} a writable directory."
        ) from exc


def create(repo: Path, name: str, base_ref: str) -> Path:
    # spec 7: git reads paths relative to -C <repo>, so work from the absolute repo.
    repo = repo.resolve()
    path = _confined(repo, name)
    branch = branch_name(name)
    remedy = (
        f"Next: if a crashed run left it behind, run daedalus_workspace.py remove "
        f"--repo {repo} --name {name}, delete the branch with git branch -D {branch} "
        "once nothing needs it, then rerun; otherwise pick a new name."
    )
    if path.exists() or path.is_symlink():
        raise WorkspaceError(f"worktree path {path} already exists. {remedy}")
    if _run(repo, "rev-parse", "--verify", "--quiet", f"refs/heads/{branch}").returncode == 0:
        raise WorkspaceError(f"branch {branch} already exists. {remedy}")
    _ensure_marker(repo)
    # A13: documented option order, branch before path before base.
    _git(repo, "worktree", "add", "-q", "-b", branch, str(path), base_ref, path=path)
    return path


def remove(repo: Path, name: str) -> None:
    repo = repo.resolve()
    path = _confined(repo, name)
    # spec 7: an already-gone worktree only needs its admin entry pruned.
    if path.exists():
        _git(repo, "worktree", "remove", "--force", str(path), path=path)
    _git(repo, "worktree", "prune")
