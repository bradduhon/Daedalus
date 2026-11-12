# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0257: a run starts when the settings files are the only uncommitted change, and its later
# clean-tree checks hold those files to the bytes they had when the run began.
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from lib import train_state, workspace
from lib.workspace import WorkspaceError, begin, finish, resume, stop

from tests.test_workspace_train import (
    LEDGER,
    NAMED,
    _built,
    _commit_all,
    _head,
    _locked_train,
    _merges,
    _nothing_written,
    _ok,
    _verified,
)

pytestmark = pytest.mark.usefixtures("isolated_env")


@pytest.fixture
def repo(project_data: Path) -> Path:
    # The same repository the workspace train tests start from.
    root = project_data.parent.parent
    (project_data / ".gitignore").write_text("*\n")
    (root / "docs").mkdir()
    (root / "docs" / "decisions.md").write_text(LEDGER)
    (root / "service-manifest.json").write_text(json.dumps(NAMED))
    _commit_all(root, "init")
    return root


SETTINGS = {"docs": {"decisions_filename": "decisions.md", "folder": "docs"}}
MANIFEST = "service-manifest.json"
CONFIG = ".claude/daedalus/config.json"


def _new_settings(repo: Path) -> Path:
    path = repo / MANIFEST
    path.write_text(json.dumps(SETTINGS))
    return path


def _status(repo: Path) -> str:
    return _ok(repo, "status", "--porcelain", "--untracked-files=all")


def _train_id(repo: Path) -> str:
    return begin(repo)[0].split()[1]


def test_begin_admits_a_changed_manifest_and_holds_its_bytes(repo: Path) -> None:
    path = _new_settings(repo)
    assert _status(repo) == f"M {MANIFEST}"
    train = _train_id(repo)
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    assert train_state.load(repo, train)["settings_uncommitted"] == {MANIFEST: digest}


def test_begin_admits_an_untracked_manifest(repo: Path) -> None:
    _ok(repo, "rm", "-q", "--cached", MANIFEST)
    _ok(repo, "commit", "-q", "-m", "untrack the manifest")
    _new_settings(repo)
    assert _status(repo) == f"?? {MANIFEST}"
    held = train_state.load(repo, _train_id(repo))["settings_uncommitted"]
    assert isinstance(held, dict) and list(held) == [MANIFEST]


def test_a_clean_tree_holds_no_settings(repo: Path) -> None:
    assert train_state.load(repo, _train_id(repo))["settings_uncommitted"] == {}


def test_split_admits_an_untracked_config_and_nothing_else(repo: Path) -> None:
    data = repo / ".claude" / "daedalus"
    (data / "config.json").write_text("{}")
    other, held = workspace.split_settings(repo, f"?? {CONFIG}\n?? {MANIFEST}x\n")
    assert other == [f"{MANIFEST}x"] and list(held) == [CONFIG]


@pytest.mark.parametrize(
    "line",
    [
        f"M  {MANIFEST}",
        f"MM {MANIFEST}",
        f"A  {MANIFEST}",
        f" D {MANIFEST}",
        f" T {MANIFEST}",
        f"R  old.json -> {MANIFEST}",
        f'?? "{MANIFEST}"',
        f"?? docs/{MANIFEST}",
        f"?? ./{MANIFEST}",
    ],
)
def test_split_refuses_every_other_shape_of_a_settings_entry(repo: Path, line: str) -> None:
    _new_settings(repo)
    other, held = workspace.split_settings(repo, line + "\n")
    assert held == {} and len(other) == 1


@pytest.mark.parametrize(
    "extra", ["staged", "untracked source", "manifest staged", "manifest link", "renamed"]
)
def test_begin_refuses_any_other_change_beside_the_settings(repo: Path, extra: str) -> None:
    path = _new_settings(repo)
    if extra == "staged":
        (repo / "docs" / "decisions.md").write_text(LEDGER + "| x |\n")
        _ok(repo, "add", "docs/decisions.md")
        want = "docs/decisions.md"
    elif extra == "untracked source":
        (repo / "app.py").write_text("print(1)\n")
        want = "app.py"
    elif extra == "manifest staged":
        _ok(repo, "add", MANIFEST)
        want = MANIFEST
    elif extra == "manifest link":
        target = repo.parent / "elsewhere.json"
        target.write_text(json.dumps(SETTINGS))
        path.unlink()
        path.symlink_to(target)
        want = MANIFEST
    else:
        _ok(repo, "mv", "docs/decisions.md", "docs/moved.md")
        want = "docs/moved.md"
    with pytest.raises(WorkspaceError) as info:
        begin(repo)
    assert want in str(info.value) and "Next: commit or stash" in str(info.value)
    _nothing_written(repo)


def test_begin_refuses_a_config_reached_through_a_linked_folder(repo: Path) -> None:
    # 0257: a link anywhere below the repository root on the way to a settings file refuses it.
    real = repo.parent / "outside"
    real.mkdir()
    (real / "config.json").write_text("{}")
    (repo / CONFIG).write_text("{}")
    assert workspace._digest(repo, CONFIG) == hashlib.sha256(b"{}").hexdigest()
    (repo / "linked").symlink_to(real)
    assert workspace._digest(repo, "linked/config.json") is None


def test_a_run_with_held_settings_merges_and_leaves_them_uncommitted(repo: Path) -> None:
    path = _new_settings(repo)
    train = _locked_train(repo)
    _verified(repo, train, _built(repo, train, "u1"))
    finish(repo)
    assert _merges(repo, f"daedalus/{train}") == [f"Merge u1 for train {train}"]
    assert _status(repo) == f"M {MANIFEST}"
    committed = json.loads(_ok(repo, "show", f"daedalus/{train}:{MANIFEST}"))
    assert committed == NAMED and json.loads(path.read_text()) == SETTINGS


def test_finish_refuses_held_settings_changed_after_begin(repo: Path) -> None:
    path = _new_settings(repo)
    train = _locked_train(repo)
    _built(repo, train, "u1")
    path.write_text(json.dumps({"docs": {"decisions_filename": "other.md"}}))
    with pytest.raises(WorkspaceError, match=MANIFEST):
        finish(repo)
    assert _merges(repo, f"daedalus/{train}") == []


def test_finish_refuses_settings_first_changed_after_begin(repo: Path) -> None:
    train = _locked_train(repo)
    _built(repo, train, "u1")
    _new_settings(repo)
    with pytest.raises(WorkspaceError, match=MANIFEST):
        finish(repo)
    assert _merges(repo, f"daedalus/{train}") == []


def test_stop_and_resume_carry_held_settings_across_the_switch(repo: Path) -> None:
    _new_settings(repo)
    train = _locked_train(repo)
    lines, ok = stop(repo, "operator", None)
    assert ok and _head(repo) == "main", lines
    resume(repo)
    assert _head(repo) == f"daedalus/{train}"
    assert _status(repo) == f"M {MANIFEST}"
