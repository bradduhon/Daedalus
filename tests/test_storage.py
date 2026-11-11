# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import hashlib
import os
import stat
from pathlib import Path

import pytest
from lib import storage


@pytest.fixture
def tmp_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    root = tmp_path / "tmproot"
    monkeypatch.setattr(storage, "TMP_ROOT", root)
    return root


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    folder = tmp_path / "repo"
    (folder / ".git").mkdir(parents=True)
    return folder


def test_project_key_is_16_hex_of_the_resolved_root_and_subfolders_share_it(repo: Path) -> None:
    sub = repo / "a" / "b"
    sub.mkdir(parents=True)
    want = hashlib.sha256(str(repo.resolve()).encode()).hexdigest()[:16]
    assert storage.project_key(repo) == want == storage.project_key(sub)


def test_project_key_of_a_path_without_a_root_is_the_path_itself(tmp_path: Path) -> None:
    plain = tmp_path / "plain"
    plain.mkdir()
    key = storage.project_key(plain)
    assert len(key) == 16 and key == storage.project_key(plain)


def test_tmp_dir_layout_and_modes(tmp_root: Path, repo: Path) -> None:
    got = storage.make_tmp_dir("self-assessment", repo)
    uid = str(os.getuid())
    assert got == tmp_root / uid / "self-assessment" / storage.project_key(repo)
    assert stat.S_IMODE(tmp_root.stat().st_mode) == 0o1777
    for folder in (tmp_root / uid, tmp_root / uid / "self-assessment", got):
        assert stat.S_IMODE(folder.stat().st_mode) == 0o700
    assert storage.check_tmp_dirs("self-assessment", repo) is None


def test_a_feature_outside_the_allow_list_is_refused(tmp_root: Path, repo: Path) -> None:
    with pytest.raises(ValueError):
        storage.tmp_dir("other", repo)
    with pytest.raises(ValueError):
        storage.data_dir("other")


def test_a_symlinked_root_is_refused(tmp_root: Path, tmp_path: Path, repo: Path) -> None:
    real = tmp_path / "real"
    real.mkdir()
    tmp_root.symlink_to(real)
    assert "symlink" in str(storage.check_tmp_dirs("self-assessment", repo))
    with pytest.raises(RuntimeError):
        storage.make_tmp_dir("self-assessment", repo)


def test_a_symlinked_inner_folder_is_refused(tmp_root: Path, tmp_path: Path, repo: Path) -> None:
    got = storage.make_tmp_dir("self-assessment", repo)
    got.rmdir()
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    got.symlink_to(elsewhere)
    assert "symlink" in str(storage.check_tmp_dirs("self-assessment", repo))


def test_a_folder_others_can_write_is_refused(tmp_root: Path, repo: Path) -> None:
    got = storage.make_tmp_dir("self-assessment", repo)
    got.chmod(0o770)
    assert "group or others" in str(storage.check_tmp_dirs("self-assessment", repo))


def test_a_folder_owned_by_another_user_is_refused(
    tmp_root: Path, repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    storage.make_tmp_dir("self-assessment", repo)
    real = os.geteuid
    monkeypatch.setattr(os, "geteuid", lambda: real() + 1)
    assert "not owned" in str(storage.check_tmp_dirs("self-assessment", repo))


def test_data_dir_prefers_the_environment_value(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("CLAUDE_PLUGIN_DATA", str(tmp_path / "env"))
    (tmp_path / "env").mkdir()
    assert storage.data_dir("self-assessment") == (tmp_path / "env").resolve() / "self-assessment"


def test_data_dir_picks_daedalus_daedalus_over_inline(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A1: the probe takes the first daedalus* folder with daedalus-inline sorted last.
    home = tmp_path / "home"
    base = home / ".claude" / "plugins" / "data"
    for name in ("daedalus-inline", "daedalus-daedalus"):
        (base / name).mkdir(parents=True)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.delenv("CLAUDE_PLUGIN_DATA", raising=False)
    got = storage.data_dir("self-assessment")
    assert got == (base / "daedalus-daedalus").resolve() / "self-assessment"


def test_data_dir_with_a_project_adds_the_shared_project_key(
    tmp_path: Path, repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "env").mkdir()
    monkeypatch.setenv("CLAUDE_PLUGIN_DATA", str(tmp_path / "env"))
    base = (tmp_path / "env").resolve() / "self-assessment"
    assert storage.data_dir("self-assessment") == base
    assert storage.data_dir("self-assessment", repo) == base / storage.project_key(repo)


def test_make_data_dir_creates_each_folder_with_mode_0700(
    tmp_path: Path, repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "env").mkdir()
    monkeypatch.setenv("CLAUDE_PLUGIN_DATA", str(tmp_path / "env"))
    plain = storage.make_data_dir("self-assessment")
    keyed = storage.make_data_dir("self-assessment", repo)
    assert keyed == plain / storage.project_key(repo)
    for folder in (plain, keyed):
        assert stat.S_IMODE(folder.stat().st_mode) == 0o700
