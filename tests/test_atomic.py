# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 21, W1.1: the one atomic writer and create-once writer.
from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest
from lib import atomic


def _mode(path: Path) -> int:
    return stat.S_IMODE(os.lstat(path).st_mode)


def _leftovers(folder: Path) -> list[str]:
    return sorted(p.name for p in folder.iterdir() if p.name.endswith(".tmp"))


def test_write_atomic_creates_a_new_file_at_0600(tmp_path: Path) -> None:
    target = tmp_path / "out.md"
    atomic.write_atomic(target, "one\r\ntwo\n")
    assert target.read_bytes() == b"one\r\ntwo\n"
    assert _mode(target) == 0o600 and _leftovers(tmp_path) == []


def test_write_atomic_keeps_the_old_mode_when_mode_is_none(tmp_path: Path) -> None:
    target = tmp_path / "ledger.md"
    target.write_text("old", encoding="utf-8")
    os.chmod(target, 0o640)
    atomic.write_atomic(target, "new")
    assert target.read_text(encoding="utf-8") == "new" and _mode(target) == 0o640


def test_write_atomic_sets_a_given_mode(tmp_path: Path) -> None:
    target = tmp_path / "notes.md"
    target.write_text("old", encoding="utf-8")
    os.chmod(target, 0o600)
    atomic.write_atomic(target, "new", 0o644)
    assert _mode(target) == 0o644


def test_write_atomic_refuses_a_link_and_leaves_its_target(tmp_path: Path) -> None:
    outside = tmp_path / "outside.md"
    outside.write_text("keep", encoding="utf-8")
    link = tmp_path / "out.md"
    link.symlink_to(outside)
    with pytest.raises(atomic.LinkRefused) as info:
        atomic.write_atomic(link, "new")
    assert isinstance(info.value, OSError)
    assert str(info.value) == atomic.R_LINK.format(path=link)
    assert str(link) in str(info.value) and "Next: delete it from your own shell" in str(info.value)
    assert outside.read_text(encoding="utf-8") == "keep" and link.is_symlink()
    assert _leftovers(tmp_path) == []


def test_write_atomic_refuses_a_dangling_link(tmp_path: Path) -> None:
    link = tmp_path / "out.md"
    link.symlink_to(tmp_path / "missing.md")
    with pytest.raises(atomic.LinkRefused):
        atomic.write_atomic(link, "new")
    assert not (tmp_path / "missing.md").exists()


def test_write_atomic_replaces_a_link_planted_after_the_check(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # 8.6: os.replace onto the unresolved name swaps the link itself, never its target.
    outside = tmp_path / "outside.md"
    outside.write_text("keep", encoding="utf-8")
    target = tmp_path / "out.md"
    monkeypatch.setattr(atomic, "refuse_links", lambda path: path.symlink_to(outside))
    atomic.write_atomic(target, "new")
    assert not target.is_symlink() and target.read_text(encoding="utf-8") == "new"
    assert outside.read_text(encoding="utf-8") == "keep"


def test_write_atomic_cleans_its_temp_file_on_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def fail(_src: object, _dst: object) -> None:
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(atomic.os, "replace", fail)
    with pytest.raises(OSError, match="No space left"):
        atomic.write_atomic(tmp_path / "out.md", "new")
    assert list(tmp_path.iterdir()) == []


def test_create_once_writes_whole_at_the_given_mode(tmp_path: Path) -> None:
    target = tmp_path / ".gitignore"
    atomic.create_once(target, "*\n", 0o600)
    assert target.read_text(encoding="utf-8") == "*\n" and _mode(target) == 0o600
    assert _leftovers(tmp_path) == []


def test_create_once_never_overwrites(tmp_path: Path) -> None:
    target = tmp_path / "config.json"
    target.write_text("mine", encoding="utf-8")
    with pytest.raises(FileExistsError):
        atomic.create_once(target, "theirs", 0o600)
    assert target.read_text(encoding="utf-8") == "mine" and _leftovers(tmp_path) == []


def test_create_once_never_follows_a_link(tmp_path: Path) -> None:
    link = tmp_path / "config.json"
    link.symlink_to(tmp_path / "elsewhere.json")
    with pytest.raises(FileExistsError):
        atomic.create_once(link, "x", 0o600)
    assert not (tmp_path / "elsewhere.json").exists() and link.is_symlink()


def test_refuse_links_passes_a_plain_path_and_a_missing_one(tmp_path: Path) -> None:
    atomic.refuse_links(tmp_path)
    atomic.refuse_links(tmp_path / "missing")
    (tmp_path / "dir-link").symlink_to(tmp_path)
    with pytest.raises(atomic.LinkRefused, match="dir-link is a symlink"):
        atomic.refuse_links(tmp_path / "dir-link")
