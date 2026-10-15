# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import copy
import json
import os
from pathlib import Path
from typing import Any

import pytest
from lib.settings_merge import (
    MERGED_KEYS,
    SettingsMergeError,
    merge,
    read_settings,
    render,
    unified_diff,
    write_atomic,
)

from tests.conftest import REPO_ROOT


def _recommended() -> dict[str, Any]:
    return json.loads((REPO_ROOT / "settings.recommended.json").read_text())


def test_empty_file_gets_every_merged_key() -> None:
    rec = _recommended()
    assert merge({}, rec) == {k: rec[k] for k in MERGED_KEYS}


def test_existing_deny_entries_are_kept_and_missing_ones_appended() -> None:
    existing = {"permissions": {"deny": ["Read(./.env)", "Read(~/.ssh/**)"]}}
    assert merge(existing, _recommended())["permissions"]["deny"] == [
        "Read(./.env)",
        "Read(~/.ssh/**)",
        "Read(~/.aws/credentials)",
        "Read(~/.gnupg/**)",
        "Read(~/.config/gh/**)",
        "Read(~/.claude/.credentials.json)",
    ]


def test_existing_sandbox_value_is_never_overwritten() -> None:
    existing = {
        "sandbox": {"enabled": False, "network": {"allowedDomains": ["example.com"]}},
        "promptCacheTtl": "5m",
    }
    rec = _recommended()
    merged = merge(existing, rec)
    assert merged["sandbox"]["enabled"] is False
    assert merged["sandbox"]["network"]["allowedDomains"] == ["example.com"]
    assert merged["promptCacheTtl"] == "5m"
    assert merged["sandbox"]["failIfUnavailable"] is True
    assert merged["sandbox"]["filesystem"] == rec["sandbox"]["filesystem"]


def test_unrelated_keys_survive_and_the_input_is_not_mutated() -> None:
    existing = {"model": "opus", "permissions": {"allow": ["Bash(ls)"]}}
    snapshot = copy.deepcopy(existing)
    merged = merge(existing, _recommended())
    assert existing == snapshot
    assert merged["model"] == "opus"
    assert merged["permissions"]["allow"] == ["Bash(ls)"]


def test_merge_is_idempotent() -> None:
    once = merge({}, _recommended())
    assert merge(once, _recommended()) == once


def test_non_merged_keys_never_leave_the_recommended_file() -> None:
    assert merge({}, {"env": {"X": "1"}, "promptCacheTtl": "1h"}) == {"promptCacheTtl": "1h"}


def test_read_settings_absent_is_empty(tmp_path: Path) -> None:
    assert read_settings(tmp_path / "none.json") == {}


def test_read_settings_empty_file_is_empty(tmp_path: Path) -> None:
    target = tmp_path / "settings.json"
    target.write_text("")
    assert read_settings(target) == {}


@pytest.mark.parametrize("body", ["{bad", "[]"])
def test_read_settings_refuses_bad_content_with_next(tmp_path: Path, body: str) -> None:
    target = tmp_path / "settings.json"
    target.write_text(body)
    with pytest.raises(SettingsMergeError) as info:
        read_settings(target)
    assert "Next:" in str(info.value)


def test_read_settings_unreadable_is_not_called_invalid_json(tmp_path: Path) -> None:
    with pytest.raises(SettingsMergeError, match="cannot be read"):
        read_settings(tmp_path)


def test_write_atomic_replaces_and_keeps_the_mode(tmp_path: Path) -> None:
    target = tmp_path / "settings.json"
    target.write_text("{}\n")
    target.chmod(0o640)
    write_atomic(target, '{"a": 1}\n')
    assert target.read_text() == '{"a": 1}\n'
    assert target.stat().st_mode & 0o777 == 0o640
    assert sorted(p.name for p in tmp_path.iterdir()) == ["settings.json"]


def test_write_atomic_creates_a_missing_parent(tmp_path: Path) -> None:
    target = tmp_path / "home" / ".claude" / "settings.json"
    write_atomic(target, "{}\n")
    assert target.read_text() == "{}\n"


def test_write_atomic_writes_through_a_symlink(tmp_path: Path) -> None:
    real = tmp_path / "dotfiles" / "settings.json"
    real.parent.mkdir()
    real.write_text("{}\n")
    link = tmp_path / "settings.json"
    link.symlink_to(real)
    write_atomic(link, '{"a": 1}\n')
    assert link.is_symlink()
    assert real.read_text() == '{"a": 1}\n'


def test_render_and_diff_show_the_change(tmp_path: Path) -> None:
    new = render({"a": 1})
    assert new == '{\n  "a": 1\n}\n'
    diff = unified_diff("", new, tmp_path / "settings.json")
    assert f"+++ {tmp_path / 'settings.json'} (after)" in diff
    assert '+  "a": 1' in diff


def test_write_atomic_leaves_no_temp_file_on_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def _fail(src: str, dst: str) -> None:
        raise OSError("replace refused")

    monkeypatch.setattr(os, "replace", _fail)
    with pytest.raises(OSError):
        write_atomic(tmp_path / "settings.json", "{}\n")
    assert list(tmp_path.iterdir()) == []
