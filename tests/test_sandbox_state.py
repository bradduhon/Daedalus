# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import json
from pathlib import Path

import pytest
from lib import sandbox_state as module
from lib.sandbox_state import (
    CONFIGURED_UNAVAILABLE,
    OFF,
    ON,
    SettingsError,
    missing_binaries,
    required_binaries,
    sandbox_line,
    sandbox_state,
)

from tests.conftest import fake_bin


@pytest.fixture
def bins(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    fake = fake_bin(tmp_path, ())
    monkeypatch.setenv("PATH", str(fake))
    return fake


def _settings(path: Path, body: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body if isinstance(body, str) else json.dumps(body))


def test_absent_settings_are_off(tmp_path: Path, bins: Path) -> None:
    assert sandbox_state(tmp_path / "repo", tmp_path / "home") == OFF


def test_enabled_with_both_binaries_is_on(tmp_path: Path, bins: Path) -> None:
    fake_bin(tmp_path, ("bwrap", "socat"))
    _settings(tmp_path / "home" / ".claude" / "settings.json", {"sandbox": {"enabled": True}})
    assert sandbox_state(tmp_path / "repo", tmp_path / "home") == ON


def test_enabled_without_a_binary_is_configured_unavailable(tmp_path: Path, bins: Path) -> None:
    fake_bin(tmp_path, ("bwrap",))
    _settings(tmp_path / "home" / ".claude" / "settings.json", {"sandbox": {"enabled": True}})
    assert sandbox_state(tmp_path / "repo", tmp_path / "home") == CONFIGURED_UNAVAILABLE


def test_enabled_false_is_off(tmp_path: Path, bins: Path) -> None:
    _settings(tmp_path / "home" / ".claude" / "settings.json", {"sandbox": {"enabled": False}})
    assert sandbox_state(tmp_path / "repo", tmp_path / "home") == OFF


def test_non_boolean_enabled_is_off(tmp_path: Path, bins: Path) -> None:
    _settings(tmp_path / "home" / ".claude" / "settings.json", {"sandbox": {"enabled": "true"}})
    assert sandbox_state(tmp_path / "repo", tmp_path / "home") == OFF


def test_project_settings_override_user(tmp_path: Path, bins: Path) -> None:
    fake_bin(tmp_path, ("bwrap", "socat"))
    _settings(tmp_path / "home" / ".claude" / "settings.json", {"sandbox": {"enabled": True}})
    _settings(tmp_path / "repo" / ".claude" / "settings.json", {"sandbox": {"enabled": False}})
    assert sandbox_state(tmp_path / "repo", tmp_path / "home") == OFF


def test_local_settings_override_project(tmp_path: Path, bins: Path) -> None:
    fake_bin(tmp_path, ("bwrap", "socat"))
    _settings(tmp_path / "repo" / ".claude" / "settings.json", {"sandbox": {"enabled": False}})
    _settings(tmp_path / "repo" / ".claude" / "settings.local.json", {"sandbox": {"enabled": True}})
    assert sandbox_state(tmp_path / "repo", tmp_path / "home") == ON


def test_malformed_settings_raise_with_next(tmp_path: Path, bins: Path) -> None:
    _settings(tmp_path / "home" / ".claude" / "settings.json", "{not json")
    with pytest.raises(SettingsError) as info:
        sandbox_state(tmp_path / "repo", tmp_path / "home")
    assert "is not valid JSON" in str(info.value) and "Next: fix" in str(info.value)


def test_macos_needs_no_binaries(
    tmp_path: Path, bins: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(module.sys, "platform", "darwin")
    assert required_binaries() == ()
    _settings(tmp_path / "home" / ".claude" / "settings.json", {"sandbox": {"enabled": True}})
    assert sandbox_state(tmp_path / "repo", tmp_path / "home") == ON


def test_linux_needs_bwrap_and_socat(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(module.sys, "platform", "linux")
    assert required_binaries() == ("bwrap", "socat")


def test_missing_binaries_names_the_absent_one(
    tmp_path: Path, bins: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(module.sys, "platform", "linux")
    fake_bin(tmp_path, ("bwrap",))
    assert missing_binaries() == ["socat"]


def test_one_line_per_state() -> None:
    assert sandbox_line(ON) == (True, "OK   sandbox: on")
    assert sandbox_line(OFF) == (False, "MISS sandbox: off. Next: run /daedalus:setup")
    assert sandbox_line(CONFIGURED_UNAVAILABLE) == (
        False,
        "MISS sandbox: configured-unavailable. Next: run /daedalus:setup",
    )
