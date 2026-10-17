# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import io
import json
import os
import subprocess
import sys
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
    sandbox_check,
    sandbox_line,
    sandbox_state,
)

from tests.conftest import SCRIPTS_DIR, fake_bin


@pytest.fixture
def bins(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    # Plan 4 minor: pin Linux so the bwrap and socat cases hold on macOS too.
    monkeypatch.setattr(module.sys, "platform", "linux")
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


@pytest.mark.parametrize("value", ["true", 1, "yes", None, [True], {"on": True}])
def test_non_boolean_enabled_is_off(tmp_path: Path, bins: Path, value: object) -> None:
    _settings(tmp_path / "home" / ".claude" / "settings.json", {"sandbox": {"enabled": value}})
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


def test_minor_3_unreadable_settings_are_not_called_invalid_json(
    tmp_path: Path, bins: Path
) -> None:
    (tmp_path / "home" / ".claude" / "settings.json").mkdir(parents=True)
    with pytest.raises(SettingsError) as info:
        sandbox_state(tmp_path / "repo", tmp_path / "home")
    assert "cannot be read" in str(info.value) and "not valid JSON" not in str(info.value)
    assert "Next:" in str(info.value)


def test_minor_3_bins_fixture_pins_linux(bins: Path) -> None:
    assert required_binaries() == ("bwrap", "socat")


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
    assert sandbox_line(OFF) == (
        False,
        "MISS sandbox: off. Next: type /daedalus:setup yourself; the model cannot run it",
    )
    assert sandbox_line(CONFIGURED_UNAVAILABLE) == (
        False,
        "MISS sandbox: configured-unavailable. Next: type /daedalus:setup yourself; "
        "the model cannot run it",
    )


def test_sandbox_check_names_malformed_settings(tmp_path: Path, bins: Path) -> None:
    _settings(tmp_path / "home" / ".claude" / "settings.json", "{not json")
    ok, line = sandbox_check(tmp_path / "repo", tmp_path / "home")
    assert not ok and line.startswith("MISS sandbox: ") and "is not valid JSON" in line


def _notice(stdin: str, home: Path, path_env: str, cwd: Path) -> subprocess.CompletedProcess[str]:
    env = dict(os.environ)
    env["HOME"] = str(home)
    env["PATH"] = path_env
    return subprocess.run(
        [sys.executable, str(SCRIPTS_DIR / "sandbox_notice.py")],
        input=stdin,
        capture_output=True,
        text=True,
        env=env,
        cwd=cwd,
        check=False,
    )


def _start(cwd: Path) -> str:
    return json.dumps({"hook_event_name": "SessionStart", "cwd": str(cwd)})


OFF_LINE = "MISS sandbox: off. Next: type /daedalus:setup yourself; the model cannot run it"


def test_notice_prints_the_doctor_line_when_off(tmp_path: Path, bins: Path) -> None:
    result = _notice(_start(tmp_path), tmp_path / "home", str(bins), tmp_path)
    assert result.returncode == 0
    assert json.loads(result.stdout) == {
        "systemMessage": OFF_LINE,
        "hookSpecificOutput": {"hookEventName": "SessionStart", "additionalContext": OFF_LINE},
    }


def test_notice_is_silent_when_on(tmp_path: Path, bins: Path) -> None:
    fake_bin(tmp_path, ("bwrap", "socat"))
    _settings(tmp_path / "home" / ".claude" / "settings.json", {"sandbox": {"enabled": True}})
    result = _notice(_start(tmp_path), tmp_path / "home", str(bins), tmp_path)
    assert result.returncode == 0 and result.stdout == ""


@pytest.mark.skipif(sys.platform == "darwin", reason="macOS needs no sandbox binaries")
def test_minor_9_notice_prints_configured_unavailable(tmp_path: Path, bins: Path) -> None:
    fake_bin(tmp_path, ("bwrap",))
    _settings(tmp_path / "home" / ".claude" / "settings.json", {"sandbox": {"enabled": True}})
    result = _notice(_start(tmp_path), tmp_path / "home", str(bins), tmp_path)
    line = (
        "MISS sandbox: configured-unavailable. Next: type /daedalus:setup yourself; "
        "the model cannot run it"
    )
    assert result.returncode == 0
    assert json.loads(result.stdout) == {
        "systemMessage": line,
        "hookSpecificOutput": {"hookEventName": "SessionStart", "additionalContext": line},
    }


@pytest.mark.parametrize("stdin", ["not json", "", "[1, 2]"])
def test_notice_falls_back_to_cwd_on_bad_input(tmp_path: Path, bins: Path, stdin: str) -> None:
    # spec 5: unreadable hook input means the current directory is the repo.
    result = _notice(stdin, tmp_path / "home", str(bins), tmp_path)
    assert result.returncode == 0
    assert json.loads(result.stdout)["systemMessage"] == OFF_LINE


def test_notice_reads_project_settings_from_the_payload_cwd(tmp_path: Path, bins: Path) -> None:
    fake_bin(tmp_path, ("bwrap", "socat"))
    repo = tmp_path / "repo"
    _settings(repo / ".claude" / "settings.json", {"sandbox": {"enabled": True}})
    result = _notice(_start(repo), tmp_path / "home", str(bins), tmp_path)
    assert result.returncode == 0 and result.stdout == ""


def test_notice_reports_malformed_settings(tmp_path: Path, bins: Path) -> None:
    _settings(tmp_path / "home" / ".claude" / "settings.json", "{not json")
    result = _notice(_start(tmp_path), tmp_path / "home", str(bins), tmp_path)
    assert result.returncode == 0
    assert json.loads(result.stdout)["systemMessage"].startswith("MISS sandbox: ")


def test_notice_failure_prints_nothing_and_exits_zero(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    import sandbox_notice

    def boom(_payload: object) -> str | None:
        raise RuntimeError("boom")

    monkeypatch.setattr(sandbox_notice, "notice", boom)
    monkeypatch.setattr(sys, "stdin", io.StringIO("{}"))
    assert sandbox_notice.main() == 0
    out = capsys.readouterr()
    assert out.out == "" and "daedalus-sandbox: boom" in out.err
