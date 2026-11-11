# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import json
import os
import stat
from pathlib import Path

import pytest
from lib import self_assessment, storage


@pytest.fixture
def home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    folder = tmp_path / "home"
    (folder / ".claude" / "daedalus").mkdir(parents=True)
    monkeypatch.setenv("HOME", str(folder))
    monkeypatch.delenv("CLAUDE_PLUGIN_DATA", raising=False)
    monkeypatch.setattr(storage, "TMP_ROOT", tmp_path / "tmproot")
    return folder


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    folder = tmp_path / "repo"
    (folder / ".git").mkdir(parents=True)
    return folder


def _personal(home: Path, body: object) -> None:
    text = body if isinstance(body, str) else json.dumps(body)
    (home / ".claude" / "daedalus" / "operator.json").write_text(text, encoding="utf-8")


def test_constants() -> None:
    assert self_assessment.MAX_HANDOVER_BYTES == 8192
    assert self_assessment.TMP_ROOT == Path("/tmp/.daedalus")


def test_enabled_true_and_false(home: Path, repo: Path) -> None:
    _personal(home, {"self_assessment": True})
    assert self_assessment.enabled(repo) is True
    _personal(home, {"self_assessment": False})
    assert self_assessment.enabled(repo) is False


def test_enabled_is_false_for_a_missing_personal_file(home: Path, repo: Path) -> None:
    assert self_assessment.enabled(repo) is False


@pytest.mark.parametrize("body", ["{not json", '{"self_assessment": "yes"}', '{"nope": 1}'])
def test_enabled_is_false_for_a_refused_file(home: Path, repo: Path, body: str) -> None:
    _personal(home, body)
    assert self_assessment.enabled(repo) is False


def test_enabled_is_false_for_an_unreadable_file(home: Path, repo: Path) -> None:
    _personal(home, {"self_assessment": True})
    path = home / ".claude" / "daedalus" / "operator.json"
    path.unlink()
    path.symlink_to(home / "elsewhere")
    assert self_assessment.enabled(repo) is False


def test_a_project_override_replaces_the_personal_value(home: Path, repo: Path) -> None:
    _personal(home, {"self_assessment": True})
    data = repo / ".claude" / "daedalus"
    data.mkdir(parents=True)
    (data / "config.json").write_text(
        json.dumps({"personal_overrides": {"self_assessment": False}})
    )
    assert self_assessment.enabled(repo) is False


def test_the_key_of_a_subfolder_equals_its_projects(home: Path, repo: Path) -> None:
    sub = repo / "x" / "y"
    sub.mkdir(parents=True)
    assert self_assessment.project_key(sub) == self_assessment.project_key(repo)


def test_handover_name_builds_only_a_valid_stamp() -> None:
    name = self_assessment.handover_name("20261111T101500Z")
    assert name == "handover-20261111T101500Z.json"
    assert self_assessment.HANDOVER_NAME.fullmatch(name)
    for bad in ("2026-11-11", "20261111T101500", "x20261111T101500Z", "20261111T101500Z\n"):
        with pytest.raises(ValueError):
            self_assessment.handover_name(bad)


def test_handover_dir_modes_and_check(home: Path, repo: Path) -> None:
    got = self_assessment.make_handover_dir(repo)
    root = storage.TMP_ROOT
    assert got == root / str(os.getuid()) / "self-assessment" / self_assessment.project_key(repo)
    assert self_assessment.handover_dir(repo) == got
    assert stat.S_IMODE(root.stat().st_mode) == 0o1777
    assert stat.S_IMODE(got.stat().st_mode) == 0o700
    assert self_assessment.check_dirs(repo) is None


def test_check_dirs_refuses_a_symlink_a_wide_mode_and_a_foreign_owner(
    home: Path, repo: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    got = self_assessment.make_handover_dir(repo)
    got.chmod(0o707)
    assert "group or others" in str(self_assessment.check_dirs(repo))
    got.chmod(0o700)
    real = os.geteuid
    monkeypatch.setattr(os, "geteuid", lambda: real() + 1)
    assert "not owned" in str(self_assessment.check_dirs(repo))
    monkeypatch.setattr(os, "geteuid", real)
    got.rmdir()
    got.symlink_to(tmp_path)
    assert "symlink" in str(self_assessment.check_dirs(repo))


def test_findings_dir_prefers_the_environment_value(
    home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "env").mkdir()
    monkeypatch.setenv("CLAUDE_PLUGIN_DATA", str(tmp_path / "env"))
    want = (tmp_path / "env").resolve() / "self-assessment" / "findings"
    assert self_assessment.findings_dir() == want


def test_findings_dir_picks_daedalus_daedalus_over_inline(home: Path) -> None:
    # A1: with both folders present the findings folder resolves under daedalus-daedalus.
    base = home / ".claude" / "plugins" / "data"
    for name in ("daedalus-inline", "daedalus-daedalus"):
        (base / name).mkdir(parents=True)
    got = self_assessment.findings_dir()
    assert got == (base / "daedalus-daedalus").resolve() / "self-assessment" / "findings"


def test_the_module_loads_no_audit_code_at_import() -> None:
    source = Path(self_assessment.__file__).read_text(encoding="utf-8")
    assert "lib.audit" not in source and "import audit" not in source
