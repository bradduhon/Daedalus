# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from lib.config import Config, load_config
from lib.ledger import resolve_ledger
from lib.manifest import CHECK_KEYS, COMMAND_KEYS, Features, Manifest
from lib.manifest import load as load_manifest
from lib.project_keys import CONFIG_FILE, KEY_ROWS, MANIFEST_FILE, config_keys, manifest_keys

from tests.conftest import SCRIPTS_DIR

SETUP = SCRIPTS_DIR / "daedalus_setup.py"


def _setup(repo: Path) -> subprocess.CompletedProcess[str]:
    env = {k: v for k, v in os.environ.items() if k != "CLAUDE_PLUGIN_DATA"}
    return subprocess.run(
        [sys.executable, str(SETUP), "--repo", str(repo)],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )


def _paths(repo: Path) -> tuple[Path, Path]:
    return repo / "service-manifest.json", repo / ".claude" / "daedalus" / "config.json"


def _present(doc: dict[str, object], key: str) -> bool:
    # 0076: a key under an object default is present itself; under a list or null, its parent is.
    head, _, rest = key.partition(".")
    head = head.removesuffix("[]")
    if head not in doc:
        return False
    child = doc[head]
    return not rest or not isinstance(child, dict) or _present(child, rest)


def test_setup_writes_both_starter_files_when_missing(repo_cwd: Path) -> None:
    result = _setup(repo_cwd)
    assert result.returncode == 0, result.stderr
    manifest, config = _paths(repo_cwd)
    # 0134, 0245: a new manifest is followed by the docs.reading_level examples line.
    assert result.stdout.splitlines() == [
        f"written: {manifest}",
        'docs.reading_level: null; examples: "standard", "expert", "profile:docs/voice-profile.md"',
        f"written: {config}",
    ]
    assert manifest.is_file() and config.is_file()
    # 0010: the data folder carries its ignore marker, as a train's start writes it.
    assert (config.parent / ".gitignore").read_text(encoding="utf-8") == "*\n"


def test_setup_never_overwrites_an_existing_file(repo_cwd: Path) -> None:
    manifest, config = _paths(repo_cwd)
    manifest.write_text('{"mine": true}\n', encoding="utf-8")
    first = _setup(repo_cwd)
    assert first.returncode == 0, first.stderr
    assert first.stdout.splitlines() == [
        f"kept: {manifest} (it already exists)",
        f"written: {config}",
    ]
    assert manifest.read_text(encoding="utf-8") == '{"mine": true}\n'
    before = config.read_bytes()
    second = _setup(repo_cwd)
    assert second.returncode == 0, second.stderr
    assert second.stdout.splitlines() == [
        f"kept: {manifest} (it already exists)",
        f"kept: {config} (it already exists)",
    ]
    assert config.read_bytes() == before


def _starters(file: str, keys: tuple[str, ...]) -> list[str]:
    return [key for key in keys if not KEY_ROWS[(file, key)].override]


def test_setup_starter_files_carry_every_starter_key_and_no_override(repo_cwd: Path) -> None:
    # 0245: the starter files hold the starter keys; an override stays out until asked for.
    assert _setup(repo_cwd).returncode == 0
    manifest, config = _paths(repo_cwd)
    m_doc = json.loads(manifest.read_text(encoding="utf-8"))
    c_doc = json.loads(config.read_text(encoding="utf-8"))
    m_keys = manifest_keys()
    assert [k for k in _starters(MANIFEST_FILE, m_keys) if not _present(m_doc, k)] == []
    c_keys = config_keys()
    assert [k for k in _starters(CONFIG_FILE, c_keys) if not _present(c_doc, k)] == []
    overrides = {
        key.partition(".")[0].removesuffix("[]")
        for file, keys in ((MANIFEST_FILE, m_keys), (CONFIG_FILE, c_keys))
        for key in keys
        if KEY_ROWS[(file, key)].override and "." not in key
    }
    assert overrides.isdisjoint(m_doc) and overrides.isdisjoint(c_doc)
    # 0072, 0076: the readers accept both files, and the config reads as the defaults.
    assert load_config(path=config) == Config()
    loaded = load_manifest(repo_cwd)
    assert loaded is not None
    assert loaded.forbidden_paths == () and loaded.forbidden_extensions == ()
    assert loaded.trains_dir is None and loaded.unit_test_cmd is None


def test_setup_starter_files_load_through_the_readers_at_their_defaults(repo_cwd: Path) -> None:
    # 0076: the jail loads the config on every hook; a starter it refused would deny every call.
    assert _setup(repo_cwd).returncode == 0
    assert load_config(cwd=str(repo_cwd)) == Config()
    # 0245, 0247: no decisions file is named, so nothing is recorded.
    want = Features(dependency_web_lookup=True, terraform_tools=True)
    assert load_manifest(repo_cwd) == Manifest(features=want)
    assert resolve_ledger(str(repo_cwd), Config()) is None


def test_setup_starter_manifest_checks_and_groups(repo_cwd: Path) -> None:
    # 0245: spec section 3; the opt-in validate switch is written false, the overrides are absent.
    assert _setup(repo_cwd).returncode == 0
    manifest, _ = _paths(repo_cwd)
    doc = json.loads(manifest.read_text(encoding="utf-8"))
    assert set(doc["checks"]) == set(CHECK_KEYS) - {"release_banned_terms"}
    assert doc["checks"]["secret_scan"] is False
    assert doc["docs"] == {"folder": "docs", "decisions_filename": None, "reading_level": None}
    assert doc["commands"] == {key: None for key in COMMAND_KEYS}
    assert doc["run_output_priority"] is None and doc["local_testing"] is None


def test_setup_refuses_a_parent_folder_that_holds_repositories(tmp_path: Path) -> None:
    # 0077: files here would become the project root of every child repository below.
    parent = tmp_path / "parent"
    for name in ("one", "two"):
        subprocess.run(["git", "init", "-q", "-b", "main", str(parent / name)], check=True)
    result = _setup(parent)
    assert result.returncode == 1
    assert "holds the repository one," in result.stdout and "Next:" in result.stdout
    assert sorted(p.name for p in parent.iterdir()) == ["one", "two"]


def test_setup_refuses_a_folder_with_a_repository_two_levels_down(tmp_path: Path) -> None:
    # 0077: a home folder whose repositories sit under projects/ is refused the same way.
    home = tmp_path / "home"
    (home / ".cache" / "x").mkdir(parents=True)
    subprocess.run(["git", "init", "-q", "-b", "main", str(home / "projects" / "repo")], check=True)
    result = _setup(home)
    assert result.returncode == 1
    assert f"holds the repository {Path('projects') / 'repo'}," in result.stdout
    assert "Next:" in result.stdout
    assert sorted(p.name for p in home.iterdir()) == [".cache", "projects"]


def test_setup_refuses_a_symlinked_repository_and_ignores_a_symlinked_folder(
    tmp_path: Path,
) -> None:
    # 0077: a project linked in from another drive is re-rooted all the same.
    elsewhere = tmp_path / "elsewhere"
    subprocess.run(["git", "init", "-q", "-b", "main", str(elsewhere / "repo")], check=True)
    (elsewhere / "plain").mkdir()
    folder = tmp_path / "folder"
    folder.mkdir()
    (folder / "plain-link").symlink_to(elsewhere / "plain")
    assert _setup(folder).returncode == 0
    (folder / "service-manifest.json").unlink()
    (folder / "linked").symlink_to(elsewhere / "repo")
    result = _setup(folder)
    assert result.returncode == 1
    assert "holds the repository linked," in result.stdout and "Next:" in result.stdout
    assert not (folder / "service-manifest.json").exists()


def test_setup_refuses_when_the_scan_cap_is_reached(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # 0077: fail closed; a tree wider than the cap is never confirmed free of repositories.
    import daedalus_setup

    monkeypatch.setattr(daedalus_setup, "SCAN_LIMIT", 3)
    wide = tmp_path / "wide"
    for name in ("a", "b", "c", "d", "e"):
        (wide / name).mkdir(parents=True)
    assert daedalus_setup.setup(wide) == 1
    out = capsys.readouterr().out
    assert "more than 3 folders, too many to confirm it holds no repository" in out
    assert "Next: run the Daedalus setup skill from inside the one repository" in out
    assert sorted(p.name for p in wide.iterdir()) == ["a", "b", "c", "d", "e"]


def test_setup_writes_in_a_plain_folder_without_repositories(tmp_path: Path) -> None:
    # 0069: a plain folder is folder scope; only a folder holding repositories is refused.
    folder = tmp_path / "notes"
    (folder / "drafts").mkdir(parents=True)
    result = _setup(folder)
    assert result.returncode == 0, result.stdout
    manifest, config = _paths(folder)
    assert manifest.is_file() and config.is_file()


def test_setup_refuses_a_symlinked_data_folder(repo_cwd: Path, tmp_path: Path) -> None:
    # 0010: a symlinked data folder would send the config write out of the project.
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (repo_cwd / ".claude").mkdir()
    (repo_cwd / ".claude" / "daedalus").symlink_to(elsewhere)
    result = _setup(repo_cwd)
    assert result.returncode == 1
    assert "Next:" in result.stdout
    assert list(elsewhere.iterdir()) == []
    assert not (repo_cwd / "service-manifest.json").exists()
