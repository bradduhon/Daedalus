# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

from lib.config import Config, load_config
from lib.ledger import resolve_ledger
from lib.manifest import FEATURE_KEYS, Features, Manifest
from lib.manifest import load as load_manifest
from lib.project_keys import config_keys, manifest_keys

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
    assert result.stdout.splitlines() == [f"written: {manifest}", f"written: {config}"]
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


def test_setup_starter_files_carry_every_reader_key_at_its_default(repo_cwd: Path) -> None:
    assert _setup(repo_cwd).returncode == 0
    manifest, config = _paths(repo_cwd)
    m_doc = json.loads(manifest.read_text(encoding="utf-8"))
    c_doc = json.loads(config.read_text(encoding="utf-8"))
    assert [k for k in manifest_keys() if not _present(m_doc, k)] == []
    assert [k for k in config_keys() if not _present(c_doc, k)] == []
    # 0072, 0076: the readers accept both files, and the config reads as the defaults.
    assert load_config(path=config) == Config()
    loaded = load_manifest(repo_cwd)
    assert loaded is not None
    assert loaded.forbidden_paths == () and loaded.forbidden_extensions == ()
    assert loaded.trains_dir is None and loaded.unit_test_cmd is None
    assert c_doc["max_concurrent_builders"] == 5


def test_setup_starter_files_load_through_the_readers_at_their_defaults(repo_cwd: Path) -> None:
    # 0076: the jail loads the config on every hook; a starter it refused would deny every call.
    assert _setup(repo_cwd).returncode == 0
    assert load_config(cwd=str(repo_cwd)) == Config()
    assert load_manifest(repo_cwd) == Manifest(features=Features(ledger=False))
    assert resolve_ledger(str(repo_cwd), Config()) is None


def test_setup_starter_manifest_has_every_feature_off(repo_cwd: Path) -> None:
    assert _setup(repo_cwd).returncode == 0
    manifest, _ = _paths(repo_cwd)
    features = json.loads(manifest.read_text(encoding="utf-8"))["features"]
    assert sorted(features) == sorted(FEATURE_KEYS)
    assert all(value in (False, None) for value in features.values()), features


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
