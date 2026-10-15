# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

from tests.conftest import SCRIPTS_DIR


def _run(
    data_dir: Path | None, repo: Path, path_env: str | None = None, home: Path | None = None
) -> subprocess.CompletedProcess[str]:
    env = dict(os.environ)
    env.pop("CLAUDE_PLUGIN_DATA", None)
    if data_dir is not None:
        env["CLAUDE_PLUGIN_DATA"] = str(data_dir)
    if path_env is not None:
        env["PATH"] = path_env
    if home is not None:
        env["HOME"] = str(home)
    return subprocess.run(
        [sys.executable, str(SCRIPTS_DIR / "daedalus_doctor.py"), "--repo", str(repo)],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )


def _git_repo(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "init", "-q", "-b", "main"], cwd=path, check=True)


def _commit_all(path: Path) -> None:
    subprocess.run(["git", "add", "-A"], cwd=path, check=True)
    subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid"]
        + ["-c", "commit.gpgsign=false", "commit", "-q", "-m", "init"],
        cwd=path,
        check=True,
    )


def _commit_all_empty(path: Path) -> None:
    subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid"]
        + ["-c", "commit.gpgsign=false", "commit", "-q", "--allow-empty", "-m", "init"],
        cwd=path,
        check=True,
    )


def _fake_tool(bin_dir: Path, name: str) -> None:
    tool = bin_dir / name
    tool.write_text("#!/bin/sh\nexit 0\n")
    tool.chmod(0o755)


def test_empty_setup_reports_every_miss_with_next(plugin_data: Path, tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    result = _run(plugin_data, repo, path_env="/nonexistent")
    assert result.returncode == 1
    lines = result.stdout.splitlines()
    misses = [line for line in lines if line.startswith("MISS")]
    assert all("Next:" in line for line in misses)
    names = " ".join(lines)
    for expected in (
        "config.json",
        "ledger",
        "standards_sources",
        "policy",
        "gitleaks",
        "bwrap",
        "socat",
        "git repository",
        "service-manifest.json",
        "contracts/",
        ".gitleaks.toml",
    ):
        assert expected in names, expected
    assert any(line.startswith("OK   python") for line in lines)
    gitleaks = next(line for line in misses if "gitleaks on PATH" in line)
    assert gitleaks.endswith(
        "Next: the Push Train scans commits with gitleaks; install it so the scan can run"
    )


def _settings(path: Path, body: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(body) if not isinstance(body, str) else body)


def _base_ref_line(result: subprocess.CompletedProcess[str]) -> str:
    return next(line for line in result.stdout.splitlines() if "worktree.baseRef" in line)


BASE_REF_MISS_NEXT = (
    'Next: set "worktree": {"baseRef": "head"} in ~/.claude/settings.json or '
    ".claude/settings.json (settings.recommended.json); otherwise coder worktrees branch "
    "from the remote default branch, not the integration branch"
)


def test_base_ref_unset_is_a_miss_naming_the_key(tmp_path: Path) -> None:
    home = tmp_path / "home"
    home.mkdir()
    result = _run(None, tmp_path, home=home)
    line = _base_ref_line(result)
    assert line == ("MISS worktree.baseRef is head: not set (default fresh). " + BASE_REF_MISS_NEXT)
    assert result.returncode == 1


def test_base_ref_head_in_user_settings_is_ok(tmp_path: Path) -> None:
    home = tmp_path / "home"
    _settings(home / ".claude" / "settings.json", {"worktree": {"baseRef": "head"}})
    assert _base_ref_line(_run(None, tmp_path, home=home)) == "OK   worktree.baseRef is head"


def test_base_ref_head_in_project_settings_is_ok(tmp_path: Path) -> None:
    home = tmp_path / "home"
    home.mkdir()
    _settings(tmp_path / ".claude" / "settings.json", {"worktree": {"baseRef": "head"}})
    assert _base_ref_line(_run(None, tmp_path, home=home)) == "OK   worktree.baseRef is head"


def test_base_ref_fresh_overrides_user_head(tmp_path: Path) -> None:
    home = tmp_path / "home"
    _settings(home / ".claude" / "settings.json", {"worktree": {"baseRef": "head"}})
    _settings(tmp_path / ".claude" / "settings.local.json", {"worktree": {"baseRef": "fresh"}})
    line = _base_ref_line(_run(None, tmp_path, home=home))
    assert line.startswith("MISS worktree.baseRef is head: set to 'fresh'. Next:")


def test_base_ref_malformed_settings_is_a_miss(tmp_path: Path) -> None:
    home = tmp_path / "home"
    _settings(home / ".claude" / "settings.json", "{not json")
    line = _base_ref_line(_run(None, tmp_path, home=home))
    assert line.startswith("MISS worktree.baseRef: ") and "is not valid JSON. Next: fix" in line


def _data(repo: Path, marker: bool = True) -> Path:
    data = repo / ".claude" / "daedalus"
    data.mkdir(parents=True)
    if marker:
        (data / ".gitignore").write_text("*\n")
    return data


def test_complete_setup_is_all_ok(plugin_data: Path, tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _git_repo(repo)
    (repo / "service-manifest.json").write_text("{}")
    (repo / "contracts").mkdir()
    (repo / "contracts" / "openapi.yaml").write_text("")
    (repo / ".gitleaks.toml").write_text("")
    data = _data(repo)
    (data / "config.json").write_text(
        json.dumps(
            {
                "ledger": {
                    "path": str(repo / "docs" / "decisions.md"),
                    "format": "markdown-table-row",
                    "id_scheme": "{seq:04d}-DAE-PLT",
                    "sequence_source": "last-row-id",
                },
                "policy": {"engine": "conftest", "path": str(repo / "policy")},
                "standards_sources": [{"kind": "rules-dir", "path": str(repo / "docs")}],
            }
        )
    )
    _commit_all(repo)
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    for name in ("gitleaks", "bwrap", "socat"):
        _fake_tool(fake_bin, name)
    home = tmp_path / "home"
    _settings(home / ".claude" / "settings.json", {"worktree": {"baseRef": "head"}})
    result = _run(plugin_data, repo, path_env=f"{fake_bin}:{os.environ['PATH']}", home=home)
    assert result.returncode == 0, result.stdout
    assert not any(line.startswith("MISS") for line in result.stdout.splitlines())
    assert f"OK   project data dir: {data} (exists)" in result.stdout.splitlines()


def test_dirty_tree_is_a_miss(plugin_data: Path, tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _git_repo(repo)
    (repo / "x.txt").write_text("dirty")
    result = _run(plugin_data, repo)
    assert "MISS clean working tree" in result.stdout


def test_absent_project_data_dir_is_ok_and_names_the_path(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _git_repo(repo)
    result = _run(None, repo, home=tmp_path / "home")
    data = repo.resolve() / ".claude" / "daedalus"
    assert f"OK   project data dir: {data} (will be created by the first hook)" in (
        result.stdout.splitlines()
    )
    assert any(line.startswith("MISS config.json") for line in result.stdout.splitlines())


def test_worktree_resolves_to_main_repo_data_dir(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _git_repo(repo)
    _commit_all_empty(repo)
    worktree = tmp_path / "wt"
    subprocess.run(["git", "worktree", "add", "-q", str(worktree)], cwd=repo, check=True)
    result = _run(None, worktree, home=tmp_path / "home")
    data = repo.resolve() / ".claude" / "daedalus"
    assert f"OK   project data dir: {data} (will be created by the first hook)" in (
        result.stdout.splitlines()
    )


def test_missing_gitignore_marker_is_a_miss(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _git_repo(repo)
    data = _data(repo, marker=False)
    result = _run(None, repo, home=tmp_path / "home")
    miss = [line for line in result.stdout.splitlines() if "gitignore marker" in line]
    assert len(miss) == 1 and miss[0].startswith("MISS") and "Next:" in miss[0]
    assert str(data / ".gitignore") in miss[0]


def test_marker_without_star_is_a_miss(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _git_repo(repo)
    data = _data(repo, marker=False)
    (data / ".gitignore").write_text("audit/\n")
    result = _run(None, repo, home=tmp_path / "home")
    assert any(
        line.startswith("MISS data dir .gitignore marker") for line in result.stdout.splitlines()
    )


def test_tracked_data_dir_is_a_miss(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _git_repo(repo)
    data = _data(repo, marker=False)
    (data / "config.json").write_text("{}")
    _commit_all(repo)
    (data / ".gitignore").write_text("*\n")
    result = _run(None, repo, home=tmp_path / "home")
    lines = result.stdout.splitlines()
    assert "OK   data dir .gitignore marker" in lines
    miss = [line for line in lines if line.startswith("MISS data dir ignored by git")]
    assert len(miss) == 1 and "tracked by git" in miss[0] and "Next:" in miss[0]


def test_ignored_data_dir_is_ok(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _git_repo(repo)
    _data(repo)
    result = _run(None, repo, home=tmp_path / "home")
    assert "OK   data dir ignored by git" in result.stdout.splitlines()


def test_symlinked_data_dir_is_a_miss_and_config_is_not_read(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _git_repo(repo)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (elsewhere / "config.json").write_text("{}")
    (repo / ".claude").mkdir()
    (repo / ".claude" / "daedalus").symlink_to(elsewhere)
    result = _run(None, repo, home=tmp_path / "home")
    lines = result.stdout.splitlines()
    assert result.returncode == 1
    assert any(
        line.startswith("MISS project data dir:") and "remove the symlink" in line for line in lines
    )
    assert any(line.startswith("MISS config.json: not read") for line in lines)


def test_tracked_file_outside_config_is_a_miss(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _git_repo(repo)
    data = _data(repo, marker=False)
    (data / "audit").mkdir()
    (data / "audit" / "old.jsonl").write_text("{}")
    _commit_all(repo)
    (data / ".gitignore").write_text("*\n")
    lines = _run(None, repo, home=tmp_path / "home").stdout.splitlines()
    assert any(line.startswith("MISS data dir ignored by git") for line in lines)
    assert any(line.startswith("MISS config.json: not read") for line in lines)


def test_cache_dir_env_is_informational(plugin_data: Path, tmp_path: Path) -> None:
    home = tmp_path / "home"
    home.mkdir()
    result = _run(plugin_data, tmp_path, home=home)
    assert f"OK   cache dir: CLAUDE_PLUGIN_DATA={plugin_data}" in result.stdout.splitlines()


def test_cache_dir_absent_is_ok(tmp_path: Path) -> None:
    home = tmp_path / "home"
    home.mkdir()
    result = _run(None, tmp_path, home=home)
    lines = result.stdout.splitlines()
    assert (
        "OK   cache dir: none yet (create it with scripts/refresh_nist_oscal.py "
        "or by hand per docs/project-requirements.md)"
    ) in lines
    assert not any(line.startswith("MISS cache") for line in lines)


def test_cache_dir_lists_globbed_matches(tmp_path: Path) -> None:
    # I5: a marketplace install and a --plugin-dir session coexist; the OK line names both.
    home = tmp_path / "home"
    base = home / ".claude" / "plugins" / "data"
    market = base / "daedalus-acme"
    inline = base / "daedalus-inline"
    market.mkdir(parents=True)
    inline.mkdir()
    result = _run(None, tmp_path, home=home)
    ok = [line for line in result.stdout.splitlines() if line.startswith("OK   cache dir")]
    assert ok == [
        f"OK   cache dir: {market}, {inline} (a --plugin-dir session uses daedalus-inline; "
        "a marketplace install uses daedalus-<marketplace>)"
    ]


def test_malformed_config_is_a_miss_with_next(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _git_repo(repo)
    (_data(repo) / "config.json").write_text("{not json")
    result = _run(None, repo, home=tmp_path / "home")
    assert result.returncode == 1
    miss = [line for line in result.stdout.splitlines() if line.startswith("MISS config.json")]
    assert len(miss) == 1
    assert "Next:" in miss[0]


def _print_cache(data_dir: Path | None, home: Path) -> subprocess.CompletedProcess[str]:
    env = dict(os.environ)
    env.pop("CLAUDE_PLUGIN_DATA", None)
    if data_dir is not None:
        env["CLAUDE_PLUGIN_DATA"] = str(data_dir)
    env["HOME"] = str(home)
    return subprocess.run(
        [sys.executable, str(SCRIPTS_DIR / "daedalus_doctor.py"), "--print-cache-dir"],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )


def test_print_cache_dir_prefers_env(plugin_data: Path, tmp_path: Path) -> None:
    home = tmp_path / "home"
    (home / ".claude" / "plugins" / "data" / "daedalus-acme").mkdir(parents=True)
    result = _print_cache(plugin_data, home)
    assert result.returncode == 0
    assert result.stdout == f"{plugin_data.resolve()}\n"


def test_print_cache_dir_uses_first_match(tmp_path: Path) -> None:
    home = tmp_path / "home"
    base = home / ".claude" / "plugins" / "data"
    (base / "daedalus-inline").mkdir(parents=True)
    (base / "daedalus-acme").mkdir()
    result = _print_cache(None, home)
    assert result.returncode == 0
    assert result.stdout == f"{(base / 'daedalus-acme').resolve()}\n"
    assert Path(result.stdout.strip()).is_absolute()


def test_print_cache_dir_none_exits_one_with_next(tmp_path: Path) -> None:
    home = tmp_path / "home"
    home.mkdir()
    result = _print_cache(None, home)
    assert result.returncode == 1
    assert result.stdout == ""
    assert result.stderr == (
        "no plugin cache dir found. Next: run /daedalus:doctor inside Claude Code once so the "
        "plugin data directory exists.\n"
    )
