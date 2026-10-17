# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
from lib.sandbox_state import required_binaries

from tests.conftest import SCRIPTS_DIR, fake_bin

# 0020: macOS needs no sandbox binaries, so binary-specific cases run only where they apply.
NEEDS_BINARIES = pytest.mark.skipif(not required_binaries(), reason="no sandbox binaries here")
SETUP = "type /daedalus:setup yourself; the model cannot run it"
SETUP_OFF = "MISS sandbox: off. Next: " + SETUP
SANDBOX_WITH_GH = {"sandbox": {"enabled": True, "excludedCommands": ["gh *", "git push *"]}}
SCAFFOLDS = ("service-manifest.json", "contracts/", ".gitleaks.toml")


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


def test_empty_setup_reports_every_miss_with_next(plugin_data: Path, tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    result = _run(plugin_data, repo, path_env=_bins(tmp_path), home=tmp_path / "home")
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
        "gh on PATH",
        "gh authenticated",
        *required_binaries(),
        "git repository",
        "service-manifest.json",
        "contracts/",
        ".gitleaks.toml",
    ):
        assert expected in names, expected
    assert any(line.startswith("OK   python") for line in lines)
    assert not any(line.startswith(("MISS " + n, "OK   " + n)) for n in SCAFFOLDS for line in lines)
    assert (
        sum(line.startswith(f"OPT  {n}: ") and "Next:" in line for n in SCAFFOLDS for line in lines)
        == 3
    )
    gitleaks = next(line for line in misses if "gitleaks on PATH" in line)
    assert gitleaks.endswith(
        "Next: the Push Train scans commits with gitleaks; install it so the scan can run"
    )


def _settings(path: Path, body: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(body) if not isinstance(body, str) else body)


def _sandbox_line(result: subprocess.CompletedProcess[str]) -> str:
    return next(line for line in result.stdout.splitlines() if line[5:].startswith("sandbox:"))


def _bins(tmp_path: Path, *names: str, exit_codes: dict[str, int] | None = None) -> str:
    return str(fake_bin(tmp_path, names, exit_codes))


def _bins_with_git(tmp_path: Path, *names: str, exit_codes: dict[str, int] | None = None) -> str:
    # spec 5: fake tools plus a link to the real git; git's own dir also holds bwrap, socat, gh.
    git = shutil.which("git")
    assert git is not None, "git is required to build the test repos"
    bins = _bins(tmp_path, *names, exit_codes=exit_codes)
    link = Path(bins) / "git"
    if not link.exists():
        link.symlink_to(git)
    return bins


def test_sandbox_off_is_a_miss_naming_setup(tmp_path: Path) -> None:
    home = tmp_path / "home"
    home.mkdir()
    result = _run(None, tmp_path, path_env=_bins(tmp_path, "bwrap", "socat"), home=home)
    assert _sandbox_line(result) == SETUP_OFF
    assert result.returncode == 1


USER_MOVE_NEXT = (
    "Next: Daedalus now writes .claude/settings.local.json per repo; remove the sandbox "
    "block from ~/.claude/settings.json from your own shell if you did not set it yourself"
)


def test_user_level_sandbox_gets_the_move_next(tmp_path: Path) -> None:
    # 0027, 0029: the doctor reads the user file for reporting and never writes it.
    home = tmp_path / "home"
    user = home / ".claude" / "settings.json"
    _settings(user, {"sandbox": {"enabled": True}})
    before = user.read_text()
    result = _run(None, tmp_path, path_env=_bins(tmp_path, "bwrap", "socat"), home=home)
    line = _sandbox_line(result)
    assert line == f"OK   sandbox: on (~/.claude/settings.json). {USER_MOVE_NEXT}"
    assert user.read_text() == before


def _gh_line(result: subprocess.CompletedProcess[str]) -> str:
    return next(line for line in result.stdout.splitlines() if "gh outside sandbox" in line)


def test_gh_outside_sandbox_ok_when_sandbox_off(tmp_path: Path) -> None:
    home = tmp_path / "home"
    home.mkdir()
    result = _run(None, tmp_path, path_env=_bins(tmp_path, "bwrap", "socat"), home=home)
    assert _gh_line(result) == "OK   gh outside sandbox: sandbox off"


def test_gh_outside_sandbox_ok_when_both_excluded(tmp_path: Path) -> None:
    # 0028: the exclusions may come from any settings file Claude Code reads.
    home = tmp_path / "home"
    _settings(home / ".claude" / "settings.json", {"sandbox": {"excludedCommands": ["gh *"]}})
    local = {"sandbox": {"enabled": True, "excludedCommands": ["git push *"]}}
    _settings(tmp_path / ".claude" / "settings.local.json", local)
    result = _run(None, tmp_path, path_env=_bins(tmp_path, "bwrap", "socat"), home=home)
    assert _gh_line(result) == "OK   gh outside sandbox"


def test_gh_outside_sandbox_miss_names_setup(tmp_path: Path) -> None:
    home = tmp_path / "home"
    home.mkdir()
    local = {"sandbox": {"enabled": True, "excludedCommands": ["gh *"]}}
    _settings(tmp_path / ".claude" / "settings.local.json", local)
    result = _run(None, tmp_path, path_env=_bins(tmp_path, "bwrap", "socat"), home=home)
    assert _gh_line(result) == (
        "MISS gh outside sandbox: sandbox.excludedCommands lacks git push *, so the Push Train "
        f"cannot reach GitHub. Next: {SETUP}"
    )
    assert result.returncode == 1


@pytest.mark.parametrize("name", ["settings.json", "settings.local.json"])
def test_sandbox_line_names_its_source_file(tmp_path: Path, name: str) -> None:
    home = tmp_path / "home"
    _settings(home / ".claude" / "settings.json", {"sandbox": {"enabled": False}})
    _settings(tmp_path / ".claude" / name, {"sandbox": {"enabled": True}})
    result = _run(None, tmp_path, path_env=_bins(tmp_path, "bwrap", "socat"), home=home)
    assert _sandbox_line(result) == f"OK   sandbox: on (.claude/{name})"


@NEEDS_BINARIES
def test_sandbox_without_binaries_is_configured_unavailable(tmp_path: Path) -> None:
    home = tmp_path / "home"
    _settings(home / ".claude" / "settings.json", {"sandbox": {"enabled": True}})
    result = _run(None, tmp_path, path_env=_bins(tmp_path), home=home)
    assert _sandbox_line(result) == ("MISS sandbox: configured-unavailable. Next: " + SETUP)


def test_sandbox_local_settings_override_user(tmp_path: Path) -> None:
    home = tmp_path / "home"
    _settings(home / ".claude" / "settings.json", {"sandbox": {"enabled": True}})
    _settings(tmp_path / ".claude" / "settings.local.json", {"sandbox": {"enabled": False}})
    result = _run(None, tmp_path, path_env=_bins(tmp_path, "bwrap", "socat"), home=home)
    assert _sandbox_line(result) == SETUP_OFF


def test_sandbox_malformed_settings_is_a_miss(tmp_path: Path) -> None:
    home = tmp_path / "home"
    _settings(home / ".claude" / "settings.json", "{not json")
    line = _sandbox_line(_run(None, tmp_path, path_env=_bins(tmp_path), home=home))
    assert line.startswith("MISS sandbox: ") and "is not valid JSON" in line and "Next: fix" in line


def test_doctor_no_longer_checks_base_ref(tmp_path: Path) -> None:
    home = tmp_path / "home"
    home.mkdir()
    result = _run(None, tmp_path, path_env=_bins(tmp_path), home=home)
    assert "worktree.baseRef" not in result.stdout


@NEEDS_BINARIES
def test_bwrap_miss_names_setup(tmp_path: Path) -> None:
    home = tmp_path / "home"
    home.mkdir()
    result = _run(None, tmp_path, path_env=_bins(tmp_path), home=home)
    assert (
        "MISS bwrap on PATH: not found. Next: install bubblewrap and socat, then " + SETUP
    ) in result.stdout.splitlines()


def test_binary_lines_follow_required_binaries(tmp_path: Path) -> None:
    home = tmp_path / "home"
    home.mkdir()
    lines = _run(None, tmp_path, path_env=_bins(tmp_path), home=home).stdout.splitlines()
    named = [m[1] for line in lines if (m := re.match(r"(?:OK  |MISS) (\S+) on PATH", line))]
    assert named == ["gitleaks", "gh", *required_binaries()]


def _state(repo: Path, home: Path, path_env: str) -> subprocess.CompletedProcess[str]:
    env = dict(os.environ)
    env["HOME"] = str(home)
    env["PATH"] = path_env
    return subprocess.run(
        [sys.executable, str(SCRIPTS_DIR / "daedalus_doctor.py"), "--sandbox-state"]
        + ["--repo", str(repo)],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )


def test_sandbox_state_flag_prints_one_word(tmp_path: Path) -> None:
    home = tmp_path / "home"
    home.mkdir()
    result = _state(tmp_path, home, _bins(tmp_path))
    assert result.returncode == 0
    assert result.stdout == "off\n"


def test_sandbox_state_flag_on(tmp_path: Path) -> None:
    home = tmp_path / "home"
    _settings(home / ".claude" / "settings.json", {"sandbox": {"enabled": True}})
    assert _state(tmp_path, home, _bins(tmp_path, "bwrap", "socat")).stdout == "on\n"


@NEEDS_BINARIES
def test_sandbox_state_flag_configured_unavailable(tmp_path: Path) -> None:
    home = tmp_path / "home"
    _settings(home / ".claude" / "settings.json", {"sandbox": {"enabled": True}})
    result = _state(tmp_path, home, _bins(tmp_path))
    assert (result.returncode, result.stdout) == (0, "configured-unavailable\n")


def test_sandbox_state_flag_malformed_exits_one(tmp_path: Path) -> None:
    home = tmp_path / "home"
    _settings(home / ".claude" / "settings.json", "{not json")
    result = _state(tmp_path, home, _bins(tmp_path))
    assert result.returncode == 1 and result.stdout == ""
    assert "Next: fix" in result.stderr


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
    bins = _bins_with_git(tmp_path, "gitleaks", "bwrap", "socat", "gh")
    home = tmp_path / "home"
    _settings(home / ".claude" / "settings.json", SANDBOX_WITH_GH)
    result = _run(plugin_data, repo, path_env=bins, home=home)
    assert result.returncode == 0, result.stdout
    assert not any(line.startswith("MISS") for line in result.stdout.splitlines())
    lines = result.stdout.splitlines()
    assert f"OK   project data dir: {data} (exists)" in lines
    assert "OK   standards_sources declared" in lines and "OK   policy declared" in lines


def _tree_line(repo: Path, tmp_path: Path) -> str:
    result = _run(None, repo, path_env=_bins_with_git(tmp_path), home=tmp_path / "home")
    return next(line for line in result.stdout.splitlines() if "clean working tree" in line)


def test_dirty_tree_is_a_miss_naming_the_paths(plugin_data: Path, tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _git_repo(repo)
    (repo / "x.txt").write_text("dirty")
    (repo / "sub").mkdir()
    (repo / "sub" / "y.txt").write_text("dirty")
    assert _tree_line(repo, tmp_path) == (
        "MISS clean working tree: uncommitted changes present: sub/y.txt, x.txt. "
        "Next: commit or stash before starting a train"
    )


def test_dirty_tree_caps_the_path_list(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _git_repo(repo)
    for n in range(12):
        (repo / f"f{n:02d}.txt").write_text("dirty")
    line = _tree_line(repo, tmp_path)
    shown = ", ".join(f"f{n:02d}.txt" for n in range(10))
    assert f"uncommitted changes present: {shown} +2 more. Next:" in line


def test_plugin_enablement_only_says_commit_settings(tmp_path: Path) -> None:
    # 0007: /plugin install leaves .claude/settings.json untracked in a fresh repo.
    repo = tmp_path / "repo"
    _git_repo(repo)
    _commit_all_empty(repo)
    _settings(repo / ".claude" / "settings.json", {"enabledPlugins": {"daedalus@x": True}})
    assert _tree_line(repo, tmp_path) == (
        "MISS clean working tree: uncommitted changes present: .claude/settings.json. "
        "Next: commit .claude/settings.json; "
        "it holds the enabledPlugins entry /plugin install wrote"
    )


def test_enablement_plus_other_paths_gets_generic_next(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _git_repo(repo)
    _settings(repo / ".claude" / "settings.json", {"enabledPlugins": {}})
    (repo / "x.txt").write_text("dirty")
    assert _tree_line(repo, tmp_path).endswith("Next: commit or stash before starting a train")


def test_clean_tree_is_ok(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _git_repo(repo)
    _commit_all_empty(repo)
    assert _tree_line(repo, tmp_path) == "OK   clean working tree"


def test_absent_scaffolds_are_opt_and_pass(tmp_path: Path) -> None:
    # 0007: no train reads the three scaffolds; absence is OPT and the doctor still exits 0.
    repo = tmp_path / "repo"
    _git_repo(repo)
    _commit_all_empty(repo)
    bins = _bins_with_git(tmp_path, "gitleaks", "gh", "bwrap", "socat")
    home = tmp_path / "home"
    _settings(home / ".claude" / "settings.json", SANDBOX_WITH_GH)
    result = _run(None, repo, path_env=bins, home=home)
    lines = result.stdout.splitlines()
    assert result.returncode == 0, result.stdout
    assert [line.split(":")[0][5:] for line in lines if line.startswith("OPT  ")] == [
        "standards_sources",
        "service-manifest.json",
        "contracts/",
        ".gitleaks.toml",
    ]
    assert lines[-1] == "daedalus doctor: all checks passed"


def test_absent_project_data_dir_is_ok_and_names_the_path(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _git_repo(repo)
    result = _run(None, repo, path_env=_bins_with_git(tmp_path), home=tmp_path / "home")
    data = repo.resolve() / ".claude" / "daedalus"
    assert f"OK   project data dir: {data} (will be created by the first hook)" in (
        result.stdout.splitlines()
    )
    assert "OK   config.json: not present, defaults in use" in result.stdout.splitlines()


def test_worktree_resolves_to_main_repo_data_dir(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _git_repo(repo)
    _commit_all_empty(repo)
    worktree = tmp_path / "wt"
    subprocess.run(["git", "worktree", "add", "-q", str(worktree)], cwd=repo, check=True)
    result = _run(None, worktree, path_env=_bins_with_git(tmp_path), home=tmp_path / "home")
    data = repo.resolve() / ".claude" / "daedalus"
    assert f"OK   project data dir: {data} (will be created by the first hook)" in (
        result.stdout.splitlines()
    )


def test_missing_gitignore_marker_is_a_miss(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _git_repo(repo)
    data = _data(repo, marker=False)
    result = _run(None, repo, path_env=_bins_with_git(tmp_path), home=tmp_path / "home")
    miss = [line for line in result.stdout.splitlines() if "gitignore marker" in line]
    assert len(miss) == 1 and miss[0].startswith("MISS") and "Next:" in miss[0]
    assert str(data / ".gitignore") in miss[0]


def test_marker_without_star_is_a_miss(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _git_repo(repo)
    data = _data(repo, marker=False)
    (data / ".gitignore").write_text("audit/\n")
    result = _run(None, repo, path_env=_bins_with_git(tmp_path), home=tmp_path / "home")
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
    result = _run(None, repo, path_env=_bins_with_git(tmp_path), home=tmp_path / "home")
    lines = result.stdout.splitlines()
    assert "OK   data dir .gitignore marker" in lines
    miss = [line for line in lines if line.startswith("MISS data dir ignored by git")]
    assert len(miss) == 1 and "tracked by git" in miss[0] and "Next:" in miss[0]


def test_ignored_data_dir_is_ok(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _git_repo(repo)
    _data(repo)
    result = _run(None, repo, path_env=_bins_with_git(tmp_path), home=tmp_path / "home")
    assert "OK   data dir ignored by git" in result.stdout.splitlines()


def test_symlinked_data_dir_is_a_miss_and_config_is_not_read(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _git_repo(repo)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (elsewhere / "config.json").write_text("{}")
    (repo / ".claude").mkdir()
    (repo / ".claude" / "daedalus").symlink_to(elsewhere)
    result = _run(None, repo, path_env=_bins_with_git(tmp_path), home=tmp_path / "home")
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
    lines = _run(
        None, repo, path_env=_bins_with_git(tmp_path), home=tmp_path / "home"
    ).stdout.splitlines()
    assert any(line.startswith("MISS data dir ignored by git") for line in lines)
    assert any(line.startswith("MISS config.json: not read") for line in lines)


def test_cache_dir_env_is_informational(plugin_data: Path, tmp_path: Path) -> None:
    home = tmp_path / "home"
    home.mkdir()
    result = _run(plugin_data, tmp_path, path_env=_bins(tmp_path), home=home)
    assert f"OK   cache dir: CLAUDE_PLUGIN_DATA={plugin_data}" in result.stdout.splitlines()


def test_cache_dir_absent_is_ok(tmp_path: Path) -> None:
    home = tmp_path / "home"
    home.mkdir()
    result = _run(None, tmp_path, path_env=_bins(tmp_path), home=home)
    lines = result.stdout.splitlines()
    assert (
        "OK   cache dir: none yet (create it with scripts/refresh_frameworks.py "
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
    result = _run(None, tmp_path, path_env=_bins(tmp_path), home=home)
    ok = [line for line in result.stdout.splitlines() if line.startswith("OK   cache dir")]
    assert ok == [
        f"OK   cache dir: {market}, {inline} (a --plugin-dir session uses daedalus-inline; "
        "a marketplace install uses daedalus-<marketplace>)"
    ]


def test_malformed_config_is_a_miss_with_next(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _git_repo(repo)
    (_data(repo) / "config.json").write_text("{not json")
    result = _run(None, repo, path_env=_bins_with_git(tmp_path), home=tmp_path / "home")
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


def test_gh_absent_is_two_misses_with_next(tmp_path: Path) -> None:
    home = tmp_path / "home"
    home.mkdir()
    lines = _run(None, tmp_path, path_env=_bins(tmp_path), home=home).stdout.splitlines()
    assert (
        "MISS gh on PATH: not found. Next: install gh (https://cli.github.com); "
        "the Push Train opens pull requests with it"
    ) in lines
    assert (
        "MISS gh authenticated: gh not on PATH. Next: install gh, then run gh auth login"
    ) in lines


def test_gh_signed_in_is_ok(tmp_path: Path) -> None:
    home = tmp_path / "home"
    home.mkdir()
    lines = _run(None, tmp_path, path_env=_bins(tmp_path, "gh"), home=home).stdout.splitlines()
    assert "OK   gh on PATH" in lines
    assert "OK   gh authenticated" in lines


def test_gh_signed_out_is_a_miss(tmp_path: Path) -> None:
    home = tmp_path / "home"
    home.mkdir()
    bins = _bins(tmp_path, "gh", exit_codes={"gh": 1})
    lines = _run(None, tmp_path, path_env=bins, home=home).stdout.splitlines()
    assert "OK   gh on PATH" in lines
    assert ("MISS gh authenticated: gh auth status exited 1. Next: run gh auth login") in lines


def test_absent_config_runs_the_ledger_probe_none_found(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _git_repo(repo)
    bins = _bins_with_git(tmp_path)
    lines = _run(None, repo, path_env=bins, home=tmp_path / "home").stdout.splitlines()
    i = lines.index("OK   config.json: not present, defaults in use")
    assert lines[i + 1] == (
        "OK   ledger: none found (the Build Train asks before creating docs/decisions.md)"
    )
    assert not any(line.startswith("MISS config.json") for line in lines)
    assert not any("ledger declared" in line for line in lines)


def test_absent_config_runs_the_ledger_probe_found(tmp_path: Path) -> None:
    from tests.conftest import REPO_ROOT

    repo = tmp_path / "repo"
    _git_repo(repo)
    (repo / "docs").mkdir()
    fixture = REPO_ROOT / "tests" / "fixtures" / "ledgers" / "table.md"
    (repo / "docs" / "decisions.md").write_text(fixture.read_text())
    bins = _bins_with_git(tmp_path)
    lines = _run(None, repo, path_env=bins, home=tmp_path / "home").stdout.splitlines()
    ledger = repo.resolve() / "docs" / "decisions.md"
    assert f"OK   ledger: {ledger} (probe, markdown-table-row)" in lines


def test_undeclared_standards_and_policy_are_optional(tmp_path: Path) -> None:
    # spec 5: absent standards_sources and policy are OK with or without config.json.
    repo = tmp_path / "repo"
    _git_repo(repo)
    bins = _bins_with_git(tmp_path)
    for with_config in (False, True):
        if with_config:
            (_data(repo) / "config.json").write_text("{}")
        lines = _run(None, repo, path_env=bins, home=tmp_path / "home").stdout.splitlines()
        assert PACK_OFFER in lines
        assert "OK   policy: not declared (optional)" in lines
        assert not any(line.startswith(("MISS standards", "MISS policy")) for line in lines)


def test_plugin_root_follows_the_cache_dir_line(tmp_path: Path) -> None:
    from tests.conftest import REPO_ROOT

    home = tmp_path / "home"
    home.mkdir()
    lines = _run(None, tmp_path, path_env=_bins(tmp_path), home=home).stdout.splitlines()
    i = next(n for n, line in enumerate(lines) if line.startswith("OK   cache dir"))
    assert lines[i + 1] == f"OK   plugin root: {REPO_ROOT}"


def test_first_run_without_config_is_all_ok(tmp_path: Path) -> None:
    # 0020: a first doctor on a clean committed repo with no config.json exits 0.
    repo = tmp_path / "repo"
    _git_repo(repo)
    (repo / "service-manifest.json").write_text("{}")
    (repo / "contracts").mkdir()
    (repo / "contracts" / "openapi.yaml").write_text("")
    (repo / ".gitleaks.toml").write_text("")
    _commit_all(repo)
    bins = _bins_with_git(tmp_path, "gitleaks", "gh", "bwrap", "socat")
    home = tmp_path / "home"
    _settings(home / ".claude" / "settings.json", SANDBOX_WITH_GH)
    result = _run(None, repo, path_env=bins, home=home)
    assert result.returncode == 0, result.stdout
    assert not any(line.startswith("MISS") for line in result.stdout.splitlines())


def test_config_without_ledger_runs_the_probe_found(tmp_path: Path) -> None:
    from tests.conftest import REPO_ROOT

    repo = tmp_path / "repo"
    _git_repo(repo)
    (_data(repo) / "config.json").write_text("{}")
    (repo / "docs").mkdir()
    fixture = REPO_ROOT / "tests" / "fixtures" / "ledgers" / "table.md"
    (repo / "docs" / "decisions.md").write_text(fixture.read_text())
    bins = _bins_with_git(tmp_path)
    lines = _run(None, repo, path_env=bins, home=tmp_path / "home").stdout.splitlines()
    i = lines.index("OK   config.json")
    ledger = repo.resolve() / "docs" / "decisions.md"
    assert lines[i + 1] == f"OK   ledger: {ledger} (probe, markdown-table-row)"
    assert not any(line.startswith("MISS ledger") for line in lines)


def test_config_without_ledger_runs_the_probe_none_found(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _git_repo(repo)
    (_data(repo) / "config.json").write_text("{}")
    bins = _bins_with_git(tmp_path)
    lines = _run(None, repo, path_env=bins, home=tmp_path / "home").stdout.splitlines()
    i = lines.index("OK   config.json")
    assert lines[i + 1] == (
        "OK   ledger: none found (the Build Train asks before creating docs/decisions.md)"
    )
    assert not any(line.startswith("MISS ledger") for line in lines)


def _declared_ledger(repo: Path, sequence_source: str) -> Path:
    path = repo / "docs" / "decisions.md"
    ledger = {
        "path": str(path),
        "format": "markdown-table-row",
        "id_scheme": "{seq:04d}-DAE-PLT",
        "sequence_source": sequence_source,
    }
    (_data(repo) / "config.json").write_text(json.dumps({"ledger": ledger}))
    return path


def test_config_ledger_with_bad_sequence_source_is_a_miss(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _git_repo(repo)
    _declared_ledger(repo, "row-count")
    bins = _bins_with_git(tmp_path)
    lines = _run(None, repo, path_env=bins, home=tmp_path / "home").stdout.splitlines()
    miss = [line for line in lines if line.startswith("MISS ledger: ")]
    assert len(miss) == 1 and "sequence_source" in miss[0] and "Next:" in miss[0]


def test_config_ledger_valid_is_ok_with_config_origin(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _git_repo(repo)
    path = _declared_ledger(repo, "last-row-id")
    bins = _bins_with_git(tmp_path)
    lines = _run(None, repo, path_env=bins, home=tmp_path / "home").stdout.splitlines()
    assert f"OK   ledger: {path} (config, markdown-table-row)" in lines
    assert not any(line.startswith("MISS ledger") for line in lines)


def test_train_marker_absent_is_ok_none(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _git_repo(repo)
    _data(repo)
    result = _run(None, repo, path_env=_bins_with_git(tmp_path), home=tmp_path / "home")
    assert "OK   train marker: none" in result.stdout.splitlines()


def test_train_marker_present_is_ok_with_unmark_next(tmp_path: Path) -> None:
    # 0023: a running train is legitimate, so the marker is never a MISS.
    repo = tmp_path / "repo"
    _git_repo(repo)
    (_data(repo) / "train.active").write_text("20261015-120000\n")
    result = _run(None, repo, path_env=_bins_with_git(tmp_path), home=tmp_path / "home")
    line = next(x for x in result.stdout.splitlines() if "train marker" in x)
    assert line.startswith("OK   train marker: present (20261015-120000)")
    root = repo.resolve()
    assert "Next: if no Daedalus train is running, run python3 ${CLAUDE_PLUGIN_ROOT}/" in line
    assert f"daedalus_workspace.py unmark --repo {root}" in line


def _framework_manifest(cache: Path, family: str, *dates: str) -> None:
    folder = cache / "frameworks" / family
    folder.mkdir(parents=True, exist_ok=True)
    entries = [{"file": f"f{n}.json", "pinned_on": d} for n, d in enumerate(dates)]
    (folder / "manifest.json").write_text(json.dumps(entries), encoding="utf-8")


def _framework_lines(stdout: str) -> list[str]:
    return [line for line in stdout.splitlines() if line[5:].startswith("frameworks ")]


def test_framework_line_ok_when_fresh(plugin_data: Path, tmp_path: Path) -> None:
    from datetime import UTC, datetime

    today = datetime.now(UTC).date().isoformat()
    _framework_manifest(plugin_data, "nist", today)
    _framework_manifest(plugin_data, "owasp", today, today)
    result = _run(plugin_data, tmp_path, path_env=_bins(tmp_path), home=tmp_path / "home")
    assert _framework_lines(result.stdout) == [
        f"OK   frameworks nist: pinned {today}",
        f"OK   frameworks owasp: pinned {today}",
    ]


def test_framework_line_old_after_90_days(tmp_path: Path) -> None:
    from datetime import date

    import daedalus_doctor

    _framework_manifest(tmp_path, "nist", "2026-10-01", "2026-06-01")
    lines = list(daedalus_doctor._framework_checks(tmp_path, date(2026, 10, 16)))
    assert lines == [
        (
            True,
            "OLD  frameworks nist: pinned 2026-06-01 (137 days). "
            "Next: refresh the framework caches with "
            "python3 <plugin>/scripts/refresh_frameworks.py",
        )
    ]
    _framework_manifest(tmp_path, "nist", "2026-07-18")
    assert list(daedalus_doctor._framework_checks(tmp_path, date(2026, 10, 16))) == [
        (True, "OK   frameworks nist: pinned 2026-07-18")
    ]


def test_old_framework_line_does_not_fail_the_doctor(plugin_data: Path, tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _git_repo(repo)
    (repo / "service-manifest.json").write_text("{}")
    (repo / "contracts").mkdir()
    (repo / "contracts" / "openapi.yaml").write_text("")
    (repo / ".gitleaks.toml").write_text("")
    _commit_all(repo)
    _framework_manifest(plugin_data, "nist", "2020-01-01")
    home = tmp_path / "home"
    _settings(home / ".claude" / "settings.json", SANDBOX_WITH_GH)
    bins = _bins_with_git(tmp_path, "gitleaks", "gh", "bwrap", "socat")
    result = _run(plugin_data, repo, path_env=bins, home=home)
    assert result.returncode == 0, result.stdout
    assert _framework_lines(result.stdout)[0].startswith("OLD  frameworks nist: pinned 2020-01-01")


def test_cis_manual_manifest_reported_the_same_way(tmp_path: Path) -> None:
    from datetime import date

    import daedalus_doctor

    _framework_manifest(tmp_path, "cis", "2026-06-01")
    assert list(daedalus_doctor._framework_checks(tmp_path, date(2026, 10, 16))) == [
        (
            True,
            "OLD  frameworks cis: pinned 2026-06-01 (137 days). Next: place a current benchmark "
            "and its manifest entry per docs/project-requirements.md",
        )
    ]


@pytest.mark.parametrize("body", ["{not json", '{"pinned_on": "2026-10-01"}', "[]", '[{"x": 1}]'])
def test_unreadable_framework_manifest_is_old_with_next(tmp_path: Path, body: str) -> None:
    from datetime import date

    import daedalus_doctor

    folder = tmp_path / "frameworks" / "owasp"
    folder.mkdir(parents=True)
    (folder / "manifest.json").write_text(body, encoding="utf-8")
    assert list(daedalus_doctor._framework_checks(tmp_path, date(2026, 10, 16))) == [
        (
            True,
            "OLD  frameworks owasp: manifest.json has no list of pinned_on dates. "
            "Next: refresh the framework caches with "
            "python3 <plugin>/scripts/refresh_frameworks.py",
        )
    ]


def test_no_manifest_no_line(plugin_data: Path, tmp_path: Path) -> None:
    (plugin_data / "frameworks" / "nist").mkdir(parents=True)
    result = _run(plugin_data, tmp_path, path_env=_bins(tmp_path), home=tmp_path / "home")
    assert _framework_lines(result.stdout) == []
    home = tmp_path / "home2"
    home.mkdir()
    result = _run(None, tmp_path, path_env=_bins(tmp_path), home=home)
    assert _framework_lines(result.stdout) == []


PACK_OFFER = (
    "OPT  standards_sources: no standards file or pack is declared. "
    "Next: to adopt the shipped baseline pack, add "
    '{"kind": "pack", "name": "baseline"} to standards_sources in .claude/daedalus/config.json'
)


def test_doctor_offers_the_baseline_pack(tmp_path: Path) -> None:
    # 0019: the offer is optional; a repo without standards still passes the doctor.
    repo = tmp_path / "repo"
    _git_repo(repo)
    (repo / "service-manifest.json").write_text("{}")
    (repo / "contracts").mkdir()
    (repo / "contracts" / "openapi.yaml").write_text("")
    (repo / ".gitleaks.toml").write_text("")
    _commit_all(repo)
    home = tmp_path / "home"
    _settings(home / ".claude" / "settings.json", SANDBOX_WITH_GH)
    bins = _bins_with_git(tmp_path, "gitleaks", "gh", "bwrap", "socat")
    result = _run(None, repo, path_env=bins, home=home)
    assert PACK_OFFER in result.stdout.splitlines()
    assert result.returncode == 0, result.stdout
    (_data(repo) / "config.json").write_text(
        json.dumps({"standards_sources": [{"kind": "pack", "name": "baseline"}]})
    )
    lines = _run(None, repo, path_env=bins, home=home).stdout.splitlines()
    assert "OK   standards_sources declared" in lines
