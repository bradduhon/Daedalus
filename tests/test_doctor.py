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

from tests.conftest import fake_bin, git, run_cli

SCAFFOLDS = ("service-manifest.json", "contracts/", ".gitleaks.toml")


def _run(
    data_dir: Path | None, repo: Path, path_env: str, home: Path | None = None
) -> subprocess.CompletedProcess[str]:
    # PATH is always the test's own; the real PATH never leaks in.
    env = dict(os.environ)
    env.pop("CLAUDE_PLUGIN_DATA", None)
    if data_dir is not None:
        env["CLAUDE_PLUGIN_DATA"] = str(data_dir)
    env["PATH"] = path_env
    if home is not None:
        env["HOME"] = str(home)
    return run_cli("daedalus_doctor.py", "--repo", str(repo), env=env)


def _git_repo(path: Path) -> None:
    # W1.4: a repo with no commit at an arbitrary path; the git_repo fixture commits once.
    path.mkdir(parents=True, exist_ok=True)
    git(path, "init", "-q", "-b", "main")


def _commit_all(path: Path) -> None:
    git(path, "add", "-A")
    git(path, "commit", "-q", "-m", "init")


def _commit_all_empty(path: Path) -> None:
    git(path, "commit", "-q", "--allow-empty", "-m", "init")


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
    # 0069, issue 52: no manifest means the secret scan is off, so a missing gitleaks is optional.
    gitleaks = next(line for line in lines if "gitleaks on PATH" in line)
    assert gitleaks.startswith("OPT  gitleaks on PATH: not found, and the secret scan is off.")
    assert "set secrets_scan to true in the features object" in gitleaks
    # issue 48: no manifest means features.github is off, so both gh lines are optional.
    gh = [line for line in lines if line[5:].startswith("gh ")]
    assert len(gh) == 2 and all(line.startswith("OPT  gh ") for line in gh)


def _settings(path: Path, body: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(body) if not isinstance(body, str) else body)


def _bins(tmp_path: Path, *names: str, exit_codes: dict[str, int] | None = None) -> str:
    return str(fake_bin(tmp_path, names, exit_codes))


def _bins_with_git(tmp_path: Path, *names: str, exit_codes: dict[str, int] | None = None) -> str:
    # spec 5: fake tools plus a link to the real git; git's own dir also holds gh.
    git = shutil.which("git")
    assert git is not None, "git is required to build the test repos"
    bins = _bins(tmp_path, *names, exit_codes=exit_codes)
    link = Path(bins) / "git"
    if not link.exists():
        link.symlink_to(git)
    return bins


def test_doctor_no_longer_checks_base_ref(tmp_path: Path) -> None:
    home = tmp_path / "home"
    home.mkdir()
    result = _run(None, tmp_path, path_env=_bins(tmp_path), home=home)
    assert "worktree.baseRef" not in result.stdout


def test_binary_lines_name_gitleaks_and_gh_only(tmp_path: Path) -> None:
    home = tmp_path / "home"
    home.mkdir()
    lines = _run(None, tmp_path, path_env=_bins(tmp_path), home=home).stdout.splitlines()
    named = [m[1] for line in lines if (m := re.match(r"(?:OK  |MISS|OPT ) (\S+) on PATH", line))]
    assert named == ["gitleaks", "gh"]


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
    bins = _bins_with_git(tmp_path, "gitleaks", "gh")
    home = tmp_path / "home"
    home.mkdir()
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
    bins = _bins_with_git(tmp_path, "gitleaks", "gh")
    home = tmp_path / "home"
    home.mkdir()
    result = _run(None, repo, path_env=bins, home=home)
    lines = result.stdout.splitlines()
    assert result.returncode == 0, result.stdout
    assert [line.split(":")[0][5:] for line in lines if line.startswith("OPT  ")] == [
        "config.json",
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
    lines = result.stdout.splitlines()
    assert f"OK   project data dir: {data} (not created yet; a train's start creates it)" in lines
    assert "OK   audit log: off until a train runs here" in lines
    assert NO_CONFIG in lines
    assert not (repo / ".claude").exists()


def test_worktree_resolves_to_main_repo_data_dir(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _git_repo(repo)
    _commit_all_empty(repo)
    worktree = tmp_path / "wt"
    git(repo, "worktree", "add", "-q", str(worktree))
    result = _run(None, worktree, path_env=_bins_with_git(tmp_path), home=tmp_path / "home")
    data = repo.resolve() / ".claude" / "daedalus"
    assert f"OK   project data dir: {data} (not created yet; a train's start creates it)" in (
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
        "a marketplace install, the published one or a local clone added with claude plugin "
        "marketplace add <clone path>, uses daedalus-<marketplace>)"
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
    return run_cli("daedalus_doctor.py", "--print-cache-dir", env=env)


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


def _github(repo: Path, value: object) -> None:
    # issue 48: a manifest holding only features.github, or no features key for the absent case.
    body = {} if value == "absent" else {"features": {"github": value}}
    (repo / "service-manifest.json").write_text(json.dumps(body), encoding="utf-8")


def test_gh_absent_is_two_misses_with_next(tmp_path: Path) -> None:
    home = tmp_path / "home"
    home.mkdir()
    _github(tmp_path, True)
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


def test_minor_7_gh_auth_timeout_names_the_timeout(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    import daedalus_doctor

    seen: dict[str, object] = {}

    def hang(cmd: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        seen.update(kwargs)
        raise subprocess.TimeoutExpired(cmd, 10)

    monkeypatch.setenv("PATH", _bins(tmp_path, "gh"))
    monkeypatch.setattr(daedalus_doctor.subprocess, "run", hang)
    _github(tmp_path, True)
    lines = [line for _, line in daedalus_doctor._gh_checks(tmp_path)]
    assert lines[1] == (
        "MISS gh authenticated: gh auth status did not finish within 10 s. "
        "Next: run gh auth status from your own shell, then gh auth login if it asks"
    )
    assert seen.get("stdin") is subprocess.DEVNULL


def test_minor_7_gh_auth_oserror_names_the_error(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    import daedalus_doctor

    def broken(cmd: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        raise PermissionError(13, "Permission denied")

    monkeypatch.setenv("PATH", _bins(tmp_path, "gh"))
    monkeypatch.setattr(daedalus_doctor.subprocess, "run", broken)
    _github(tmp_path, True)
    line = [line for _, line in daedalus_doctor._gh_checks(tmp_path)][1]
    assert line.startswith("MISS gh authenticated: gh auth status could not run (")
    assert "Permission denied" in line and "exited" not in line and "Next:" in line


def test_gh_signed_out_is_a_miss(tmp_path: Path) -> None:
    home = tmp_path / "home"
    home.mkdir()
    bins = _bins(tmp_path, "gh", exit_codes={"gh": 1})
    _github(tmp_path, True)
    lines = _run(None, tmp_path, path_env=bins, home=home).stdout.splitlines()
    assert "OK   gh on PATH" in lines
    assert ("MISS gh authenticated: gh auth status exited 1. Next: run gh auth login") in lines


GH_OFF = ", and features.github is off in service-manifest.json"


@pytest.mark.parametrize("value", ["absent", False, None])
def test_gh_lines_are_opt_when_github_is_off(tmp_path: Path, value: object) -> None:
    # issue 48: off, a missing or signed-out gh never fails the doctor, as gitleaks with no scan.
    import daedalus_doctor

    _github(tmp_path, value)
    assert daedalus_doctor.github_on(tmp_path) is False
    home = tmp_path / "home"
    home.mkdir()
    lines = _run(None, tmp_path, path_env=_bins(tmp_path), home=home).stdout.splitlines()
    assert (
        f"OPT  gh on PATH: not found{GH_OFF}. Next: install gh (https://cli.github.com); "
        "the Push Train opens pull requests with it"
    ) in lines
    assert (
        f"OPT  gh authenticated: gh not on PATH{GH_OFF}. Next: install gh, then run gh auth login"
    ) in lines
    bins = _bins(tmp_path, "gh", exit_codes={"gh": 1})
    lines = _run(None, tmp_path, path_env=bins, home=home).stdout.splitlines()
    assert "OK   gh on PATH" in lines
    assert f"OPT  gh authenticated: gh auth status exited 1{GH_OFF}. Next: run gh auth login" in (
        lines
    )


def test_gh_lines_are_ok_when_github_is_on_and_gh_is_signed_in(tmp_path: Path) -> None:
    import daedalus_doctor

    _github(tmp_path, True)
    assert daedalus_doctor.github_on(tmp_path) is True
    home = tmp_path / "home"
    home.mkdir()
    lines = _run(None, tmp_path, path_env=_bins(tmp_path, "gh"), home=home).stdout.splitlines()
    assert "OK   gh on PATH" in lines and "OK   gh authenticated" in lines


def test_refused_manifest_counts_github_on(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    # issue 48: a typo in the manifest never hides a missing gh, as the gitleaks line treats one.
    import daedalus_doctor

    _github(tmp_path, "yes")
    monkeypatch.setenv("PATH", _bins(tmp_path))
    assert daedalus_doctor.github_on(tmp_path) is True
    lines = [line for _, line in daedalus_doctor._gh_checks(tmp_path)]
    assert len(lines) == 2 and all(line.startswith("MISS gh ") for line in lines)


def test_absent_config_runs_the_ledger_probe_none_found(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _git_repo(repo)
    bins = _bins_with_git(tmp_path)
    lines = _run(None, repo, path_env=bins, home=tmp_path / "home").stdout.splitlines()
    i = lines.index(NO_CONFIG)
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
    i = lines.index(NO_CONFIG)
    assert lines[i + 1] == f"OK   ledger: {ledger} (probe, markdown-table-row)"


def test_minor_8_manifest_ledger_block_reports_manifest_origin(tmp_path: Path) -> None:
    from tests.conftest import REPO_ROOT

    repo = tmp_path / "repo"
    _git_repo(repo)
    fixture = REPO_ROOT / "tests" / "fixtures" / "ledgers" / "manifest-override.json"
    (repo / "service-manifest.json").write_text(fixture.read_text())
    (_data(repo) / "config.json").write_text("{}")
    bins = _bins_with_git(tmp_path)
    lines = _run(None, repo, path_env=bins, home=tmp_path / "home").stdout.splitlines()
    i = lines.index("OK   config.json")
    ledger = repo.resolve() / "docs" / "decisions.md"
    assert lines[i + 1] == f"OK   ledger: {ledger} (manifest, markdown-table-row)"


def test_manifest_line_reports_jail_narrowing_counts(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _git_repo(repo)
    narrowing = {"forbidden_paths": ["infra/", "Makefile"], "forbidden_extensions": [".pem"]}
    (repo / "service-manifest.json").write_text(json.dumps({"jail_narrowing": narrowing}))
    bins = _bins_with_git(tmp_path)
    lines = _run(None, repo, path_env=bins, home=tmp_path / "home").stdout.splitlines()
    want = "OK   service-manifest.json: jail_narrowing 2 paths, 1 extensions"
    assert want in lines


@pytest.mark.parametrize("body", ["{ not json", '{"jail_narrowing": {"forbidden_paths": "x"}}'])
def test_unusable_manifest_is_a_miss_with_next(tmp_path: Path, body: str) -> None:
    repo = tmp_path / "repo"
    _git_repo(repo)
    (repo / "service-manifest.json").write_text(body)
    bins = _bins_with_git(tmp_path)
    result = _run(None, repo, path_env=bins, home=tmp_path / "home")
    line = next(x for x in result.stdout.splitlines() if x.startswith("MISS service-manifest"))
    assert "Next: " in line
    assert result.returncode != 0


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
    # 0020: exit 0 on a clean repo with no config.json once three files are committed:
    # service-manifest.json, contracts/openapi.yaml and .gitleaks.toml.
    repo = tmp_path / "repo"
    _git_repo(repo)
    (repo / "service-manifest.json").write_text("{}")
    (repo / "contracts").mkdir()
    (repo / "contracts" / "openapi.yaml").write_text("")
    (repo / ".gitleaks.toml").write_text("")
    _commit_all(repo)
    bins = _bins_with_git(tmp_path, "gitleaks", "gh")
    home = tmp_path / "home"
    home.mkdir()
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


def test_minor_final_review_marker_id_drops_control_characters(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _git_repo(repo)
    (_data(repo) / "train.active").write_text("2026\x1b[31m1015\x07-12\x7f0000\nsecond\n")
    result = _run(None, repo, path_env=_bins_with_git(tmp_path), home=tmp_path / "home")
    line = next(x for x in result.stdout.splitlines() if "train marker" in x)
    assert line.startswith("OK   train marker: present (2026[31m1015-120000) at ")
    assert not any(ord(c) < 32 or ord(c) == 127 for c in line)


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
    home.mkdir()
    bins = _bins_with_git(tmp_path, "gitleaks", "gh")
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
    home.mkdir()
    bins = _bins_with_git(tmp_path, "gitleaks", "gh")
    result = _run(None, repo, path_env=bins, home=home)
    assert PACK_OFFER in result.stdout.splitlines()
    assert result.returncode == 0, result.stdout
    (_data(repo) / "config.json").write_text(
        json.dumps({"standards_sources": [{"kind": "pack", "name": "baseline"}]})
    )
    lines = _run(None, repo, path_env=bins, home=home).stdout.splitlines()
    assert "OK   standards_sources declared" in lines


SETUP_NEXT = "Next: run the Daedalus setup skill (/daedalus:setup) to write a starter "
NO_CONFIG = f"OPT  config.json: not present, defaults in use. {SETUP_NEXT}config.json"


def test_doctor_opt_lines_name_the_setup_skill(tmp_path: Path) -> None:
    # 0076: a missing manifest or config is optional; the next step is the setup skill.
    repo = tmp_path / "repo"
    _git_repo(repo)
    _commit_all_empty(repo)
    home = tmp_path / "home"
    home.mkdir()
    result = _run(None, repo, path_env=_bins_with_git(tmp_path, "gitleaks", "gh"), home=home)
    lines = result.stdout.splitlines()
    assert NO_CONFIG in lines
    assert (
        f"OPT  service-manifest.json: not found at repo root. {SETUP_NEXT}service-manifest.json"
    ) in lines
    assert result.returncode == 0, result.stdout


def _typecheck_lines(repo: Path, command: str | None) -> list[str]:
    import daedalus_doctor

    stack = {"typecheck_cmd": command}
    (repo / "service-manifest.json").write_text(json.dumps({"stack": stack}), encoding="utf-8")
    return [line for _, line in daedalus_doctor._typecheck_check(repo)]


def test_typecheck_result_line_is_printed_on_success(tmp_path: Path) -> None:
    command = f"{sys.executable} -c \"print('Success: no issues found')\""
    assert _typecheck_lines(tmp_path, command) == [
        f"OK   typecheck ({command}): Success: no issues found"
    ]


def test_typecheck_failure_is_a_miss_with_next(tmp_path: Path) -> None:
    command = f"{sys.executable} -c \"print('Found 2 errors'); raise SystemExit(1)\""
    (line,) = _typecheck_lines(tmp_path, command)
    assert line.startswith(f"MISS typecheck ({command}): exited 1: Found 2 errors. Next: run ")


def test_typecheck_timeout_is_a_miss(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    import daedalus_doctor

    def hang(cmd: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        assert kwargs["timeout"] == daedalus_doctor.TYPECHECK_TIMEOUT_S
        raise subprocess.TimeoutExpired(cmd, 1)

    monkeypatch.setattr(daedalus_doctor.subprocess, "run", hang)
    (line,) = _typecheck_lines(tmp_path, "mypy scripts")
    assert "did not finish within 120 s" in line and line.startswith("MISS typecheck")


def test_typecheck_missing_tool_is_a_miss(tmp_path: Path) -> None:
    (line,) = _typecheck_lines(tmp_path, "no-such-typechecker-xyz scripts")
    assert line.startswith("MISS typecheck (no-such-typechecker-xyz scripts): could not run (")


def test_no_typecheck_line_when_undeclared(tmp_path: Path) -> None:
    import daedalus_doctor

    assert _typecheck_lines(tmp_path, None) == []
    (tmp_path / "service-manifest.json").unlink()
    assert list(daedalus_doctor._typecheck_check(tmp_path)) == []


def _tag_lines(repo: Path, tmp_path: Path) -> list[str]:
    lines = _run(None, repo, path_env=_bins_with_git(tmp_path), home=tmp_path / "home").stdout
    return [line for line in lines.splitlines() if "version tag" in line]


def test_untagged_version_is_an_opt_line(git_repo: Path, tmp_path: Path) -> None:
    # issue 47: VERSION names a version no tag carries; the line is optional and has no Next.
    (git_repo / "VERSION").write_text("3.3.0\n", encoding="utf-8")
    _commit_all(git_repo)
    assert _tag_lines(git_repo, tmp_path) == ["OPT  version tag: v3.3.0 has no tag"]
    git(git_repo, "tag", "v3.3.0")
    assert _tag_lines(git_repo, tmp_path) == []


def test_annotated_tag_counts_as_a_tag(git_repo: Path, tmp_path: Path) -> None:
    (git_repo / "VERSION").write_text("1.2.3", encoding="utf-8")
    _commit_all(git_repo)
    git(git_repo, "tag", "-a", "v1.2.3", "-m", "release")
    assert _tag_lines(git_repo, tmp_path) == []


@pytest.mark.parametrize("body", [None, "v3.3.0", "3.3", "not a version", "\xff"])
def test_no_version_tag_line_without_a_bare_version(
    git_repo: Path, tmp_path: Path, body: str | None
) -> None:
    if body is not None:
        (git_repo / "VERSION").write_bytes(body.encode("latin-1"))
    assert _tag_lines(git_repo, tmp_path) == []


def _hook_lines(fake_claude: Path, tmp_path: Path, script: str) -> list[str]:
    # U2 -> D9: the fake claude prints what script says; PATH holds only the test's bin folder.
    fake_claude.write_text(f"#!/bin/sh\n{script}\n", encoding="utf-8")
    bins = _bins(tmp_path)
    assert (Path(bins) / "claude").exists()
    lines = _run(None, tmp_path, path_env=bins, home=tmp_path / "home").stdout.splitlines()
    return [line for line in lines if "hook failure mode" in line]


def test_old_claude_code_gets_the_hook_failure_line(fake_claude: Path, tmp_path: Path) -> None:
    assert _hook_lines(fake_claude, tmp_path, "echo '2.1.280 (Claude Code)'") == [
        "OPT  hook failure mode: Claude Code 2.1.280 ignores onFailure; "
        "2.1.295 or later (the documented minimum) blocks a timed-out hook"
    ]


@pytest.mark.parametrize("printed", ["2.1.295 (Claude Code)", "2.2.0", "3.0.1 (Claude Code)"])
def test_current_claude_code_gets_no_hook_failure_line(
    fake_claude: Path, tmp_path: Path, printed: str
) -> None:
    assert _hook_lines(fake_claude, tmp_path, f"echo '{printed}'") == []


@pytest.mark.parametrize(
    "script", ["echo 'Claude Code'", "echo ''", "echo '2.1.280'; exit 3", "exit 1"]
)
def test_unreadable_claude_version_skips_the_line(
    fake_claude: Path, tmp_path: Path, script: str
) -> None:
    assert _hook_lines(fake_claude, tmp_path, script) == []


def test_no_claude_on_path_skips_the_line(tmp_path: Path) -> None:
    home = tmp_path / "home"
    lines = _run(None, tmp_path, path_env=_bins(tmp_path), home=home).stdout.splitlines()
    assert not any("hook failure mode" in line for line in lines)


def test_claude_version_timeout_skips_the_line(
    monkeypatch: pytest.MonkeyPatch, fake_claude: Path
) -> None:
    import daedalus_doctor

    seen: dict[str, object] = {}

    def hang(cmd: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        seen.update(kwargs, argv=cmd)
        raise subprocess.TimeoutExpired(cmd, daedalus_doctor.CLAUDE_TIMEOUT_S)

    monkeypatch.setattr(daedalus_doctor.subprocess, "run", hang)
    assert list(daedalus_doctor._hook_failure_check()) == []
    argv = seen["argv"]
    assert isinstance(argv, list) and argv[1:] == ["--version"]
    assert Path(argv[0]).name == "claude" and seen["timeout"] == daedalus_doctor.CLAUDE_TIMEOUT_S
    assert seen["stdin"] is subprocess.DEVNULL and "shell" not in seen


def test_no_version_tag_line_outside_a_repository(tmp_path: Path) -> None:
    folder = tmp_path / "plain"
    folder.mkdir()
    (folder / "VERSION").write_text("3.3.0\n", encoding="utf-8")
    assert _tag_lines(folder, tmp_path) == []
