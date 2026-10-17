# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import builtins
import copy
import errno
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

import pytest
from lib.settings_merge import (
    MERGED_KEYS,
    SettingsMergeError,
    merge,
    read_settings,
    write_atomic,
)

from tests.conftest import REPO_ROOT, SCRIPTS_DIR, fake_bin


def _recommended() -> dict[str, Any]:
    return json.loads((REPO_ROOT / "settings.recommended.json").read_text())


def test_empty_file_gets_every_merged_key() -> None:
    rec = _recommended()
    assert MERGED_KEYS == (
        "sandbox",
        "permissions.deny",
        "promptCacheTtl",
        "subagentPromptCacheTtl",
    )
    assert merge({}, rec) == {
        "sandbox": rec["sandbox"],
        "permissions": {"deny": rec["permissions"]["deny"]},
        "promptCacheTtl": rec["promptCacheTtl"],
        "subagentPromptCacheTtl": rec["subagentPromptCacheTtl"],
    }


def test_only_permissions_deny_leaves_the_recommended_file() -> None:
    rec = {"permissions": {"allow": ["Bash(*)"], "defaultMode": "auto", "deny": ["Read(x)"]}}
    assert merge({}, rec) == {"permissions": {"deny": ["Read(x)"]}}
    assert merge({}, {"permissions": {"allow": ["Bash(*)"]}}) == {}


@pytest.mark.parametrize(
    ("existing", "dotted"),
    [
        ({"sandbox": True}, "sandbox"),
        ({"permissions": {"deny": "Read(x)"}}, "permissions.deny"),
        ({"sandbox": {"filesystem": {"denyRead": "~/.ssh"}}}, "sandbox.filesystem.denyRead"),
    ],
)
def test_type_conflict_is_refused_naming_the_key(existing: dict[str, Any], dotted: str) -> None:
    snapshot = copy.deepcopy(existing)
    with pytest.raises(SettingsMergeError, match=f"key {dotted} is not .*Next:"):
        merge(existing, _recommended())
    assert existing == snapshot


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
    target = tmp_path / ".claude" / "settings.local.json"
    target.parent.mkdir()
    target.write_text("{}\n")
    target.chmod(0o640)
    write_atomic(target, '{"a": 1}\n', tmp_path)
    assert target.read_text() == '{"a": 1}\n'
    assert target.stat().st_mode & 0o777 == 0o640
    assert sorted(p.name for p in target.parent.iterdir()) == ["settings.local.json"]


def test_write_atomic_creates_a_missing_parent(tmp_path: Path) -> None:
    target = tmp_path / "repo" / ".claude" / "settings.local.json"
    write_atomic(target, "{}\n", tmp_path / "repo")
    assert target.read_text() == "{}\n"


def test_write_atomic_writes_through_a_symlink_inside_the_repo(tmp_path: Path) -> None:
    real = tmp_path / ".claude" / "shared" / "settings.local.json"
    real.parent.mkdir(parents=True)
    real.write_text("{}\n")
    link = tmp_path / ".claude" / "settings.local.json"
    link.symlink_to(real)
    write_atomic(link, '{"a": 1}\n', tmp_path)
    assert link.is_symlink()
    assert real.read_text() == '{"a": 1}\n'


@pytest.mark.parametrize("kind", ["file-link", "dir-link", "outside"])
def test_write_atomic_refuses_a_path_outside_the_repo_claude_dir(tmp_path: Path, kind: str) -> None:
    # 0029: setup writes only under <repo>/.claude, whatever a symlink says.
    repo, elsewhere = tmp_path / "repo", tmp_path / "home" / ".claude"
    elsewhere.mkdir(parents=True)
    target = repo / ".claude" / "settings.local.json"
    if kind == "file-link":
        target.parent.mkdir(parents=True)
        target.symlink_to(elsewhere / "settings.json")
    elif kind == "dir-link":
        repo.mkdir()
        (repo / ".claude").symlink_to(elsewhere)
    else:
        target = elsewhere / "settings.json"
    with pytest.raises(SettingsMergeError, match="Next:"):
        write_atomic(target, "{}\n", repo)
    assert list(elsewhere.iterdir()) == []


def test_write_atomic_leaves_no_temp_file_on_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def _fail(src: str, dst: str) -> None:
        raise OSError("replace refused")

    monkeypatch.setattr(os, "replace", _fail)
    (tmp_path / ".claude").mkdir()
    with pytest.raises(OSError):
        write_atomic(tmp_path / ".claude" / "settings.local.json", "{}\n", tmp_path)
    assert list((tmp_path / ".claude").iterdir()) == []


IGNORE = ".claude/settings.local.json\n"


def _repo(tmp_path: Path, ignore: str | None = IGNORE) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    if ignore is not None:
        (repo / ".gitignore").write_text(ignore)
    return repo


def _local(repo: Path) -> Path:
    return repo / ".claude" / "settings.local.json"


def _setup(
    tmp_path: Path,
    names: tuple[str, ...],
    os_release: str = "ID=fedora\n",
    repo: Path | None = None,
    extra: tuple[str, ...] = (),
    cwd: Path | None = None,
) -> subprocess.CompletedProcess[str]:
    # 0029: HOME is a scratch directory; setup must never touch it.
    release = tmp_path / "os-release"
    release.write_text(os_release)
    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    args = ["--os-release", str(release), *extra]
    if repo is not None:
        args = ["--repo", str(repo), *args]
    return subprocess.run(
        [sys.executable, str(SCRIPTS_DIR / "daedalus_setup.py"), *args],
        capture_output=True,
        text=True,
        env={**os.environ, "PATH": _bins(tmp_path, names), "HOME": str(home)},
        cwd=cwd or repo or tmp_path,
        check=False,
    )


def _bins(tmp_path: Path, names: tuple[str, ...]) -> str:
    # 0020: stub sandbox tools plus the real git, which setup needs for check-ignore.
    git = shutil.which("git")
    assert git is not None
    bins = fake_bin(tmp_path, names)
    if not (bins / "git").exists():
        (bins / "git").symlink_to(git)
    return str(bins)


def _home_untouched(tmp_path: Path) -> None:
    assert list((tmp_path / "home").iterdir()) == []


def test_setup_without_binaries_prints_the_apt_line_and_writes_nothing(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    result = _setup(tmp_path, (), "ID=ubuntu\nID_LIKE=debian\n", repo)
    assert result.returncode == 1
    assert result.stdout == (
        "daedalus setup: bwrap, socat not on PATH; nothing written. "
        "Next: run sudo apt-get install -y bubblewrap socat, then rerun /daedalus:setup\n"
    )
    assert not (repo / ".claude").exists()
    _home_untouched(tmp_path)


def test_setup_without_one_binary_names_its_package_elsewhere(tmp_path: Path) -> None:
    result = _setup(tmp_path, ("bwrap",), repo=_repo(tmp_path))
    assert result.returncode == 1
    assert result.stdout == (
        "daedalus setup: socat not on PATH; nothing written. Next: install the packages "
        "socat with your distribution's package manager, then rerun /daedalus:setup\n"
    )


def test_setup_writes_the_repo_local_file_only(tmp_path: Path) -> None:
    # 0027: the target is <repo>/.claude/settings.local.json, nothing else.
    repo = _repo(tmp_path)
    _local(repo).parent.mkdir()
    _local(repo).write_text('{"model": "opus"}\n')
    result = _setup(tmp_path, ("bwrap", "socat"), repo=repo)
    assert result.returncode == 0, result.stdout + result.stderr
    assert f"+++ {_local(repo)} (after)" in result.stdout
    assert result.stdout.endswith("Restart Claude Code to apply\n")
    data = json.loads(_local(repo).read_text())
    assert data["model"] == "opus" and data["sandbox"]["enabled"] is True
    assert "worktree" not in data and "env" not in data
    assert sorted(p.name for p in (repo / ".claude").iterdir()) == ["settings.local.json"]
    _home_untouched(tmp_path)


def test_setup_defaults_to_the_repo_of_the_current_directory(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    sub = repo / "pkg"
    sub.mkdir()
    result = _setup(tmp_path, ("bwrap", "socat"), cwd=sub)
    assert result.returncode == 0, result.stdout + result.stderr
    assert _local(repo).is_file() and not (sub / ".claude").exists()


def test_setup_carries_the_cache_ttls_repo_local(tmp_path: Path) -> None:
    # 0029: the two cache settings land in the repo file, never in user settings.
    repo = _repo(tmp_path)
    assert _setup(tmp_path, ("bwrap", "socat"), repo=repo).returncode == 0
    data = json.loads(_local(repo).read_text())
    assert data["promptCacheTtl"] == "1h" and data["subagentPromptCacheTtl"] == "1h"
    _home_untouched(tmp_path)


def test_setup_refuses_when_not_ignored(tmp_path: Path) -> None:
    repo = _repo(tmp_path, ignore=None)
    result = _setup(tmp_path, ("bwrap", "socat"), repo=repo)
    assert result.returncode == 1
    assert result.stdout == (
        f"daedalus setup: .claude/settings.local.json is not git-ignored in {repo}; "
        "nothing written. Next: add .claude/settings.local.json to .gitignore, "
        "then rerun /daedalus:setup\n"
    )
    assert not (repo / ".claude").exists()


def test_setup_refuses_outside_a_git_repository(tmp_path: Path) -> None:
    plain = tmp_path / "plain"
    plain.mkdir()
    result = _setup(tmp_path, ("bwrap", "socat"), repo=plain)
    assert result.returncode == 1 and "Next:" in result.stdout
    assert not (plain / ".claude").exists()


def test_setup_second_run_writes_nothing(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    _setup(tmp_path, ("bwrap", "socat"), repo=repo)
    before = _local(repo).stat().st_mtime_ns
    result = _setup(tmp_path, ("bwrap", "socat"), repo=repo)
    assert result.returncode == 0
    assert result.stdout == (
        f"daedalus setup: {_local(repo)} already holds the recommended settings; nothing written.\n"
    )
    assert _local(repo).stat().st_mtime_ns == before


def test_setup_refuses_malformed_settings(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    _local(repo).parent.mkdir()
    _local(repo).write_text("{bad")
    result = _setup(tmp_path, ("bwrap", "socat"), repo=repo)
    assert result.returncode == 1
    assert "is not valid JSON" in result.stderr and "Next:" in result.stderr
    assert _local(repo).read_text() == "{bad"


def test_setup_refuses_a_type_conflict_and_writes_nothing(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    _local(repo).parent.mkdir()
    _local(repo).write_text('{"sandbox": true}\n')
    result = _setup(tmp_path, ("bwrap", "socat"), repo=repo)
    assert result.returncode == 1
    assert "settings key sandbox is not a JSON object" in result.stderr
    assert "Next:" in result.stderr
    assert _local(repo).read_text() == '{"sandbox": true}\n'


def test_setup_has_no_settings_option(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    target = tmp_path / "home" / ".claude" / "settings.json"
    result = _setup(tmp_path, ("bwrap", "socat"), repo=repo, extra=("--settings", str(target)))
    assert result.returncode == 2 and "unrecognized arguments: --settings" in result.stderr
    assert not target.exists()


def _prepare(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("PATH", _bins(tmp_path, ("bwrap", "socat")))
    (tmp_path / "home").mkdir(exist_ok=True)


def _main(repo: Path) -> int:
    import daedalus_setup

    return daedalus_setup.main(["--repo", str(repo), "--os-release", "/nonexistent"])


def test_setup_never_opens_a_write_path_outside_the_repo(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # 0029: every write-mode open, temp file and replace lands under <repo>/.claude.
    repo = _repo(tmp_path)
    targets: list[str] = []
    real_open, real_os_open = builtins.open, os.open
    real_mkstemp, real_write_text, real_replace = tempfile.mkstemp, Path.write_text, os.replace

    def rec_open(file: Any, mode: str = "r", *args: Any, **kwargs: Any) -> Any:
        if isinstance(file, (str, os.PathLike)) and set(mode) & set("wax+"):
            targets.append(str(file))
        return real_open(file, mode, *args, **kwargs)

    def rec_os_open(path: Any, flags: int, *args: Any, **kwargs: Any) -> int:
        write = os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_APPEND | os.O_TRUNC
        if flags & write:
            targets.append(str(path))
        return real_os_open(path, flags, *args, **kwargs)

    def rec_mkstemp(*args: Any, **kwargs: Any) -> tuple[int, str]:
        fd, name = real_mkstemp(*args, **kwargs)
        targets.append(name)
        return fd, name

    def rec_write_text(self: Path, *args: Any, **kwargs: Any) -> int:
        targets.append(str(self))
        return real_write_text(self, *args, **kwargs)

    def rec_replace(src: Any, dst: Any, *args: Any, **kwargs: Any) -> None:
        targets.extend([str(src), str(dst)])
        real_replace(src, dst, *args, **kwargs)

    _prepare(tmp_path, monkeypatch)
    monkeypatch.setattr(builtins, "open", rec_open)
    monkeypatch.setattr(os, "open", rec_os_open)
    monkeypatch.setattr(tempfile, "mkstemp", rec_mkstemp)
    monkeypatch.setattr(Path, "write_text", rec_write_text)
    monkeypatch.setattr(os, "replace", rec_replace)
    code = _main(repo)
    monkeypatch.undo()
    assert code == 0
    assert targets, "setup recorded no write at all"
    claude = (repo / ".claude").resolve()
    for target in targets:
        resolved = Path(target).resolve()
        assert resolved == claude or claude in resolved.parents, target
    assert list((tmp_path / "home").iterdir()) == []


@pytest.mark.parametrize("code", [errno.EACCES, errno.EPERM, errno.EROFS])
def test_setup_reports_a_read_only_target_with_next(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], code: int
) -> None:
    import daedalus_setup

    repo = _repo(tmp_path)

    def denied(path: Path, text: str, root: Path) -> None:
        raise OSError(code, os.strerror(code), str(path))

    monkeypatch.setattr(daedalus_setup, "write_atomic", denied)
    _prepare(tmp_path, monkeypatch)
    assert _main(repo) == 1
    plugin = Path(daedalus_setup.__file__).resolve().parent.parent
    assert capsys.readouterr().out == (
        f"daedalus setup: cannot write {_local(repo)} ({errno.errorcode[code]}); the sandbox "
        "protects settings files. Next: run python3 "
        f"{plugin}/scripts/daedalus_setup.py --repo {repo} from your own shell\n"
    )
