# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
from lib import train_state, workspace
from lib.config import PACKS_DIR
from lib.workspace import (
    WorkspaceError,
    begin,
    create,
    finish,
    lock,
    mark_train,
    resume,
    stop,
    train_marker,
)

from tests.conftest import SCRIPTS_DIR

LEDGER = "| Id | Date | Ruling | Supersedes | Follow-ups |\n|---|---|---|---|---|\n"


def _git(repo: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", "-C", str(repo), *args], capture_output=True, text=True, check=False
    )


def _ok(repo: Path, *args: str) -> str:
    result = _git(repo, *args)
    assert result.returncode == 0, result.stderr
    return result.stdout.strip()


def _commit_all(repo: Path, message: str) -> None:
    _ok(repo, "add", "-A")
    _ok(repo, "commit", "-q", "-m", message)


def _head(repo: Path) -> str:
    return _ok(repo, "rev-parse", "--abbrev-ref", "HEAD")


def _cli(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPTS_DIR / "daedalus_workspace.py"), *args],
        capture_output=True,
        text=True,
        check=False,
    )


@pytest.fixture(autouse=True)
def _isolated_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # 0020: a temp HOME keeps the operator's settings and plugin cache out of these tests.
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.delenv("CLAUDE_PLUGIN_DATA", raising=False)
    for key in ("AUTHOR", "COMMITTER"):
        monkeypatch.setenv(f"GIT_{key}_NAME", "t")
        monkeypatch.setenv(f"GIT_{key}_EMAIL", "t@example.invalid")
    monkeypatch.setenv("GIT_CONFIG_COUNT", "1")
    monkeypatch.setenv("GIT_CONFIG_KEY_0", "commit.gpgsign")
    monkeypatch.setenv("GIT_CONFIG_VALUE_0", "false")


@pytest.fixture
def repo(project_data: Path) -> Path:
    root = project_data.parent.parent
    (project_data / ".gitignore").write_text("*\n")
    (root / "docs").mkdir()
    (root / "docs" / "decisions.md").write_text(LEDGER)
    _commit_all(root, "init")
    return root


@pytest.fixture
def charter(tmp_path: Path, repo: Path) -> Path:
    root = tmp_path.resolve() / "charter"
    root.mkdir()
    _ok(root, "init", "-q", "-b", "main")
    (root / "README.md").write_text("charter\n")
    _commit_all(root, "init")
    config = repo / ".claude" / "daedalus" / "config.json"
    config.write_text(json.dumps({"charter_root": str(root)}))
    return root


def _nothing_written(repo: Path) -> None:
    assert not train_marker(repo).exists()
    assert not (repo / train_state.STATE_DIR).exists()


def test_begin_prints_the_state_block_seed(repo: Path) -> None:
    lines = begin(repo)
    prefixes = ["train: ", "ledger: ", "charter_root: ", "policy: ", "cache: "]
    prefixes.append("standards ")
    assert [line.split(" ")[0] + " " for line in lines] == prefixes
    train = lines[0].split()[1]
    sha = _ok(repo, "rev-parse", "HEAD")
    assert lines[0] == f"train: {train}  base: main @ {sha}  audit session: pending"
    assert (
        lines[1] == f"ledger: {repo / 'docs' / 'decisions.md'} (probe, markdown-table-row, seq=0)"
    )
    assert lines[2] == "charter_root: none  charter base: none"
    assert lines[3] == "policy: none declared  standards: 0 sources"
    assert lines[4] == "cache: unresolved"
    assert lines[5] == "standards packs: none declared"
    state = train_state.load(repo, train)
    assert state["base_branch"] == "main" and state["base_sha"] == sha
    assert "audit_session" not in state and state["units"] == []
    assert train_marker(repo).read_text() == f"{train}\n"
    assert (repo / "docs" / ".tmp" / "daedalus" / ".gitignore").read_text() == "*\n"
    assert _git(repo, "status", "--porcelain").stdout == ""


def test_begin_cli_prints_six_lines(repo: Path) -> None:
    result = _cli("begin", "--repo", str(repo))
    assert result.returncode == 0, result.stderr
    assert len(result.stdout.splitlines()) == 6


def _hook(payload: dict[str, Any]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPTS_DIR / "enforce_agent_jail.py")],
        input=json.dumps(payload),
        capture_output=True,
        text=True,
        check=False,
    )


def _hooks_live(repo: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPTS_DIR / "verify_audit_chain.py"), "--hooks-live"]
        + ["--repo", str(repo)],
        capture_output=True,
        text=True,
        check=False,
    )


def _fresh(repo_cwd: Path) -> None:
    (repo_cwd / "docs").mkdir()
    (repo_cwd / "docs" / "decisions.md").write_text(LEDGER)
    _commit_all(repo_cwd, "init")


def test_begin_creates_the_data_dir_and_the_next_hook_record_proves_hooks_live(
    repo_cwd: Path, hook_input: Any
) -> None:
    # 0035: a hook record naming begin creates nothing; begin itself creates the data dir.
    _fresh(repo_cwd)
    command = f"python3 /p/scripts/daedalus_workspace.py begin --repo {repo_cwd}"
    jail = _hook(hook_input(tool_input={"command": command}))
    assert jail.returncode == 0, jail.stderr
    assert not (repo_cwd / ".claude").exists()
    lines = begin(repo_cwd)
    data = repo_cwd / ".claude" / "daedalus"
    assert (data / ".gitignore").read_text() == "*\n"
    assert lines[0].endswith("audit session: pending")
    assert train_marker(repo_cwd).is_file()
    verify = f"python3 /p/scripts/verify_audit_chain.py --hooks-live --repo {repo_cwd}"
    jail = _hook(hook_input(tool_input={"command": verify}, tool_use_id="toolu_2"))
    assert jail.returncode == 0, jail.stderr
    result = _hooks_live(repo_cwd)
    assert result.returncode == 0, result.stdout
    assert result.stdout.startswith("OK hooks live: session sess-test, chain intact (1 records)")


def test_hooks_live_after_begin_without_a_hook_record_is_not_live(repo_cwd: Path) -> None:
    _fresh(repo_cwd)
    begin(repo_cwd)
    result = _hooks_live(repo_cwd)
    assert result.returncode == 1
    assert "NOT LIVE:" in result.stdout + result.stderr


def test_begin_stops_on_a_dirty_tree(repo: Path) -> None:
    (repo / "stray.txt").write_text("x\n")
    with pytest.raises(WorkspaceError) as info:
        begin(repo)
    assert "stray.txt" in str(info.value) and "Next: commit or stash" in str(info.value)
    _nothing_written(repo)


def test_begin_refuses_a_detached_head(repo: Path) -> None:
    _ok(repo, "switch", "-q", "--detach")
    with pytest.raises(WorkspaceError, match="Next:"):
        begin(repo)
    _nothing_written(repo)


def test_begin_asks_the_ledger_question_with_exit_three(repo: Path) -> None:
    _ok(repo, "rm", "-q", "docs/decisions.md")
    _ok(repo, "commit", "-q", "-m", "drop ledger")
    result = _cli("begin", "--repo", str(repo))
    assert result.returncode == 3, result.stderr
    assert result.stdout.splitlines() == [
        "ledger: none declared and none found.",
        "This repo has no decision ledger. Options: name an existing file, or let Daedalus "
        "create docs/decisions.md as a table. Which?",
        "| Id | Date | Ruling | Supersedes | Follow-ups |",
        "|---|---|---|---|---|",
    ]
    _nothing_written(repo)
    assert not (repo / "docs" / ".tmp").exists()


def test_begin_branches_a_clean_charter(repo: Path, charter: Path) -> None:
    lines = begin(repo)
    train = lines[0].split()[1]
    assert lines[2] == f"charter_root: {charter}  charter base: main"
    assert _head(charter) == f"daedalus/{train}"
    state = train_state.load(repo, train)
    assert state["charter_base"] == "main" and state["charter_branch_created"] is True


def test_begin_stops_on_a_dirty_charter(repo: Path, charter: Path) -> None:
    (charter / "draft.md").write_text("x\n")
    with pytest.raises(WorkspaceError) as info:
        begin(repo)
    assert "draft.md" in str(info.value) and "Next:" in str(info.value)
    assert _head(charter) == "main"
    _nothing_written(repo)


def test_begin_switches_the_charter_back_when_a_later_step_fails(
    repo: Path, charter: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def _bad(repo: Path, train_id: str, state: dict[str, Any]) -> None:
        raise train_state.TrainStateError("state file not written. Next: fix the state dir")

    monkeypatch.setattr(workspace.train_state, "save", _bad)
    with pytest.raises(WorkspaceError, match="Next: fix the state dir"):
        begin(repo)
    assert _head(charter) == "main"
    _nothing_written(repo)


def test_begin_invalid_config_stops_with_its_next(repo: Path) -> None:
    (repo / ".claude" / "daedalus" / "config.json").write_text("{")
    with pytest.raises(WorkspaceError) as info:
        begin(repo)
    assert "not valid JSON" in str(info.value) and "Next:" in str(info.value)
    _nothing_written(repo)


def test_begin_reports_policy_and_cache(
    repo: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cache = tmp_path / "cache"
    cache.mkdir()
    monkeypatch.setenv("CLAUDE_PLUGIN_DATA", str(cache))
    config = {
        "policy": {"engine": "conftest", "path": "policy/"},
        "standards_sources": [{"kind": "file", "path": "STANDARDS.md"}],
    }
    (repo / ".claude" / "daedalus" / "config.json").write_text(json.dumps(config))
    lines = begin(repo)
    assert lines[3] == "policy: conftest policy  standards: 1 sources"
    assert lines[4] == f"cache: {cache.resolve()}/frameworks"
    assert os.path.isabs(lines[4].split()[1])


def test_begin_prints_the_declared_pack_path(repo: Path) -> None:
    # 0019, 0026: the standards specialist reads a pack at the path begin resolves.
    config = {"standards_sources": [{"kind": "pack", "name": "baseline"}]}
    (repo / ".claude" / "daedalus" / "config.json").write_text(json.dumps(config))
    lines = begin(repo)
    assert lines[3] == "policy: none declared  standards: 1 sources"
    pack = PACKS_DIR / "baseline"
    assert lines[5] == f"standards packs: baseline at {pack}"
    assert pack.is_absolute() and (pack / "rules.md").is_file()


def _train(repo: Path) -> str:
    return begin(repo)[0].split()[1]


def _subject(repo: Path, ref: str = "HEAD") -> str:
    return _ok(repo, "log", "-1", "--format=%s", ref)


def _contract(root: Path, rel: str = "contracts/api.md", text: str = "packet v1\n") -> Path:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    return path


def test_lock_commits_the_contract_on_the_integration_branch(repo: Path) -> None:
    train = _train(repo)
    base = _ok(repo, "rev-parse", "HEAD")
    path = _contract(repo)
    lines = lock(repo, "contracts/api.md", 1)
    sha = _ok(repo, "rev-parse", f"daedalus/{train}")
    assert lines == [f"lock: {sha}", f"contract: {path} v1"]
    assert _head(repo) == f"daedalus/{train}" and sha != base
    assert _subject(repo) == "Lock contract api v1"
    assert _ok(repo, "rev-parse", "HEAD~1") == base
    state = train_state.load(repo, train)
    assert state["lock_sha"] == sha and state["packet_version"] == 1
    assert state["contract_path"] == str(path) and state["contract_repo"] == str(repo)
    assert _git(repo, "status", "--porcelain").stdout == ""


def test_lock_skips_an_unchanged_contract(repo: Path) -> None:
    train = _train(repo)
    _contract(repo)
    first = lock(repo, "contracts/api.md", 1)
    again = lock(repo, "contracts/api.md", 2)
    assert again == [first[0], "contract unchanged, no commit"]
    assert train_state.load(repo, train)["packet_version"] == 2


def test_lock_refuses_a_missing_file(repo: Path) -> None:
    _train(repo)
    with pytest.raises(WorkspaceError) as info:
        lock(repo, "contracts/api.md", 1)
    assert str(info.value) == (
        f"contract-spec did not save the packet at {repo / 'contracts' / 'api.md'}. "
        "Next: start the Build Train again (/daedalus:build-train)."
    )


def test_lock_refuses_a_version_not_raised(repo: Path) -> None:
    train = _train(repo)
    _contract(repo)
    lock(repo, "contracts/api.md", 2)
    _contract(repo, text="packet v2\n")
    with pytest.raises(WorkspaceError) as info:
        lock(repo, "contracts/api.md", 2)
    assert str(info.value) == (
        "packet_version 2 does not exceed 2. Next: ask contract-spec for a higher packet_version."
    )
    assert _subject(repo) == "Lock contract api v2"
    assert train_state.load(repo, train)["packet_version"] == 2


def test_lock_revises_with_the_revise_message(repo: Path) -> None:
    train = _train(repo)
    _contract(repo)
    lock(repo, "contracts/api.md", 1)
    _contract(repo, text="packet v2\n")
    lines = lock(repo, "contracts/api.md", 2)
    assert _subject(repo) == "Revise contract api v2"
    assert lines[0] == f"lock: {_ok(repo, 'rev-parse', f'daedalus/{train}')}"


def test_lock_commits_a_charter_contract_in_the_charter(repo: Path, charter: Path) -> None:
    train = _train(repo)
    base = _ok(repo, "rev-parse", "HEAD")
    path = _contract(charter, "specs/api.md")
    lines = lock(repo, str(path), 1)
    assert lines == [f"lock: {base}", f"contract: {path} v1"]
    assert _head(charter) == f"daedalus/{train}"
    assert _subject(charter) == "Lock contract api v1"
    assert _head(repo) == f"daedalus/{train}"
    assert train_state.load(repo, train)["contract_repo"] == str(charter)


@pytest.mark.parametrize("rel", ["src/api.md", "contracts/sub/api.md", "contracts/API.md"])
def test_lock_refuses_a_path_outside_contracts(repo: Path, rel: str) -> None:
    _train(repo)
    _contract(repo, rel)
    with pytest.raises(WorkspaceError, match="Next:"):
        lock(repo, rel, 1)


def test_lock_without_a_train_refuses(repo: Path) -> None:
    _contract(repo)
    with pytest.raises(WorkspaceError, match="Next:"):
        lock(repo, "contracts/api.md", 1)


def test_lock_cli_exit_codes(repo: Path) -> None:
    _train(repo)
    missing = _cli("lock", "--repo", str(repo), "--contract", "contracts/api.md", "--version", "1")
    assert missing.returncode == 1 and "Next:" in missing.stderr
    _contract(repo)
    done = _cli("lock", "--repo", str(repo), "--contract", "contracts/api.md", "--version", "1")
    assert done.returncode == 0, done.stderr
    assert done.stdout.startswith("lock: ")


DEFAULT_NEXT = "Next: start the Build Train again (/daedalus:build-train)"


def _locked_train(repo: Path) -> str:
    train = _train(repo)
    _contract(repo)
    lock(repo, "contracts/api.md", 1)
    return train


def _unit(repo: Path, train: str, slug: str) -> Path:
    return create(repo, f"{train}-{slug}", f"daedalus/{train}")


def test_stop_without_a_train_says_nothing_to_stop(repo: Path) -> None:
    lines, ok = stop(repo, "operator", None)
    assert ok and lines == ["nothing to stop", DEFAULT_NEXT]


def test_stop_with_a_marker_and_no_state_only_unmarks(repo: Path) -> None:
    mark_train(repo, "20261016-120000")
    lines, ok = stop(repo, "crash", None)
    assert ok and lines[0] == "Stopped train 20261016-120000: crash"
    assert lines[-1] == DEFAULT_NEXT
    assert not train_marker(repo).exists()


def test_stop_tears_down_only_recorded_units(repo: Path) -> None:
    train = _locked_train(repo)
    unit = _unit(repo, train, "u1")
    (unit / "new.txt").write_text("x\n")
    extra = repo / ".claude" / "worktrees" / "extra"
    _ok(repo, "worktree", "add", "-q", "-b", "other", str(extra), "main")
    lines, ok = stop(repo, "operator", None)
    assert ok, lines
    assert f"discarding {unit}:" in lines and "  ?? new.txt" in lines
    assert not unit.exists() and extra.is_dir()
    assert not any(str(extra) in line for line in lines)
    assert _ok(repo, "rev-parse", "--verify", f"daedalus-unit/{train}-u1")


def test_stop_switches_back_to_base(repo: Path) -> None:
    train = _locked_train(repo)
    lines, ok = stop(repo, "operator", None)
    assert ok and _head(repo) == "main"
    assert lines[0] == f"Stopped train {train}: operator"
    assert f"switched {repo} to main" in lines and lines[-1] == DEFAULT_NEXT


def test_stop_keeps_a_dirty_main_checkout_on_the_train_branch(repo: Path) -> None:
    train = _locked_train(repo)
    (repo / "stray.txt").write_text("x\n")
    lines, ok = stop(repo, "operator", "ignored")
    assert ok and _head(repo) == f"daedalus/{train}"
    assert f"kept on daedalus/{train}: stray.txt" in lines
    assert lines[-1] == (
        f"Next: commit or discard those files on daedalus/{train} from your own shell, "
        "then run git switch main"
    )


def test_stop_keeps_an_uncommitted_contract(repo: Path) -> None:
    train = _locked_train(repo)
    _contract(repo, text="packet v2\n")
    lines, ok = stop(repo, "contract revision refused", None)
    assert ok and _head(repo) == f"daedalus/{train}"
    assert f"kept on daedalus/{train}: contracts/api.md" in lines


def test_stop_keeps_the_integration_branch_for_an_uncommitted_charter_contract(
    repo: Path, charter: Path
) -> None:
    train = _train(repo)
    path = _contract(charter, "specs/api.md")
    lock(repo, str(path), 1)
    path.write_text("packet v2\n")
    lines, ok = stop(repo, "contract revision refused", None)
    assert ok and _head(repo) == f"daedalus/{train}" and _head(charter) == f"daedalus/{train}"
    assert f"kept on daedalus/{train}: charter/specs/api.md" in lines
    assert lines[-1].startswith(f"Next: commit or discard those files on daedalus/{train}")


def test_stop_keeps_a_dirty_charter(repo: Path, charter: Path) -> None:
    train = _train(repo)
    (charter / "specs").mkdir()
    (charter / "specs" / "api.md").write_text("draft\n")
    lines, ok = stop(repo, "operator", None)
    assert ok and _head(charter) == f"daedalus/{train}"
    assert f"kept on daedalus/{train} in charter: specs/api.md" in lines
    assert lines[-1] == (
        f"Next: commit or discard those files on daedalus/{train} in charter from your own "
        f"shell, then run git -C {charter} switch main"
    )


def test_stop_switches_the_charter_back(repo: Path, charter: Path) -> None:
    _train(repo)
    lines, ok = stop(repo, "operator", None)
    assert ok and _head(charter) == "main"
    assert f"switched {charter} to main" in lines


def test_stop_after_merge_stays_on_the_integration_branch(repo: Path) -> None:
    train = _locked_train(repo)
    train_state.update(repo, train, merged=True)
    lines, ok = stop(repo, "train complete", "review the integration branch")
    assert ok and _head(repo) == f"daedalus/{train}"
    assert lines[-1] == "Next: review the integration branch"


def test_stop_next_precedence(repo: Path) -> None:
    train = _locked_train(repo)
    assert stop(repo, "a", None)[0][-1] == DEFAULT_NEXT
    mark_train(repo, train)
    assert stop(repo, "b", "fix the spec")[0][-1] == "Next: fix the spec"
    mark_train(repo, train)
    _ok(repo, "switch", "-q", f"daedalus/{train}")
    (repo / "stray.txt").write_text("x\n")
    assert stop(repo, "c", "fix the spec")[0][-1].startswith("Next: commit or discard")


def test_stop_remove_failure_exits_one_with_the_manual_command(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    train = _locked_train(repo)
    unit = _unit(repo, train, "u1")

    def _fail(repo: Path, name: str) -> None:
        raise WorkspaceError("git worktree remove failed (locked). Next: fix the cause.")

    monkeypatch.setattr(workspace, "remove", _fail)
    lines, ok = stop(repo, "operator", "ignored")
    assert not ok
    assert lines[-1] == (
        f"Next: run git worktree remove --force {unit} and git worktree prune from your own shell"
    )
    assert not train_marker(repo).exists()


def test_stop_always_unmarks(repo: Path) -> None:
    _locked_train(repo)
    (repo / "stray.txt").write_text("x\n")
    lines, _ = stop(repo, "operator", None)
    assert f"cleared {train_marker(repo)}" in lines
    assert not train_marker(repo).exists()


def test_stop_cli_prints_the_lines(repo: Path) -> None:
    train = _locked_train(repo)
    result = _cli("stop", "--repo", str(repo), "--reason", "operator", "--next", "say hi")
    assert result.returncode == 0, result.stderr
    out = result.stdout.splitlines()
    assert out[0] == f"Stopped train {train}: operator" and out[-1] == "Next: say hi"


def test_mark_train_names_the_marker_when_it_cannot_write(repo: Path) -> None:
    # 0023: a directory at the marker path is the operator's to remove, not a doctor case.
    train_marker(repo).mkdir()
    with pytest.raises(WorkspaceError) as info:
        mark_train(repo, "20261016-120000")
    assert f"Next: remove {train_marker(repo)} from your own shell" in str(info.value)


def _built(repo: Path, train: str, slug: str, name: str = "", text: str = "x\n") -> Path:
    unit = _unit(repo, train, slug)
    (unit / (name or f"{slug}.txt")).write_text(text)
    _commit_all(unit, f"build {slug}")
    return unit


def _merges(repo: Path, ref: str) -> list[str]:
    return _ok(repo, "log", "--merges", "--reverse", "--format=%s", ref).splitlines()


def test_finish_merges_every_unit_in_order(repo: Path) -> None:
    train = _locked_train(repo)
    _built(repo, train, "u1")
    _built(repo, train, "u2")
    lines = finish(repo)
    assert lines[0] == f"merged 2 units into daedalus/{train}"
    assert _merges(repo, f"daedalus/{train}") == [
        f"Merge u1 for train {train}",
        f"Merge u2 for train {train}",
    ]
    assert (repo / "u1.txt").is_file() and (repo / "u2.txt").is_file()


def test_finish_refuses_a_dirty_main_checkout(repo: Path) -> None:
    train = _locked_train(repo)
    _built(repo, train, "u1")
    (repo / "stray.txt").write_text("x\n")
    with pytest.raises(WorkspaceError) as info:
        finish(repo)
    assert "stray.txt" in str(info.value)
    assert "Next: inspect and discard those changes from your own shell" in str(info.value)
    assert _merges(repo, f"daedalus/{train}") == []


def test_finish_refuses_a_unit_not_descending_from_the_lock(repo: Path) -> None:
    train = _locked_train(repo)
    unit = create(repo, f"{train}-u1", "main")
    (unit / "u1.txt").write_text("x\n")
    _commit_all(unit, "build u1")
    with pytest.raises(WorkspaceError) as info:
        finish(repo)
    assert str(info.value) == (
        f"Unit daedalus-unit/{train}-u1 does not descend from the integration branch. "
        "Next: rerun the train; if it repeats, file an issue with the train summary."
    )
    assert _merges(repo, f"daedalus/{train}") == []


def test_finish_aborts_and_names_conflicts(repo: Path) -> None:
    train = _locked_train(repo)
    _built(repo, train, "u1", "shared.txt", "one\n")
    _built(repo, train, "u2", "shared.txt", "two\n")
    with pytest.raises(WorkspaceError) as info:
        finish(repo)
    message = str(info.value)
    assert (
        "shared.txt" in message
        and f"Next: inspect or delete the leftover daedalus/{train}" in message
    )
    assert _head(repo) == "main"
    assert _git(repo, "rev-parse", "--verify", "--quiet", "MERGE_HEAD").returncode != 0
    assert _git(repo, "status", "--porcelain").stdout == ""


def test_finish_tears_down_and_marks_merged(repo: Path) -> None:
    train = _locked_train(repo)
    unit = _built(repo, train, "u1")
    lines = finish(repo)
    assert not unit.exists() and f"removed {unit}" in lines
    assert train_state.load(repo, train)["merged"] is True
    assert _head(repo) == f"daedalus/{train}"
    stopped, ok = stop(repo, "train complete", None)
    assert ok and _head(repo) == f"daedalus/{train}"


def test_resume_remarks_and_switches_back(repo: Path, charter: Path) -> None:
    train = _locked_train(repo)
    stop(repo, "operator", None)
    assert _head(repo) == "main" and _head(charter) == "main"
    lines = resume(repo)
    assert lines[0] == f"resumed train {train}"
    assert train_marker(repo).read_text() == f"{train}\n"
    assert _head(repo) == f"daedalus/{train}" and _head(charter) == f"daedalus/{train}"


def test_resume_refuses_a_dirty_checkout_it_would_switch(repo: Path) -> None:
    _locked_train(repo)
    stop(repo, "operator", None)
    (repo / "stray.txt").write_text("x\n")
    with pytest.raises(WorkspaceError, match="stray.txt"):
        resume(repo)
    assert not train_marker(repo).exists() and _head(repo) == "main"


def test_resume_after_merge_stays_put(repo: Path) -> None:
    train = _locked_train(repo)
    train_state.update(repo, train, merged=True)
    stop(repo, "ledger mismatch", None)
    _ok(repo, "switch", "-q", "main")
    assert resume(repo) == [f"resumed train {train}"]
    assert _head(repo) == "main"


def test_resume_without_any_train_refuses(repo: Path) -> None:
    with pytest.raises(WorkspaceError, match="Next:"):
        resume(repo)


def test_finish_and_resume_cli_exit_codes(repo: Path) -> None:
    train = _locked_train(repo)
    (repo / "stray.txt").write_text("x\n")
    refused = _cli("finish", "--repo", str(repo))
    assert refused.returncode == 1 and "Next:" in refused.stderr
    (repo / "stray.txt").unlink()
    _built(repo, train, "u1")
    done = _cli("finish", "--repo", str(repo))
    assert done.returncode == 0, done.stderr
    assert done.stdout.splitlines()[0] == f"merged 1 units into daedalus/{train}"
    stop(repo, "operator", None)
    again = _cli("resume", "--repo", str(repo))
    assert again.returncode == 0, again.stderr
    assert again.stdout.splitlines()[0] == f"resumed train {train}"
