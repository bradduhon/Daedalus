# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

import pytest
from lib import jail, train_state
from lib.config import Config
from lib.unit_binding import bindings_path, claim, rebind, record_dispatch
from lib.workspace import create, mark_train

from tests.hook_chain import judge as decide

TRAIN = "20261016-120000"
CODER = "daedalus:repo-coder"


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True)


@pytest.fixture
def units(repo_cwd: Path, project_data: Path) -> dict[str, Path]:
    ident = ["-c", "user.name=t", "-c", "user.email=t@example.invalid"]
    _git(repo_cwd, *ident, "commit", "-q", "--allow-empty", "-m", "base")
    _git(repo_cwd, "branch", f"daedalus/{TRAIN}")
    train_state.save(repo_cwd, TRAIN, {"train_id": TRAIN})
    mark_train(repo_cwd, TRAIN)
    made = {name: create(repo_cwd, name, f"daedalus/{TRAIN}") for name in ("u1", "u2")}
    jail._registered_worktrees.cache_clear()
    return made


def _dispatch(repo: Path, prompt: str, subagent: str = CODER) -> dict[str, Any]:
    tool_input = {"description": "unit", "prompt": prompt, "subagent_type": subagent}
    return {"tool_name": "Agent", "tool_input": tool_input, "cwd": str(repo), "session_id": "s"}


def _write(repo: Path, agent_id: str, path: Path) -> dict[str, Any]:
    return {
        "tool_name": "Write",
        "tool_input": {"file_path": str(path), "content": "x\n"},
        "cwd": str(repo),
        "agent_type": CODER,
        "agent_id": agent_id,
        "session_id": "s",
    }


def _bash(repo: Path, agent_id: str, command: str) -> dict[str, Any]:
    payload = _write(repo, agent_id, repo)
    payload.update(tool_name="Bash", tool_input={"command": command})
    return payload


def _ok(payload: dict[str, Any]) -> None:
    d = decide(payload, Config())
    assert d.allow, d.reason


def _refused(payload: dict[str, Any], *needles: str) -> str:
    d = decide(payload, Config())
    assert not d.allow
    reason = str(d.reason)
    assert "Next:" in reason and all(n in reason for n in needles), reason
    return reason


def test_dispatch_requires_one_worktree_line(repo_cwd: Path, units: dict[str, Path]) -> None:
    _refused(_dispatch(repo_cwd, "build the thing"), "Worktree:")
    two = f"Worktree: {units['u1']}\nWorktree: {units['u2']}\n"
    _refused(_dispatch(repo_cwd, two), "Worktree:")
    _refused(_dispatch(repo_cwd, f"Worktree: {units['u1']} extra"), "Worktree:")
    _ok(_dispatch(repo_cwd, f"Contract above.\nWorktree: {units['u1']}\nGo."))


def test_dispatch_refuses_an_unrecorded_path(repo_cwd: Path, units: dict[str, Path]) -> None:
    stray = repo_cwd / ".claude" / "worktrees" / "u9"
    _refused(_dispatch(repo_cwd, f"Worktree: {stray}"), "Next: name the unit worktree")
    _refused(_dispatch(repo_cwd, "Worktree: relative/u1"), "Worktree:")


def test_dispatch_refuses_a_second_dispatch_to_an_unbound_unit(
    repo_cwd: Path, units: dict[str, Path]
) -> None:
    _ok(_dispatch(repo_cwd, f"Worktree: {units['u1']}"))
    _refused(_dispatch(repo_cwd, f"Worktree: {units['u1']}"), "already dispatched")
    _ok(_dispatch(repo_cwd, f"Worktree: {units['u2']}"))


def test_dispatch_rules_skip_other_agents_and_trainless_repos(
    repo_cwd: Path, units: dict[str, Path], tmp_path: Path
) -> None:
    _ok(_dispatch(repo_cwd, "no worktree line", subagent="daedalus:security-auditor"))
    plain = tmp_path / "plain"
    plain.mkdir()
    _ok(_dispatch(plain, "no worktree line"))


def test_first_write_claims_the_dispatched_unit(repo_cwd: Path, units: dict[str, Path]) -> None:
    _ok(_dispatch(repo_cwd, f"Worktree: {units['u1']}"))
    _ok(_write(repo_cwd, "a-1", units["u1"] / "src" / "a.py"))
    data = json.loads(bindings_path(repo_cwd, TRAIN).read_text(encoding="utf-8"))
    assert data == {"units": {"u1": {"agent_id": "a-1"}}}


def test_unit_binding_rebinds_a_warm_coder_to_the_next_worktree(
    repo_cwd: Path, units: dict[str, Path]
) -> None:
    # 0086: the coder that built u1 moves to u2; u1 closes to it and to every other coder.
    _ok(_dispatch(repo_cwd, f"Worktree: {units['u1']}"))
    _ok(_write(repo_cwd, "a-1", units["u1"] / "src" / "a.py"))
    assert rebind(repo_cwd, TRAIN, "a-2", "u1", "u2") is not None
    assert rebind(repo_cwd, TRAIN, "a-1", "u1", "u2") is None
    _ok(_write(repo_cwd, "a-1", units["u2"] / "src" / "b.py"))
    _refused(_write(repo_cwd, "a-1", units["u1"] / "src" / "a.py"), "finished", "u2")
    _refused(_write(repo_cwd, "a-9", units["u1"] / "src" / "a.py"), "finished")
    _refused(_write(repo_cwd, "a-9", units["u2"] / "src" / "b.py"), "belongs to coder a-1")
    _refused(_dispatch(repo_cwd, f"Worktree: {units['u2']}"), "bound to coder a-1")
    assert rebind(repo_cwd, TRAIN, "a-1", "u1", "u2") is not None
    data = json.loads(bindings_path(repo_cwd, TRAIN).read_text(encoding="utf-8"))
    assert data == {
        "units": {"u1": {"agent_id": None, "retired_to": "u2"}, "u2": {"agent_id": "a-1"}}
    }


def test_bound_agent_writes_its_unit(repo_cwd: Path, units: dict[str, Path]) -> None:
    _ok(_dispatch(repo_cwd, f"Worktree: {units['u1']}"))
    _ok(_write(repo_cwd, "a-1", units["u1"] / "src" / "a.py"))
    _ok(_write(repo_cwd, "a-1", units["u1"] / "tests" / "test_a.py"))
    _ok(_bash(repo_cwd, "a-1", f"git -C {units['u1']} commit -m 'Add a'"))


def test_second_agent_refused_in_a_claimed_unit(repo_cwd: Path, units: dict[str, Path]) -> None:
    # issue 29: two coders, one unit; the second is refused at its first write.
    _ok(_dispatch(repo_cwd, f"Worktree: {units['u1']}"))
    _ok(_write(repo_cwd, "a-1", units["u1"] / "src" / "a.py"))
    _refused(_write(repo_cwd, "a-2", units["u1"] / "src" / "b.py"), "belongs to coder a-1")


def test_bound_agent_refused_in_a_sibling_unit(repo_cwd: Path, units: dict[str, Path]) -> None:
    for name in ("u1", "u2"):
        _ok(_dispatch(repo_cwd, f"Worktree: {units[name]}"))
    _ok(_write(repo_cwd, "a-1", units["u1"] / "src" / "a.py"))
    _refused(_write(repo_cwd, "a-1", units["u2"] / "src" / "a.py"), "bound to unit u1")
    _ok(_write(repo_cwd, "a-2", units["u2"] / "src" / "a.py"))
    _refused(_write(repo_cwd, "a-2", units["u1"] / "src" / "x.py"), "belongs to coder a-1")


def test_git_dash_c_commit_into_a_sibling_refused(repo_cwd: Path, units: dict[str, Path]) -> None:
    for name in ("u1", "u2"):
        _ok(_dispatch(repo_cwd, f"Worktree: {units[name]}"))
    _ok(_write(repo_cwd, "a-1", units["u1"] / "src" / "a.py"))
    _refused(_bash(repo_cwd, "a-1", f"git -C {units['u2']} commit -m x"), "bound to unit u1")
    _refused(_bash(repo_cwd, "a-1", f"git -C {units['u2']} add -A"), "bound to unit u1")
    _refused(_bash(repo_cwd, "a-1", f"touch {units['u2']}/src/x.py"), "bound to unit u1")
    both = f"touch {units['u1']}/src/y.py {units['u2']}/src/y.py"
    _refused(_bash(repo_cwd, "a-1", both), "one unit worktree")


def test_write_to_an_undispatched_unit_refused(repo_cwd: Path, units: dict[str, Path]) -> None:
    _refused(_write(repo_cwd, "a-1", units["u1"] / "src" / "a.py"), "never dispatched")


def test_coder_write_without_a_train_refused(repo_cwd: Path, units: dict[str, Path]) -> None:
    (repo_cwd / ".claude" / "daedalus" / "train.active").unlink()
    reason = _refused(_write(repo_cwd, "a-1", units["u1"] / "src" / "a.py"))
    assert reason.endswith("Next: start coders from /daedalus:build-train.")


def test_claim_falls_back_to_the_session_without_an_agent_id(
    repo_cwd: Path, units: dict[str, Path]
) -> None:
    # B1: a coder run as the session agent (--agent) arrives without an agent_id.
    _ok(_dispatch(repo_cwd, f"Worktree: {units['u1']}"))
    payload = _write(repo_cwd, "", units["u1"] / "src" / "a.py")
    _ok(payload)
    assert claim(repo_cwd, TRAIN, "session:s", "u1") is None
    payload["session_id"] = ""
    _refused(payload, "agent_id")


def test_library_refusals_carry_next(repo_cwd: Path, project_data: Path) -> None:
    train_state.save(repo_cwd, TRAIN, {"train_id": TRAIN})
    assert record_dispatch(repo_cwd, TRAIN, "u1") is None
    for reason in (
        record_dispatch(repo_cwd, TRAIN, "u1"),
        claim(repo_cwd, TRAIN, "a-1", "u2"),
    ):
        assert reason is not None and "Next:" in reason
    assert claim(repo_cwd, TRAIN, "a-1", "u1") is None
    assert "Next:" in str(record_dispatch(repo_cwd, TRAIN, "u1"))


def test_symlinked_bindings_file_fails_closed(
    repo_cwd: Path, project_data: Path, tmp_path: Path
) -> None:
    train_state.save(repo_cwd, TRAIN, {"train_id": TRAIN})
    target = tmp_path / "elsewhere.json"
    target.write_text("{}", encoding="utf-8")
    bindings_path(repo_cwd, TRAIN).symlink_to(target)
    reason = record_dispatch(repo_cwd, TRAIN, "u1")
    assert reason is not None and "symlink" in reason and "Next:" in reason
    assert target.read_text(encoding="utf-8") == "{}"
