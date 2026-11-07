# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# issue 188: each dispatched agent is judged against the run that started it.
from __future__ import annotations

import json
import stat
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from lib import audit, dispatch_binding, jail, train_state
from lib.workspace import mark_train

from tests.conftest import CFG, audit_records, git
from tests.hook_chain import judge
from tests.jail_cases import _git_init, _refusal
from tests.payloads import _cred
from tests.test_dispatch_binding import seed_plan

TRAIN = "20261107-010000"
SESSION = "s188"
Run = Callable[[str, dict[str, Any]], Any]


def _run_repo(path: Path) -> tuple[Path, Path, Path]:
    # issue 188: a repo with one recorded unit, a recorded plan and the coder's brief.
    repo = _git_init(path)
    git(repo, "commit", "-q", "--allow-empty", "-m", "init")
    wt = repo / ".claude" / "worktrees" / "u1"
    git(repo, "worktree", "add", "-q", "-b", "daedalus-unit/u1", str(wt))
    (repo / ".claude" / "daedalus").mkdir(exist_ok=True)
    unit = {"name": "u1", "branch": "daedalus-unit/u1", "path": str(wt)}
    train_state.save(repo, TRAIN, {"train_id": TRAIN, "units": [unit]})
    mark_train(repo, TRAIN)
    seed_plan(repo, TRAIN)
    brief = repo / "docs" / ".tmp" / "daedalus" / TRAIN / "briefs" / "u1.md"
    brief.parent.mkdir(parents=True)
    brief.write_text(f"Worktree: {wt}\n", encoding="utf-8")
    return repo, wt.resolve(), brief


def _call(cwd: Path, tool: str, agent: str | None = None, **tool_input: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "session_id": SESSION,
        "hook_event_name": "PreToolUse",
        "cwd": str(cwd),
        "tool_name": tool,
        "tool_input": tool_input,
        "tool_use_id": "toolu_1",
    }
    if agent is not None:
        payload.update(agent_type="daedalus:coder", agent_id=agent)
    return payload


def _dispatch(run_script: Run, repo: Path, wt: Path, brief: Path) -> None:
    prompt = f"Brief: {brief}\nWorktree: {wt}\n"
    payload = _call(repo, "Agent", subagent_type="daedalus:coder", prompt=prompt, description="u")
    result = run_script("enforce_agent_jail.py", payload)
    assert result.returncode == 0 and not result.stdout, (result.stdout, result.stderr)


@pytest.fixture
def two_runs(
    tmp_path: Path, run_script: Run
) -> tuple[tuple[Path, Path, Path], tuple[Path, Path, Path]]:
    # issue 188: one coder per run; each first reads its brief while the session sits elsewhere.
    a, b = _run_repo(tmp_path / "a"), _run_repo(tmp_path / "b")
    _dispatch(run_script, *a)
    _dispatch(run_script, *b)
    for agent, (_, _, brief), away in (("agent-a", a, b[0]), ("agent-b", b, a[0])):
        payload = _call(away, "Read", agent, file_path=str(brief))
        result = run_script("enforce_agent_jail.py", payload)
        assert result.returncode == 0, result.stderr
    return a, b


def _write(run_script: Run, cwd: Path, agent: str, target: Path) -> Any:
    payload = _call(cwd, "Write", agent, file_path=str(target), content="x\n")
    return run_script("enforce_agent_jail.py", payload)


def test_each_coder_writes_only_in_its_own_run(two_runs: Any, run_script: Run) -> None:
    # issue 188: the session cwd sits in the other repository for both coders.
    (repo_a, wt_a, _), (repo_b, wt_b, _) = two_runs
    for agent, own, theirs, away in (
        ("agent-a", wt_a, wt_b, repo_b),
        ("agent-b", wt_b, wt_a, repo_a),
    ):
        result = _write(run_script, away, agent, own / "x.py")
        assert result.returncode == 0, (agent, result.stderr)
        assert _write(run_script, away, agent, theirs / "y.py").returncode == 2, agent
    rows = [r for r in audit_records(audit.log_path(SESSION, str(wt_a))) if r["agent_id"]]
    moved = [r for r in rows if r["agent_id"] == "agent-a" and r["payload_cwd"] == str(repo_b)]
    assert moved and all(r["cwd"] == str(wt_a) for r in moved), rows
    claim = moved[0]["binding"]
    assert claim == {"train_id": TRAIN, "repo": str(repo_a), "worktree": str(wt_a), "claim": "path"}


def test_a_relative_write_of_a_moved_agent_is_refused(two_runs: Any, run_script: Run) -> None:
    # issue 188: the shell still runs in the session folder, so a relative target is refused.
    (_, wt_a, _), (repo_b, _, _) = two_runs
    for command in ("touch rel.txt", "echo x > out.txt", "cd sub", "git commit -m x"):
        result = run_script(
            "enforce_agent_jail.py", _call(repo_b, "Bash", "agent-a", command=command)
        )
        assert result.returncode == 2, command
        assert "Next: name every path you write, redirect to or cd into" in result.stderr, command
    assert jail.relative_write(f"touch {wt_a}/x 2>&1 > /dev/null") is None
    assert jail.relative_write(f"cd {wt_a} && ls") is None


def test_an_unbound_daedalus_agent_is_judged_by_its_payload_cwd(
    two_runs: Any, run_script: Run
) -> None:
    # issue 188: no pending entry of its type, so its cwd stays and no relative rule applies.
    _, (repo_b, _, _) = two_runs
    payload = _call(repo_b, "Bash", "agent-z", command="touch rel.txt")
    result = run_script("enforce_agent_jail.py", payload)
    assert "name every path you write" not in result.stderr
    rows = [r for r in audit_records(audit.log_path(SESSION, str(repo_b))) if r["agent_id"]]
    row = [r for r in rows if r["agent_id"] == "agent-z"][-1]
    assert (row["cwd"], row["payload_cwd"], row["binding"]) == (str(repo_b), None, None)


def _store(plugin_data: Path) -> Path:
    return plugin_data / dispatch_binding.RUN_BINDINGS / f"{SESSION}.json"


def test_the_store_is_private_and_a_claim_never_moves(
    two_runs: Any, plugin_data: Path, run_script: Run
) -> None:
    # issue 188, AC-6: folder 0700, file 0600; a claimed agent keeps its entry.
    (repo_a, _, _), (repo_b, _, _) = two_runs
    store = _store(plugin_data)
    assert stat.S_IMODE(store.parent.stat().st_mode) == 0o700
    assert stat.S_IMODE(store.stat().st_mode) == 0o600
    hook = _call(repo_b, "Read", "agent-a", file_path=str(repo_b / "README.md"))
    bound = dispatch_binding.bound_run({**hook, "agent_type": "daedalus:coder"})
    assert bound is not None and bound.repo == str(repo_a) and not bound.claimed_now


@pytest.mark.parametrize(
    "text", ["not json", '{"version": 2, "entries": []}', '{"version": 1, "entries": [{}]}']
)
def test_a_malformed_store_applies_no_binding(two_runs: Any, plugin_data: Path, text: str) -> None:
    # issue 188: malformed input falls back to the payload cwd.
    (_, _, brief), _ = two_runs
    _store(plugin_data).write_text(text, encoding="utf-8")
    hook = _call(brief.parent, "Read", "agent-a", file_path=str(brief))
    assert dispatch_binding.bound_run(hook) is None


def test_a_stale_binding_is_ignored(two_runs: Any, run_script: Run) -> None:
    # issue 188: a cleared marker ends the binding.
    (repo_a, _, brief), (repo_b, _, _) = two_runs
    (repo_a / ".claude" / "daedalus" / "train.active").unlink()
    assert (
        dispatch_binding.bound_run(_call(repo_b, "Read", "agent-a", file_path=str(brief))) is None
    )


def test_a_bad_session_id_has_no_store(plugin_data: Path) -> None:
    # issue 188: the file name comes from a full SESSION_ID match only.
    for session in ("../x", "a/b", "", None, "x y"):
        assert dispatch_binding.run_store(session) is None
    assert dispatch_binding.run_store("ok-1") == _store(plugin_data).with_name("ok-1.json")


def test_the_oldest_pending_entry_is_claimed_without_a_path(
    tmp_path: Path, run_script: Run
) -> None:
    # issue 188: a first call naming no path in a run repo takes the oldest entry of its type.
    a = _run_repo(tmp_path / "a")
    _dispatch(run_script, *a)
    hook = _call(tmp_path, "Bash", "agent-q", command="ls")
    bound = dispatch_binding.bound_run(hook)
    assert bound is not None and bound.claim == "oldest" and bound.repo == str(a[0])


def test_run_bindings_are_refused_to_agents(
    marked_repo: Path, plugin_data: Path, cred_home: Path
) -> None:
    # issue 188: the store sits in the plugin data folder, which no agent writes.
    store = str(_store(plugin_data))
    cwd = str(marked_repo)
    for agent in ("coder", "general-purpose"):
        for tool, tool_input in (
            ("Write", {"file_path": store}),
            ("Bash", {"command": f"echo x > {store}"}),
        ):
            assert not judge(_cred(agent, tool, cwd, **tool_input), CFG).allow, (agent, tool)


def test_a_foreign_agent_follows_the_host_outside_claude(
    marked_repo: Path, other_repo: Path, cred_home: Path
) -> None:
    # issue 188: a general-purpose agent with a run active writes the project, not .claude/.
    cwd, agent = str(marked_repo), "general-purpose"
    for tool, tool_input in (
        ("Write", {"file_path": f"{cwd}/notes.md"}),
        ("Bash", {"command": "gh issue list"}),
        ("Bash", {"command": f"git -C {other_repo} commit -m x"}),
        ("Bash", {"command": "python3 tools/report.py"}),
    ):
        d = jail.decide(_cred(agent, tool, cwd, **tool_input), CFG)
        assert d.allow, (tool_input, d.reason)
    d = jail.decide(_cred(agent, "Write", cwd, file_path=f"{cwd}/.claude/settings.json"), CFG)
    assert not d.allow and "may not write under" in str(d.reason)
    key = str(cred_home / ".ssh" / "id_ed25519")
    d = jail.decide(_cred(agent, "Read", cwd, file_path=key), CFG)
    assert not d.allow and d.reason == _refusal(key)


def test_the_audit_record_carries_null_binding_fields() -> None:
    # issue 188, AU-3: both fields are present and null when no binding moved the call.
    record = audit.build_record({"hook_event_name": "PreToolUse", "cwd": "/x"})
    assert record["payload_cwd"] is None and record["binding"] is None
    moved = audit.build_record({"cwd": "/w", "payload_cwd": "/s", "binding": {"claim": "path"}})
    assert (moved["payload_cwd"], moved["binding"]) == ("/s", {"claim": "path"})
    assert json.loads(audit.canonical(moved))["payload_cwd"] == "/s"
