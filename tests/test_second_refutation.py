# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# issue 187: each REFUTED verifier reply counts once on its unit; the second frees the unit.
from __future__ import annotations

from functools import partial
from pathlib import Path
from typing import Any

from lib import jail, train_runner, train_state, unit_binding, workspace
from lib.config import Config

from tests.conftest import CFG, CWD, REPO_ROOT, append_handback
from tests.hook_chain import decide, judge
from tests.payloads import _b
from tests.test_train_runner import (
    SESSION,
    _agent_stop,
    _integration,
    _probe_stage,
    _record,
    _started,
    _state,
    _train_cli,
    _write_train,
)
from tests.test_train_runner import _isolated_env as _isolated_env  # noqa: F401
from tests.test_train_runner import plugin as plugin  # noqa: F401
from tests.test_train_runner import repo as repo  # noqa: F401
from tests.test_unit_binding import _ok, _refused, _write
from tests.test_workspace_train import PLAN_BLOCK, REFUTED_REPLY, VERIFIED_REPLY

# agents/verifier.md, 0205: a run's stop tail is a digest whose last line names the saved report.
DIGEST = "[VERDICT: REFUTED] row 1\ncorrected=0\n[VERDICT: REFUTED] row 1\nreport: replies/v.md"


def _unit_train(repo: Path, plugin: Path) -> tuple[str, Path]:
    # A main-session run with unit u1 in its worktree, a recorded plan and an audit session.
    _write_train(plugin, [_probe_stage()], ("repository",))
    _started(repo, plugin)
    _integration(repo)
    train = str(_state(repo)["train_id"])
    unit = workspace.create(repo, f"{train}-u1", f"daedalus/{train}")
    plan = repo / "docs" / ".tmp" / "daedalus" / train / "plan.md"
    plan.parent.mkdir(parents=True, exist_ok=True)
    plan.write_text(f"# plan\n\n{PLAN_BLOCK}", encoding="utf-8")
    assert train_runner.record_plan(repo, plan).code == 0
    train_state.update(repo, train, audit_session=SESSION)
    _record(repo, hook_event_name="SessionStart", tool_name=None, tool_input=None)
    jail._registered_worktrees.cache_clear()
    return train, unit


def _verifier_dispatch(repo: Path, unit: Path) -> None:
    # The main session's dispatch carries no agent_type; the Unit worktree line opens a window.
    prompt = f"Check every claim.\nUnit worktree: {unit}\n"
    _record(
        repo, tool_name="Agent", tool_input={"subagent_type": "daedalus:verifier", "prompt": prompt}
    )


def _unit(repo: Path, name: str) -> dict[str, Any]:
    return next(u for u in train_state.units(_state(repo)) if u["name"] == name)


def test_two_refutations_in_one_window_escalate_and_free_the_unit(
    repo: Path,  # noqa: F811
    plugin: Path,  # noqa: F811
) -> None:
    train, unit = _unit_train(repo, plugin)
    name = f"{train}-u1"
    assert unit_binding.record_dispatch(repo, train, name) is None
    assert unit_binding.claim(repo, train, "agent-sonnet", name) is None
    assert train_runner.coder_model(repo, "U1").lines[0] == "sonnet"
    _verifier_dispatch(repo, unit)
    _agent_stop(repo, "verifier", REFUTED_REPLY)
    assert train_runner.refuted(repo, "U1").lines == ["refuted U1: 1"]
    # The warm resume names no worktree; the second reply is a hand-back, then a digest stop.
    _record(repo, tool_name="SendMessage", tool_input={"to": "a1", "message": "Check the fix."})
    maker = partial(dict, session_id=SESSION, cwd=str(repo), tool_use_id="toolu_hb")
    append_handback(maker, REFUTED_REPLY, "daedalus:verifier")
    _agent_stop(repo, "verifier", DIGEST)
    assert train_runner.refuted(repo, "U1").lines == ["refuted U1: 2"]
    records = workspace._audit_records(repo, _state(repo))
    assert workspace.unit_refutations(records, unit) < 2
    second = train_runner.coder_model(repo, "U1")
    assert second.lines == ["opus", "coder U1: opus (second refutation)"]
    freed = {"agent_id": None, "released": True, "retired": ["agent-sonnet"]}
    assert unit_binding._read(unit_binding.bindings_path(repo, train))[name] == freed
    # A cold coder dispatch from the main session runs with a warning and records no dispatch,
    # so the coder's first write binds the still released unit.
    prompt = f"The verifier refuted this unit twice.\nWorktree: {unit}\n"
    tool_input = {"description": "unit", "prompt": prompt, "subagent_type": "daedalus:coder"}
    dispatch = {"tool_name": "Agent", "tool_input": tool_input, "cwd": str(repo)}
    warned = judge({**dispatch, "session_id": SESSION}, Config())
    assert warned.warn and "did not print a dispatch of coder" in str(warned.reason)
    assert unit_binding._read(unit_binding.bindings_path(repo, train))[name] == freed
    _ok(_write(repo, "agent-opus", unit / "u1.txt"))
    _refused(_write(repo, "agent-sonnet", unit / "u1.txt"), "second refutation")
    assert train_runner.coder_model(repo, "U1").lines == second.lines
    bound = {"agent_id": "agent-opus", "retired": ["agent-sonnet"]}
    assert unit_binding._read(unit_binding.bindings_path(repo, train))[name] == bound


def test_refuted_records_each_reply_once_and_refuses_one_not_refuted(
    repo: Path,  # noqa: F811
    plugin: Path,  # noqa: F811
) -> None:
    train, unit = _unit_train(repo, plugin)
    argv = ("refuted", "--repo", str(repo), "--unit", "u1")
    none = _train_cli(repo, *argv)
    assert none.returncode == 1 and "holds no verifier reply" in none.stdout
    assert "Next:" in none.stdout
    _verifier_dispatch(repo, unit)
    seq = _agent_stop(repo, "verifier", REFUTED_REPLY)["seq"]
    for _ in range(2):
        done = _train_cli(repo, *argv)
        assert (done.returncode, done.stdout) == (0, "refuted u1: 1\n"), done.stderr
    assert _unit(repo, f"{train}-u1")["refutations"] == [seq]
    _agent_stop(repo, "verifier", VERIFIED_REPLY)
    refused = _train_cli(repo, *argv)
    assert refused.returncode == 1 and "does not end with [VERDICT: REFUTED]" in refused.stdout
    assert "Next:" in refused.stdout
    assert _unit(repo, f"{train}-u1")["refutations"] == [seq]


def test_a_refuted_verdict_then_an_operator_check_fail_reach_the_escalated_tier(
    repo: Path,  # noqa: F811
    plugin: Path,  # noqa: F811
) -> None:
    train, unit = _unit_train(repo, plugin)
    _verifier_dispatch(repo, unit)
    _agent_stop(repo, "verifier", REFUTED_REPLY)
    assert train_runner.refuted(repo, "U1").lines == ["refuted U1: 1"]
    # The fix pass verifies; the operator then fails its check, which has no verifier reply.
    verified = _agent_stop(repo, "verifier", VERIFIED_REPLY)["seq"]
    argv = ("refuted", "--repo", str(repo), "--unit", "U1", "--operator-check", "Scene loads")
    for _ in range(2):
        done = _train_cli(repo, *argv)
        assert (done.returncode, done.stdout) == (0, "refuted U1: 2\n"), done.stderr
    key = f"operator check after seq {verified}: Scene loads"
    assert _unit(repo, f"{train}-u1")["refutations"][1] == key
    escalated = train_runner.coder_model(repo, "U1")
    assert escalated.lines == ["opus", "coder U1: opus (second refutation)"]


def test_refuted_is_the_orchestrators_train_subcommand() -> None:
    command = f"python3 {REPO_ROOT / 'scripts'}/daedalus_train.py refuted --repo {CWD} --unit U1"
    assert decide(_b("orchestrator", command), CFG).allow
    for agent in ("coder", "auditor", "charter-docs", "releaser"):
        assert not decide(_b(agent, command), CFG).allow, agent
