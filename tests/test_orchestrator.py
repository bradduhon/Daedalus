# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0060: the orchestrator agent starts and resumes agents under its dispatch gate; no one else does.
from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path
from typing import Any

import pytest
from lib import jail, router, train_state, unit_binding
from lib.config import Config
from lib.train_scope import KNOWN_AGENTS
from lib.workspace import create, mark_train

from tests.conftest import CWD, REPO_ROOT
from tests.hook_chain import evaluate, load
from tests.hook_chain import judge as decide
from tests.test_dispatch_binding import TRAIN, seed_plan

ORCHESTRATOR = "daedalus:orchestrator"
AGENT_FILE = REPO_ROOT / "agents" / "orchestrator.md"
CODER_ID = "coder-1"


def _call(tool: str, cwd: str, **tool_input: object) -> dict[str, object]:
    return {
        "agent_type": ORCHESTRATOR,
        "agent_id": "orch-1",
        "session_id": "s",
        "tool_name": tool,
        "tool_input": dict(tool_input),
        "cwd": cwd,
    }


def _start(cwd: str, subagent: str, prompt: str = "x") -> dict[str, object]:
    return _call("Agent", cwd, subagent_type=subagent, prompt=prompt, description="d")


def _resume(cwd: str, to: str, message: object) -> dict[str, object]:
    return _call("SendMessage", cwd, to=to, message=message)


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True)


@pytest.fixture
def units(repo_cwd: Path, project_data: Path) -> tuple[Path, Path]:
    ident = ["-c", "user.name=t", "-c", "user.email=t@example.invalid"]
    _git(repo_cwd, *ident, "commit", "-q", "--allow-empty", "-m", "base")
    _git(repo_cwd, "branch", f"daedalus/{TRAIN}")
    train_state.save(repo_cwd, TRAIN, {"train_id": TRAIN})
    mark_train(repo_cwd, TRAIN)
    first = create(repo_cwd, "u1", f"daedalus/{TRAIN}")
    second = create(repo_cwd, "u2", f"daedalus/{TRAIN}")
    jail._registered_worktrees.cache_clear()
    return first, second


def _bindings(repo: Path) -> dict[str, Any]:
    path = unit_binding.bindings_path(repo, TRAIN)
    return dict(json.loads(path.read_text(encoding="utf-8"))["units"])


def _bound_to_u1(repo: Path, first: Path) -> None:
    # issue 29: the dispatch records u1, and the coder's first write binds it.
    seed_plan(repo, TRAIN)
    d = decide(_start(str(repo), "daedalus:repo-coder", f"Build.\nWorktree: {first}\n"), Config())
    assert d.allow, d.reason
    assert unit_binding.claim(repo, TRAIN, CODER_ID, "u1") is None


@pytest.mark.parametrize("tool", ["Agent", "SendMessage"])
def test_orchestrator_may_start_and_resume_agents(tool: str) -> None:
    payload = (
        _start(CWD, "daedalus:web-researcher") if tool == "Agent" else _resume(CWD, "a1", "go")
    )
    assert router.route(payload, REPO_ROOT) == (True, None, "")


@pytest.mark.parametrize("tool", ["Agent", "SendMessage", "Task"])
def test_every_other_routed_agent_is_refused_agent_and_sendmessage(tool: str) -> None:
    for agent in sorted(KNOWN_AGENTS - {"main", "orchestrator"}):
        payload = {**_start(CWD, "daedalus:web-researcher"), "agent_type": f"daedalus:{agent}"}
        payload["tool_name"] = tool
        allow, reason, hook = router.route(payload, REPO_ROOT)
        assert (allow, reason, hook) == (False, jail.R_TOOL, "tool_bound"), agent
    task = {**_start(CWD, "daedalus:web-researcher"), "tool_name": "Task"}
    assert router.route(task, REPO_ROOT) == (False, jail.R_TOOL, "tool_bound")


@pytest.mark.parametrize(
    "subagent",
    ["general-purpose", "Explore", "repo-coder", "daedalus:mystery", "other:planner", ""],
)
def test_orchestrator_starts_only_catalog_agents(subagent: str) -> None:
    gate = load("dispatch_gate")
    assert evaluate("dispatch_gate", _start(CWD, subagent)) == gate.R_FOREIGN_AGENT


@pytest.mark.parametrize("agent", ["pr-train-conductor", "orchestrator"])
def test_orchestrator_never_starts_the_conductor_or_itself(agent: str) -> None:
    reason = evaluate("dispatch_gate", _start(CWD, f"daedalus:{agent}"))
    assert reason is not None and agent in reason and "Next:" in reason


def test_coder_dispatch_refused_without_a_recorded_plan(
    repo_cwd: Path, units: tuple[Path, Path]
) -> None:
    payload = _start(str(repo_cwd), "daedalus:repo-coder", f"Build.\nWorktree: {units[0]}\n")
    d = decide(payload, Config())
    assert not d.allow and "records no plan" in str(d.reason), d.reason
    assert not unit_binding.bindings_path(repo_cwd, TRAIN).exists()
    seed_plan(repo_cwd, TRAIN)
    assert decide(payload, Config()).allow


@pytest.mark.parametrize("prompt", ["Build the unit.", "Worktree: a\nWorktree: b", "Worktree: rel"])
def test_coder_dispatch_refused_without_a_worktree_line(
    repo_cwd: Path, units: tuple[Path, Path], prompt: str
) -> None:
    seed_plan(repo_cwd, TRAIN)
    d = decide(_start(str(repo_cwd), "daedalus:repo-coder", prompt), Config())
    assert not d.allow and "'Worktree: <absolute path>'" in str(d.reason), d.reason


def test_warm_resume_rebinds_the_unit(repo_cwd: Path, units: tuple[Path, Path]) -> None:
    # 0086, spec 8: the resume moves the coder's binding; the main session never writes it.
    first, second = units
    _bound_to_u1(repo_cwd, first)
    message = f"RESUME. Brief file: b.md\nWorktree: {second}\nGo."
    d = decide(_resume(str(repo_cwd), CODER_ID, message), Config())
    assert d.allow, d.reason
    bound = _bindings(repo_cwd)
    assert bound["u1"] == {"agent_id": None, "retired_to": "u2"}
    assert bound["u2"] == {"agent_id": CODER_ID}
    assert unit_binding.claim(repo_cwd, TRAIN, CODER_ID, "u2") is None
    assert "moved on to unit u2" in str(unit_binding.claim(repo_cwd, TRAIN, CODER_ID, "u1"))
    # 0086: a repeat of the same resume, or the runner's own rebind, finds the coder bound.
    assert decide(_resume(str(repo_cwd), CODER_ID, message), Config()).allow


def test_resume_without_a_worktree_line_binds_nothing(
    repo_cwd: Path, units: tuple[Path, Path]
) -> None:
    _bound_to_u1(repo_cwd, units[0])
    before = _bindings(repo_cwd)
    assert decide(_resume(str(repo_cwd), CODER_ID, "RESUME. Research payload: x"), Config()).allow
    assert _bindings(repo_cwd) == before


def test_resume_with_two_worktree_lines_is_refused(
    repo_cwd: Path, units: tuple[Path, Path]
) -> None:
    first, second = units
    _bound_to_u1(repo_cwd, first)
    message = f"Worktree: {first}\nWorktree: {second}"
    reason = evaluate("dispatch_gate", _resume(str(repo_cwd), CODER_ID, message))
    gate = load("dispatch_gate")
    assert reason == gate.dispatch_binding.R_RESUME_LINE


def test_resume_without_a_target_is_refused(repo_cwd: Path, units: tuple[Path, Path]) -> None:
    _bound_to_u1(repo_cwd, units[0])
    reason = evaluate("dispatch_gate", _resume(str(repo_cwd), "", f"Worktree: {units[1]}"))
    assert reason == load("dispatch_gate").dispatch_binding.R_RESUME_TARGET


def test_resume_of_an_unbound_coder_is_refused(repo_cwd: Path, units: tuple[Path, Path]) -> None:
    _bound_to_u1(repo_cwd, units[0])
    reason = evaluate("dispatch_gate", _resume(str(repo_cwd), "stranger", f"Worktree: {units[1]}"))
    assert reason is not None and "coder stranger holds no unit" in reason and "Next:" in reason
    assert "u2" not in _bindings(repo_cwd)


def test_resume_into_a_dispatched_unit_is_refused(repo_cwd: Path, units: tuple[Path, Path]) -> None:
    first, second = units
    _bound_to_u1(repo_cwd, first)
    other = _start(str(repo_cwd), "daedalus:repo-coder", f"Worktree: {second}")
    assert decide(other, Config()).allow
    reason = evaluate("dispatch_gate", _resume(str(repo_cwd), CODER_ID, f"Worktree: {second}"))
    assert reason is not None and "unit u2 was already dispatched" in reason


def test_resume_naming_a_path_outside_the_train_is_refused(
    repo_cwd: Path, units: tuple[Path, Path], tmp_path: Path
) -> None:
    _bound_to_u1(repo_cwd, units[0])
    message = {"text": f"Worktree: {tmp_path}"}
    reason = evaluate("dispatch_gate", _resume(str(repo_cwd), CODER_ID, message))
    assert reason is not None and "is not a unit worktree of train" in reason


@pytest.mark.parametrize("key", ["content", "summary", "body"])
def test_resume_gate_reads_every_field_but_the_target(
    repo_cwd: Path, units: tuple[Path, Path], key: str
) -> None:
    # 0086: the message key is ASSUMED, so a Worktree: line under any other key still rebinds.
    first, second = units
    _bound_to_u1(repo_cwd, first)
    payload = _call("SendMessage", str(repo_cwd), to=CODER_ID, **{key: f"Worktree: {second}"})
    assert decide(payload, Config()).allow
    assert _bindings(repo_cwd)["u2"] == {"agent_id": CODER_ID}


def test_resume_target_field_is_not_scanned(repo_cwd: Path, units: tuple[Path, Path]) -> None:
    _bound_to_u1(repo_cwd, units[0])
    payload = _call("SendMessage", str(repo_cwd), to=f"Worktree: {units[1]}", message="go")
    assert decide(payload, Config()).allow
    assert "u2" not in _bindings(repo_cwd)


def test_orchestrator_writes_only_its_scratch_folder_and_summary(
    repo_cwd: Path, units: tuple[Path, Path]
) -> None:
    # 0060: the summary and the train folder pass; the rest of docs/ and the ledger do not.
    scratch = repo_cwd / "docs" / ".tmp" / "daedalus"
    allowed = [scratch / TRAIN / "briefs" / "u1.md", scratch / f"{TRAIN}-summary.md"]
    refused = [
        repo_cwd / "docs" / "howto" / "README.md",
        repo_cwd / "docs" / "private" / "specs" / "x.md",
        repo_cwd / "docs" / "decisions.md",
        scratch / "20261015-090000-summary.md",
        scratch / "20261015-090000" / "plan.md",
        repo_cwd / "src" / "a.py",
    ]
    for path in allowed:
        payload = _call("Write", str(repo_cwd), file_path=str(path), content="x")
        assert decide(payload, Config()).allow, path
    for path in refused:
        payload = _call("Write", str(repo_cwd), file_path=str(path), content="x")
        d = decide(payload, Config())
        assert not d.allow and "Next:" in str(d.reason), path


def test_orchestrator_without_the_dispatch_gate_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # 0060: an agent file that drops its dispatch gate loses Agent and SendMessage.
    agents = tmp_path / "agents"
    agents.mkdir()
    text = AGENT_FILE.read_text(encoding="utf-8")
    gate = next(ln for ln in text.splitlines() if "dispatch_gate.py" in ln)
    (agents / "orchestrator.md").write_text(text.replace(gate + "\n", ""), encoding="utf-8")
    module = load("tool_bound")
    monkeypatch.setattr(module, "PLUGIN_ROOT", tmp_path)
    for payload in (_start(CWD, "daedalus:planner"), _resume(CWD, "a1", "go")):
        assert evaluate("tool_bound", payload) == module.R_NO_DISPATCH_GATE
    assert evaluate("tool_bound", _call("Read", CWD, file_path=f"{CWD}/a")) is None


_RECIPE_CMD = re.compile(r"`(python3 <plugin root>/scripts/[^`]+)`")
INSPECT = [
    "git merge-base --is-ancestor abc123 daedalus-unit/t-u1",
    f"git -C {CWD} rev-parse daedalus/t",
    "git -C /work/Charter status --porcelain",
    f"sha256sum {CWD}/contracts/c.md {CWD}/docs/.tmp/daedalus/t/standards-packet.md",
    "find /work/rules -type f -newermt '2026-10-19 12:00'",
    f"cat {CWD}/.claude/daedalus/config.json",
    "git diff abc123...daedalus/t --stat",
]


def _recipe_commands() -> list[str]:
    text = AGENT_FILE.read_text(encoding="utf-8").split("\n---\n", 1)[1]
    # The rules line names the template `python3 <plugin root>/scripts/<script>` itself.
    found = [
        m.replace("<plugin root>", str(REPO_ROOT))
        for m in _RECIPE_CMD.findall(text)
        if "/scripts/<script>" not in m
    ]
    return [re.sub(r"<[^>]+>", "x", m.replace("<repo>", CWD)) for m in found]


def test_recipe_names_every_train_script_it_may_run() -> None:
    commands = _recipe_commands()
    names = {cmd.split()[1].rsplit("/", 1)[1] for cmd in commands}
    allowlist = load("command_allowlist")
    # refresh_frameworks.py is the operator's own-shell Next line, never the orchestrator's call.
    assert names - {"refresh_frameworks.py"} == set(allowlist.TRAIN_SCRIPTS)


@pytest.mark.usefixtures("jail_fakes")
def test_recipe_commands_pass_the_orchestrator_hooks() -> None:
    # 0060: every plugin script command and read the recipe runs passes the orchestrator's chain.
    commands = [c for c in _recipe_commands() if "refresh_frameworks.py" not in c]
    assert len(commands) >= 10
    for command in [*commands, *INSPECT]:
        payload = _call("Bash", CWD, command=command)
        assert router.route(payload, REPO_ROOT) == (True, None, ""), command
