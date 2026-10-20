# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0044: the router runs each Daedalus agent's listed hooks in-process, first deny wins.
from __future__ import annotations

import os
import subprocess
from collections.abc import Callable
from pathlib import Path
from typing import Any

import enforce_agent_jail
import pytest
from lib import audit, dispatch_binding, jail, router

from tests.conftest import CFG, CWD, REPO_ROOT, WT, write_train_marker

NEXT = "Next: add the agent file with its shape and hooks block, or start a catalog agent."
COMMAND = (
    '        - {{type: command, command: "python3 ${{CLAUDE_PLUGIN_ROOT}}/scripts/checks/{}"}}'
)
REAL_AGENTS = sorted(p.stem for p in (REPO_ROOT / "agents").glob("*.md"))


@pytest.fixture(autouse=True)
def _fresh_modules(monkeypatch: pytest.MonkeyPatch) -> None:
    # 0044: modules are cached per process by stem; each case starts with an empty cache.
    monkeypatch.setattr(router, "_MODULES", {})


def _agent(root: Path, name: str, hooks: list[str] | None, raw: list[str] | None = None) -> None:
    lines = ["---", f"name: {name}", "description: probe agent", "tools: Read, Bash"]
    lines += ["model: haiku", "shape: finder"]
    if hooks is not None:
        lines += ["hooks:", "  PreToolUse:", "    - hooks:"]
        lines += [
            COMMAND.format(h.replace(" ", ".py ", 1) if " " in h else f"{h}.py") for h in hooks
        ]
    lines += raw or []
    lines += ["---", "probe body", ""]
    (root / "agents").mkdir(parents=True, exist_ok=True)
    (root / "agents" / f"{name}.md").write_text("\n".join(lines), encoding="utf-8")


def _script(root: Path, stem: str, body: str) -> None:
    checks = root / "scripts" / "checks"
    checks.mkdir(parents=True, exist_ok=True)
    (checks / f"{stem}.py").write_text(body, encoding="utf-8")


def _tracing(stem: str, allow: bool = True, reason: str | None = None) -> str:
    return (
        "from lib import hook_io\n\n\n"
        "def decide(hook_input, flags):\n"
        f"    hook_input.setdefault('trace', []).append(({stem!r}, tuple(flags)))\n"
        f"    return hook_io.HookDecision({allow!r}, {reason!r})\n"
    )


def _input(agent: str, tool: str = "Bash", **fields: str) -> dict[str, object]:
    tool_input: dict[str, object] = dict(fields) or {"command": "ls"}
    return {"agent_type": agent, "tool_name": tool, "tool_input": tool_input, "cwd": CWD}


def test_router_runs_listed_hooks_in_order(tmp_path: Path) -> None:
    hooks = ["network_tools --web", "credential_paths", "tool_bound"]
    _agent(tmp_path, "probe", hooks)
    for stem in ("network_tools", "credential_paths", "tool_bound"):
        _script(tmp_path, stem, _tracing(stem))
    hook_input = _input("probe")
    assert router.route(hook_input, tmp_path) == (True, None, "")
    want = [("network_tools", ("--web",)), ("credential_paths", ()), ("tool_bound", ())]
    assert hook_input["trace"] == want
    # 0044: a second call reuses the imported modules.
    assert set(router._MODULES) == {"network_tools", "credential_paths", "tool_bound"}
    assert router.route(_input("probe"), tmp_path) == (True, None, "")


def test_first_deny_wins_and_names_the_hook(tmp_path: Path) -> None:
    _agent(tmp_path, "probe", ["credential_paths", "tool_bound", "network_tools"])
    _script(tmp_path, "credential_paths", _tracing("credential_paths"))
    _script(tmp_path, "tool_bound", _tracing("tool_bound", False, "refused here. Next: stop."))
    _script(tmp_path, "network_tools", _tracing("network_tools", False, "never reached"))
    hook_input = _input("probe")
    got = router.route(hook_input, tmp_path)
    assert got == (False, "refused here. Next: stop.", "tool_bound")
    assert [stem for stem, _ in hook_input["trace"]] == ["credential_paths", "tool_bound"]


@pytest.mark.parametrize(
    ("body", "cause"),
    [
        ("raise RuntimeError('boom')\n", "RuntimeError: boom"),
        ("import sys\nsys.exit(0)\n", "SystemExit: 0"),
        ("def decide(\n", "SyntaxError"),
        (None, "FileNotFoundError"),
    ],
)
def test_hook_import_failure_denies(tmp_path: Path, body: str | None, cause: str) -> None:
    _agent(tmp_path, "probe", ["credential_paths"])
    if body is not None:
        _script(tmp_path, "credential_paths", body)
    allow, reason, hook = router.route(_input("probe"), tmp_path)
    assert (allow, hook) == (False, "credential_paths")
    assert str(reason).startswith("hook credential_paths failed closed ("), reason
    assert cause in str(reason)
    assert "credential_paths" not in router._MODULES


@pytest.mark.parametrize("body", ["X = 1\n", "decide = 3\n"])
def test_hook_without_decide_denies(tmp_path: Path, body: str) -> None:
    _agent(tmp_path, "probe", ["tool_bound"])
    _script(tmp_path, "tool_bound", body)
    want = (False, "hook tool_bound failed closed (no decide function)", "tool_bound")
    assert router.route(_input("probe"), tmp_path) == want


@pytest.mark.parametrize(
    ("raised", "cause"),
    [("ValueError('bad input')", "ValueError: bad input"), ("SystemExit(0)", "SystemExit: 0")],
)
def test_hook_decide_raising_denies(tmp_path: Path, raised: str, cause: str) -> None:
    _agent(tmp_path, "probe", ["tool_bound"])
    _script(tmp_path, "tool_bound", f"def decide(hook_input, flags):\n    raise {raised}\n")
    want = (False, f"hook tool_bound failed closed ({cause})", "tool_bound")
    assert router.route(_input("probe"), tmp_path) == want


@pytest.mark.parametrize(
    ("value", "kind"), [("None", "NoneType"), ("(True, None)", "tuple"), ("'allow'", "str")]
)
def test_hook_returning_no_decision_denies(tmp_path: Path, value: str, kind: str) -> None:
    _agent(tmp_path, "probe", ["tool_bound"])
    _script(tmp_path, "tool_bound", f"def decide(hook_input, flags):\n    return {value}\n")
    want = (False, f"hook tool_bound failed closed (decide returned {kind})", "tool_bound")
    assert router.route(_input("probe"), tmp_path) == want


def test_router_starts_no_process(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, jail_fakes: None
) -> None:
    started: list[str] = []

    def refuse(name: str) -> Callable[..., Any]:
        def boom(*args: Any, **kwargs: Any) -> Any:
            started.append(name)
            raise AssertionError(f"the router started a process through {name}")

        return boom

    for name in ("Popen", "run", "call", "check_call", "check_output", "getoutput"):
        monkeypatch.setattr(subprocess, name, refuse(f"subprocess.{name}"))
    for name in dir(os):
        if name.startswith(("exec", "spawn", "posix_spawn")) or name in {"system", "fork", "popen"}:
            monkeypatch.setattr(os, name, refuse(f"os.{name}"))
    _agent(tmp_path, "probe", ["credential_paths", "tool_bound"])
    _script(tmp_path, "credential_paths", _tracing("credential_paths"))
    _script(tmp_path, "tool_bound", _tracing("tool_bound", False, "stop. Next: x."))
    assert router.route(_input("probe"), tmp_path) == (False, "stop. Next: x.", "tool_bound")
    router._MODULES.clear()
    for name in REAL_AGENTS:
        read = _input(name, "Read", file_path=f"{CWD}/README.md")
        assert router.route(read, REPO_ROOT) == (True, None, ""), name
    assert started == []


@pytest.mark.parametrize("name", ["ghost", "../agents/repo-coder", "Repo-Coder", "a:b"])
def test_agent_without_a_file_is_refused_with_no_binding(tmp_path: Path, name: str) -> None:
    _agent(tmp_path, "probe", ["tool_bound"])
    want = f"no binding exists for agent '{name}': agents/{name}.md is missing (0044). {NEXT}"
    assert router.route(_input(name), tmp_path) == (False, want, "router")
    assert router.route(_input(name), REPO_ROOT) == (False, want, "router")


def test_agent_without_a_hooks_block_is_refused_with_no_binding(tmp_path: Path) -> None:
    _agent(tmp_path, "probe", None)
    want = f"no binding exists for agent 'probe': agents/probe.md has no hooks block (0044). {NEXT}"
    assert router.route(_input("probe"), tmp_path) == (False, want, "router")


@pytest.mark.parametrize(
    "command",
    [
        "python3 /tmp/evil.py",
        "python3 ${CLAUDE_PLUGIN_ROOT}/scripts/checks/../../evil.py",
        "bash ${CLAUDE_PLUGIN_ROOT}/scripts/checks/tool_bound.py",
        "python3 ${CLAUDE_PLUGIN_ROOT}/scripts/checks/not_shipped.py",
    ],
)
def test_command_outside_the_checks_form_is_refused(tmp_path: Path, command: str) -> None:
    raw = ["hooks:", "  PreToolUse:", "    - hooks:"]
    raw += [f'        - {{type: command, command: "{command}"}}']
    _agent(tmp_path, "probe", None, raw)
    _script(tmp_path, "tool_bound", _tracing("tool_bound"))
    allow, reason, hook = router.route(_input("probe"), tmp_path)
    assert (allow, hook) == (False, "router")
    assert str(reason).startswith(str(tmp_path / "agents" / "probe.md")), reason
    assert "Next: use only the hooks block form of spec 5.4" in str(reason)
    assert router._MODULES == {}


def test_main_session_duties_unchanged(monkeypatch: pytest.MonkeyPatch, jail_fakes: None) -> None:
    # 0044: the main session stays with lib.jail: tripwires, the code-write refusal, dispatch.
    for agent in ("main", ""):
        want = (False, "the main session is not routed (0044).", "router")
        assert router.route(_input(agent), REPO_ROOT) == want
    main = {"tool_name": "Bash", "tool_input": {"command": "git status"}, "cwd": CWD}
    assert jail.decide(main, CFG).allow
    push = {**main, "tool_input": {"command": "git push --force origin main"}}
    assert not jail.decide(push, CFG).allow
    write = {"tool_name": "Write", "tool_input": {"file_path": f"{WT}/src/a.py"}, "cwd": CWD}
    # 0105: the code write asks the operator rather than refusing.
    asked = jail.decide(write, CFG)
    assert asked.ask and "Build Train" in str(asked.reason)
    seen: list[dict[str, object]] = []

    def dispatch(tool_input: dict[str, object], cwd: str) -> str:
        seen.append(tool_input)
        return "dispatch refused. Next: name one unit."

    monkeypatch.setattr(dispatch_binding, "_dispatch_reason", dispatch)
    agent_call = {"tool_name": "Agent", "tool_input": {"prompt": "x"}, "cwd": CWD}
    d = jail.decide(agent_call, CFG)
    # 0106: the operator's dispatch is asked with the skipped invariant, never blocked.
    want = jail.ASK_DISPATCH.format(reason="dispatch refused. Next: name one unit.")
    assert (d.allow, d.ask, d.reason) == (False, True, want)
    assert seen == [{"prompt": "x"}]


def test_unknown_agent_refused_only_in_a_train(
    run_script: Any, hook_input: Any, repo_cwd: Path
) -> None:
    # 0023, 0035: a foreign agent is not routed; lib.jail refuses it only while a train runs.
    payload = hook_input(agent_type="ghost", tool_input={"command": "touch x"})
    assert run_script("enforce_agent_jail.py", payload).returncode == 0
    write_train_marker(repo_cwd)
    result = run_script("enforce_agent_jail.py", payload)
    # 0100: a foreign agent reads during a train; a write is what blocks.
    assert result.returncode == 2 and "read-only while" in result.stderr
    assert "no binding exists" not in result.stderr


def test_daedalus_agent_routed_outside_a_train(run_script: Any, hook_input: Any) -> None:
    # 0023: a Daedalus agent meets its hooks with or without a train.
    payload = hook_input(agent_type="daedalus:repo-coder", tool_input={"command": "git push o x"})
    result = run_script("enforce_agent_jail.py", payload)
    assert result.returncode == 2
    assert result.stderr.startswith("daedalus-jail[repo-coder]: git_push: no remote git")
    ghost = hook_input(agent_type="daedalus:mystery", tool_input={"command": "ls"})
    result = run_script("enforce_agent_jail.py", ghost)
    want = "daedalus-jail[mystery]: router: no binding exists for agent 'mystery'"
    assert result.returncode == 2 and result.stderr.startswith(want)


# 0044: one fixture input per agent file and the hook its chain names as the first deny.
DENIALS = {
    "repo-coder": (_input("repo-coder", command="git push origin x"), "git_push"),
    "contract-spec": (_input("contract-spec", "Write", file_path=f"{CWD}/src/a.py"), "root_writes"),
    "charter-docs": (_input("charter-docs", command="ls"), "command_allowlist"),
    "security-auditor": (
        _input("security-auditor", "Write", file_path=f"{CWD}/docs/x.md"),
        "tool_bound",
    ),
    "nist-specialist": (_input("nist-specialist", command="curl x"), "network_tools"),
    "cis-specialist": (_input("cis-specialist", command="git checkout x"), "read_only_bash"),
    "web-researcher": (_input("web-researcher", command="ls"), "tool_bound"),
    "planner": (_input("planner", command="ls"), "tool_bound"),
    "standards-rules-specialist": (
        _input("standards-rules-specialist", "WebFetch", url="https://x"),
        "tool_bound",
    ),
    "pr-train-conductor": (
        _input("daedalus:pr-train-conductor", command="gh pr merge 3"),
        "gh_classes",
    ),
    "orchestrator": (
        _input("daedalus:orchestrator", "Agent", subagent_type="general-purpose", prompt="x"),
        "dispatch_gate",
    ),
}


def test_denials_cover_every_agent_file() -> None:
    assert set(DENIALS) == set(REAL_AGENTS)


@pytest.mark.parametrize("agent", sorted(DENIALS))
def test_audit_reason_names_the_denying_hook(
    agent: str,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    jail_fakes: None,
) -> None:
    payload, hook = DENIALS[agent]
    records: list[tuple[str, str | None]] = []

    def record(hook_input: dict[str, object], decision: str, reason: str | None) -> None:
        records.append((decision, reason))

    monkeypatch.setattr(audit, "audit_append", record)
    raw = str(payload["agent_type"])
    assert enforce_agent_jail._judge(dict(payload), raw) == 2
    [(decision, reason)] = records
    assert decision == "block" and str(reason).startswith(f"{hook}: "), reason
    assert capsys.readouterr().err.startswith(f"daedalus-jail[{agent}]: {hook}: ")
    allow, bare, named = router.route(dict(payload), REPO_ROOT)
    assert (allow, named) == (False, hook) and reason == f"{hook}: {bare}"


def test_allowed_call_audits_no_reason(monkeypatch: pytest.MonkeyPatch, jail_fakes: None) -> None:
    records: list[tuple[str, str | None]] = []

    def record(hook_input: dict[str, object], decision: str, reason: str | None) -> None:
        records.append((decision, reason))

    monkeypatch.setattr(audit, "audit_append", record)
    payload = _input("repo-coder", "Write", file_path=f"{WT}/src/a.py")
    assert enforce_agent_jail._judge(payload, "repo-coder") == 0
    assert records == [("allow", None)]
