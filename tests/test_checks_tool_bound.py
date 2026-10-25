# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0044: the tool_bound hook; cases copied from tests/test_jail.py run each agent's chain.
from __future__ import annotations

import pytest
from lib import hook_io, jail
from lib.jail import KNOWN_AGENTS

from tests.conftest import CFG, CWD
from tests.hook_chain import (
    decide,
    evaluate,
    internal_error_denies,
    load,
    malformed_input_denies,
    outside_tools_allow,
    payload,
    run_script,
    unknown_flag_denies,
)
from tests.payloads import _b, _t, _w

pytestmark = pytest.mark.usefixtures("jail_fakes")
HOOK = "tool_bound"


def test_every_block_reason_has_next() -> None:
    cases = [
        _w("security-auditor", f"{CWD}/src/a.py"),
        _b("web-researcher", "ls"),
        _w("repo-coder", f"{CWD}/infra/a.tf"),
        _b("repo-coder", "git push origin x"),
    ]
    for hook_input in cases:
        d = decide(hook_input, CFG)
        assert not d.allow and "Next:" in d.reason


def test_workers_cannot_spawn_agents() -> None:
    assert not decide(_t("repo-coder", "Agent"), CFG).allow


def test_workers_cannot_send_messages() -> None:
    assert not decide(_t("repo-coder", "SendMessage"), CFG).allow


class TestReadOnlyAgents:
    @pytest.mark.parametrize("agent", ["security-auditor", "nist-specialist", "cis-specialist"])
    def test_no_writes(self, agent: str) -> None:
        for tool in ("Write", "Edit", "MultiEdit", "NotebookEdit"):
            assert not decide(_w(agent, f"{CWD}/docs/x.md", tool), CFG).allow


class TestConductor:
    def test_no_writes(self) -> None:
        assert not decide(_w("pr-train-conductor", f"{CWD}/docs/x.md"), CFG).allow


class TestNoShellAgents:
    @pytest.mark.parametrize("agent", ["web-researcher", "standards-rules-specialist"])
    def test_blocks_bash_and_writes(self, agent: str) -> None:
        assert not decide(_b(agent, "ls"), CFG).allow
        assert not decide(_w(agent, f"{CWD}/docs/x.md"), CFG).allow


class TestRegressionToolsAndCwd:
    @pytest.mark.parametrize("tool", ["Task", "Agent", "mcp__claude_ai_Gmail__create_draft"])
    def test_workers_blocked_from_meta_tools(self, tool: str) -> None:
        # 0060: the orchestrator's Agent call passes tool_bound and meets its dispatch gate.
        for agent in sorted(KNOWN_AGENTS - {"main"}):
            d = decide(_t(agent, tool), CFG)
            if agent == "orchestrator" and tool == "Agent":
                assert not d.allow and evaluate(HOOK, _t(agent, tool)) is None
                continue
            assert (
                not d.allow
                and d.reason
                == "workers use only their allowlisted tools. Next: ask the orchestrating session."
            )


@pytest.mark.parametrize("tool", ["Agent", "SendMessage"])
def test_only_the_orchestrator_may_start_and_resume_agents(tool: str) -> None:
    # 0060: Agent and SendMessage pass tool_bound for the orchestrator alone.
    for agent in sorted(KNOWN_AGENTS - {"main"}):
        want = None if agent == "orchestrator" else jail.R_TOOL
        assert evaluate(HOOK, _t(f"daedalus:{agent}", tool)) == want, agent
    assert evaluate(HOOK, _t("orchestrator", "Task")) == jail.R_TOOL


def test_tool_bound_judges_the_hook_alone() -> None:
    assert evaluate(HOOK, _t("verifier", "Write")) == jail.R_TOOL
    assert evaluate(HOOK, _t("nist-specialist", "Glob")) == jail.R_TOOL
    assert evaluate(HOOK, _t("web-researcher", "WebFetch")) is None
    assert evaluate(HOOK, _t("daedalus:repo-coder", "Edit")) is None


@pytest.mark.parametrize("agent", ["main", "mystery", "../agents/repo-coder", "Repo-Coder", ""])
def test_tool_bound_denies_an_agent_without_a_file(agent: str) -> None:
    reason = evaluate(HOOK, {**_t("repo-coder", "Read"), "agent_type": agent})
    assert reason is not None and "is missing" in reason and "Next:" in reason, reason


def test_tool_bound_fixture_decisions() -> None:
    allow = {"decision": "allow", "reason": ""}
    deny = {"decision": "deny", "reason": jail.R_TOOL}
    assert run_script(HOOK, payload("Edit")) == allow
    assert run_script(HOOK, payload("WebFetch")) == deny
    assert run_script(HOOK, payload("Write", agent="verifier")) == deny


def test_tool_bound_allows_tools_outside_its_tools() -> None:
    # 0044: tool_bound judges every tool, so only the agent's own listed tools pass.
    assert load(HOOK).TOOLS == hook_io.EVERY_TOOL
    outside_tools_allow(HOOK, "Read")


def test_tool_bound_unknown_flag_denies() -> None:
    unknown_flag_denies(HOOK, payload("Read"))


def test_tool_bound_malformed_input_denies() -> None:
    malformed_input_denies(HOOK)


def test_tool_bound_internal_error_denies_and_names_the_hook() -> None:
    internal_error_denies(HOOK, payload("Read"))
