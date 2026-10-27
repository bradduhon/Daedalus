# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0044: the network_tools hook; cases copied from tests/test_jail.py run each agent's chain.
from __future__ import annotations

from pathlib import Path

import pytest
from lib import jail, shell

from tests.conftest import CFG
from tests.hook_chain import (
    decide,
    evaluate,
    internal_error_denies,
    payload,
    run_script,
)
from tests.payloads import _b, _t

pytestmark = pytest.mark.usefixtures("jail_fakes")
HOOK = "network_tools"


class TestRepoCoder:
    @pytest.mark.parametrize(
        "command",
        [
            "git push origin x",
            "git remote add o u",
            "git fetch",
            "git pull",
            "curl https://x",
            "wget x",
            "ssh host",
            "scp a b",
            "nc -l 1",
            "aws s3 ls",
            "gh pr list",
            "npm test && curl x",
        ],
    )
    def test_remote_and_network_blocked(self, command: str) -> None:
        assert not decide(_b("repo-coder", command), CFG).allow

    def test_no_web_tools(self) -> None:
        assert not decide(_t("repo-coder", "WebFetch"), CFG).allow
        assert not decide(_t("repo-coder", "WebSearch"), CFG).allow


class TestNoShellAgents:
    def test_only_researcher_may_fetch(self) -> None:
        assert decide(_t("web-researcher", "WebFetch"), CFG).allow
        assert decide(_t("web-researcher", "WebSearch"), CFG).allow
        assert not decide(_t("standards-rules-specialist", "WebFetch"), CFG).allow
        assert not decide(_t("framework-specialist", "WebFetch"), CFG).allow


class TestRound3WorkerHygiene:
    def test_repo_coder_hidden_network_and_remote(self) -> None:
        for command in ("find . -exec curl x {} +", "find . -exec git push origin x {} +"):
            assert not decide(_b("repo-coder", command), CFG).allow, command


@pytest.mark.parametrize("agent", ["repo-coder", "security-auditor", "charter-docs"])
def test_claude_by_real_path_is_refused(fake_claude: Path, tmp_path: Path, agent: str) -> None:
    # issue 55: the versioned file, a link to it, or node running it, whatever the word says.
    link = tmp_path.resolve() / "c"
    link.symlink_to(fake_claude)
    for command in (
        f"{fake_claude} -p hi",
        f"{link} -p hi",
        f"cd {tmp_path.resolve()} && ./c -p hi",
        f"timeout 5 {link}",
        f"node {link}",
    ):
        assert evaluate(HOOK, _b(agent, command)) == shell.R_CLAUDE_PATH, (agent, command)


def test_other_paths_beside_claude_pass(fake_claude: Path, tmp_path: Path) -> None:
    other = fake_claude.parent / "tool"
    other.write_text("#!/bin/sh\n")
    for command in (f"{other} -x", f"cat {fake_claude.parent}/notes", "ls /usr/bin"):
        assert evaluate(HOOK, _b("repo-coder", command)) is None, command


def test_network_tools_judges_the_hook_alone() -> None:
    assert evaluate(HOOK, _t("repo-coder", "WebFetch")) == jail.R_WEB_RESEARCHER_ONLY
    assert evaluate(HOOK, _t("repo-coder", "WebFetch"), "--web") is None
    assert evaluate(HOOK, _t("repo-coder", "WebSearch"), "--gh") == jail.R_CONDUCTOR_WEB
    assert evaluate(HOOK, _b("repo-coder", "curl x")) == jail.R_NETWORK
    assert evaluate(HOOK, _b("repo-coder", "gh pr list")) == jail.R_NETWORK
    assert evaluate(HOOK, _b("repo-coder", "gh pr list"), "--gh") is None
    assert evaluate(HOOK, _b("repo-coder", "curl x"), "--gh") == jail.R_NETWORK
    # spec 8: rg, grep and jq arguments and commit messages are exempt words.
    assert evaluate(HOOK, _b("repo-coder", "rg curl src")) is None
    assert evaluate(HOOK, _b("repo-coder", "git commit -m 'fix curl'")) is None


def test_network_tools_fixture_decisions() -> None:
    web = payload("WebFetch", url="https://example.com")
    assert run_script(HOOK, web) == {"decision": "deny", "reason": jail.R_WEB_RESEARCHER_ONLY}
    assert run_script(HOOK, web, "--web") == {"decision": "allow", "reason": ""}
    curl = payload("Bash", command="curl https://x")
    assert run_script(HOOK, curl) == {"decision": "deny", "reason": jail.R_NETWORK}


def test_network_tools_internal_error_denies_and_names_the_hook() -> None:
    internal_error_denies(HOOK, payload("Bash", command="ls"))
