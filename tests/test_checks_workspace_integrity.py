# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0044: the workspace_integrity hook; cases copied from tests/test_jail.py run each agent's chain.
from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest
from lib import jail

from tests.conftest import CFG, CWD
from tests.hook_chain import (
    decide,
    evaluate,
    internal_error_denies,
    malformed_input_denies,
    outside_tools_allow,
    payload,
    run_script,
    unknown_flag_denies,
)
from tests.test_jail import DATA, _b, _w

pytestmark = pytest.mark.usefixtures("jail_fakes")
HOOK = "workspace_integrity"


class TestRegressionToolsAndCwd:
    @pytest.mark.parametrize("cwd", ["", "relative/repo"])
    def test_missing_cwd_fails_closed(self, cwd: str) -> None:
        for agent in ("repo-coder",):
            for hook_input in (_b(agent, "git status"), _w(agent, f"{CWD}/src/a.py")):
                hook_input["cwd"] = cwd
                d = decide(hook_input, CFG)
                assert not d.allow and "no absolute cwd" in d.reason, (agent, cwd)


class TestRound3DotGitWrites:
    @pytest.mark.parametrize(
        ("agent", "path"),
        [
            ("repo-coder", f"{CWD}/src/../.git/config"),
            ("repo-coder", f"{CWD}/src/.git/config"),
            ("charter-docs", "/work/Charter/.git/config"),
            ("contract-spec", f"{CWD}/contracts/.git/x"),
        ],
    )
    def test_blocked(self, agent: str | None, path: str) -> None:
        d = decide(_w(agent, path), CFG)
        assert not d.allow and ".git/" in d.reason


class TestFinalDataDir:
    @pytest.fixture(autouse=True)
    def _env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("CLAUDE_PLUGIN_DATA", DATA)

    @pytest.mark.parametrize("agent", ["repo-coder", "charter-docs", "contract-spec"])
    @pytest.mark.parametrize("tool", ["Write", "Edit", "MultiEdit"])
    def test_tool_writes_block_for_every_agent(self, agent: str | None, tool: str) -> None:
        d = decide(_w(agent, f"{DATA}/config.json", tool), CFG)
        assert not d.allow and "written by hooks only" in d.reason, (agent, tool)


class TestProjectDataDir:
    # 0010: <repo>/.claude/daedalus is written by hooks only and never committed.
    P = f"{CWD}/.claude/daedalus"

    @pytest.mark.parametrize("agent", ["repo-coder", "charter-docs", "contract-spec"])
    @pytest.mark.parametrize("tool", ["Write", "Edit", "MultiEdit"])
    def test_tool_writes_block_for_every_agent(self, agent: str | None, tool: str) -> None:
        d = decide(_w(agent, f"{self.P}/config.json", tool), CFG)
        assert not d.allow and "<repo>/.claude/daedalus/config.json" in str(d.reason)

    def test_worktree_cwd_protects_main_repo_data_dir(self, repo_cwd: Path, tmp_path: Path) -> None:
        git = ["git", "-C", str(repo_cwd), "-c", "user.name=t", "-c", "user.email=t@x.invalid"]
        subprocess.run([*git, "commit", "-q", "--allow-empty", "-m", "i"], check=True)
        wt = tmp_path.resolve() / "wt"
        subprocess.run([*git, "worktree", "add", "-q", str(wt)], check=True)
        hook_input = {
            "tool_name": "Write",
            "tool_input": {"file_path": f"{repo_cwd}/.claude/daedalus/config.json"},
            "cwd": str(wt),
            "agent_type": "repo-coder",
        }
        assert not decide(hook_input, CFG).allow


def test_workspace_integrity_judges_the_hook_alone() -> None:
    assert evaluate(HOOK, _w("repo-coder", f"{CWD}/.git/config")) == jail.R_DOTGIT
    assert evaluate(HOOK, _w("repo-coder", f"{CWD}/.claude/daedalus/x")) == jail.R_DATA_DIR
    assert evaluate(HOOK, {**_b("repo-coder", "ls"), "cwd": "rel"}) == jail.R_NO_CWD
    assert evaluate(HOOK, _w("repo-coder", f"{CWD}/.gitignore")) is None
    # issue 75: a Bash write into the data folder is refused here too.
    assert evaluate(HOOK, _b("repo-coder", "touch .claude/daedalus/x")) == jail.R_DATA_DIR
    assert evaluate(HOOK, _b("repo-coder", "ls .claude/daedalus")) is None


@pytest.mark.parametrize("agent", ["repo-coder", "security-auditor", "orchestrator"])
@pytest.mark.parametrize(
    "command",
    [
        "mkfifo {data}/train_state.lock",
        "mkfifo -m 600 {data}/audit/s.jsonl.lock",
        "mknod {data}/bindings.lock p",
        "shred -u {data}/audit/s.jsonl",
        "cd {repo} && mkfifo .claude/daedalus/x.lock",
        "echo x > {data}/x",
    ],
)
def test_bash_plants_in_the_data_folder_are_refused(agent: str, command: str) -> None:
    # issue 75: a FIFO planted at a lock path hangs the next hook that opens it.
    filled = command.format(data=f"{CWD}/.claude/daedalus", repo=CWD)
    assert evaluate(HOOK, _b(agent, filled)) == jail.R_DATA_DIR
    assert not decide(_b(agent, filled), CFG).allow


def test_workspace_integrity_fixture_decisions() -> None:
    allow = {"decision": "allow", "reason": ""}
    dotgit = payload("Write", file_path=f"{CWD}/.git/hooks/pre-commit")
    assert run_script(HOOK, dotgit) == {"decision": "deny", "reason": jail.R_DOTGIT}
    nocwd = json.dumps({"tool_name": "Bash", "tool_input": {"command": "ls"}, "cwd": ""})
    assert run_script(HOOK, nocwd) == {"decision": "deny", "reason": jail.R_NO_CWD}
    assert run_script(HOOK, payload("Write", file_path=f"{CWD}/src/a.py")) == allow


def test_workspace_integrity_allows_tools_outside_its_tools() -> None:
    outside_tools_allow(HOOK, "Read")


def test_workspace_integrity_unknown_flag_denies() -> None:
    unknown_flag_denies(HOOK, payload("Write", file_path=f"{CWD}/src/a.py"))


def test_workspace_integrity_malformed_input_denies() -> None:
    malformed_input_denies(HOOK)


def test_workspace_integrity_internal_error_denies_and_names_the_hook() -> None:
    internal_error_denies(HOOK, payload("Write", file_path=f"{CWD}/src/a.py"))
