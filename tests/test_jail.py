# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from typing import Any

import pytest
from lib import jail
from lib.config import Config, LedgerDecl
from lib.jail import CONDUCTOR_GIT, KNOWN_AGENTS, decide, split_pipeline, tokenize

from tests.conftest import REPO_ROOT

CWD = "/work/repo"
CFG = Config(
    charter_root=Path("/work/Charter"),
    ledger=LedgerDecl(
        Path("/work/Charter/decision-log.md"), "markdown-table-row", "{seq:04d}", "last-row-id"
    ),
)


WT = f"{CWD}/.claude/worktrees/20261015-120000-u1"
FAKE_UNITS = frozenset({f"{CWD}/.claude/worktrees/u1", WT})


@pytest.fixture(autouse=True)
def _fake_unit_worktrees(monkeypatch: pytest.MonkeyPatch) -> None:
    # 0022: CWD is not a real repo; register its fake unit worktrees, real repos query git.
    real = getattr(jail, "_registered_worktrees", None)

    def fake(repo: str) -> frozenset[str]:
        if repo == CWD:
            return FAKE_UNITS
        return real(repo) if real is not None else frozenset()

    monkeypatch.setattr(jail, "_registered_worktrees", fake, raising=False)


def _w(agent: str | None, path: str, tool: str = "Write") -> dict[str, Any]:
    payload: dict[str, Any] = {"tool_name": tool, "tool_input": {"file_path": path}, "cwd": CWD}
    if agent:
        payload["agent_type"] = agent
    return payload


def _b(agent: str | None, command: str) -> dict[str, Any]:
    payload: dict[str, Any] = {"tool_name": "Bash", "tool_input": {"command": command}, "cwd": CWD}
    if agent:
        payload["agent_type"] = agent
    return payload


def _t(agent: str, tool: str) -> dict[str, Any]:
    return {"tool_name": tool, "tool_input": {}, "cwd": CWD, "agent_type": agent}


def test_known_agents_match_spec_matrix() -> None:
    assert KNOWN_AGENTS == frozenset(
        {
            "main",
            "repo-coder",
            "contract-spec",
            "charter-docs",
            "security-auditor",
            "nist-specialist",
            "cis-specialist",
            "pr-train-conductor",
            "web-researcher",
            "standards-rules-specialist",
            "boundary-tester",
        }
    )


def test_unknown_agent_fails_closed() -> None:
    d = decide(_b("mystery", "ls"), CFG)
    assert not d.allow and "fail closed" in d.reason and d.reason.endswith(".")


def test_every_block_reason_has_next() -> None:
    cases = [
        _w("security-auditor", f"{CWD}/src/a.py"),
        _b("web-researcher", "ls"),
        _b("x", "ls"),
        _w("repo-coder", f"{CWD}/infra/a.tf"),
        _b("repo-coder", "git push origin x"),
    ]
    for payload in cases:
        d = decide(payload, CFG)
        assert not d.allow and "Next:" in d.reason


@pytest.mark.parametrize(
    "command",
    [
        "git push --force origin main",
        "git push -f origin main",
        "git push origin --delete x",
        "git push --force-with-lease",
        "rm -rf /",
        "sudo mkfs.ext4 /dev/sda",
        "dd if=/dev/zero of=/dev/sda",
        "git clean -fd",
        "git commit -S -m x",
        "gpg --sign x",
        "ssh-keygen -Y sign -f k x",
    ],
)
def test_universal_tripwires_block_everyone(command: str) -> None:
    for agent in (None, "main", "repo-coder", "pr-train-conductor", "charter-docs"):
        assert not decide(_b(agent, command), CFG).allow, (agent, command)


def test_workers_cannot_spawn_agents() -> None:
    assert not decide(_t("repo-coder", "Agent"), CFG).allow
    assert decide({"tool_name": "Agent", "tool_input": {}, "cwd": CWD}, CFG).allow


def test_workers_cannot_send_messages() -> None:
    assert not decide(_t("repo-coder", "SendMessage"), CFG).allow
    assert decide({"tool_name": "SendMessage", "tool_input": {}, "cwd": CWD}, CFG).allow
    assert decide(_t("main", "SendMessage"), CFG).allow


def test_daedalus_namespaced_agent_acts_as_bare_agent(monkeypatch: pytest.MonkeyPatch) -> None:
    for flag in (None, "1"):
        if flag:
            monkeypatch.setenv("DAEDALUS_LIVE_TEST", flag)
        else:
            monkeypatch.delenv("DAEDALUS_LIVE_TEST", raising=False)
        assert decide(_b("daedalus:repo-coder", "pytest -q"), CFG).allow, flag
        assert not decide(_b("daedalus:repo-coder", "git push origin x"), CFG).allow, flag


def test_test_namespace_fails_closed_without_flag(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("DAEDALUS_LIVE_TEST", raising=False)
    d = decide(_b("daedalus-probe:repo-coder", "pytest -q"), CFG)
    assert not d.allow and "fail closed" in d.reason
    monkeypatch.setenv("DAEDALUS_LIVE_TEST", "true")
    assert not decide(_b("daedalus-probe:repo-coder", "pytest -q"), CFG).allow


def test_test_namespace_acts_as_bare_agent_with_flag(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DAEDALUS_LIVE_TEST", "1")
    assert decide(_b("daedalus-probe:repo-coder", "pytest -q"), CFG).allow
    assert not decide(_b("daedalus-probe:repo-coder", "git push origin x"), CFG).allow


@pytest.mark.parametrize("flag", [None, "1"])
@pytest.mark.parametrize("agent", ["daedalus:main", "daedalus-probe:main"])
def test_namespaced_main_blocks(
    agent: str, flag: str | None, monkeypatch: pytest.MonkeyPatch
) -> None:
    if flag:
        monkeypatch.setenv("DAEDALUS_LIVE_TEST", flag)
    else:
        monkeypatch.delenv("DAEDALUS_LIVE_TEST", raising=False)
    assert not decide(_b(agent, "git status"), CFG).allow


@pytest.mark.parametrize("agent", ["daedalus:main", "daedalus-probe:main"])
def test_namespaced_main_reason(agent: str, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DAEDALUS_LIVE_TEST", "1")
    d = decide(_b(agent, "git status"), CFG)
    assert not d.allow and "orchestrator role" in d.reason and "Next:" in d.reason


def test_bare_main_still_allows() -> None:
    assert decide(_b(None, "git status"), CFG).allow


@pytest.mark.parametrize(
    "agent",
    ["otherplugin:repo-coder", "daedalus-x:repo-coder", "daedalus:", "daedalus:mystery"],
)
def test_foreign_or_empty_namespace_fails_closed(agent: str) -> None:
    d = decide(_b(agent, "pytest -q"), CFG)
    assert not d.allow and "fail closed" in d.reason


def test_namespaced_unknown_reason_names_normalized_agent() -> None:
    d = decide(_b("daedalus:mystery", "ls"), CFG)
    assert "'mystery'" in d.reason


def test_bare_repo_coder_unchanged() -> None:
    assert decide(_b("repo-coder", "pytest -q"), CFG).allow
    assert not decide(_b("repo-coder", "git push origin x"), CFG).allow


def test_main_cannot_write_application_code() -> None:
    assert not decide(_w(None, f"{CWD}/src/app.py"), CFG).allow
    assert not decide(_w(None, f"{CWD}/tests/test_app.py", "Edit"), CFG).allow
    assert decide(_w(None, f"{CWD}/docs/x.md"), CFG).allow
    assert decide(_b(None, "git status"), CFG).allow


class TestRepoCoder:
    def test_writes_inside_src_and_tests_only(self) -> None:
        # 0022: the main checkout's src/ and tests/ are refused; see TestUnitWorktree.
        assert not decide(_w("repo-coder", f"{CWD}/src/a.py"), CFG).allow
        assert not decide(_w("repo-coder", f"{CWD}/tests/test_a.py", "Edit"), CFG).allow
        assert not decide(_w("repo-coder", f"{CWD}/service-manifest.json"), CFG).allow
        assert not decide(_w("repo-coder", f"{CWD}/src/../infra/a.tf"), CFG).allow
        assert not decide(_w("repo-coder", "/other/repo/src/a.py"), CFG).allow

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

    def test_local_work_allowed(self) -> None:
        for command in (
            "pytest -q",
            "npm run test:unit",
            f"git -C {WT} add -A && git -C {WT} commit -m 'WIP: yield'",
            "git diff",
        ):
            assert decide(_b("repo-coder", command), CFG).allow, command

    def test_no_web_tools(self) -> None:
        assert not decide(_t("repo-coder", "WebFetch"), CFG).allow
        assert not decide(_t("repo-coder", "WebSearch"), CFG).allow


class TestContractSpec:
    def test_writes_contracts_or_charter_specs_only(self) -> None:
        assert decide(_w("contract-spec", f"{CWD}/contracts/openapi.yaml"), CFG).allow
        assert decide(_w("contract-spec", "/work/Charter/specs/x.md"), CFG).allow
        assert not decide(_w("contract-spec", f"{CWD}/src/a.py"), CFG).allow
        assert not decide(_w("contract-spec", "/work/Charter/decision-log.md"), CFG).allow

    def test_without_charter_root_only_contracts(self) -> None:
        assert not decide(_w("contract-spec", "/work/Charter/specs/x.md"), Config()).allow


class TestCharterDocs:
    def test_ledger_file_is_never_written_directly(self) -> None:
        d = decide(_w("charter-docs", "/work/Charter/decision-log.md"), CFG)
        assert not d.allow and "append_ledger.py" in d.reason

    def test_writes_charter_or_docs(self) -> None:
        assert decide(_w("charter-docs", "/work/Charter/audit/s.md"), CFG).allow
        assert decide(_w("charter-docs", f"{CWD}/docs/x.md"), CFG).allow
        assert not decide(_w("charter-docs", f"{CWD}/src/a.py"), CFG).allow

    def test_bash_allowlist(self) -> None:
        ok = [
            f"python3 {REPO_ROOT}/scripts/append_ledger.py --probe",
            "git add docs/decisions.md",
            "git commit -m x",
            "git status",
        ]
        bad = ["git push", "python3 other.py", "rm x", "curl x", "git add -A && git push"]
        bad += ["git add -A", "git merge --no-ff b", "git worktree list", "mkdir -p docs/.tmp"]
        bad += ["sha256sum x", "cat x", "ls"]
        for command in ok:
            assert decide(_b("charter-docs", command), CFG).allow, command
        for command in bad:
            assert not decide(_b("charter-docs", command), CFG).allow, command


class TestReadOnlyAgents:
    @pytest.mark.parametrize("agent", ["security-auditor", "nist-specialist", "cis-specialist"])
    def test_no_writes(self, agent: str) -> None:
        for tool in ("Write", "Edit", "MultiEdit", "NotebookEdit"):
            assert not decide(_w(agent, f"{CWD}/docs/x.md", tool), CFG).allow

    def test_auditor_read_only_pipelines_including_two_pipes(self) -> None:
        ok = [
            "git diff main...daedalus/u1",
            "git log --oneline -5 | head -n 3",
            "rg TODO src | sort | uniq -c",
            "git show HEAD:src/a.py | grep -n secret | head",
            "cat x | jq .a",
            "find . -name '*.py' | wc -l",
            "git branch -a",
            "stat x",
        ]
        bad = [
            "git diff | tee out.txt",
            "cat x > y",
            "ls; rm x",
            "git diff && git push",
            "echo `id`",
            "cat $(ls)",
            "git checkout main",
            "git diff | head | python3 -c 1",
            "sed -i s/a/b/ x",
            "gpg --list-keys",
        ]
        for command in ok:
            assert decide(_b("security-auditor", command), CFG).allow, command
        for command in bad:
            assert not decide(_b("security-auditor", command), CFG).allow, command

    def test_specialists_read_only_set(self) -> None:
        assert decide(_b("nist-specialist", "sha256sum catalog.json"), CFG).allow
        assert decide(_b("cis-specialist", "git diff main...b | head"), CFG).allow
        assert not decide(_b("nist-specialist", "curl https://nist.gov"), CFG).allow
        assert not decide(_b("cis-specialist", "git checkout x"), CFG).allow


class TestConductor:
    def test_push_without_force_and_pr_ops(self) -> None:
        ok = [
            "git push -u origin daedalus/t1",
            "git status",
            "git log --oneline -3",
            "git add -A",
            "git commit -m x",
            "gh pr create --title t --body-file docs/.tmp/pr.md",
            "gh pr edit 3 --body-file /tmp/pr.md",
            "gh run watch 123",
            "gh run list",
            "gitleaks detect --redact --log-opts=main..b",
        ]
        bad = [
            "gh pr merge 3",
            "gh pr close 3",
            "gh repo delete x",
            "git push --force",
            "curl x",
            "npm test",
            "git checkout main",
            "gh pr create && gh pr merge 1",
        ]
        for command in ok:
            assert decide(_b("pr-train-conductor", command), CFG).allow, command
        for command in bad:
            assert not decide(_b("pr-train-conductor", command), CFG).allow, command

    def test_no_writes(self) -> None:
        assert not decide(_w("pr-train-conductor", f"{CWD}/docs/x.md"), CFG).allow


class TestNoShellAgents:
    @pytest.mark.parametrize("agent", ["web-researcher", "standards-rules-specialist"])
    def test_blocks_bash_and_writes(self, agent: str) -> None:
        assert not decide(_b(agent, "ls"), CFG).allow
        assert not decide(_w(agent, f"{CWD}/docs/x.md"), CFG).allow

    def test_only_researcher_may_fetch(self) -> None:
        assert decide(_t("web-researcher", "WebFetch"), CFG).allow
        assert decide(_t("web-researcher", "WebSearch"), CFG).allow
        assert not decide(_t("standards-rules-specialist", "WebFetch"), CFG).allow
        assert not decide(_t("nist-specialist", "WebFetch"), CFG).allow


class TestBoundaryTester:
    def test_writes_only_tests_adversarial(self) -> None:
        assert decide(_w("boundary-tester", f"{CWD}/tests/adversarial/t.py"), CFG).allow
        assert not decide(_w("boundary-tester", f"{CWD}/tests/unit/t.py"), CFG).allow
        assert not decide(_w("boundary-tester", f"{CWD}/src/a.py"), CFG).allow

    def test_bash_tests_and_local_git_only(self) -> None:
        for command in (
            "pytest tests/adversarial -q",
            "npm run test:unit",
            "git add -A",
            "git commit -m x",
            "git diff",
            "cat x",
        ):
            assert decide(_b("boundary-tester", command), CFG).allow, command
        for command in ("git push", "curl x", "rm -rf tests", "pip install requests"):
            assert not decide(_b("boundary-tester", command), CFG).allow, command


def test_split_pipeline() -> None:
    assert split_pipeline("a | b | c") == ["a", "b", "c"]
    assert split_pipeline("a; b") is None
    assert split_pipeline("a && b") is None
    assert split_pipeline("a || b") is None
    assert split_pipeline("a > f") is None
    assert split_pipeline("a < f") is None
    assert split_pipeline("echo `x`") is None
    assert split_pipeline("echo $(x)") is None


# Fix round 1: hardening regressions.
BASH_AGENTS = [
    "repo-coder",
    "charter-docs",
    "security-auditor",
    "nist-specialist",
    "cis-specialist",
    "pr-train-conductor",
    "boundary-tester",
]
PIPE_ALLOWED = {"security-auditor", "nist-specialist", "cis-specialist"}
SEPARATORS = [
    "git diff & git diff",
    "git diff\ngit diff",
    "git diff\rgit diff",
    "git diff || git diff",
    "git diff $(git diff)",
    "git diff `git diff`",
    "git diff > f",
    "git diff >> f",
    "git diff 2> f",
    "git diff &> f",
    "git diff < f",
    "git diff |& head",
    "git diff <(git diff)",
    "git diff >(cat)",
]


@pytest.mark.parametrize("agent", BASH_AGENTS)
def test_plain_git_diff_is_allowed_baseline(agent: str | None) -> None:
    assert decide(_b(agent, "git diff"), CFG).allow


@pytest.mark.parametrize("command", SEPARATORS)
@pytest.mark.parametrize("agent", BASH_AGENTS)
def test_separator_matrix_blocks(agent: str | None, command: str) -> None:
    d = decide(_b(agent, command), CFG)
    assert not d.allow and "Next:" in d.reason, (agent, command)


@pytest.mark.parametrize("agent", [a for a in BASH_AGENTS if a not in PIPE_ALLOWED])
def test_pipe_blocked_where_not_allowed(agent: str) -> None:
    assert not decide(_b(agent, "git diff | head"), CFG).allow


def test_tokenize() -> None:
    assert tokenize("git add -A && git commit -m 'a b'") == [
        ["git", "add", "-A"],
        ["git", "commit", "-m", "a b"],
    ]
    assert tokenize("a | b ; c") == [["a"], ["b"], ["c"]]
    for bad in ("a & b", "a\nb", "a > f", "a 2> f", "a &> f", "a |& b", "a <(b)", "echo 'x", ""):
        assert tokenize(bad) is None, bad


@pytest.mark.parametrize(
    "command",
    [
        "git push origin +main",
        "git push origin :main",
        "git -C . push --force",
        "git -C /x -c a=b push -f origin x",
        "git push -fu origin x",
        "git push --mirror",
        "git push --prune origin",
        "git push --no-verify origin x",
        "git push -d origin x",
        "git push --force-with-lease=x origin x",
        "env git push --force",
        "X=1 git push -f origin x",
        "sudo -u root git push --force",
        "/opt/bin/git push --force",
        "git -C /x clean -n",
        "git --no-pager clean -n",
        "rm -fr /",
        "rm -r -f /",
        "rm --recursive --force /",
        "rm -rf /*",
        "rm -rf ~",
        "rm -rf $HOME",
        "rm -rf //",
        "git commit -Sm x",
        "git commit --gpg-sign=K -m x",
        "git commit --gpg-sign -m x",
        "git -c commit.gpgsign=true commit -m x",
        "git tag -s v1 -m x",
        "git tag -u K v1",
        "git merge -S b",
        "gpg2 --sign x",
        "ssh-keygen -Ysign -f k x",
        "bash -c 'git push --force'",
        "sh -c 'git clean -fd'",
    ],
)
def test_universal_tripwire_regressions(command: str) -> None:
    for agent in (None, "main", "repo-coder", "pr-train-conductor", "charter-docs"):
        d = decide(_b(agent, command), CFG)
        assert not d.allow and "Next:" in d.reason, (agent, command)


def test_main_ordinary_commands_still_allowed() -> None:
    for command in (
        "git push origin feature/x",
        "git push -u origin feature/x",
        "rm -rf build",
        "git commit -m 'fix -S flag doc'",
        "git -c commit.gpgsign=false commit -m x",
        "git log | head",
        "bash -c 'git status'",
    ):
        assert decide(_b(None, command), CFG).allow, command


@pytest.mark.parametrize("command", ["$GIT push origin x", "git $SUB origin x"])
def test_workers_blocked_on_variable_commands(command: str) -> None:
    for agent in ("repo-coder", "pr-train-conductor", "charter-docs"):
        assert not decide(_b(agent, command), CFG).allow, (agent, command)


# Fix round 2: main is bound only by the tripwires and the src/tests write rule.
@pytest.mark.parametrize(
    "command",
    [
        'git add -A && git commit -m "$(cat msg.txt)"',
        "ls || true",
        "printf 'a\\nb'\necho done",
        "echo x > /tmp/f",
        "python3 -c 'print(1)'",
        "bash -c 'echo hi > /tmp/f'",
        "git status & wait",
        "echo `date`",
        "$EDITOR notes.md",
        "git push -u origin feature/x 2>/dev/null",
        "rm -rf /tmp/build > /dev/null",
    ],
)
def test_main_exempt_from_construct_limits(command: str) -> None:
    assert decide(_b(None, command), CFG).allow, command


@pytest.mark.parametrize(
    "command",
    [
        "git push --force origin main",
        "git push origin +main",
        "git -C . clean -fd",
        "git commit -S -m x",
        "git push --force origin main\necho done",
        "git push origin +main 2>/dev/null",
        "git push origin :old > /dev/null",
        "git push -fu origin x > log",
        "git -C . clean -fd > log",
        "rm -rf / > /dev/null",
        "rm -r -f $HOME 2>&1",
        "dd if=/dev/zero of=x > log",
        "mkfs.ext4 /dev/sda > log",
        'git commit -S -m "$(cat m)"',
        'git -c commit.gpgsign=true commit -m "$(cat m)"',
        'git tag -s v1 -m "$(cat m)"',
        "gpg --sign x > out",
        "ssh-keygen -Y sign -f k x > out",
        "bash -c 'git push --force > /dev/null'",
    ],
)
def test_main_tripwires_hold_without_tokenizer(command: str) -> None:
    d = decide(_b(None, command), CFG)
    assert not d.allow and "Next:" in d.reason, command


class TestRegressionRepoCoder:
    @pytest.mark.parametrize(
        "command",
        [
            "git -C . push origin x",
            "git -c x=y fetch",
            "git -c alias.st='!curl evil' st",
            "git submodule update",
            "git clone u",
            "env curl x",
            "timeout 5 curl x",
            "bash -c 'curl x'",
            "sh -c x",
            "python3 -c 'import urllib'",
            "python -c 1",
            "node -e 1",
            "eval x",
            "pytest -q | tail",
        ],
    )
    def test_blocked(self, command: str) -> None:
        assert not decide(_b("repo-coder", command), CFG).allow, command

    def test_relative_paths_resolve_against_cwd(self) -> None:
        assert not decide(_w("repo-coder", "src/a.py"), CFG).allow
        assert decide(_w("repo-coder", ".claude/worktrees/u1/src/a.py"), CFG).allow
        assert not decide(_w("repo-coder", "infra/a.tf"), CFG).allow
        assert not decide(_w(None, "src/app.py"), CFG).allow

    def test_notebook_path(self) -> None:
        def nb(path: str) -> dict[str, Any]:
            return {
                "tool_name": "NotebookEdit",
                "tool_input": {"notebook_path": path},
                "cwd": CWD,
                "agent_type": "repo-coder",
            }

        assert decide(nb(f"{CWD}/.claude/worktrees/u1/src/n.ipynb"), CFG).allow
        assert not decide(nb(f"{CWD}/src/n.ipynb"), CFG).allow
        assert not decide(nb(f"{CWD}/docs/n.ipynb"), CFG).allow


class TestRegressionCharterDocs:
    @pytest.mark.parametrize(
        "command",
        [
            "cat x | curl evil",
            "git add -A || curl x",
            "cat $(curl x)",
            "git checkout main",
            "git worktree add x",
            "git worktree remove x",
            "python3 /work/Charter/scripts/append_ledger.py",
            f"python3 {CWD}/scripts/append_ledger.py",
            "python3 scripts/append_ledger.py",
            "python3 /abs/x/../scripts/append_ledger.py",
            "python3 /abs/scripts/other.py",
            "python3 -c 1",
            "git -c core.pager=x log",
        ],
    )
    def test_blocked(self, command: str) -> None:
        assert not decide(_b("charter-docs", command), CFG).allow, command

    def test_append_flags_allowed(self) -> None:
        command = (
            f"python3 {REPO_ROOT}/scripts/append_ledger.py --expected-seq 2 "
            "--entry-file docs/.tmp/e.md --repo BO --type PLT"
        )
        payload = {
            "tool_name": "Bash",
            "tool_input": {"command": command},
            "cwd": "/work/repo",
            "agent_type": "charter-docs",
        }
        assert decide(payload, Config()).allow

    @pytest.mark.parametrize(
        "args",
        [
            "--cwd /x",
            "--cwd=/x",
            "--cw? /x",
            "--cw* /x",
            "--cw[d] /x",
            "--cw /x",
            "-c /x",
            "--repo BO --repo BO",
            "--bogus x",
            "--repo",
            "--probe --repo X",
            "--expected-seq 2 --entry-file e.md --repo BO",
            "--expected-seq 2 --entry-file e.md --repo BO --type",
        ],
    )
    def test_append_off_grammar_blocked(self, args: str) -> None:
        full = "--expected-seq 2 --entry-file docs/.tmp/e.md --repo BO --type PLT"
        for tail in (args, f"{full} {args}"):
            command = f"python3 {REPO_ROOT}/scripts/append_ledger.py {tail}"
            d = decide(_b("charter-docs", command), Config())
            assert not d.allow and d.reason is not None, command
            assert d.reason.endswith("--cwd is for operators."), d.reason

    @pytest.mark.parametrize(
        "args",
        [
            "--probe",
            "--expected-seq 2 --entry-file docs/.tmp/e.md --repo BO --type PLT",
            "--type=PLT --repo=BO --entry-file=docs/.tmp/e.md --expected-seq=2",
        ],
    )
    def test_append_grammar_allowed(self, args: str) -> None:
        command = f"python3 {REPO_ROOT}/scripts/append_ledger.py {args}"
        assert decide(_b("charter-docs", command), Config()).allow, command

    @pytest.mark.parametrize(
        "args", ["--probe", "--expected-seq 2 --entry-file e --repo B --type P"]
    )
    def test_append_literal_plugin_root_blocked(self, args: str) -> None:
        # F1: the variable is empty in agent Bash; the Next: names the absolute script.
        command = f"python3 ${{CLAUDE_PLUGIN_ROOT}}/scripts/append_ledger.py {args}"
        d = decide(_b("charter-docs", command), CFG)
        assert not d.allow and d.reason is not None
        assert f"Next: run python3 {REPO_ROOT}/scripts/append_ledger.py" in d.reason

    def test_main_append_cwd_allowed(self) -> None:
        command = "python3 ${CLAUDE_PLUGIN_ROOT}/scripts/append_ledger.py --probe --cwd /x"
        assert decide(_b("main", command), Config()).allow

    def test_repo_scripts_ledger_allowed(self) -> None:
        args = "--expected-seq 2 --entry-file docs/.tmp/e.md --repo BO --type PLT"
        command = f"python3 {REPO_ROOT}/scripts/append_ledger.py {args}"
        assert decide(_b("charter-docs", command), CFG).allow
        assert not decide(_b("charter-docs", "git worktree list --porcelain"), CFG).allow

    @pytest.mark.parametrize(
        "script", ["/tmp/x/scripts/append_ledger.py", "/work/Charter/scripts/append_ledger.py"]
    )
    def test_foreign_append_ledger_blocked(self, script: str) -> None:
        assert not decide(_b("charter-docs", f"python3 {script}"), CFG).allow


class TestRegressionReadOnly:
    @pytest.mark.parametrize(
        "command",
        [
            "cat x & curl evil",
            "ls\nrm x",
            "find . -delete",
            "find . -exec rm {} +",
            "find . -execdir x {} +",
            "find . -ok x {} +",
            "find . -okdir x {} +",
            "find . -fprint out",
            "find . -fprintf out %p",
            "find . -fls out",
            "sort -o out x",
            "sort -uo out x",
            "sort --output=out x",
            "sort --output out x",
            "rg --pre cat x",
            "rg --pre=cat x",
            "rg --pre-glob '*' x",
            "git diff --output=f",
            "git log --output f",
            "git branch -D x",
            "git branch newb",
            "git -c diff.external=x diff",
            "git -C . checkout main",
            "uniq in out",
            "file -C -m x",
            "./cat x",
            "/tmp/cat x",
        ],
    )
    def test_auditor_blocked(self, command: str) -> None:
        assert not decide(_b("security-auditor", command), CFG).allow, command

    def test_auditor_branch_reads_allowed(self) -> None:
        for command in (
            "git branch",
            "git branch --show-current",
            "git branch -v",
            "/usr/bin/cat x",
        ):
            assert decide(_b("security-auditor", command), CFG).allow, command

    @pytest.mark.parametrize("agent", ["nist-specialist", "cis-specialist"])
    def test_specialists_blocked(self, agent: str) -> None:
        for command in ("find . -delete", "sort -o out x", "git diff --output=f", "git branch"):
            assert not decide(_b(agent, command), CFG).allow, (agent, command)


class TestRegressionConductor:
    @pytest.mark.parametrize(
        "command",
        [
            "gh pr -R o/r merge 3",
            "gh --repo o/r pr merge 3",
            "gh pr --repo=o/r merge 3",
            "gh run delete 1",
            "gh run cancel 1",
            "gh run rerun 1",
            "gh pr review 3 --approve",
            "gh pr ready 3",
            "gh api x",
            "gh repo view",
            "gh pr",
            "git push origin HEAD:main",
            "git push origin b:master",
            "git push origin main",
            "git push origin refs/heads/main",
            "git -C . push origin HEAD:main",
            "git push --all origin",
            "git -C . checkout main",
            "gitleaks protect",
            # Round 3 grammar: refspec form flipped from allowed (round 1) to blocked.
            "git push origin daedalus/t1:daedalus/t1",
        ],
    )
    def test_blocked(self, command: str) -> None:
        assert not decide(_b("pr-train-conductor", command), CFG).allow, command

    def test_default_branch_reason(self) -> None:
        d = decide(_b("pr-train-conductor", "git push origin HEAD:main"), CFG)
        assert d.reason and "never push to the default branch (0001)" in d.reason

    def test_allowed(self) -> None:
        for command in (
            "gh -R o/r pr view 3",
            "gh pr checks 3",
            "gh pr comment 3 --body-file docs/.tmp/c.md",
            "gh pr diff 3",
            "gh run view 1",
            "gh pr list --repo o/r",
        ):
            assert decide(_b("pr-train-conductor", command), CFG).allow, command


class TestRegressionBoundaryTester:
    @pytest.mark.parametrize(
        "command",
        [
            "npm install x",
            "npm i x",
            "npm add x",
            "npm ci",
            "npm link",
            "npm exec x",
            "npm x y",
            "npx x",
            "uv add x",
            "uv pip install x",
            "uv tool run x",
            "uv run --with x pytest",
            "pip install x",
            "go get x",
            "go install x",
            "cargo install x",
            "cargo add x",
            "make",
            "make test",
            "node -e 1",
            "python3 -c 1",
            "python3 evil.py",
        ],
    )
    def test_blocked(self, command: str) -> None:
        assert not decide(_b("boundary-tester", command), CFG).allow, command

    def test_allowed(self) -> None:
        for command in (
            "npm test",
            "uv run pytest -q",
            "python -m pytest tests/adversarial",
            "go test ./...",
            "cargo test",
            "node t.js",
        ):
            assert decide(_b("boundary-tester", command), CFG).allow, command


class TestRegressionToolsAndCwd:
    @pytest.mark.parametrize("tool", ["Task", "Agent", "mcp__claude_ai_Gmail__create_draft"])
    def test_workers_blocked_from_meta_tools(self, tool: str) -> None:
        for agent in sorted(KNOWN_AGENTS - {"main"}):
            d = decide(_t(agent, tool), CFG)
            assert (
                not d.allow
                and d.reason == "workers use only their allowlisted tools. Next: ask Fable."
            )

    def test_main_may_use_mcp(self) -> None:
        assert decide({"tool_name": "mcp__x__y", "tool_input": {}, "cwd": CWD}, CFG).allow

    @pytest.mark.parametrize("cwd", ["", "relative/repo"])
    def test_missing_cwd_fails_closed(self, cwd: str) -> None:
        for agent in (None, "repo-coder"):
            for payload in (_b(agent, "git status"), _w(agent, f"{CWD}/src/a.py")):
                payload["cwd"] = cwd
                d = decide(payload, CFG)
                assert not d.allow and "no absolute cwd" in d.reason, (agent, cwd)


# Fix round 3: worker grammars, quote-aware tokenizer, hardened main fallback.
HOME = os.path.normpath(os.path.expanduser("~"))
WORKERS_WITH_SHELL = [a for a in BASH_AGENTS]


class TestRound3Breakage:
    def test_quoted_filters_allowed(self) -> None:
        assert decide(_b("security-auditor", "jq '.[] | .name' x.json"), CFG).allow
        assert decide(_b("security-auditor", "rg 'foo|bar' src"), CFG).allow
        assert decide(_b("nist-specialist", "jq -r '.controls[] | .id' c.json"), CFG).allow
        assert decide(_b("security-auditor", "grep -n 'a;b' x"), CFG).allow
        assert decide(_b("security-auditor", "grep -n '$x' src"), CFG).allow

    def test_quoted_separators_in_commit_message(self) -> None:
        for command in (
            f"git -C {WT} commit -m 'fix: a; b'",
            f"git -C {WT} commit -m 'a > b'",
            f"git -C {WT} commit -m 'a | b && c'",
            f"git -C {WT} commit -m 'cost: $5'",
            f"git -C {WT} commit -m 'fix curl handling'",
        ):
            assert decide(_b("repo-coder", command), CFG).allow, command

    def test_split_pipeline_is_quote_aware(self) -> None:
        assert split_pipeline("jq '.a | .b' x | head") == ["jq '.a | .b' x", "head"]
        assert tokenize("git commit -m 'a; b'") == [["git", "commit", "-m", "a; b"]]


class TestRound3ConductorPushGrammar:
    @pytest.mark.parametrize(
        "command",
        [
            "git push -u origin feat/x",
            "git push --set-upstream origin feat/x",
            "git push origin a.b_c",
        ],
    )
    def test_allowed(self, command: str) -> None:
        assert decide(_b("pr-train-conductor", command), CFG).allow

    @pytest.mark.parametrize(
        "command",
        [
            "git push origin feat/x extra",
            "git push --mirror origin",
            "git push origin HEAD:heads/main",
            "git push origin 'refs/heads/*:refs/heads/*'",
            "git push origin --branches",
            "git push upstream feat/x",
            "git push origin",
            "git push",
            "git push -u origin -x",
            "git push -o ci.skip origin feat/x",
            "git push origin .hidden",
            "git push origin master",
            "git push -C . origin feat/x",
            "git -C . push origin feat/x",
            "git push --repo=origin feat/x",
        ],
    )
    def test_blocked(self, command: str) -> None:
        d = decide(_b("pr-train-conductor", command), CFG)
        assert not d.allow and "Next:" in d.reason, command

    def test_grammar_reason(self) -> None:
        d = decide(_b("pr-train-conductor", "git push origin feat/x extra"), CFG)
        assert d.reason and "one named branch to origin" in d.reason


class TestRound3WorkerGitGrammar:
    @pytest.mark.parametrize(
        ("agent", "command"),
        [
            ("security-auditor", "git log --output=x"),
            ("security-auditor", "git diff --ext-diff"),
            ("security-auditor", "git log --format=%H --output=y"),
            ("security-auditor", "git show --textconv HEAD"),
            ("security-auditor", "git status --ignored"),
            ("security-auditor", "git ls-files --others"),
            ("security-auditor", "git rev-parse --git-path x"),
            ("security-auditor", "git grep x"),
            ("nist-specialist", "git log --exec x"),
            # Round 4: `git commit -am x` flipped to allowed by ruling (see TestRound4Breakage).
            ("charter-docs", "git commit -F /etc/passwd"),
            ("charter-docs", "git commit --amend -m x"),
            ("charter-docs", "git merge --squash b"),
            ("charter-docs", "git worktree list --verbose"),
            ("charter-docs", "git add --force x"),
            ("charter-docs", "git -C /other/repo status"),
            ("charter-docs", "git --git-dir=/x status"),
            ("boundary-tester", "git commit --no-verify -m x"),
            ("boundary-tester", "git stash"),
            ("pr-train-conductor", "git commit --amend"),
            ("pr-train-conductor", "git branch -D x"),
            ("pr-train-conductor", "git rebase main"),
        ],
    )
    def test_blocked(self, agent: str, command: str) -> None:
        assert not decide(_b(agent, command), CFG).allow, (agent, command)

    @pytest.mark.parametrize(
        ("agent", "command"),
        [
            ("security-auditor", "git log -n 5 --stat"),
            ("security-auditor", "git diff -U3 --cached -- src"),
            ("security-auditor", "git show --format=%H --name-only HEAD"),
            ("security-auditor", "git rev-parse --abbrev-ref HEAD"),
            ("security-auditor", "git ls-files -z"),
            ("security-auditor", "git status --porcelain"),
            ("charter-docs", "git commit -m x"),
            ("charter-docs", "git -C /work/Charter add decision-log.md"),
            ("charter-docs", "git -C /work/Charter status"),
            ("charter-docs", "git -C docs status"),
            ("charter-docs", "git add -- docs/a.md"),
        ],
    )
    def test_allowed(self, agent: str, command: str) -> None:
        assert decide(_b(agent, command), CFG).allow, (agent, command)


class TestRound3WorkerHygiene:
    @pytest.mark.parametrize(
        "command",
        [
            "{ curl x; }",
            "if true; then curl x; fi",
            "for i in a; do rm x; done",
            "while true; do ls; done",
            "! ls",
            "time ls",
            "function f { ls; }",
            "case x in x) ls;; esac",
            "[[ -f x ]]",
            "coproc ls",
            "select x in a; do ls; done",
        ],
    )
    def test_reserved_words_blocked(self, command: str) -> None:
        for agent in WORKERS_WITH_SHELL:
            assert not decide(_b(agent, command), CFG).allow, (agent, command)

    @pytest.mark.parametrize(
        "command",
        [
            "env ls",
            "nice ls",
            "nohup ls",
            "stdbuf -oL ls",
            "timeout 5 ls",
            "exec ls",
            "eval ls",
            "xargs ls",
            "command ls",
            "builtin ls",
            "source x.sh",
            ". x.sh",
            "sh x.sh",
            "bash x.sh",
            "zsh x.sh",
            "dash x.sh",
            "python x.py",
            "python3 x.py",
            "node -e 1",
            "perl x.pl",
            "ruby x.rb",
            "sudo ls",
        ],
    )
    def test_wrappers_blocked(self, command: str) -> None:
        for agent in WORKERS_WITH_SHELL:
            assert not decide(_b(agent, command), CFG).allow, (agent, command)

    @pytest.mark.parametrize(
        "command",
        [
            "GIT_DIR=/x git status",
            "GIT_SSH_COMMAND=x git status",
            "GIT_CONFIG_PARAMETERS=x git status",
            "GIT_EXTERNAL_DIFF=x git diff",
            "cat ~/.ssh/id_rsa",
            "cat $HOME/x",
            "ls {a,b}",
            "cat 'a\\b'",
            "git diff ${X}",
        ],
    )
    def test_env_and_token_hygiene(self, command: str) -> None:
        for agent in WORKERS_WITH_SHELL:
            assert not decide(_b(agent, command), CFG).allow, (agent, command)

    def test_git_config_read_only_for_repo_coder(self) -> None:
        assert decide(_b("repo-coder", "git config --get user.name"), CFG).allow
        assert decide(_b("repo-coder", "git config --list"), CFG).allow
        for command in (
            "git config core.hooksPath x",
            "git config --global x y",
            "git config --get-all x --add y",
            "git config --unset x",
        ):
            assert not decide(_b("repo-coder", command), CFG).allow, command

    def test_repo_coder_hidden_network_and_remote(self) -> None:
        for command in ("find . -exec curl x {} +", "find . -exec git push origin x {} +"):
            assert not decide(_b("repo-coder", command), CFG).allow, command

    def test_runner_forms_still_allowed(self) -> None:
        for agent in ("repo-coder", "boundary-tester"):
            for command in ("python3 -m pytest -q", "node t.js", "uv run pytest"):
                assert decide(_b(agent, command), CFG).allow, (agent, command)


class TestRound3SortPytestGitleaks:
    @pytest.mark.parametrize(
        "command",
        [
            "sort --out=f x",
            "sort --o=f x",
            "sort --compress-program=gzip x",
            "sort --compress-prog=gzip x",
            "sort -T /tmp x",
            "sort --temporary-directory=/tmp x",
        ],
    )
    def test_sort_denies(self, command: str) -> None:
        assert not decide(_b("security-auditor", command), CFG).allow, command

    @pytest.mark.parametrize(
        "command",
        [
            "pytest --basetemp=/tmp/x",
            "pytest --basetemp /tmp/x",
            "python -m pytest --basetemp x",
            "uv run pytest --basetemp=x",
        ],
    )
    def test_basetemp_denied(self, command: str) -> None:
        for agent in ("repo-coder", "boundary-tester"):
            assert not decide(_b(agent, command), CFG).allow, (agent, command)

    def test_gitleaks_report_path(self) -> None:
        conductor = "pr-train-conductor"
        for form in ("--report-path=/tmp/r.json", "--report-path /tmp/r.json"):
            assert decide(_b(conductor, f"gitleaks detect --redact {form}"), CFG).allow
        for command in (
            "gitleaks detect --report-path /var/x/r.json",
            "gitleaks detect -r /etc/x",
            "gitleaks detect --report-path=/tmp/../etc/x",
            "gitleaks detect --log-opts=--output=/x",
            "gitleaks detect --report-path=r.json",
        ):
            assert not decide(_b(conductor, command), CFG).allow, command


class TestRound3DotGitWrites:
    @pytest.mark.parametrize(
        ("agent", "path"),
        [
            (None, f"{CWD}/.git/hooks/pre-commit"),
            ("repo-coder", f"{CWD}/src/../.git/config"),
            ("repo-coder", f"{CWD}/src/.git/config"),
            ("charter-docs", "/work/Charter/.git/config"),
            ("contract-spec", f"{CWD}/contracts/.git/x"),
            ("boundary-tester", f"{CWD}/tests/adversarial/.git/x"),
        ],
    )
    def test_blocked(self, agent: str | None, path: str) -> None:
        d = decide(_w(agent, path), CFG)
        assert not d.allow and ".git/" in d.reason

    def test_gitignore_is_not_dotgit(self) -> None:
        assert decide(_w(None, f"{CWD}/.gitignore"), CFG).allow


class TestRound3MainHardened:
    @pytest.mark.parametrize(
        "command",
        [
            # B1: grouping and reserved words fall back to the regex.
            "{ git push --force; }",
            "if true; then git push --force; fi",
            "for b in x; do git clean -fd; done",
            "time git push -f origin x",
            "(git push --force)",
            "! git clean -fd",
            # B2: wrappers, eval, interpreters, xargs.
            "eval git push --force",
            "eval 'git push' '--force'",
            "bash -o pipefail -c 'git push --force'",
            "bash --norc -c 'git clean -fd'",
            "bash -c -- 'git clean -fd'",
            "sh -xc 'git push -f origin x'",
            "python3 -c 'import os; os.system(\"git push --force\")'",
            'python3 -c \'import subprocess; subprocess.run(["git", "push", "--force"])\'',
            "perl -e 'system(\"git push -f\")'",
            "ruby -e 'system(\"git clean -fd\")'",
            'node -e \'require("child_process").execSync("git push --force")\'',
            "sudo --unknown-opt git push --force",
            "env -S 'git push --force'",
            "echo x | xargs git push",
            "xargs -n1 git commit -S",
            "nice -n 5 git push --force",
            "timeout 5 git push --force",
            "stdbuf -oL git push -f origin x",
            "command git clean -fd",
            # B3: variables in tripwire-relevant arguments route to the fallback.
            "git push origin ${X:-+main}",
            "git push origin ${IFS}--force",
            'git commit -m "$MSG" -S',
            "git push origin $X:main",
            # B4: abbreviated long options.
            "git push --forc origin x",
            "git push --mirr origin",
            "git push --del origin x",
            "git push --de origin x",
            "git push --no-verif origin x",
            "git commit --gpg -m x",
            "git tag --si v1",
            "git tag --local=K v1",
            "rm --rec --forc /",
            "rm --r /",
            # B5: default branch, wildcard, --branches.
            "git push origin HEAD:heads/main",
            "git push origin 'refs/heads/*:refs/heads/*'",
            "git push origin --branches",
            "git push --all origin",
            "git push origin main",
            "git push origin feature/master",
            # B9: fallback normalization.
            "git push --for\\\nce origin x",
            "git push '--force' origin x > /dev/null",
            "git push $'--force' origin x > f",
            "g\\it push -f origin x > f",
            'git push "--force" origin x 2>&1',
            # B10: GIT_CONFIG env signing.
            "GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=commit.gpgsign GIT_CONFIG_VALUE_0=true "
            "git commit -m x",
            "GIT_CONFIG_PARAMETERS=\"'commit.gpgsign'='true'\" git commit -m x",
            "env GIT_CONFIG_KEY_0=tag.gpgSign git tag v1",
            # B11: home and brace targets.
            "rm -rf ~/",
            'rm -rf "$HOME"',
            "rm -rf ${HOME}/*",
            "rm -rf /{,}",
            f"rm -rf {HOME}",
            f"rm -rf {HOME}/*",
            "rm -rf /.",
        ],
    )
    def test_blocked(self, command: str) -> None:
        d = decide(_b(None, command), CFG)
        assert not d.allow and "Next:" in d.reason, command

    @pytest.mark.parametrize(
        "command",
        [
            "git push origin feature/x",
            "git push origin $REF",
            "GIT_PAGER=cat git log",
            "bash -o pipefail -c 'git status'",
            "python3 -c 'print(1)'",
            "eval echo hi",
            "rm -rf ./build",
            "rm -rf ~/scratch/build",
            "command -v git",
            "git commit -m 'docs: never git push --force'",
        ],
    )
    def test_allowed(self, command: str) -> None:
        assert decide(_b(None, command), CFG).allow, command


class TestRound4MainFallback:
    @pytest.mark.parametrize(
        "command",
        [
            # N1: $-leading command words.
            "$'git' push --force origin main",
            "$'g'it push --force origin main",
            "$'rm' -rf /",
            "${X:-git} clean -fd",
            '"$git" push --force origin main',
            "$(echo git) clean -fd",
            # N2: brace expansion of flags and command words.
            "git push {-f,} origin feat",
            "git push {--force,} origin feat",
            "git {push,} --force origin feat",
            "git push origin {:,}feat",
            "rm {-rf,} /",
            # N3: quoted separator plus a construct that defeats tokenize.
            "git -c x='y;z' push --force origin main >/dev/null",
            "git -c x='y|z' push --force origin main >/dev/null",
            "git -c x='y&z' push --force origin main >/dev/null",
            "git -c x='y(z' push --force origin main >/dev/null",
            "git -c x='a;b' clean -fd >/dev/null",
            "git commit -m 'a;b' -S >/dev/null",
            "git push -o 'a;b' --force origin main >/dev/null",
            "git commit -m 'a;b' -S\n",
            # N4: home ancestors.
            "rm -rf ~/..",
            "rm -rf ~/../",
            "rm -rf $HOME/..",
            f"rm -rf {HOME}/..",
            "rm -r ~/..",
            "rm -rf ~/.. > log",
            "rm -rf $HOME/../.. > log",
            f"rm -rf {HOME}/.. > log",
            f"rm -rf {os.path.dirname(HOME)} > log",
            f"rm -rf {os.path.dirname(HOME)}",
            "{git,} push --force origin main",
            'git push origin "Main"',
            "git -c core.pager=x log",
            "git --config-env=alias.x=Y x",
            # N5: --m is the unique prefix of --mirror.
            "git push --m origin feat",
            "git push --m origin feat > log",
            # N7: -c keys that change push or execution behavior.
            "git -c remote.origin.mirror=true push",
            "git -c push.default=matching push",
            "git -c protocol.ext.allow=always clone ext::sh -c x",
            "git -c Remote.Origin.Push=+refs/heads/*:refs/heads/* push",
            "git -c core.hooksPath=/tmp/h commit -m x",
            "git -c core.sshCommand=x fetch",
            "git -c alias.p=push p",
            "git -c remote.origin.mirror=true push > log",
            # Default branches casefold.
            "git push origin Main",
            "git push origin MASTER",
            "git push origin Main > log",
        ],
    )
    def test_blocked(self, command: str) -> None:
        d = decide(_b(None, command), CFG)
        assert not d.allow and "Next:" in d.reason, command

    @pytest.mark.parametrize(
        "command",
        [
            "git -c color.ui=false log",
            "git push origin $REF",
            "git push origin feature/main-fix",
            "$EDITOR notes.md",
            "rm -rf ~/scratch/build/..",
            "rm -rf /tmp/x/..",
            "git push origin feat > log",
        ],
    )
    def test_allowed(self, command: str) -> None:
        assert decide(_b(None, command), CFG).allow, command

    def test_fallback_asymmetry_for_main_word_in_branch(self) -> None:
        # Kept as ruled: the fallback over-blocks a main word inside a branch name.
        assert not decide(_b(None, "git push origin feature/main-fix > log"), CFG).allow


class TestRound5BraceFallback:
    @pytest.mark.parametrize(
        "command",
        [
            "rm -rf /h{ome,} > log",
            "rm {-rf,} /h{ome,}",
            "rm -rf {/,} > log",
            "rm -{r,}f /h{ome,} > log",
            "sudo rm --rec /h{ome,} > log",
            "sudo -u root rm -rf /h{ome,} > log",
            "sudo -u root git push origin ma{in,} > log",
            "timeout -s KILL 5 rm -rf /h{ome,} > log",
            "git push origin ma{in,}",
            "git push origin ma{in,} > log",
            "git push {-f,} origin feat > log",
            "git -C . {push,} origin feat > log",
            f"rm -rf ~/../{os.path.basename(HOME)} > log",
            "rm -rf ~/../../ > log",
            f"rm -rf {HOME}/../{os.path.basename(HOME)} > log",
            'rm -rf "$HOME/x/.." > log',
        ],
    )
    def test_blocked(self, command: str) -> None:
        d = decide(_b(None, command), CFG)
        assert not d.allow and "Next:" in d.reason, command

    @pytest.mark.parametrize(
        "command",
        [
            "echo {a,b}",
            "ls {src,tests}",
            "git log --grep='{x}'",
            "echo {a,b} > f",
            "ls {src,tests} > f",
            "git log --grep='{x}' > f",
            "rm -f {a,b}.tmp > log",
            "rm -rf ~/scratch/build/.. > log",
            "git commit -m 'fix {push} docs' > log",
        ],
    )
    def test_allowed(self, command: str) -> None:
        assert decide(_b(None, command), CFG).allow, command


class TestRound4Conductor:
    @pytest.mark.parametrize(
        "command",
        [
            "gitleaks detect -r/work/repo/src/a.py",
            "gitleaks detect -vr/work/repo/src/a.py",
            "git push origin Main",
            "git push origin MASTER",
            "git push -u origin mAsTeR",
        ],
    )
    def test_blocked(self, command: str) -> None:
        assert not decide(_b("pr-train-conductor", command), CFG).allow, command

    @pytest.mark.parametrize(
        "command",
        [
            "gitleaks detect --redact -r /tmp/x.json",
            "gitleaks detect --redact -r=/tmp/x.json",
            "gitleaks detect --redact -r/tmp/x.json",
            "gitleaks detect --redact --report-path /tmp/x.json",
            "git push origin feature/main-fix",
        ],
    )
    def test_allowed(self, command: str) -> None:
        assert decide(_b("pr-train-conductor", command), CFG).allow, command


class TestRound4Breakage:
    @pytest.mark.parametrize(
        ("agent", "command"),
        [
            ("security-auditor", "git log -n5"),
            ("security-auditor", "git log --grep=fix --no-merges --all"),
            ("security-auditor", "git log -S needle --oneline"),
            ("security-auditor", "git log -G pattern"),
            ("security-auditor", "git log --author=brad"),
            ("security-auditor", "git diff --word-diff --color=never"),
            ("nist-specialist", "git log -n5 --all"),
            ("charter-docs", "git diff --cached"),
            ("charter-docs", "git log --oneline -3"),
            ("charter-docs", "git status --porcelain"),
            ("boundary-tester", "git add --all"),
            ("boundary-tester", "git commit -m x -- tests/adversarial/t.py"),
            ("boundary-tester", "git commit -am x"),
            ("repo-coder", "CI=1 npm test"),
            ("boundary-tester", "CI=1 pytest"),
            ("boundary-tester", "CI=1 TZ=UTC LANG=C LC_ALL=C pytest"),
            ("boundary-tester", "NODE_ENV=test npm test"),
            ("boundary-tester", "PYTHONDONTWRITEBYTECODE=1 python3 -m pytest"),
        ],
    )
    def test_allowed(self, agent: str, command: str) -> None:
        assert decide(_b(agent, command), CFG).allow, (agent, command)

    @pytest.mark.parametrize(
        ("agent", "command"),
        [
            ("boundary-tester", "LD_PRELOAD=x pytest"),
            ("boundary-tester", "PATH=/tmp pytest"),
            ("boundary-tester", "CI=1 LD_PRELOAD=x pytest"),
            ("boundary-tester", "CI=1"),
            ("repo-coder", "PATH=/tmp npm test"),
            ("security-auditor", "GIT_CONFIG_PARAMETERS=x git log"),
            ("security-auditor", "git log --output=x"),
            ("security-auditor", "git diff --color=always"),
            ("charter-docs", "git commit --amend -am x"),
            ("charter-docs", "git commit -m x -S"),
        ],
    )
    def test_blocked(self, agent: str, command: str) -> None:
        assert not decide(_b(agent, command), CFG).allow, (agent, command)


# Final whole-branch review fixes (I1, I3, I4, I7, m4).
DATA = "/tmp/daedalus-test-data/daedalus-inline"


class TestFinalRemotePlumbing:
    @pytest.mark.parametrize(
        "command",
        [
            "git send-pack origin +HEAD:refs/heads/main",
            "git -C . send-pack origin HEAD:refs/heads/x",
            "git send-pack origin +HEAD:refs/heads/main > /dev/null",
            "git credential fill",
            "git credential-store get",
            "git http-push https://x/r.git HEAD",
        ],
    )
    def test_main_blocks(self, command: str) -> None:
        d = decide(_b(None, command), CFG)
        assert not d.allow and "Next:" in d.reason, command

    @pytest.mark.parametrize(
        "command",
        [
            "git send-pack origin HEAD:refs/heads/x",
            "git http-push https://x/r.git HEAD",
            "git fetch-pack origin",
            "git upload-pack .",
            "git receive-pack .",
            "git credential-cache exit",
        ],
    )
    def test_repo_coder_blocks(self, command: str) -> None:
        assert not decide(_b("repo-coder", command), CFG).allow, command

    def test_commit_message_naming_plumbing_still_allowed(self) -> None:
        assert decide(_b(None, "git commit -m 'document send-pack and credential'"), CFG).allow
        assert decide(_b(None, "git commit -m 'credential fix' > /dev/null"), CFG).allow


class TestFinalCoderGitAllowlist:
    @pytest.mark.parametrize(
        "command",
        [
            "git update-ref refs/heads/main HEAD",
            "git branch -f main HEAD",
            "git branch -D x",
            "git branch -d x",
            "git branch -m x",
            "git symbolic-ref HEAD refs/heads/main",
            "git reflog expire --all",
            "git checkout main",
            "git checkout -- docs/x.md",
            "git restore docs/x.md",
            "git restore -- ../other/a.py",
            "git restore -- src/a.py",
            "git checkout -- tests/test_a.py src/b.py",
            "git checkout -- .claude/worktrees/u1/src/a.py src/b.py",
            "git stash drop",
            "git stash",
            "git merge x",
            "git config core.editor x",
            "git worktree add ../x",
        ],
    )
    def test_blocked(self, command: str) -> None:
        d = decide(_b("repo-coder", command), CFG)
        assert not d.allow and "Next:" in d.reason, command

    @pytest.mark.parametrize(
        "command",
        [
            "git stash list",
            "git stash push -m wip",
            "git stash pop",
            "git restore -- .claude/worktrees/u1/src/a.py",
            "git checkout -- .claude/worktrees/u1/tests/test_a.py .claude/worktrees/u1/src/b.py",
            "git -C .claude/worktrees/u1 restore -- src/a.py",
            "git branch",
            "git branch --show-current",
            "git worktree list",
            "git status",
            "git log --oneline -5",
            "git show --stat",
            "git rev-parse HEAD",
            "git ls-files",
            "git config --get user.name",
        ],
    )
    def test_allowed(self, command: str) -> None:
        assert decide(_b("repo-coder", command), CFG).allow, command


class TestLiveRunGrammar:
    @pytest.mark.parametrize(
        "command",
        [
            "git status -sb",
            "git status -bs",
            "git status -s",
            "git status -b",
            "git status --short",
            "git status --branch",
            "git status --short --branch",
            "git status -s -b src",
            "git status --porcelain=v2 --show-stash",
            "git status --porcelain=v1",
        ],
    )
    def test_status_read_forms_allowed(self, command: str) -> None:
        # F3b: read-only status flags, alone or bundled.
        assert decide(_b("repo-coder", command), CFG).allow, command
        assert decide(_b("pr-train-conductor", command), CFG).allow, command

    @pytest.mark.parametrize(
        "command",
        [
            "git status -sbx",
            "git status -u",
            "git status --porcelain=v3",
            "git status --ignored",
            "git status -sb && git commit --amend -m x",
            "git status -sb && git branch -D x",
            "git status -sb && git stash drop",
        ],
    )
    def test_status_writes_and_unknown_flags_blocked(self, command: str) -> None:
        d = decide(_b("repo-coder", command), CFG)
        assert not d.allow and "Next:" in d.reason, command

    @pytest.mark.parametrize(
        "command",
        ["python3 -m mypy src tests", "python3 -m mypy src/hello.py", "python -m mypy src"],
    )
    def test_mypy_with_paths_allowed(self, command: str) -> None:
        # F3c: the test-runner rule admits mypy with path operands.
        assert decide(_b("repo-coder", command), CFG).allow, command
        assert decide(_b("boundary-tester", command), CFG).allow, command

    @pytest.mark.parametrize(
        "command",
        [
            "python3 -m mypy --cache-dir /tmp/x src",
            "python3 -m mypy --config-file=x.ini src",
            "python3 -m mypy -c 1",
            "python3 -m mypyc src",
            "python3 -c 'import mypy'",
        ],
    )
    def test_mypy_flags_blocked(self, command: str) -> None:
        assert not decide(_b("repo-coder", command), CFG).allow, command

    @pytest.mark.parametrize(
        "command",
        [
            "git status",
            "git log --oneline -5",
            "git diff --stat",
            "git branch --show-current",
            "git branch -a -v",
            "git rev-parse --abbrev-ref HEAD",
        ],
    )
    def test_conductor_read_commands_allowed(self, command: str) -> None:
        # N9: the git reads agents/pr-train-conductor.md lists.
        assert decide(_b("pr-train-conductor", command), CFG).allow, command

    @pytest.mark.parametrize(
        "command",
        ["git remote -v", "git remote get-url origin", "git branch -vv", "git rev-parse @{u}"],
    )
    def test_conductor_remote_reads_blocked(self, command: str) -> None:
        assert not decide(_b("pr-train-conductor", command), CFG).allow, command

    def test_conductor_block_message_matches_its_git_grammar(self) -> None:
        # N9: the message lists exactly CONDUCTOR_GIT.
        d = decide(_b("pr-train-conductor", "git remote -v"), CFG)
        assert d.reason is not None
        listed = d.reason.split("limited to git ", 1)[1].split(",", 1)[0]
        assert set(listed.split("/")) == CONDUCTOR_GIT

    @pytest.mark.parametrize("command", ["python3 -m mypy @args.txt", "python3 -m mypy src @a"])
    def test_mypy_argfile_blocked(self, command: str) -> None:
        # M1: an @file operand smuggles flags past the path-only rule.
        assert not decide(_b("repo-coder", command), CFG).allow, command


class TestFinalCoderWriteTargets:
    @pytest.mark.parametrize(
        "command",
        [
            "cp src/a.py docs/project-requirements.md",
            "sed -i s/a/b/ contracts/openapi.yaml",
            "tee service-manifest.json",
            "mv src/a.py /tmp/a.py",
            "ln -s /etc/passwd src/p",
            "install -m 644 src/a.py /usr/local/bin/a",
            "truncate -s 0 service-manifest.json",
            "dd of=contracts/x.yaml",
            "rsync -a src/ ../other/",
            "cp --target-directory=docs/x src/a.py",
            "sed -i.bak -e s/a/b/ docs/x.md",
            "cp src/../infra/a.tf src/a.tf",
        ],
    )
    def test_blocked(self, command: str) -> None:
        d = decide(_b("repo-coder", command), CFG)
        assert not d.allow and d.reason.startswith("Bash write outside src/ or tests/:"), command
        assert "Next:" in d.reason

    @pytest.mark.parametrize(
        "command",
        [
            "cp .claude/worktrees/u1/src/a.py .claude/worktrees/u1/src/b.py",
            "sed -i s/a/b/ .claude/worktrees/u1/src/a.py",
            "tee .claude/worktrees/u1/tests/out.txt",
            "mv .claude/worktrees/u1/src/a.py .claude/worktrees/u1/tests/a.py",
            "install -m 644 .claude/worktrees/u1/src/a.py .claude/worktrees/u1/src/b.py",
            "truncate -s 0 .claude/worktrees/u1/tests/out.txt",
            "sed -n 1p docs/x.md",
            "sed --in-place=.bak s/a/b/ .claude/worktrees/u1/src/a.py",
        ],
    )
    def test_allowed(self, command: str) -> None:
        assert decide(_b("repo-coder", command), CFG).allow, command

    @pytest.mark.parametrize(
        "command",
        [
            "cp src/a.py src/b.py",
            "sed -i s/a/b/ src/a.py",
            "tee tests/out.txt",
            "mv .claude/worktrees/u1/src/a.py tests/a.py",
            "install -m 644 src/a.py src/b.py",
            "truncate -s 0 tests/out.txt",
            "sed --in-place=.bak s/a/b/ src/a.py",
        ],
    )
    def test_main_checkout_blocked(self, command: str) -> None:
        # 0022: the same grammar aimed at the main checkout is refused.
        d = decide(_b("repo-coder", command), CFG)
        assert not d.allow and d.reason.startswith("Bash write outside src/ or tests/"), command


class TestFinalDataDir:
    @pytest.fixture(autouse=True)
    def _env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("CLAUDE_PLUGIN_DATA", DATA)

    @pytest.mark.parametrize("agent", [None, "repo-coder", "charter-docs", "contract-spec"])
    @pytest.mark.parametrize("tool", ["Write", "Edit", "MultiEdit"])
    def test_tool_writes_block_for_every_agent(self, agent: str | None, tool: str) -> None:
        d = decide(_w(agent, f"{DATA}/config.json", tool), CFG)
        assert not d.allow and "written by hooks only" in d.reason, (agent, tool)

    def test_notebook_edit_blocks(self) -> None:
        payload: dict[str, Any] = {
            "tool_name": "NotebookEdit",
            "tool_input": {"notebook_path": f"{DATA}/n.ipynb"},
            "cwd": CWD,
        }
        assert not decide(payload, CFG).allow

    def test_main_still_writes_elsewhere(self) -> None:
        assert decide(_w(None, f"{CWD}/docs/x.md"), CFG).allow

    def test_unset_env_leaves_main_write_alone(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("CLAUDE_PLUGIN_DATA")
        assert decide(_w(None, f"{DATA}/config.json"), CFG).allow

    @pytest.mark.parametrize(
        "command",
        [
            "echo {} > ~/.claude/plugins/data/daedalus-inline/config.json",
            "tee $CLAUDE_PLUGIN_DATA/config.json",
            "sed -i s/a/b/ ~/.claude/plugins/data/daedalus/config.json",
            "rm ~/.claude/plugins/data/daedalus-inline/audit/s.jsonl",
            f"mv {DATA}/audit/s.jsonl /tmp/y",
            "cp /tmp/f ${CLAUDE_PLUGIN_DATA}/config.json",
            f"truncate -s 0 {HOME}/.claude/plugins/data/daedalus/audit/s.jsonl",
            "python3 -c 'open(1)' ~/.claude/plugins/data/daedalus",
            f"cd {DATA} && rm audit/s.jsonl",
        ],
    )
    def test_main_bash_writes_block(self, command: str) -> None:
        d = decide(_b(None, command), CFG)
        assert not d.allow and "written by hooks only" in d.reason, command

    @pytest.mark.parametrize(
        "command",
        [
            "cat ~/.claude/plugins/data/daedalus-inline/audit/s.jsonl",
            "jq 'select(.seq > 3)' ~/.claude/plugins/data/daedalus-inline/audit/s.jsonl",
            "tail -n 5 $CLAUDE_PLUGIN_DATA/audit/s.jsonl",
            "cat ~/.claude/plugins/data/daedalus/audit/s.jsonl 2>/dev/null",
            f"jq -c . {DATA}/audit/s.jsonl | tail -n 3",
        ],
    )
    def test_main_bash_reads_allowed(self, command: str) -> None:
        assert decide(_b(None, command), CFG).allow, command


class TestProjectDataDir:
    # 0010: <repo>/.claude/daedalus is written by hooks only and never committed.
    P = f"{CWD}/.claude/daedalus"

    @pytest.mark.parametrize("agent", [None, "repo-coder", "charter-docs", "contract-spec"])
    @pytest.mark.parametrize("tool", ["Write", "Edit", "MultiEdit"])
    def test_tool_writes_block_for_every_agent(self, agent: str | None, tool: str) -> None:
        d = decide(_w(agent, f"{self.P}/config.json", tool), CFG)
        assert not d.allow and "<repo>/.claude/daedalus/config.json" in str(d.reason)

    @pytest.mark.parametrize(
        "path", [".claude/daedalus/config.json", "/elsewhere/wt/.claude/daedalus/audit/s.jsonl"]
    )
    def test_relative_and_other_worktree_paths_block(self, path: str) -> None:
        assert not decide(_w(None, path), CFG).allow, path

    def test_worktree_cwd_protects_main_repo_data_dir(self, repo_cwd: Path, tmp_path: Path) -> None:
        git = ["git", "-C", str(repo_cwd), "-c", "user.name=t", "-c", "user.email=t@x.invalid"]
        subprocess.run([*git, "commit", "-q", "--allow-empty", "-m", "i"], check=True)
        wt = tmp_path.resolve() / "wt"
        subprocess.run([*git, "worktree", "add", "-q", str(wt)], check=True)
        payload = {
            "tool_name": "Write",
            "tool_input": {"file_path": f"{repo_cwd}/.claude/daedalus/config.json"},
            "cwd": str(wt),
            "agent_type": "repo-coder",
        }
        assert not decide(payload, CFG).allow

    def test_sibling_claude_dir_write_allowed_for_main(self) -> None:
        assert decide(_w(None, f"{CWD}/.claude/settings.local.json"), CFG).allow

    @pytest.mark.parametrize(
        "command",
        [
            "echo {} > .claude/daedalus/config.json",
            f"tee {CWD}/.claude/daedalus/config.json",
            "rm .claude/daedalus/audit/s.jsonl",
            "mv .claude/daedalus /tmp/x",
            "cp /tmp/c.json .claude/daedalus/config.json",
            "sed -i s/a/b/ .claude/daedalus/config.json",
            "truncate -s 0 .claude/daedalus/audit/s.jsonl",
        ],
    )
    def test_main_bash_writes_block(self, command: str) -> None:
        d = decide(_b(None, command), CFG)
        assert not d.allow and "written by hooks only" in str(d.reason), command

    @pytest.mark.parametrize(
        "command",
        [
            "cat .claude/daedalus/audit/s.jsonl",
            "jq 'select(.seq > 3)' .claude/daedalus/audit/s.jsonl",
            "tail -n 5 .claude/daedalus/audit/s.jsonl 2>/dev/null",
            "ls -la .claude/daedalus",
        ],
    )
    def test_main_bash_reads_allowed(self, command: str) -> None:
        assert decide(_b(None, command), CFG).allow, command

    @pytest.mark.parametrize("agent", [None, "repo-coder", "boundary-tester", "pr-train-conductor"])
    @pytest.mark.parametrize(
        "command",
        [
            "git add .claude/daedalus/config.json",
            "git add -f .claude/daedalus",
            "git add ./.claude/daedalus/audit",
            f"git add {CWD}/.claude/daedalus/config.json",
            "git stage .claude/daedalus/config.json",
            "git commit -m x -- .claude/daedalus/config.json",
            "git commit -m x .claude/daedalus/config.json",
            "git -C .claude add daedalus",
            "git -C .claude/daedalus add config.json",
            "git add -- .claude/daedalus",
            "git add :/.claude/daedalus",
        ],
    )
    def test_git_add_commit_of_data_dir_blocks(self, agent: str | None, command: str) -> None:
        d = decide(_b(agent, command), CFG)
        assert not d.allow and "never committed" in str(d.reason), (agent, command)

    @pytest.mark.parametrize(
        "command",
        ["git add -f .", "git add --force .claude", "git add -f src/x*", "git add -Af :/"],
    )
    def test_main_forced_add_of_ancestor_or_glob_blocks(self, command: str) -> None:
        d = decide(_b(None, command), CFG)
        assert not d.allow and "never committed" in str(d.reason), command

    @pytest.mark.parametrize(
        "command",
        [
            "git add -A",
            "git add src/a.py",
            'git commit -m "keep .claude/daedalus out of git"',
            "git status --porcelain",
        ],
    )
    def test_ordinary_git_add_commit_allowed(self, command: str) -> None:
        assert decide(_b(None, command), CFG).allow, command
        # 0022: the coder runs the same command inside its unit worktree.
        assert decide(_b("repo-coder", f"git -C {WT} {command[4:]}"), CFG).allow, command

    @pytest.mark.parametrize(
        "command",
        [
            "cd .claude && echo x > daedalus/audit/s.jsonl",
            "echo x > .claude//daedalus/audit/s.jsonl",
            "echo x > ./.claude/./daedalus/audit/s.jsonl",
            "touch .claude/daedalus/x",
            "ln -sf /dev/null .claude/daedalus/config.json",
            "mkdir -p .claude/daedalus/audit",
            "chmod 777 .claude/daedalus",
            "install -m 600 /tmp/c .claude/daedalus/config.json",
            "cd /work/repo/.claude; rm daedalus/audit/s.jsonl",
        ],
    )
    def test_review_write_probes_block_for_main(self, command: str) -> None:
        d = decide(_b(None, command), CFG)
        assert not d.allow and "written by hooks only" in str(d.reason), command

    @pytest.mark.parametrize(
        "command",
        [
            "git update-index --add .claude/daedalus/config.json",
            "git update-index --force-add .claude//daedalus/config.json",
            "git update-index --add --cacheinfo 100644,abc123,.claude/daedalus/config.json",
            "git update-index --add --cacheinfo=100644,abc123,.claude/daedalus/config.json",
            "git update-index --add --stdin",
            "git update-index --index-info",
            "cd .claude && git add -f daedalus",
            "cd .claude && git update-index --add daedalus/config.json",
            "cd .claude/daedalus && git add -f config.json",
            "cd .claude/daedalus/audit && git add -f s.jsonl",
            "cd /work/repo/.claude/daedalus; git commit -m x -- config.json",
        ],
    )
    def test_review_git_probes_block_for_main(self, command: str) -> None:
        d = decide(_b(None, command), CFG)
        assert not d.allow and "never committed" in str(d.reason), command

    @pytest.mark.parametrize(
        "command",
        [
            "git stash -a",
            "git stash --all",
            "git stash -u",
            "git stash --include-untracked",
            "git stash push -u -m wip",
            "git stash save --include-untracked",
            "git stash push -ku",
            "git stash push --a",
            "git stash push --al",
            "git stash --a",
            "git stash push --i",
            "git stash push --inc",
            "git stash save --in",
        ],
    )
    def test_stash_of_untracked_blocks_for_main(self, command: str) -> None:
        d = decide(_b(None, command), CFG)
        assert not d.allow and "stash tracked changes only" in str(d.reason), command

    @pytest.mark.parametrize(
        "command",
        [
            "git stash",
            "git stash push -m x",
            "git stash push -m -u",
            "git stash push --keep-index",
            "git stash push --no-all",
            "git stash push --patch",
            "git stash list",
            "git stash pop",
            "cat .claude/daedalus/audit/s.jsonl",
            "cd .claude && ls",
            "cd src && touch a.py",
            "git update-index --refresh",
        ],
    )
    def test_review_benign_commands_allowed_for_main(self, command: str) -> None:
        assert decide(_b(None, command), CFG).allow, command


class TestFinalConductorGh:
    C = "pr-train-conductor"

    @pytest.mark.parametrize(
        "command",
        [
            "gh pr create --title x --body-file ~/.ssh/id_rsa",
            "gh pr create --title x --body-file /etc/passwd",
            "gh pr create -F ../secrets.md --title x",
            "gh pr edit 3 --body-file=/var/x/notes.md",
            "gh pr comment 3 --body-file -",
            "gh pr create --title x --body-file docs/.tmp/../../x.md",
            "gh -R o/r pr create --title x --body b",
            "gh pr comment 3 --repo o/r --body b",
            "gh pr edit 3 --repo=o/r --title t",
        ],
    )
    def test_blocked(self, command: str) -> None:
        d = decide(_b(self.C, command), CFG)
        assert not d.allow and "Next:" in d.reason, command

    def test_repo_flag_reason(self) -> None:
        d = decide(_b(self.C, "gh -R o/r pr create --title x --body b"), CFG)
        assert d.reason is not None and d.reason.startswith("the conductor works in the current")

    @pytest.mark.parametrize(
        "command",
        [
            "gh pr create --title x --body-file docs/.tmp/pr.md",
            "gh pr create --title x -F /tmp/pr.md",
            "gh pr comment 3 --body-file docs/.tmp/c.md",
            "gh -R o/r pr view 3",
        ],
    )
    def test_allowed(self, command: str) -> None:
        assert decide(_b(self.C, command), CFG).allow, command


class TestFinalSubagentAsMain:
    def test_agent_id_without_type_blocks(self) -> None:
        payload = _b(None, "git status")
        payload["agent_id"] = "a1b2c3"
        d = decide(payload, CFG)
        assert not d.allow and d.reason.startswith("a subagent may not run as main.")

    def test_agent_id_with_explicit_main_blocks(self) -> None:
        payload = _b("main", "git status")
        payload["agent_id"] = "a1b2c3"
        assert not decide(payload, CFG).allow

    def test_empty_agent_id_allows(self) -> None:
        payload = _b(None, "git status")
        payload["agent_id"] = ""
        assert decide(payload, CFG).allow

    def test_decision_carries_normalized_agent(self) -> None:
        assert decide(_b("daedalus:repo-coder", "git push origin x"), CFG).agent == "repo-coder"


# Fix wave after the whole-branch review (I1, I3, I4, M1).
def _git_init(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "init", "-q", "-b", "main"], cwd=path, check=True)
    return path.resolve()


def _wr(cwd: Path, path: Path, tool: str = "Write") -> dict[str, Any]:
    payload = _w("charter-docs", str(path), tool)
    payload["cwd"] = str(cwd)
    return payload


_MANIFEST_LEDGER = {
    "path": "docs/adr.md",
    "format": "markdown-table-row",
    "id_scheme": "{seq:04d}",
    "sequence_source": "last-row-id",
}


class TestFixWaveLedgerResolution:
    @pytest.mark.parametrize("tool", ["Write", "Edit"])
    def test_manifest_ledger_blocked(self, tmp_path: Path, tool: str) -> None:
        repo = _git_init(tmp_path / "repo")
        manifest = {"ledger": _MANIFEST_LEDGER}
        (repo / "service-manifest.json").write_text(json.dumps(manifest))
        d = decide(_wr(repo, repo / "docs" / "adr.md", tool), Config())
        assert not d.allow and d.reason is not None and "append_ledger.py" in d.reason
        assert decide(_wr(repo, repo / "docs" / "notes.md", tool), Config()).allow

    @pytest.mark.parametrize("tool", ["Write", "Edit"])
    def test_probed_ledger_blocked(self, tmp_path: Path, tool: str) -> None:
        repo = _git_init(tmp_path / "repo")
        (repo / "docs").mkdir()
        (repo / "docs" / "decisions.md").write_text("| Id | Date |\n|---|---|\n")
        d = decide(_wr(repo, repo / "docs" / "decisions.md", tool), Config())
        assert not d.allow and d.reason is not None and "append_ledger.py" in d.reason

    def test_default_ledger_protected_beside_a_declared_one(self, tmp_path: Path) -> None:
        repo = _git_init(tmp_path / "repo")
        (repo / "docs").mkdir()
        (repo / "docs" / "decisions.md").write_text("| Id | Date |\n|---|---|\n")
        cfg = Config(ledger=LedgerDecl(repo / "LEDGER.md", "heading-entry", "{seq}", "last-row-id"))
        assert not decide(_wr(repo, repo / "docs" / "decisions.md"), cfg).allow
        assert not decide(_wr(repo, repo / "LEDGER.md"), cfg).allow

    def test_config_ledger_still_blocked(self, tmp_path: Path) -> None:
        repo = _git_init(tmp_path / "repo")
        decl = LedgerDecl(repo / "docs" / "log.md", "markdown-table-row", "{seq}", "last-row-id")
        assert not decide(_wr(repo, repo / "docs" / "log.md"), Config(ledger=decl)).allow

    def test_no_ledger_nothing_protected(self, tmp_path: Path) -> None:
        repo = _git_init(tmp_path / "repo")
        assert decide(_wr(repo, repo / "docs" / "decisions.md"), Config()).allow

    @staticmethod
    def _probed(tmp_path: Path) -> Path:
        repo = _git_init(tmp_path / "repo")
        (repo / "docs" / ".tmp").mkdir(parents=True)
        (repo / "docs" / "decisions.md").write_text("| Id | Date |\n|---|---|\n")
        return repo

    def test_case_variant_spelling_blocked(self, tmp_path: Path) -> None:
        # FW-I1: casefold branch; Decisions.md does not exist as a separate file.
        repo = self._probed(tmp_path)
        target = repo / "docs" / "Decisions.md"
        if not target.exists():
            assert not decide(_wr(repo, target), Config()).allow
        else:
            assert os.path.samefile(target, repo / "docs" / "decisions.md")
            assert not decide(_wr(repo, target, "Edit"), Config()).allow

    def test_hardlink_to_ledger_blocked(self, tmp_path: Path) -> None:
        # FW-I1: samefile branch; an existing name that is the ledger's inode.
        repo = self._probed(tmp_path)
        alias = repo / "docs" / "alias.md"
        os.link(repo / "docs" / "decisions.md", alias)
        assert not decide(_wr(repo, alias, "Edit"), Config()).allow

    def test_symlink_to_ledger_blocked(self, tmp_path: Path) -> None:
        repo = self._probed(tmp_path)
        link = repo / "docs" / "link.md"
        link.symlink_to(repo / "docs" / "decisions.md")
        assert not decide(_wr(repo, link), Config()).allow

    def test_dotdot_path_to_ledger_blocked(self, tmp_path: Path) -> None:
        repo = self._probed(tmp_path)
        d = decide(_wr(repo, Path(f"{repo}/docs/.tmp/../decisions.md")), Config())
        assert not d.allow

    def test_other_doc_allowed_beside_ledger(self, tmp_path: Path) -> None:
        repo = self._probed(tmp_path)
        assert decide(_wr(repo, repo / "docs" / "other.md"), Config()).allow
        (repo / "docs" / "other.md").write_text("x")
        assert decide(_wr(repo, repo / "docs" / "other.md", "Edit"), Config()).allow

    def test_malformed_manifest_fails_closed_with_next(self, tmp_path: Path) -> None:
        repo = _git_init(tmp_path / "repo")
        (repo / "service-manifest.json").write_text("{not json")
        d = decide(_wr(repo, repo / "docs" / "notes.md"), Config())
        assert not d.allow and d.reason is not None
        assert "fail closed" in d.reason and "Next: fix the manifest syntax." in d.reason

    def test_append_ledger_cli_still_allowed(self, tmp_path: Path) -> None:
        repo = _git_init(tmp_path / "repo")
        (repo / "service-manifest.json").write_text(json.dumps({"ledger": _MANIFEST_LEDGER}))
        args = "--expected-seq 1 --entry-file docs/.tmp/e.md --repo BO --type PLT"
        payload = _b("charter-docs", f"python3 {REPO_ROOT}/scripts/append_ledger.py {args}")
        payload["cwd"] = str(repo)
        assert decide(payload, Config()).allow


class TestFixWaveConductorGh:
    C = "pr-train-conductor"

    @pytest.mark.parametrize(
        "command",
        [
            "gh pr create --title x --body b",
            "gh pr create --title x -b b",
            "gh pr create --title x --body=b",
            "gh pr create --title x -bb",
            "gh pr create --title x -db b",
            "gh pr create --title x --body-file docs/.tmp/pr.md --body b",
            "gh pr create --title x --body-file docs/.tmp/pr.md --body=b",
            "gh pr create --title x --body-file docs/.tmp/pr.md -bb",
            "gh pr edit 3 --body-file docs/.tmp/pr.md -db b",
            "gh pr create --title x",
            "gh pr edit 3 --body b",
            "gh pr edit 3 -b b",
            "gh pr edit 3 --body=b",
            "gh pr edit 3 --title t",
            "gh pr comment 3 --body b",
            "gh pr comment 3 -b b",
            "gh pr comment 3 --body=b",
            "gh pr comment 3",
        ],
    )
    def test_inline_body_blocked(self, command: str) -> None:
        d = decide(_b(self.C, command), CFG)
        assert not d.allow and d.reason is not None, command
        assert d.reason.startswith("gh pr create/edit/comment take the body only"), d.reason
        assert "Next: write the body to docs/.tmp/ and pass --body-file" in d.reason

    @pytest.mark.parametrize(
        "command",
        [
            "gh pr edit daedalus/T --base dev --body-file docs/.tmp/pr.md",
            "gh pr edit daedalus/T --base=dev --body-file docs/.tmp/pr.md",
            "gh pr edit daedalus/T -B dev --body-file docs/.tmp/pr.md",
            "gh pr edit daedalus/T -Bdev --body-file docs/.tmp/pr.md",
        ],
    )
    def test_edit_base_blocked(self, command: str) -> None:
        d = decide(_b(self.C, command), CFG)
        assert not d.allow and d.reason is not None, command
        assert d.reason.startswith("gh pr edit may not change the base branch.")
        assert "Next:" in d.reason

    @pytest.mark.parametrize(
        "command",
        [
            "gh pr create --base main --head daedalus/T --title x --body-file docs/.tmp/pr.md",
            "gh pr create --title x -F /tmp/pr.md",
            "gh pr create --title x --body-file=/tmp/pr.md",
            "gh pr edit daedalus/T --body-file docs/.tmp/pr.md",
            "gh pr comment 3 --body-file docs/.tmp/c.md",
            "gh pr comment 3 -F/tmp/c.md",
            "gh pr edit daedalus/T -F/tmp/Build-body.md",
            "gh pr view daedalus/T --json url",
        ],
    )
    def test_allowed(self, command: str) -> None:
        assert decide(_b(self.C, command), CFG).allow, command


class TestFixWaveGitleaksRedact:
    C = "pr-train-conductor"

    @pytest.mark.parametrize(
        "command",
        [
            'gitleaks detect --log-opts="abc..daedalus/T"',
            "gitleaks detect",
            "gitleaks detect --redact=50 --log-opts=abc..daedalus/T",
            "gitleaks detect --redact=0",
            "gitleaks detect --log-opts --redact",
        ],
    )
    def test_unredacted_blocked(self, command: str) -> None:
        d = decide(_b(self.C, command), CFG)
        assert not d.allow and d.reason is not None, command
        assert "Next: rerun it as gitleaks detect --redact" in d.reason

    @pytest.mark.parametrize(
        "command",
        [
            'gitleaks detect --redact --log-opts="abc..daedalus/T"',
            "gitleaks detect --log-opts=abc..daedalus/T --redact",
            "gitleaks detect --redact=100 --log-opts=abc..daedalus/T",
        ],
    )
    def test_redacted_allowed(self, command: str) -> None:
        assert decide(_b(self.C, command), CFG).allow, command


class TestFixWaveCharterDocsBash:
    @pytest.mark.parametrize(
        "command",
        [
            "git merge --no-ff x",
            "git merge --no-ff -m x b",
            "git -C /work/Charter add -A",
            "git add -A",
            "git add --all",
            "git add -u",
            "git add .",
            "git add ./",
            "git add docs/",
            "git add -- .",
            "git add docs/.",
            "git add :/",
            "git add -f docs/a.md",
            "git add",
            "git commit -am x",
            "git commit -F docs/.tmp/msg.txt",
            "git commit -m x -- docs/a.md",
            "git commit -q -m x",
            "git worktree list",
            "git branch",
            "git rev-parse HEAD",
            "mkdir -p docs/.tmp",
            "cat docs/a.md",
            "ls docs",
            "sha256sum x",
        ],
    )
    def test_blocked(self, command: str) -> None:
        d = decide(_b("charter-docs", command), CFG)
        assert not d.allow and d.reason is not None, command
        assert "Next:" in d.reason

    def test_reason_names_the_grammar(self) -> None:
        d = decide(_b("charter-docs", "git merge --no-ff x"), CFG)
        assert d.reason is not None and d.reason.startswith(
            "charter-docs Bash is limited to append_ledger.py, git add <path>, git commit -m,"
        )

    @pytest.mark.parametrize(
        "command",
        [
            "git add docs/decisions.md",
            "git add -- docs/a.md docs/b.md",
            "git commit -m x",
            "git status",
            "git log --oneline -3",
            "git diff --cached",
            "git -C /work/Charter add decision-log.md",
            "git -C /work/Charter commit -m x",
            "git -C /work/Charter status --porcelain",
            "git -C /work/Charter log -n 1",
            "git -C /work/Charter diff --stat",
        ],
    )
    def test_allowed(self, command: str) -> None:
        assert decide(_b("charter-docs", command), CFG).allow, command


def test_coder_writes_inside_a_unit_worktree() -> None:
    # 0022: the coder's cwd is the main checkout; its code dirs live in the unit worktree.
    assert decide(_w("repo-coder", f"{WT}/src/a.py"), CFG).allow
    assert decide(_w("repo-coder", f"{WT}/tests/test_a.py", "Edit"), CFG).allow
    assert decide(_b("repo-coder", f"cp {WT}/src/a.py {WT}/src/b.py"), CFG).allow


@pytest.mark.parametrize(
    "path",
    [
        f"{WT}/infra/a.tf",
        f"{WT}/README.md",
        f"{CWD}/.claude/worktrees/src/a.py",
        f"{CWD}/.claude/worktrees/x/../../daedalus/src/a.py",
        "/other/repo/.claude/worktrees/u1/src/a.py",
    ],
)
def test_coder_unit_worktree_outside_code_dirs_is_refused(path: str) -> None:
    assert not decide(_w("repo-coder", path), CFG).allow, path


def test_main_never_writes_unit_worktree_code() -> None:
    d = decide(_w(None, f"{WT}/src/a.py"), CFG)
    assert not d.allow and "Fable does not write application code" in str(d.reason)


def test_coder_restores_paths_inside_its_unit_worktree() -> None:
    assert decide(_b("repo-coder", f"git restore -- {WT}/src/a.py"), CFG).allow


def test_coder_cannot_write_the_main_checkout() -> None:
    # 0022: coders own a unit worktree; the main checkout is never their write target.
    assert not decide(_w("repo-coder", f"{CWD}/src/a.py"), CFG).allow
    assert not decide(_w("repo-coder", f"{CWD}/tests/test_a.py", "Edit"), CFG).allow
    assert not decide(_b("repo-coder", f"cp a {CWD}/src/b.py"), CFG).allow
    assert not decide(_b("repo-coder", f"git restore -- {CWD}/src/a.py"), CFG).allow


def test_coder_pathspec_resolves_against_git_dash_c() -> None:
    # 0022 P3: a relative pathspec names a path under the -C directory, else under cwd.
    assert decide(_b("repo-coder", f"git -C {WT} restore -- src/a.py"), CFG).allow
    assert decide(_b("repo-coder", f"git -C {WT} checkout -- tests/test_a.py"), CFG).allow
    assert not decide(_b("repo-coder", f"git -C {CWD} restore -- src/a.py"), CFG).allow
    assert not decide(_b("repo-coder", f"git -C {WT} restore -- ../../../src/a.py"), CFG).allow
    assert not decide(_b("repo-coder", f"git -C {WT} restore -- README.md"), CFG).allow
    assert decide(_b("repo-coder", f"git restore -- {WT}/src/a.py"), CFG).allow


def _unit_repo(path: Path) -> tuple[Path, Path]:
    repo = _git_init(path)
    git = ["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@t"]
    git += ["-c", "commit.gpgsign=false"]
    subprocess.run([*git, "commit", "-q", "--allow-empty", "-m", "init"], check=True)
    wt = repo / ".claude" / "worktrees" / "u1"
    subprocess.run([*git, "worktree", "add", "-q", "-b", "daedalus-unit/u1", str(wt)], check=True)
    return repo, wt.resolve()


def _cwd(payload: dict[str, Any], cwd: Path) -> dict[str, Any]:
    payload["cwd"] = str(cwd)
    return payload


def test_coder_unit_worktree_through_a_symlinked_root(tmp_path: Path) -> None:
    # 0022: a symlinked path to the repo and the real path resolve to one worktree base.
    repo, _ = _unit_repo(tmp_path / "real")
    link = tmp_path / "link"
    link.symlink_to(repo)
    for cwd, root in ((link, repo), (repo, link), (link, link)):
        payload = _w("repo-coder", f"{root}/.claude/worktrees/u1/src/a.py")
        payload["cwd"] = str(cwd)
        assert decide(payload, CFG).allow, (cwd, root)
        payload = _w("repo-coder", f"{root}/src/a.py")
        payload["cwd"] = str(cwd)
        assert not decide(payload, CFG).allow, (cwd, root)


@pytest.mark.parametrize(
    "command",
    [
        f"git -C {WT}/src restore -- :/README.md",
        f"git -C {WT}/src checkout -- :/",
        f"git -C {WT}/src restore -- ':(top)src/a.py'",
        f"git -C {WT} restore -- ':!src/a.py'",
        f"git -C {WT} add :/",
        f"git -C {WT} commit -m x -- :/",
    ],
)
def test_coder_pathspec_magic_is_refused(command: str) -> None:
    # 0022: :/ and :(top) are worktree-top relative; the jail cannot resolve them lexically.
    assert not decide(_b("repo-coder", command), CFG).allow, command


@pytest.mark.parametrize("agent", ["repo-coder", "contract-spec", "charter-docs"])
@pytest.mark.parametrize(
    "command",
    [
        f"export GIT_WORK_TREE={CWD}; git -C {WT} restore -- src/a.py",
        f"export GIT_DIR={CWD}/.git; git -C {WT} restore -- src/a.py",
        f"export GIT_WORK_TREE={CWD}; git -C {WT}/src restore -- :/src/a.py",
        f"declare -x FOO=1; tee {WT}/src/a.py",
        "typeset -x FOO=1",
        "readonly FOO=1",
        "export FOO",
        "set -a",
        "set -ea",
        "set -o allexport",
    ],
)
def test_worker_shell_variable_export_is_refused(agent: str, command: str) -> None:
    d = decide(_b(agent, command), CFG)
    assert not d.allow and "shell variables" in str(d.reason), (agent, command)


def test_coder_plain_unit_worktree_bash_write_still_allowed() -> None:
    assert decide(_b("repo-coder", f"tee {WT}/src/a.py"), CFG).allow
    assert decide(_b("repo-coder", "set -e"), CFG).allow


def test_coder_unregistered_worktree_dir_is_refused(tmp_path: Path) -> None:
    # 0022: only a git-registered worktree under .claude/worktrees is a unit worktree.
    repo, wt = _unit_repo(tmp_path / "repo")
    evil = repo / ".claude" / "worktrees" / "evil"
    (evil / "src").mkdir(parents=True)
    assert decide(_cwd(_w("repo-coder", f"{wt}/src/a.py"), repo), CFG).allow
    assert not decide(_cwd(_w("repo-coder", f"{evil}/src/a.py"), repo), CFG).allow
    assert not decide(_cwd(_b("repo-coder", f"tee {evil}/src/a.py"), repo), CFG).allow
    assert not decide(_w("repo-coder", f"{CWD}/.claude/worktrees/u2/src/a.py"), CFG).allow


@pytest.mark.parametrize(
    "command",
    [
        f"mkdir -p {CWD}/.claude/worktrees/evil/src",
        "mkdir -p .claude/worktrees/evil/src",
        "touch infra/a.tf",
        f"rm {CWD}/infra/a.tf",
        f"rmdir {CWD}/infra/x",
        f"unlink {CWD}/src/a.py",
        f"chmod 755 {CWD}/scripts/a.sh",
    ],
)
def test_coder_file_mutators_outside_unit_worktree_are_refused(command: str) -> None:
    assert not decide(_b("repo-coder", command), CFG).allow, command


@pytest.mark.parametrize(
    "command",
    [
        f"mkdir -p {WT}/src/pkg",
        f"touch {WT}/tests/__init__.py",
        f"rm {WT}/src/old.py",
        f"chmod 755 {WT}/src/run.py",
    ],
)
def test_coder_file_mutators_inside_unit_worktree_are_allowed(command: str) -> None:
    assert decide(_b("repo-coder", command), CFG).allow, command


@pytest.mark.parametrize(
    "command",
    [
        f"cd {CWD}/infra && tee .claude/worktrees/u1/src/a.py",
        "pushd /tmp && tee .claude/worktrees/u1/src/a.py",
        "cd /tmp && git restore -- .claude/worktrees/u1/src/a.py",
        "cd /tmp && git -C .claude/worktrees/u1 restore -- src/a.py",
        "cd /tmp; cp .claude/worktrees/u1/src/a.py .claude/worktrees/u1/src/b.py",
    ],
)
def test_coder_relative_write_after_cd_is_refused(command: str) -> None:
    # 0022: relative operands after cd resolve against the hook cwd, not the cd target.
    d = decide(_b("repo-coder", command), CFG)
    assert not d.allow and "absolute" in str(d.reason), command


@pytest.mark.parametrize(
    "command",
    [
        f"cd {WT} && tee {WT}/src/a.py",
        f"cd /tmp && git -C {WT} restore -- src/a.py",
        f"cd {WT} && python3 -m pytest -q",
    ],
)
def test_coder_absolute_write_after_cd_is_allowed(command: str) -> None:
    assert decide(_b("repo-coder", command), CFG).allow, command


def test_coder_cwd_inside_a_real_unit_worktree(tmp_path: Path) -> None:
    # 0022: a hook cwd of the worktree or its src/ still binds writes to that worktree.
    repo, wt = _unit_repo(tmp_path / "repo")
    (wt / "src").mkdir()
    for cwd in (wt, wt / "src"):
        assert decide(_cwd(_w("repo-coder", f"{wt}/src/a.py"), cwd), CFG).allow, cwd
        assert decide(_cwd(_w("repo-coder", f"{wt}/tests/t.py"), cwd), CFG).allow, cwd
        assert not decide(_cwd(_w("repo-coder", f"{repo}/src/a.py"), cwd), CFG).allow, cwd
        assert not decide(_cwd(_w("repo-coder", f"{wt}/README.md"), cwd), CFG).allow, cwd
    assert decide(_cwd(_w("repo-coder", "src/a.py"), wt), CFG).allow


@pytest.mark.parametrize("agent", ["repo-coder", "contract-spec", "charter-docs"])
@pytest.mark.parametrize(
    "command",
    [
        f"hash pytest=/bin/rm; pytest {CWD}/infra/a.tf",
        "hash -p /bin/rm pytest; pytest x",
        f"alias git=tee; git -C {WT} status",
        "unalias ls",
        "unset PATH; git status",
        "shopt -s expand_aliases",
        "enable -n test",
        "setopt aliases",
        "unsetopt hashcmds",
        "builtin cd /tmp",
        "command rm x",
        "eval ls",
        "exec ls",
        "source x.sh",
        ". x.sh",
    ],
)
def test_worker_shell_state_builtins_are_refused(agent: str, command: str) -> None:
    # 0022: a builtin that rebinds what a later segment runs voids every later check.
    assert not decide(_b(agent, command), CFG).allow, (agent, command)


def test_coder_plain_git_status_in_unit_worktree_allowed() -> None:
    assert decide(_b("repo-coder", f"git -C {WT} status"), CFG).allow


@pytest.mark.parametrize(
    "command",
    [
        "mkdir newdir",
        "touch NEWFILE",
        "mkdir -m 700 infra2",
        f"chown x {CWD}/infra/a.tf",
        f"chgrp x {CWD}/infra/a.tf",
        f"chown x:y {WT}/src/a.py {CWD}/infra/a.tf",
        f"install --mode=644 {WT}/src/a.py {CWD}/bin/a",
        f"find {CWD}/infra -delete",
        f"find {WT}/src -exec rm {{}} +",
        f"find {WT}/src -fprint {CWD}/x",
    ],
)
def test_coder_bare_and_owner_operands_are_paths(command: str) -> None:
    # 0022: every non-option operand of a coder write command is a path, no heuristic.
    assert not decide(_b("repo-coder", command), CFG).allow, command


@pytest.mark.parametrize(
    "command",
    [
        f"mkdir {WT}/src/pkg",
        f"mkdir -m 700 {WT}/src/pkg",
        f"touch {WT}/tests/__init__.py",
        f"chown x {WT}/src/a.py",
        f"chmod 755 {WT}/src/a.py",
        f"install -m 644 -o x {WT}/src/a.py {WT}/src/b.py",
        f"install --mode=644 {WT}/src/a.py {WT}/src/b.py",
        f"truncate -s 0 {WT}/tests/out.txt",
        f"find {WT}/src -name '*.py'",
    ],
)
def test_coder_unit_worktree_operands_allowed(command: str) -> None:
    assert decide(_b("repo-coder", command), CFG).allow, command


@pytest.mark.parametrize(
    "command",
    [
        "git add -A",
        "git add .",
        "git add -- src/a.py",
        "git commit -m x",
        "git commit -a -m x",
        f"git -C {CWD} add -A",
        f"git -C {CWD}/.claude/worktrees/evil commit -m x",
        f"cd {CWD}/.claude/worktrees/u1 && git commit -a -m x",
    ],
)
def test_coder_add_and_commit_outside_unit_worktree_refused(command: str) -> None:
    # 0022: staging or committing in the main checkout lands on the main branch.
    assert not decide(_b("repo-coder", command), CFG).allow, command


@pytest.mark.parametrize(
    "command",
    [
        f"git -C {WT} add -A",
        f"git -C {WT} add -- {WT}/src/a.py",
        f"git -C {WT} commit -m 'WIP: yield'",
        f"git -C {WT}/src commit -m x",
    ],
)
def test_coder_add_and_commit_in_unit_worktree_allowed(command: str) -> None:
    assert decide(_b("repo-coder", command), CFG).allow, command


def test_coder_add_and_commit_with_cwd_in_real_unit_worktree(tmp_path: Path) -> None:
    repo, wt = _unit_repo(tmp_path / "repo")
    assert decide(_cwd(_b("repo-coder", "git add -A"), wt), CFG).allow
    assert decide(_cwd(_b("repo-coder", "git commit -m x"), wt), CFG).allow
    assert not decide(_cwd(_b("repo-coder", "git add -A"), repo), CFG).allow
