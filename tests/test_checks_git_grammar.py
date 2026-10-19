# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0044: the git_grammar hook; cases copied from tests/test_jail.py run each agent's chain.
from __future__ import annotations

import subprocess
from pathlib import Path

import pytest
from lib import jail
from lib.config import Config
from lib.shell import CONDUCTOR_GIT

from tests.conftest import CFG, CWD, TRAIN_BRANCH, WT
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
from tests.test_checks_git_push import audited_train
from tests.test_jail import BASH_AGENTS, _b

pytestmark = pytest.mark.usefixtures("jail_fakes")
HOOK = "git_grammar"


@pytest.mark.parametrize("agent", BASH_AGENTS)
def test_plain_git_diff_is_allowed_baseline(agent: str | None) -> None:
    assert decide(_b(agent, "git diff"), CFG).allow


class TestRound3Breakage:
    def test_quoted_separators_in_commit_message(self) -> None:
        for command in (
            f"git -C {WT} commit -m 'fix: a; b'",
            f"git -C {WT} commit -m 'a > b'",
            f"git -C {WT} commit -m 'a | b && c'",
            f"git -C {WT} commit -m 'cost: $5'",
            f"git -C {WT} commit -m 'fix curl handling'",
        ):
            assert decide(_b("repo-coder", command), CFG).allow, command


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
            ("repo-coder", "CI=1 npm test"),
        ],
    )
    def test_allowed(self, agent: str, command: str) -> None:
        assert decide(_b(agent, command), CFG).allow, (agent, command)

    @pytest.mark.parametrize(
        ("agent", "command"),
        [
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


class TestFixWaveCharterDocsBash:
    def test_reason_names_the_grammar(self) -> None:
        d = decide(_b("charter-docs", "git merge --no-ff x"), CFG)
        assert d.reason is not None and d.reason.startswith(
            "charter-docs Bash is limited to append_ledger.py, git add <path>, git commit -m,"
        )


def test_coder_pathspec_resolves_against_git_dash_c() -> None:
    # 0022: a relative pathspec names a path under the -C directory, else under cwd.
    assert decide(_b("repo-coder", f"git -C {WT} restore -- src/a.py"), CFG).allow
    assert decide(_b("repo-coder", f"git -C {WT} checkout -- tests/test_a.py"), CFG).allow
    assert not decide(_b("repo-coder", f"git -C {CWD} restore -- src/a.py"), CFG).allow
    assert not decide(_b("repo-coder", f"git -C {WT} restore -- ../../../src/a.py"), CFG).allow
    assert decide(_b("repo-coder", f"git -C {WT} restore -- README.md"), CFG).allow
    assert decide(_b("repo-coder", f"git restore -- {WT}/src/a.py"), CFG).allow


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


def test_coder_plain_git_status_in_unit_worktree_allowed() -> None:
    assert decide(_b("repo-coder", f"git -C {WT} status"), CFG).allow


def test_git_grammar_judges_the_hook_alone() -> None:
    coder = ("--allow", "coder")
    assert evaluate(HOOK, _b("repo-coder", "git merge x"), *coder) == jail.R_CODER_GIT
    assert evaluate(HOOK, _b("repo-coder", "git status && ls -la"), *coder) is None
    assert evaluate(HOOK, _b("charter-docs", "git add -A"), "--allow", "docs") == jail.R_DOCS_BASH
    conductor = ("--allow", "conductor")
    assert evaluate(HOOK, _b("pr-train-conductor", "git push origin x"), *conductor) is None
    assert evaluate(HOOK, _b("x", "git fetch"), *conductor) == jail.R_CONDUCTOR_BASH
    assert evaluate(HOOK, _b("x", "git add x"), "--allow", "read-only") == jail.R_AUDITOR_BASH
    assert evaluate(HOOK, _b("x", "git branch"), "--allow", "specialist") == jail.R_SPECIALIST_BASH
    assert evaluate(HOOK, _b("x", "git status")) is not None


def test_git_grammar_fixture_decisions() -> None:
    merge = payload("Bash", command="git merge x")
    want = {"decision": "deny", "reason": jail.R_CODER_GIT}
    assert run_script(HOOK, merge, "--allow", "coder") == want
    status = payload("Bash", command="git status")
    assert run_script(HOOK, status, "--allow", "coder") == {"decision": "allow", "reason": ""}
    bad = run_script(HOOK, status, "--allow", "everything")
    assert bad["decision"] == "deny" and bad["reason"].startswith("hook git_grammar failed closed")


def test_git_grammar_allows_tools_outside_its_tools() -> None:
    outside_tools_allow(HOOK, "Write", "--allow", "coder")


def test_git_grammar_unknown_flag_denies() -> None:
    unknown_flag_denies(HOOK, payload("Bash", command="git status"))


def test_git_grammar_malformed_input_denies() -> None:
    malformed_input_denies(HOOK, "--allow", "coder")


def test_git_grammar_internal_error_denies_and_names_the_hook() -> None:
    internal_error_denies(HOOK, payload("Bash", command="git status"), "--allow", "coder")


C = "pr-train-conductor"
SLUG = "acme/charter"
CHARTER_BODY = f"--body-file {CWD}/docs/.tmp/daedalus/20261015-120000-charter-pr.md"


def _charter(tmp_path: Path, url: str = f"https://github.com/{SLUG}.git") -> Path:
    charter = tmp_path / "Charter"
    subprocess.run(["git", "init", "-q", str(charter)], check=True)
    subprocess.run(["git", "-C", str(charter), "remote", "add", "origin", url], check=True)
    return charter


def _pr_create(repo: str, head: str = TRAIN_BRANCH) -> str:
    return f"gh pr create {repo} --base main --head {head} --title t {CHARTER_BODY}"


@pytest.mark.parametrize("command", ["git push origin HEAD", "git push -u origin HEAD"])
def test_push_refuses_head_as_the_refspec(command: str) -> None:
    # issue 11: HEAD is refused by name, whatever it resolves to.
    d = decide(_b(C, command), CFG)
    assert not d.allow and d.reason == jail.R_CONDUCTOR_PUSH_HEAD, command
    assert "Next:" in d.reason
    assert decide(_b(C, "git push origin head"), CFG).reason == jail.R_CONDUCTOR_PUSH_HEAD


@pytest.mark.parametrize(
    "branch", ["feat/x", "daedalus/20261015-120001", "daedalus/20261015-120000/x", "DAEDALUS/x"]
)
def test_push_refuses_a_refspec_other_than_the_train_branch(branch: str) -> None:
    # issue 11: the one branch the conductor pushes is the active train's integration branch.
    d = decide(_b(C, f"git push -u origin {branch}"), CFG)
    assert not d.allow and d.reason == jail.R_CONDUCTOR_PUSH_BRANCH.format(branch=TRAIN_BRANCH)
    assert f"Next: `git push -u origin {TRAIN_BRANCH}`." in d.reason


@pytest.mark.parametrize(
    "command",
    [
        f"git push -u origin {TRAIN_BRANCH}",
        f"git push --set-upstream origin {TRAIN_BRANCH}",
        f"git push origin {TRAIN_BRANCH}",
    ],
)
def test_push_admits_the_train_branch(command: str) -> None:
    d = decide(_b(C, command), CFG)
    assert d.allow, d.reason


def test_push_reads_the_branch_from_the_train_marker(repo_cwd: Path, project_data: Path) -> None:
    # issue 11: the active train is the id on the first line of the train marker.
    def push(branch: str) -> jail.Decision:
        return decide({**_b(C, f"git push -u origin {branch}"), "cwd": str(repo_cwd)}, Config())

    assert push(TRAIN_BRANCH).reason == jail.R_CONDUCTOR_NO_TRAIN
    audited_train(repo_cwd, "20261016-120000")
    assert push("daedalus/20261016-120000").allow
    refused = push(TRAIN_BRANCH)
    assert refused.reason == jail.R_CONDUCTOR_PUSH_BRANCH.format(branch="daedalus/20261016-120000")


@pytest.mark.parametrize("flag", ["-u", "--set-upstream"])
def test_conductor_pushes_the_charter_branch_when_a_charter_root_is_declared(
    tmp_path: Path, flag: str
) -> None:
    # 0078: the charter root's train branch, pushed after the code pull request.
    charter = _charter(tmp_path)
    d = decide(_b(C, f"git -C {charter} push {flag} origin {TRAIN_BRANCH}"), Config(charter))
    assert d.allow, d.reason


def test_conductor_charter_push_refused_without_a_declared_charter_root(tmp_path: Path) -> None:
    # 0078: without charter_root in config.json neither charter form runs.
    charter = _charter(tmp_path)
    push = decide(_b(C, f"git -C {charter} push -u origin {TRAIN_BRANCH}"), Config())
    assert not push.allow and push.reason == jail.R_CONDUCTOR_CHARTER
    assert "Next:" in push.reason
    pr = decide(_b(C, _pr_create(f"--repo {SLUG}")), Config())
    assert not pr.allow and pr.reason == jail.R_CONDUCTOR_REPO


def test_conductor_grammar_admits_dash_c_only_for_the_charter_root(tmp_path: Path) -> None:
    # 0078: -C names the declared charter root exactly, and only on the train branch push.
    charter = _charter(tmp_path)
    other = tmp_path / "other"
    other.mkdir()
    cfg = Config(charter)
    for command in (
        f"git -C {other} push -u origin {TRAIN_BRANCH}",
        f"git -C {charter}/sub push -u origin {TRAIN_BRANCH}",
        f"git -C {charter} -C . push -u origin {TRAIN_BRANCH}",
        f"git --no-pager -C {charter} push -u origin {TRAIN_BRANCH}",
        f"git -C {CWD} push -u origin {TRAIN_BRANCH}",
    ):
        d = decide(_b(C, command), cfg)
        assert not d.allow and d.reason == jail.R_CONDUCTOR_CHARTER, command
    head = decide(_b(C, f"git -C {charter} push -u origin HEAD"), cfg)
    assert head.reason == jail.R_CONDUCTOR_PUSH_HEAD
    foreign = decide(_b(C, f"git -C {charter} push -u origin feat/x"), cfg)
    assert foreign.reason == jail.R_CONDUCTOR_PUSH_BRANCH.format(branch=TRAIN_BRANCH)
    for sub in ("status", "log", "diff", "branch", "add x", "commit -m x", "rev-parse HEAD"):
        assert not decide(_b(C, f"git -C {charter} {sub}"), cfg).allow, sub
    # 0078: a charter nested in the repo is still out of reach for every other subcommand.
    nested = Config(Path(f"{CWD}/docs/private"))
    for sub in ("status", "log", "add x", "commit -m x"):
        d = decide(_b(C, f"git -C {CWD}/docs/private {sub}"), nested)
        assert not d.allow and d.reason == jail.R_CONDUCTOR_CHARTER, sub
    assert decide(_b(C, f"git -C {CWD}/docs status"), nested).allow
    assert decide(_b(C, f"git -C {CWD}/docs/private push -u origin {TRAIN_BRANCH}"), nested).allow


def test_conductor_charter_pr_create_targets_only_the_charter_remote(tmp_path: Path) -> None:
    # 0078: --repo is admitted on gh pr create only, naming the charter root's origin.
    cfg = Config(_charter(tmp_path))
    for repo in (f"--repo {SLUG}", f"-R {SLUG}", f"--repo={SLUG}"):
        d = decide(_b(C, _pr_create(repo)), cfg)
        assert d.allow, (repo, d.reason)
    assert decide(_b(C, _pr_create(f"--repo {SLUG}").replace("--head", "-H")), cfg).allow
    for command in (
        _pr_create("--repo acme/other"),
        _pr_create(f"--repo {SLUG.upper()}"),
        _pr_create(f"-R{SLUG}"),
        _pr_create(f"--repo {SLUG} -R acme/other"),
        _pr_create(f"--repo {SLUG} -dR acme/other"),
        _pr_create(f"--repo {SLUG}", head="feat/x"),
        _pr_create(f"--repo {SLUG}", head="HEAD"),
        _pr_create(f"--repo {SLUG}", head=f"{TRAIN_BRANCH} --head feat/x"),
        f"gh pr create --repo {SLUG} --base main --title t {CHARTER_BODY}",
        f"gh pr edit {TRAIN_BRANCH} --repo {SLUG} {CHARTER_BODY}",
        f"gh pr comment 3 --repo {SLUG} {CHARTER_BODY}",
        f"gh pr create -dR {SLUG} --base main --head feat/x --title t {CHARTER_BODY}",
    ):
        d = decide(_b(C, command), cfg)
        assert not d.allow and "Next:" in str(d.reason), command
        if " pr create " in command:
            assert d.reason == jail.R_CONDUCTOR_REPO, command
    assert decide(_b(C, _pr_create("")), cfg).allow


@pytest.mark.parametrize(
    ("url", "slug"),
    [
        ("https://github.com/acme/charter.git", "acme/charter"),
        ("https://github.com/acme/charter", "acme/charter"),
        ("https://x-access-token:secret@github.com/acme/charter.git", "acme/charter"),
        ("git@github.com:acme/charter.git", "acme/charter"),
        ("ssh://git@github.com/acme/charter.git", "acme/charter"),
        ("https://ghe.example.com/acme/charter.git", "ghe.example.com/acme/charter"),
        ("/srv/git/charter.git", None),
        ("https://github.com/acme/charter/extra", None),
    ],
)
def test_charter_remote_slug_forms(url: str, slug: str | None) -> None:
    # 0078: the slug gh --repo must equal, derived from the charter root's origin URL.
    assert jail._remote_slug(url) == slug


def test_charter_pr_create_refusal_never_prints_the_remote(tmp_path: Path) -> None:
    url = f"https://x-access-token:secret@github.com/{SLUG}.git"
    cfg = Config(_charter(tmp_path, url))
    assert decide(_b(C, _pr_create(f"--repo {SLUG}")), cfg).allow
    d = decide(_b(C, _pr_create("--repo acme/other")), cfg)
    assert "secret" not in str(d.reason) and "github.com" not in str(d.reason)
