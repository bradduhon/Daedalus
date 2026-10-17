# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0044: the read_only_bash hook; cases copied from tests/test_jail.py run each agent's chain.
from __future__ import annotations

import pytest
from lib import jail

from tests.conftest import CFG
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
from tests.test_jail import _b

pytestmark = pytest.mark.usefixtures("jail_fakes")
HOOK = "read_only_bash"


class TestReadOnlyAgents:
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


class TestRound3Breakage:
    def test_quoted_filters_allowed(self) -> None:
        assert decide(_b("security-auditor", "jq '.[] | .name' x.json"), CFG).allow
        assert decide(_b("security-auditor", "rg 'foo|bar' src"), CFG).allow
        assert decide(_b("nist-specialist", "jq -r '.controls[] | .id' c.json"), CFG).allow
        assert decide(_b("security-auditor", "grep -n 'a;b' x"), CFG).allow
        assert decide(_b("security-auditor", "grep -n '$x' src"), CFG).allow


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


def test_read_only_bash_judges_the_hook_alone() -> None:
    ro = ("--git", "read-only")
    assert evaluate(HOOK, _b("x", "git log | head"), *ro) is None
    assert evaluate(HOOK, _b("x", "git push"), *ro) == jail.R_AUDITOR_BASH
    assert evaluate(HOOK, _b("x", "git log"), "--git", "specialist") is None
    assert evaluate(HOOK, _b("x", "git status"), "--git", "specialist") == jail.R_SPECIALIST_BASH
    want = "Bash is limited to read-only inspection and git add, commit, diff, log, status."
    assert str(evaluate(HOOK, _b("x", "git push"), "--git", "docs")).startswith(want)
    assert evaluate(HOOK, _b("x", "cat x")) is None
    assert evaluate(HOOK, _b("x", "git log")) is not None


def test_read_only_bash_declares_no_test_runner_flag() -> None:
    # 0051: --test-runner is reserved for unit 3.1 and is not declared in group 1.
    assert set(load(HOOK).FLAGS) == {"--git"}


def test_read_only_bash_fixture_decisions() -> None:
    log = payload("Bash", command="git log --oneline -3 | head")
    assert run_script(HOOK, log, "--git", "read-only") == {"decision": "allow", "reason": ""}
    rm = payload("Bash", command="rm x")
    want = {"decision": "deny", "reason": jail.R_AUDITOR_BASH}
    assert run_script(HOOK, rm, "--git", "read-only") == want
    status = payload("Bash", command="git status")
    want = {"decision": "deny", "reason": jail.R_SPECIALIST_BASH}
    assert run_script(HOOK, status, "--git", "specialist") == want


def test_read_only_bash_allows_tools_outside_its_tools() -> None:
    outside_tools_allow(HOOK, "Write", "--git", "read-only")


def test_read_only_bash_unknown_flag_denies() -> None:
    unknown_flag_denies(HOOK, payload("Bash", command="ls"))


def test_read_only_bash_malformed_input_denies() -> None:
    malformed_input_denies(HOOK, "--git", "read-only")


def test_read_only_bash_internal_error_denies_and_names_the_hook() -> None:
    internal_error_denies(HOOK, payload("Bash", command="ls"), "--git", "read-only")
