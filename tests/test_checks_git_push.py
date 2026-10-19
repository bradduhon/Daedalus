# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0044: the git_push hook; cases copied from tests/test_jail.py run each agent's chain.
from __future__ import annotations

from pathlib import Path

import pytest
from lib import jail

from tests.conftest import CFG, TRAIN_BRANCH, write_train_marker
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
from tests.test_jail import _b

pytestmark = pytest.mark.usefixtures("jail_fakes")
HOOK = "git_push"
C = "pr-train-conductor"


def test_bare_repo_coder_unchanged() -> None:
    assert decide(_b("repo-coder", "pytest -q"), CFG).allow
    assert not decide(_b("repo-coder", "git push origin x"), CFG).allow


class TestRound3ConductorPushGrammar:
    @pytest.mark.parametrize(
        "command",
        [
            f"git push -u origin {TRAIN_BRANCH}",
            f"git push --set-upstream origin {TRAIN_BRANCH}",
            f"git push origin {TRAIN_BRANCH}",
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


class TestFinalRemotePlumbing:
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


def test_git_push_judges_the_hook_alone() -> None:
    assert evaluate(HOOK, _b("repo-coder", "git fetch")) == jail.R_REMOTE_GIT
    assert evaluate(HOOK, _b("repo-coder", "git stash push -m x")) is None
    assert evaluate(HOOK, _b("repo-coder", "find . -exec git push {} +")) == jail.R_REMOTE_GIT
    assert evaluate(HOOK, _b(C, f"git push origin {TRAIN_BRANCH}"), "--conductor") is None
    assert evaluate(HOOK, _b(C, "git push origin x y"), "--conductor") == jail.R_CONDUCTOR_PUSH
    assert evaluate(HOOK, _b(C, "git push origin feat/x")) == jail.R_REMOTE_GIT


def test_git_push_fixture_decisions(tmp_path: Path) -> None:
    # issue 11: the standalone script reads the branch from a real train marker.
    write_train_marker(tmp_path)
    push = payload("Bash", str(tmp_path), command="git push origin daedalus/20261017-120000")
    assert run_script(HOOK, push) == {"decision": "deny", "reason": jail.R_REMOTE_GIT}
    assert run_script(HOOK, push, "--conductor") == {"decision": "allow", "reason": ""}
    extra = payload("Bash", command="git push origin feat/x extra")
    want = {"decision": "deny", "reason": jail.R_CONDUCTOR_PUSH}
    assert run_script(HOOK, extra, "--conductor") == want


def test_git_push_allows_tools_outside_its_tools() -> None:
    outside_tools_allow(HOOK, "Write")


def test_git_push_unknown_flag_denies() -> None:
    unknown_flag_denies(HOOK, payload("Bash", command="git status"))


def test_git_push_malformed_input_denies() -> None:
    malformed_input_denies(HOOK, "--conductor")


def test_git_push_internal_error_denies_and_names_the_hook() -> None:
    internal_error_denies(HOOK, payload("Bash", command="git status"))
