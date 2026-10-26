# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0044: the git_push hook; cases copied from tests/test_jail.py run each agent's chain.
from __future__ import annotations

from pathlib import Path

import pytest
from lib import jail, train_state

from tests.conftest import CFG, TRAIN_BRANCH
from tests.conftest import git as _git
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
from tests.jail_cases import (
    GATE_BRANCH,
    GATE_NEXT,
    GATE_TRAIN,
    LEDGER,
    _ledger_commit,
    approve,
    audited_train,
    move_tip,
    seed_train,
)
from tests.payloads import _b
from tests.test_operator_gates import GATE_KEY, exempt_round

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


def test_git_push_fixture_decisions(repo_cwd: Path) -> None:
    # issue 11, spec 4.2: the standalone script reads the branch and verdict of a real train.
    audited_train(repo_cwd, "20261017-120000")
    push = payload("Bash", str(repo_cwd), command="git push origin daedalus/20261017-120000")
    assert run_script(HOOK, push) == {"decision": "deny", "reason": jail.R_REMOTE_GIT}
    assert run_script(HOOK, push, "--conductor") == {"decision": "allow", "reason": ""}
    extra = payload("Bash", command="git push origin feat/x extra")
    want = {"decision": "deny", "reason": jail.R_CONDUCTOR_PUSH}
    assert run_script(HOOK, extra, "--conductor") == want


def _conductor_push(repo: Path, branch: str = GATE_BRANCH) -> str | None:
    hook_input: dict[str, object] = {
        "tool_name": "Bash",
        "tool_input": {"command": f"git push -u origin {branch}"},
        "cwd": str(repo),
        "agent_type": C,
    }
    return evaluate(HOOK, hook_input, "--conductor")


def test_push_with_no_verdict_is_refused(repo_cwd: Path) -> None:
    seed_train(repo_cwd, state=False)
    missing = _conductor_push(repo_cwd)
    assert missing is not None and missing.endswith(GATE_NEXT) and "no train state" in missing
    train_state.save(repo_cwd, GATE_TRAIN, {"train_id": GATE_TRAIN})
    none = _conductor_push(repo_cwd)
    assert none is not None and none.endswith(GATE_NEXT) and "no verdict" in none
    tip = _git(repo_cwd, "rev-parse", GATE_BRANCH).stdout.strip()
    rejected = {"status": "rejected", "tip": tip, "round": 2, "seq": 9}
    train_state.update(repo_cwd, GATE_TRAIN, verdict=rejected)
    refused = _conductor_push(repo_cwd)
    assert refused is not None and "rejected" in refused and refused.endswith(GATE_NEXT)


def test_push_with_a_moved_tip_is_refused(repo_cwd: Path) -> None:
    approve(repo_cwd, seed_train(repo_cwd))
    moved = move_tip(repo_cwd)
    reason = _conductor_push(repo_cwd)
    assert reason is not None and reason.endswith(GATE_NEXT) and moved[:12] in reason


def test_push_with_the_approved_tip_is_allowed(repo_cwd: Path) -> None:
    approve(repo_cwd, seed_train(repo_cwd))
    assert _conductor_push(repo_cwd) is None
    hook_input = {
        "tool_name": "Bash",
        "tool_input": {"command": f"git push -u origin {GATE_BRANCH}"},
        "cwd": str(repo_cwd),
        "agent_type": C,
    }
    assert decide(hook_input, CFG).allow


def test_push_naming_another_branch_at_the_approved_tip_is_refused(repo_cwd: Path) -> None:
    # spec 4.2: the tip read is the marker's train branch; another branch never stands in.
    approve(repo_cwd, seed_train(repo_cwd))
    _git(repo_cwd, "branch", "feat/x", GATE_BRANCH)
    reason = _conductor_push(repo_cwd, "feat/x")
    assert reason == jail.R_CONDUCTOR_PUSH_BRANCH.format(branch=GATE_BRANCH)


def test_push_with_every_finding_exempted_on_the_tip_is_allowed(repo_cwd: Path) -> None:
    # 0133: a rejected round passes once each of its findings carries an exemption.
    old = seed_train(repo_cwd)
    exempt_round(repo_cwd, GATE_TRAIN, old)
    assert _conductor_push(repo_cwd) is None
    blank = {"ledger_id": "", "tip": old, "tracking": "issue"}
    train_state.update(repo_cwd, GATE_TRAIN, exemptions={"1": {GATE_KEY: blank}})
    assert _conductor_push(repo_cwd) is not None
    exempt_round(repo_cwd, GATE_TRAIN, old)
    move_tip(repo_cwd)
    stale = _conductor_push(repo_cwd)
    assert stale is not None and stale.endswith(GATE_NEXT)


def test_push_after_the_single_ledger_commit_is_allowed(repo_cwd: Path) -> None:
    # 59, spec 3.5: the verdict covers the judged tip; the train's ledger commit on it passes.
    approve(repo_cwd, seed_train(repo_cwd))
    _ledger_commit(repo_cwd, LEDGER)
    assert _conductor_push(repo_cwd) is None


@pytest.mark.parametrize("paths", [(LEDGER, "src/app.py"), ("src/app.py",)], ids=str)
def test_push_after_a_commit_beyond_the_ledger_is_refused(
    repo_cwd: Path, paths: tuple[str, ...]
) -> None:
    approve(repo_cwd, seed_train(repo_cwd))
    moved = _ledger_commit(repo_cwd, *paths)
    reason = _conductor_push(repo_cwd)
    assert reason is not None and reason.endswith(GATE_NEXT) and moved[:12] in reason
    assert "with a commit that changes more than the ledger" in reason


def test_push_after_two_ledger_commits_is_refused(repo_cwd: Path) -> None:
    approve(repo_cwd, seed_train(repo_cwd))
    _ledger_commit(repo_cwd, LEDGER)
    (repo_cwd / LEDGER).write_text("second row\n", encoding="utf-8")
    _git(repo_cwd, "commit", "-q", "-am", "second ledger")
    reason = _conductor_push(repo_cwd)
    assert reason is not None and "is not one plain commit on top of it" in reason


def test_git_push_allows_tools_outside_its_tools() -> None:
    outside_tools_allow(HOOK, "Write")


def test_git_push_unknown_flag_denies() -> None:
    unknown_flag_denies(HOOK, payload("Bash", command="git status"))


def test_git_push_malformed_input_denies() -> None:
    malformed_input_denies(HOOK, "--conductor")


def test_git_push_internal_error_denies_and_names_the_hook() -> None:
    internal_error_denies(HOOK, payload("Bash", command="git status"))
