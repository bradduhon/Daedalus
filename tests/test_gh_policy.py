# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import shlex
from pathlib import Path
from typing import Any

import pytest
from lib.config import Config
from lib.gh_policy import classify, gh_reason
from lib.jail import decide

AGENTS = ("main", "pr-train-conductor", "repo-coder", "general-purpose")
MERGE = [
    "gh pr merge 5",
    "gh pr merge --auto 5",
    "gh api -X PUT repos/o/r/pulls/5/merge",
    "gh api graphql -f query='mutation { mergePullRequest(input: {}) { clientMutationId } }'",
]
DELETE = [
    "gh repo delete o/r --yes",
    "gh release delete v1",
    "gh issue delete 3",
    "gh api -X DELETE repos/o/r/git/refs/heads/x",
    "gh api --method DELETE repos/o/r",
    "gh api -XDELETE repos/o/r/issues/comments/1",
    "gh pr close 5 --delete-branch",
    "gh issue comment 3 --delete-last",
]
ADMIN = [
    "gh repo edit --visibility public",
    "gh repo rename x",
    "gh repo archive",
    "gh secret set X",
    "gh variable set X",
    "gh ruleset list",
    "gh api -X PATCH repos/o/r",
    "gh api -X PUT repos/o/r/branches/main/protection",
    "gh api -X PUT repos/o/r/collaborators/u",
    "gh api -X POST repos/o/r/hooks",
    "gh api -X POST repos/o/r/keys",
]
DEFAULT_DENY = [
    "gh alias set co 'pr merge'",
    "gh co 5",
    "gh extension install x/y",
    "gh api -f title=x repos/o/r/issues",
    "gh api --input body.json repos/o/r/issues",
    "gh api graphql -F query=@q.graphql",
]
CONDUCTOR_OK = [
    "gh pr create --title t --body-file docs/.tmp/pr.md",
    "gh pr view 3",
    "gh pr list",
    "gh pr checks 3",
    "gh run list",
    "gh run view 1",
    "gh run watch 1",
]


@pytest.fixture
def train_repo(repo_cwd: Path, project_data: Path) -> Path:
    # 0023: inside a train, so unknown agents meet the gh policy and the train rule alike.
    (project_data / "train.active").write_text("20261016-120000\n", encoding="utf-8")
    return repo_cwd


def _bash(repo: Path, agent: str, command: str) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "tool_name": "Bash",
        "tool_input": {"command": command},
        "cwd": str(repo),
        "session_id": "s",
    }
    if agent != "main":
        payload["agent_type"] = agent
        payload["agent_id"] = "a-1"
    return payload


def _reason(repo: Path, agent: str, command: str) -> str:
    d = decide(_bash(repo, agent, command), Config())
    assert not d.allow, (agent, command)
    return str(d.reason)


def _class_refused(repo: Path, agent: str, command: str, klass: str, nxt: str) -> None:
    reason = _reason(repo, agent, command)
    assert f"is a {klass} command, refused for every session (0028)" in reason, reason
    assert reason.endswith(f"Next: {nxt}."), reason


@pytest.mark.parametrize("agent", AGENTS)
@pytest.mark.parametrize("command", MERGE)
def test_merge_class_refused(train_repo: Path, agent: str, command: str) -> None:
    _class_refused(train_repo, agent, command, "merge", "the operator merges in the GitHub UI")


@pytest.mark.parametrize("agent", AGENTS)
@pytest.mark.parametrize("command", DELETE)
def test_delete_class_refused(train_repo: Path, agent: str, command: str) -> None:
    nxt = "delete from your own shell if you mean it"
    _class_refused(train_repo, agent, command, "delete", nxt)


@pytest.mark.parametrize("agent", AGENTS)
@pytest.mark.parametrize("command", ADMIN)
def test_admin_class_refused(train_repo: Path, agent: str, command: str) -> None:
    nxt = "change repository settings from your own shell"
    _class_refused(train_repo, agent, command, "admin", nxt)


@pytest.mark.parametrize("agent", AGENTS)
@pytest.mark.parametrize("command", DEFAULT_DENY)
def test_default_deny(train_repo: Path, agent: str, command: str) -> None:
    nxt = "only the Push Train's conductor runs gh"
    _class_refused(train_repo, agent, command, "default-deny", nxt)


@pytest.mark.parametrize("command", CONDUCTOR_OK)
def test_conductor_allowlist(train_repo: Path, command: str) -> None:
    d = decide(_bash(train_repo, "pr-train-conductor", command), Config())
    assert d.allow, d.reason
    for agent in ("repo-coder", "general-purpose"):
        reason = _reason(train_repo, agent, command)
        assert "(0028)" in reason and "Next: only the Push Train's conductor runs gh." in reason


def test_conductor_pr_edit_waits_on_k1(train_repo: Path) -> None:
    # K1: pr edit is off the 0028 list until ruled; the Push Train's edit step waits on it.
    command = "gh pr edit 3 --body-file docs/.tmp/pr.md"
    _class_refused(
        train_repo,
        "pr-train-conductor",
        command,
        "default-deny",
        "only the Push Train's conductor runs gh",
    )


def test_main_may_run_only_gh_auth_status(train_repo: Path) -> None:
    assert decide(_bash(train_repo, "main", "gh auth status"), Config()).allow
    for command in ("gh pr view 3", "gh pr list", "gh issue list", "gh run list"):
        reason = _reason(train_repo, "main", command)
        assert "not on the main gh list (0028)" in reason and "Next:" in reason


def test_repo_coder_gh_and_git_push_refused(train_repo: Path) -> None:
    for command in ("gh pr view 3", "gh auth status", "git push origin feat/x"):
        assert "(0028" in _reason(train_repo, "repo-coder", command), command


def test_git_push_only_for_the_conductor(train_repo: Path) -> None:
    for agent in ("main", "repo-coder", "general-purpose"):
        for command in ("git push origin feat/x", "git -C . push -u origin feat/x"):
            reason = _reason(train_repo, agent, command)
            assert "git push runs only in the Push Train's conductor (0028, 0030)" in reason
            assert reason.endswith(
                "Next: push from your own shell, or through /daedalus:push-train."
            )
    ok = decide(_bash(train_repo, "pr-train-conductor", "git push origin feat/x"), Config())
    assert ok.allow, ok.reason
    gated = decide(_bash(train_repo, "pr-train-conductor", "git push origin feat/x y"), Config())
    assert not gated.allow and "0028" not in str(gated.reason)


@pytest.mark.parametrize(
    "command",
    [
        'bash -c "gh pr merge 5"',
        "env gh pr merge 5",
        "cd x && gh pr merge 5",
        "sudo -u root gh pr merge 5",
        "find . -exec gh pr merge 5 ;",
        'python3 -c \'import subprocess; subprocess.run(["gh", "pr", "merge", "5"])\'',
        "echo `date`; gh pr merge 5",
        "eval 'gh pr merge 5'",
    ],
)
def test_main_regex_fallback_refuses_hidden_gh(train_repo: Path, command: str) -> None:
    reason = _reason(train_repo, "main", command)
    assert "(0028)" in reason and "Next:" in reason, reason


def test_regex_fallback_without_segments() -> None:
    assert gh_reason("main", "gh auth status", None) is None
    for command in ("gh pr view 3 $(x)", "x; /usr/bin/gh repo delete", "git -C . push origin x"):
        reason = gh_reason("main", command, None)
        assert reason is not None and "Next:" in reason, command
    assert gh_reason("main", "echo `date`", None) is None
    assert gh_reason("pr-train-conductor", "git push origin x", None) is None


@pytest.mark.parametrize(
    ("command", "klass"),
    [
        ("gh api repos/o/r/pulls", "default-deny"),
        ("gh api -X GET search/issues -f q=x", "default-deny"),
        ("gh api -X=DELETE repos/o/r", "delete"),
        ("gh api -iXDELETE repos/o/r", "delete"),
        ("gh api --method=delete repos/o/r", "delete"),
        ("gh api -X POST repos/o/r/merges", "merge"),
        ("gh api -f x=1 https://api.github.com/repos/o/r/rulesets", "admin"),
        ("gh api -X PATCH orgs/o", "admin"),
        ("gh api graphql -f query='mutation { deleteRef(input: {}) { x } }'", "delete"),
        ("gh api graphql -f query='mutation { updateRepository(input: {}) { x } }'", "admin"),
        ("gh api graphql -f query='mutation { addStar(input: {}) { x } }'", "default-deny"),
        ("gh api graphql -f query='query { viewer { login } }'", "default-deny"),
        ("gh --repo o/r pr merge 3", "merge"),
        ("gh pr close 5 -d", "delete"),
        ("gh release delete-asset v1 a.zip", "delete"),
        ("gh repo deploy-key add k.pub", "admin"),
        ("gh pr view 3", "allow"),
        ("gh issue list", "allow"),
        ("gh pr", "default-deny"),
    ],
)
def test_classify(command: str, klass: str) -> None:
    assert classify(shlex.split(command))[0] == klass
