# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import shlex
from pathlib import Path
from typing import Any

import pytest
from lib import router, train_state
from lib.config import Config
from lib.gh_policy import (
    CONDUCTOR_GH,
    allowlist_applies,
    classify,
    conductor_gh_refusal,
    gh_reason,
)

from tests.conftest import REPO_ROOT
from tests.hook_chain import judge as decide
from tests.test_checks_git_push import (
    GATE_BRANCH,
    GATE_NEXT,
    GATE_TRAIN,
    _git,
    approve,
    move_tip,
    seed_train,
)

# 0044: repo-coder's chain refuses gh and git push in network_tools and git_push first.
AGENTS = ("main", "pr-train-conductor", "general-purpose")
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
MERGE_NEXT = "the operator merges in the GitHub UI"
# spec 4.2: gh pr create also needs the verdict; test_pr_create_follows_the_same_gate covers it.
CONDUCTOR_OK = [
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


def _denying_hook(repo: Path, agent: str, command: str) -> str:
    allow, reason, hook = router.route(_bash(repo, agent, command), REPO_ROOT)
    assert not allow and reason, (agent, command)
    return hook


def _class_refused(repo: Path, agent: str, command: str, klass: str, nxt: str) -> None:
    reason = _reason(repo, agent, command)
    assert f"is a {klass} command, refused while a train runs and to every Daedalus" in reason
    assert reason.endswith(f"Next: {nxt}."), reason


@pytest.mark.parametrize("agent", AGENTS)
@pytest.mark.parametrize("command", MERGE)
def test_merge_class_refused(train_repo: Path, agent: str, command: str) -> None:
    if agent == "pr-train-conductor" and "{" in command:
        # 0044: the conductor's shell_tripwires hook refuses a brace token before gh_classes.
        assert _denying_hook(train_repo, agent, command) == "shell_tripwires"
        return
    _class_refused(train_repo, agent, command, "merge", MERGE_NEXT)


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
    reason = _reason(train_repo, "general-purpose", command)
    assert "(0028)" in reason and "Next: only the Push Train's conductor runs gh." in reason
    assert _denying_hook(train_repo, "repo-coder", command) == "network_tools"


EDIT_NEXT = "edit only the body with --body-file; the operator changes anything else on the PR"


@pytest.mark.parametrize(
    "command",
    [
        "gh pr edit 3 --body-file docs/.tmp/pr.md",
        "gh pr edit https://github.com/o/r/pull/3 -F docs/.tmp/pr.md",
        "gh pr edit daedalus/x --body-file=docs/.tmp/pr.md",
        "gh pr edit -Fdocs/.tmp/pr.md",
    ],
)
def test_conductor_may_edit_its_pr_body(train_repo: Path, command: str) -> None:
    # K1: body-only pr edit is on the conductor's list.
    assert classify(shlex.split(command)) == ("allow", "pr edit")
    d = decide(_bash(train_repo, "pr-train-conductor", command), Config())
    assert d.allow, d.reason


@pytest.mark.parametrize("command", ["gh pr edit 3 --body x", "gh pr edit 3 -b x"])
def test_pr_edit_inline_body_passes_policy_then_the_file_rule(
    train_repo: Path, command: str
) -> None:
    # K1: the policy allows the body flags; the conductor's file-only body rule still refuses.
    assert classify(shlex.split(command)) == ("allow", "pr edit")
    assert "only from --body-file" in _reason(train_repo, "pr-train-conductor", command)


@pytest.mark.parametrize(
    "command",
    [
        "gh pr edit 3 --title t --body-file docs/.tmp/pr.md",
        "gh pr edit 3 -t t",
        "gh pr edit 3 --add-label x",
        "gh pr edit 3 --remove-reviewer u",
        "gh pr edit 3 --base main",
        "gh pr edit 3 -B main",
        "gh pr edit 3 --milestone m",
        "gh pr edit 3 4 --body-file docs/.tmp/pr.md",
        "gh -R o/r pr edit 3 --body-file docs/.tmp/pr.md",
        "gh pr edit 3 -R o/r --body-file docs/.tmp/pr.md",
    ],
)
def test_conductor_pr_edit_other_flags_refused(train_repo: Path, command: str) -> None:
    # K1: anything beyond the body is default-deny with its own Next line.
    assert classify(shlex.split(command)) == ("default-deny", "pr edit")
    _class_refused(train_repo, "pr-train-conductor", command, "default-deny", EDIT_NEXT)


MAIN_READS = [
    "gh auth status",
    "gh issue view 3",
    "gh issue list",
    "gh pr view 3",
    "gh pr list",
    "gh pr checks 3",
    "gh run list",
    "gh run view 1",
    "gh run watch 1",
]


@pytest.mark.parametrize("command", MAIN_READS)
def test_main_may_view_issues_and_prs_during_a_train(train_repo: Path, command: str) -> None:
    # B7: main reads the tracker and CI while a train runs.
    d = decide(_bash(train_repo, "main", command), Config())
    assert d.allow, d.reason


@pytest.mark.parametrize(
    "command",
    ["gh pr create --title t --body-file docs/.tmp/pr.md", "gh pr edit 3 --body-file x.md"],
)
def test_main_pr_create_is_refused(train_repo: Path, command: str) -> None:
    # B7: pull request writes stay with the Push Train's conductor.
    reason = _reason(train_repo, "main", command)
    assert "not on the main gh list (0028)" in reason and "Next:" in reason


def test_pr_create_follows_the_same_gate(repo_cwd: Path) -> None:
    # spec 4.2: pr create passes only on an approved verdict or an exception for the exact tip.
    command = "gh pr create --title t --body-file docs/.tmp/pr.md"
    tip = seed_train(repo_cwd)
    no_verdict = _reason(repo_cwd, "pr-train-conductor", command)
    assert no_verdict.endswith(GATE_NEXT) and "no verdict" in no_verdict
    approve(repo_cwd, tip)
    d = decide(_bash(repo_cwd, "pr-train-conductor", command), Config())
    assert d.allow, d.reason
    move_tip(repo_cwd)
    assert _reason(repo_cwd, "pr-train-conductor", command).endswith(GATE_NEXT)
    moved = _git(repo_cwd, "rev-parse", GATE_BRANCH).strip()
    exception = {"ledger_id": "0104-DAE-PLT", "tip": moved}
    train_state.update(repo_cwd, GATE_TRAIN, exception=exception)
    d = decide(_bash(repo_cwd, "pr-train-conductor", command), Config())
    assert d.allow, d.reason
    assert "(0028)" in _reason(repo_cwd, "general-purpose", command)
    assert _denying_hook(repo_cwd, "repo-coder", command) == "network_tools"


HEAD_NEXT = (
    "Next: drop --head so the pull request opens from the current branch, "
    f"or pass --head {GATE_BRANCH}."
)


@pytest.mark.parametrize(
    "head",
    [
        "--head feat/x",
        "-H feat/x",
        "--head=feat/x",
        "-Hfeat/x",
        "-H=feat/x",
        "-dH feat/x",
        f"--head o:{GATE_BRANCH}",
        f"--head {GATE_BRANCH} --head feat/x",
    ],
)
def test_pr_create_head_naming_another_branch_is_refused(repo_cwd: Path, head: str) -> None:
    # spec 4.2: the verdict covers the train branch only, so --head names nothing else.
    approve(repo_cwd, seed_train(repo_cwd))
    command = f"gh pr create {head} --title t --body-file docs/.tmp/pr.md"
    assert _reason(repo_cwd, "pr-train-conductor", command).endswith(HEAD_NEXT), head


@pytest.mark.parametrize(
    "head",
    ["", f"--head {GATE_BRANCH}", f"-H {GATE_BRANCH}", f"--head={GATE_BRANCH}", "--title -H"],
)
def test_pr_create_head_on_the_train_branch_passes(repo_cwd: Path, head: str) -> None:
    approve(repo_cwd, seed_train(repo_cwd))
    command = f"gh pr create {head} --title t --body-file docs/.tmp/pr.md"
    d = decide(_bash(repo_cwd, "pr-train-conductor", command), Config())
    assert d.allow, (head, d.reason)


def test_pr_create_without_head_off_the_train_branch_is_refused(repo_cwd: Path) -> None:
    # spec 4.2: with no --head, gh opens from the checked-out branch; it must be the train's.
    approve(repo_cwd, seed_train(repo_cwd))
    _git(repo_cwd, "switch", "-q", "-c", "feat/x")
    command = "gh pr create --title t --body-file docs/.tmp/pr.md"
    reason = _reason(repo_cwd, "pr-train-conductor", command)
    assert reason.endswith(
        f"Next: pass --head {GATE_BRANCH} so the pull request opens from the audited branch."
    )
    with_head = f"gh pr create --head {GATE_BRANCH} --title t --body-file docs/.tmp/pr.md"
    d = decide(_bash(repo_cwd, "pr-train-conductor", with_head), Config())
    assert d.allow, d.reason


def test_repo_coder_gh_and_git_push_refused(train_repo: Path) -> None:
    for command in ("gh pr view 3", "gh auth status"):
        assert _denying_hook(train_repo, "repo-coder", command) == "network_tools", command
    assert _denying_hook(train_repo, "repo-coder", "git push origin feat/x") == "git_push"


def test_git_push_only_for_the_conductor(train_repo: Path) -> None:
    for agent in ("main", "general-purpose"):
        for command in ("git push origin feat/x", "git -C . push -u origin feat/x"):
            reason = _reason(train_repo, agent, command)
            assert "git push runs only in the Push Train's conductor (0028, 0030)" in reason
            assert reason.endswith(
                "Next: push from your own shell, or through /daedalus:push-train."
            )
    # spec 4.2: past the 0028 list, a train with no state meets the verdict gate.
    push = "git push origin daedalus/20261016-120000"
    unaudited = _reason(train_repo, "pr-train-conductor", push)
    assert "0028" not in unaudited and unaudited.endswith(GATE_NEXT)
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
    assert "(0028" in reason and "Next:" in reason, reason


def test_regex_fallback_without_segments() -> None:
    assert gh_reason("main", "gh auth status", None) is None
    for command in ("gh pr view 3 $(x)", "x; /usr/bin/gh repo delete", "git -C . push origin x"):
        reason = gh_reason("main", command, None)
        assert reason is not None and "Next:" in reason, command
    assert gh_reason("main", "echo `date`", None) is None
    assert gh_reason("pr-train-conductor", "git push origin x", None) is None


@pytest.fixture
def plain_repo(repo_cwd: Path, project_data: Path) -> Path:
    # 0035: no train marker, so the main session and unknown agents are untouched.
    return repo_cwd


OUTSIDE_A_TRAIN = [
    *MERGE,
    *DELETE,
    *ADMIN,
    *DEFAULT_DENY,
    "gh pr view 3",
    "gh pr edit 3 --title t",
    "git push origin feat/x",
    'bash -c "gh pr merge 5"',
    "echo `date`; gh pr merge 5",
]


@pytest.mark.parametrize("agent", ("main", "general-purpose"))
@pytest.mark.parametrize("command", OUTSIDE_A_TRAIN)
def test_main_and_unknown_agents_untouched_outside_a_train(
    plain_repo: Path, agent: str, command: str
) -> None:
    d = decide(_bash(plain_repo, agent, command), Config())
    assert d.allow, (agent, command, d.reason)


@pytest.mark.parametrize("agent", ("main", "general-purpose"))
def test_marker_brings_back_the_gate(plain_repo: Path, agent: str) -> None:
    # 0035: the same command flips from allow to refuse when a train marks the repo.
    assert decide(_bash(plain_repo, agent, "gh pr merge 5"), Config()).allow
    (plain_repo / ".claude" / "daedalus" / "train.active").write_text("20261016-120000\n")
    _class_refused(plain_repo, agent, "gh pr merge 5", "merge", MERGE_NEXT)
    assert "(0028, 0030)" in _reason(plain_repo, agent, "git push origin feat/x")


def test_daedalus_agents_gated_outside_a_train(plain_repo: Path) -> None:
    # 0035: a Daedalus agent meets the gh gate with or without a train.
    _class_refused(plain_repo, "pr-train-conductor", "gh pr merge 5", "merge", MERGE_NEXT)
    assert _denying_hook(plain_repo, "repo-coder", "gh pr merge 5") == "network_tools"
    assert _denying_hook(plain_repo, "repo-coder", "git push origin feat/x") == "git_push"


def test_main_push_into_a_train_repo_from_elsewhere(train_repo: Path, tmp_path: Path) -> None:
    # 0035: git -C naming a marked repo counts as acting in that train.
    other = tmp_path / "other"
    other.mkdir()
    reason = _reason(other, "main", f"git -C {train_repo} push origin feat/x")
    assert "(0028, 0030)" in reason


def test_allowlist_applies(plain_repo: Path) -> None:
    cwd = str(plain_repo)
    assert allowlist_applies("pr-train-conductor", cwd) and allowlist_applies("repo-coder", "")
    assert not allowlist_applies("main", cwd) and not allowlist_applies("general-purpose", cwd)
    assert not allowlist_applies("main", "relative/path")
    (plain_repo / ".claude" / "daedalus" / "train.active").write_text("20261016-120000\n")
    assert allowlist_applies("main", cwd) and allowlist_applies("general-purpose", cwd)


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


def test_conductor_gh_refusal_names_only_the_built_set() -> None:
    # 0001, 0028: the refusal lists CONDUCTOR_GH and nothing it does not build.
    text = conductor_gh_refusal()
    assert text == (
        "conductor gh is limited to gh pr checks, create, edit, list, view and "
        "gh run list, view, watch; the operator is the merge gate (0001). Next: report the PR URL."
    )
    named = {
        (group.split()[1], sub.strip())
        for group in text.split("limited to ", 1)[1].split(";", 1)[0].split(" and ")
        for sub in group.split(" ", 2)[2].split(",")
    }
    assert named == CONDUCTOR_GH
    for drift in ("status", "comment", "diff"):
        assert drift not in text
