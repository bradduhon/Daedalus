# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0044, 0028: the gh_classes hook; cases copied from tests/test_jail.py run each agent's chain.
from __future__ import annotations

import pytest
from lib import gh_policy, jail

from tests.conftest import CFG, REPO_ROOT
from tests.hook_chain import (
    decide,
    evaluate,
    first_deny,
    internal_error_denies,
    payload,
    run_script,
)
from tests.payloads import _b

pytestmark = pytest.mark.usefixtures("jail_fakes")
HOOK = "gh_classes"
C = "releaser"


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
        assert not decide(_b("releaser", command), CFG).allow, command

    def test_allowed(self) -> None:
        for command in (
            "gh -R o/r pr view 3",
            "gh pr checks 3",
            "gh run view 1",
            "gh pr list --repo o/r",
        ):
            assert decide(_b("releaser", command), CFG).allow, command


class TestFinalConductorGh:
    C = "releaser"

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
        assert d.reason == jail.R_CONDUCTOR_REPO

    @pytest.mark.parametrize(
        "command",
        [
            "gh pr create --title x --body-file docs/.tmp/pr.md",
            "gh pr create --title x -F /tmp/pr.md",
            "gh -R o/r pr view 3",
        ],
    )
    def test_allowed(self, command: str) -> None:
        assert decide(_b(self.C, command), CFG).allow, command


class TestFixWaveConductorGh:
    C = "releaser"

    @pytest.mark.parametrize(
        "command",
        [
            "gh pr create --title x --body b",
            "gh pr create --title x -b b",
            "gh pr create --title x --body=b",
            "gh pr create --title x -bb",
            "gh pr create --title x --body-file docs/.tmp/pr.md --body b",
            "gh pr create --title x --body-file docs/.tmp/pr.md --body=b",
            "gh pr create --title x --body-file docs/.tmp/pr.md -bb",
            "gh pr create --title x",
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
            "gh pr create --base main --head daedalus/T --title x --body-file docs/.tmp/pr.md",
            "gh pr create --title x -F /tmp/pr.md",
            "gh pr create --title x --body-file=/tmp/pr.md",
            "gh pr view daedalus/T --json url",
        ],
    )
    def test_allowed(self, command: str) -> None:
        assert decide(_b(self.C, command), CFG).allow, command

    @pytest.mark.parametrize(
        "command",
        [
            "gh pr edit 3 --title t",
            "gh pr comment 3 --body b",
            "gh pr comment 3 -b b",
            "gh pr comment 3 --body=b",
            "gh pr comment 3",
            "gh pr edit daedalus/T --base dev --body-file docs/.tmp/pr.md",
            "gh pr edit daedalus/T --base=dev --body-file docs/.tmp/pr.md",
            "gh pr edit daedalus/T -B dev --body-file docs/.tmp/pr.md",
            "gh pr edit daedalus/T -Bdev --body-file docs/.tmp/pr.md",
            "gh pr comment 3 --body-file docs/.tmp/c.md",
            "gh pr comment 3 -F/tmp/c.md",
            "gh pr diff 3",
        ],
    )
    def test_edit_comment_diff_refused_by_0028(self, command: str) -> None:
        # K1, 0028: comment, diff and any pr edit beyond the body are off the 0028 list.
        d = decide(_b(self.C, command), CFG)
        assert not d.allow and "is a default-deny command" in str(d.reason), command

    @pytest.mark.parametrize(
        "command",
        [
            "gh pr edit daedalus/T --body-file docs/.tmp/pr.md",
            "gh pr edit daedalus/T -F/tmp/Build-body.md",
            "gh pr edit 3 --body-file /tmp/pr.md",
        ],
    )
    def test_pr_edit_body_file_allowed(self, command: str) -> None:
        # K1: the conductor may replace its PR body from a file.
        d = decide(_b(self.C, command), CFG)
        assert d.allow, (command, d.reason)

    @pytest.mark.parametrize(
        "command", ["gh pr edit 3 --body b", "gh pr edit 3 -b b", "gh pr edit 3 --body=b"]
    )
    def test_pr_edit_inline_body_refused(self, command: str) -> None:
        # K1: the body comes only from --body-file.
        d = decide(_b(self.C, command), CFG)
        assert not d.allow and "only from --body-file" in str(d.reason), command


@pytest.mark.parametrize("agent", [C, "coder", "auditor"])
@pytest.mark.parametrize(
    "command",
    [
        "gh pr create --title x -db b",
        "gh pr edit 3 --body-file docs/.tmp/pr.md -db b",
        "gh pr create -dH feat/x --title t --body-file docs/.tmp/pr.md",
        "gh pr create -dR o/r --title t --body-file docs/.tmp/pr.md",
        "gh api -iXDELETE repos/o/r",
        "gh pr close -cd 5",
        "gh run list -aL 5",
        "gh pr create --title x --body-file",
    ],
)
def test_bundled_short_flags_and_missing_values_fail_closed(agent: str, command: str) -> None:
    # issue 76: gh_policy.gh_args refuses a short bundle or a value flag with no value.
    assert evaluate(HOOK, _b(agent, command), *(["--conductor"] if agent == C else [])) == (
        gh_policy.R_GH_BUNDLE
    )


def test_gh_classes_judges_the_hook_alone() -> None:
    merge = str(evaluate(HOOK, _b(C, "gh pr merge 3"), "--conductor"))
    assert "is a merge command" in merge
    assert evaluate(HOOK, _b(C, "gh run list"), "--conductor") is None
    repo = evaluate(HOOK, _b(C, "gh pr create -R o/r --body-file docs/.tmp/x"), "--conductor")
    assert repo == jail.R_CONDUCTOR_REPO
    assert evaluate(HOOK, _b(C, "gh pr create --title x"), "--conductor") == jail.R_BODY_INLINE
    assert evaluate(HOOK, _b(C, "gh pr create --title x")) is None
    assert "not on the coder gh list" in str(evaluate(HOOK, _b("coder", "gh pr view 1")))


def test_charter_docs_ledger_value_naming_git_push_is_refused_by_gh_classes() -> None:
    # 0044 parity: the gh gate's text fallback refuses `git push` inside an argument value.
    args = '--expected-seq 2 --entry-file docs/.tmp/e.md --repo DAE --type "git push"'
    hook_input = _b("charter-docs", f"python3 {REPO_ROOT}/scripts/append_ledger.py {args}")
    assert first_deny(hook_input, CFG) == (HOOK, str(evaluate(HOOK, hook_input)))
    assert "git push runs only in the Push Train's releaser" in str(evaluate(HOOK, hook_input))


def test_gh_classes_fixture_decisions() -> None:
    merge = payload("Bash", agent=C, command="gh pr merge 3")
    got = run_script(HOOK, merge, "--conductor")
    assert got["decision"] == "deny" and "is a merge command" in got["reason"]
    view = payload("Bash", agent=C, command="gh pr view 3")
    assert run_script(HOOK, view, "--conductor") == {"decision": "allow", "reason": ""}
    body = payload("Bash", agent=C, command="gh pr create --title x --body b")
    want = {"decision": "deny", "reason": jail.R_BODY_INLINE}
    assert run_script(HOOK, body, "--conductor") == want
    assert gh_policy.conductor_gh_refusal().startswith("conductor gh is limited to")


def test_gh_classes_internal_error_denies_and_names_the_hook() -> None:
    internal_error_denies(HOOK, payload("Bash", agent=C, command="gh run list"), "--conductor")
