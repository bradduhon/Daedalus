# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import re
from pathlib import Path

import pytest

from tests.conftest import REPO_ROOT
from tests.skill_helpers import (
    _AGENT_REF,
    _SKILL_SCRIPT,
    ASSETS_CMD,
    MAIN,
    MARK,
    REAUDIT_CMD,
    RELEASE,
    RELEASE_CMD,
    UNMARK,
    _conductor_commands,
    _conductor_decide,
    _release,
    _run_skill,
    _section,
    _split,
)


def test_release_step_finds_the_merge_commit_and_keeps_the_fallback_question() -> None:
    # 0252: the merge commit comes from a git read; the old question stays as the fallback.
    text = _release()
    assert "ask for the merge commit sha on `<base branch>` and run" not in text
    assert "fetch origin <base branch>`" in text
    assert "--grep=" not in text and "squash" not in text.lower()
    assert "whose second parent is the tip the releaser pushed (0279, 0282)" in text
    assert "ask the operator for the merge commit sha on `<base branch>` instead" in text


def _skill_reads(text: str) -> tuple[str, str]:
    merge = re.search(r"`(git -C <repo> log origin/<base branch> --merges[^`]+)`", text)
    ancestry = re.search(r"`(git merge-base --is-ancestor daedalus/<train-id> [^`]+)`", text)
    assert merge and ancestry
    return merge.group(1), ancestry.group(1)


def _run_history(tmp_path: Path, name: str, squash: bool) -> tuple[Path, str, str]:
    # 0279: a run branch of three commits merged into main by --no-ff or by a squash.
    from tests.conftest import git

    repo = tmp_path / name
    repo.mkdir()
    git(repo, "init", "-q", "-b", "main")
    git(repo, "commit", "-q", "--allow-empty", "-m", "Start")
    git(repo, "switch", "-q", "-c", "daedalus/20261112-120000")
    for n in (1, 2, 3):
        (repo / f"unit{n}.txt").write_text(f"unit {n}\n")
        git(repo, "add", "-A")
        git(repo, "commit", "-q", "-m", f"Add unit {n}")
    tip = git(repo, "rev-parse", "HEAD").stdout.strip()
    git(repo, "switch", "-q", "main")
    git(repo, "commit", "-q", "--allow-empty", "-m", "Move main")
    pr = "12"
    if squash:
        git(repo, "merge", "-q", "--squash", "daedalus/20261112-120000")
        git(repo, "commit", "-q", "-m", f"Run 20261112-120000 (#{pr})")
    else:
        message = f"Merge pull request #{pr} from owner/daedalus/20261112-120000"
        git(repo, "merge", "-q", "--no-ff", "daedalus/20261112-120000", "-m", message)
    git(repo, "update-ref", "refs/remotes/origin/main", "HEAD")
    return repo, tip, git(repo, "rev-parse", "HEAD").stdout.strip()


def test_release_reads_find_the_merge_commit_and_refuse_a_squash(tmp_path: Path) -> None:
    # 0252, 0282: run the skill's reads, as written, against a real merge and squash history.
    import json
    import shlex
    import subprocess
    import sys

    from tests.conftest import SCRIPTS_DIR

    merge_cmd, ancestry_cmd = _skill_reads(_release())
    repo, tip, merge_sha = _run_history(tmp_path, "merged", squash=False)
    payload = {"hook_event_name": "PreToolUse", "tool_name": "Bash", "cwd": str(repo)}
    payload["tool_input"] = {"command": merge_cmd.replace("<repo>", str(repo))}
    payload["session_id"] = "sess-main"
    hook = subprocess.run(
        [sys.executable, str(SCRIPTS_DIR / "enforce_agent_jail.py")],
        input=json.dumps(payload),
        capture_output=True,
        text=True,
        check=False,
        cwd=repo,
    )
    assert hook.returncode == 0 and "daedalus-jail" not in hook.stderr, hook.stderr

    def run(root: Path, command: str) -> subprocess.CompletedProcess[str]:
        filled = command.replace("<repo>", str(root)).replace("<base branch>", "main")
        argv = shlex.split(filled.replace("<train-id>", "20261112-120000"))
        return subprocess.run(argv, capture_output=True, text=True, check=False, cwd=root)

    merges = [line.split() for line in run(repo, merge_cmd).stdout.splitlines()]
    assert [m[0] for m in merges if len(m) > 2 and m[2] == tip] == [merge_sha]
    assert run(repo, ancestry_cmd).returncode == 0
    squashed, squash_tip, _ = _run_history(tmp_path, "squashed", squash=True)
    merges = [line.split() for line in run(squashed, merge_cmd).stdout.splitlines()]
    assert [m[0] for m in merges if len(m) > 2 and m[2] == squash_tip] == []
    assert run(squashed, ancestry_cmd).returncode == 1


def test_push_train_proof_names_the_exemption_path() -> None:
    # issue 62, 0133: --approved passes on an approved verdict or every finding exempted.
    step = _release().split("\n9. ", 1)[1].split("\n10. ", 1)[0]
    assert "whose every finding carries the operator's exemption (issue 62, 0133)" in step
    assert "an approved audit verdict on the current tip" in step


def test_push_train_dispatches_only_the_conductor() -> None:
    # 73, spec 3.3: the recovery round alone starts the auditor from this session.
    text = _release()
    assert set(_AGENT_REF.findall(text)) == {"releaser", "auditor"}
    outside = text.replace(_section(text, "## Recovery round", "## Push"), "")
    assert set(_AGENT_REF.findall(outside)) == {"releaser"}


def test_push_train_leaves_the_merge_to_the_operator() -> None:
    text = _release()
    assert "never merge" in text.lower() or "operator merges" in text
    assert "gh pr merge" not in text
    assert "--force" not in text


def test_push_train_uses_the_conductor_push_grammar_and_scan() -> None:
    text = _release()
    assert "git push -u origin" in text
    assert "gitleaks detect" in text
    assert "gitleaks version" in text
    # Work-order line 24: the body is the summary plus its Closes and Refs lines.
    assert "--body-file <repo>/docs/.tmp/daedalus/<train-id>/pr-body.md" in text
    assert "--body-file <repo>/docs/.tmp/daedalus/<train-id>-summary.md" not in text
    assert "daedalus_workspace.py pr-body --repo <repo> --train <train-id>`" in text


def test_push_train_proves_live_hooks_with_the_script() -> None:
    # 0024: the log reading moved to verify_audit_chain.py; test_audit_proof.py holds it.
    text = _release()
    step = text.split("\n8. ", 1)[1].split("\n9. ", 1)[0]
    assert (
        "`python3 ${CLAUDE_PLUGIN_ROOT}/scripts/verify_audit_chain.py --hooks-live --repo <repo>`"
    ) in step
    assert "Grep" not in text
    assert "docs/.tmp/daedalus/" in text
    assert "Next: build the work first with `/daedalus:run` and the task." in text


def test_push_train_ends_with_the_operator_checklist() -> None:
    hand_off = _release().split("## Hand-off", 1)[1]
    for item in ("1. Review", "2. Check CI", "3. Merge"):
        assert item in hand_off, item
    # M2, issue 19: check the merge, leave the branch, then force-delete it from the own shell.
    # 0279, 0282: the operator merges with a merge commit, and item 4 checks the run's ancestry.
    item3 = hand_off.split("\n3. ", 1)[1].split("\n4. ", 1)[0]
    assert item3.startswith("Merge the pull request with a merge commit")
    assert "rebase" not in item3 and "squash" not in item3.lower()
    item4 = hand_off.split("\n4. ", 1)[1].split("\n5. ", 1)[0]
    assert "the run's commits are not on `<base branch>`" in item4
    assert "Daedalus expects one. Next:" in item4
    assert item4.startswith(
        "Check that the pull request is merged with `gh pr view <url> --json state`"
    )
    assert (
        "from your own shell, run `git switch <base branch>` and delete the branch with "
        "`git branch -D daedalus/<train-id>`."
    ) in item4
    item6 = hand_off.split("\n6. ", 1)[1].split("\n\n", 1)[0]
    assert "`gh pr view <charter url> --json state`" in item6
    assert (
        "from your own shell, run `git -C <charter_root> switch <charter base>` and "
        "`git -C <charter_root> branch -D daedalus/<train-id>`."
    ) in item6
    assert "branch -d " not in _release()
    assert item6.index("gh pr view") < item6.index("branch -D")
    assert "5. Run `/daedalus:audit-report <session>`" in hand_off


def test_push_skill_hand_off_names_the_release_step() -> None:
    # 0068, 0071, 0075: the hand-off names the release step; the main session alone publishes.
    hand_off = _release().split("## Hand-off", 1)[1]
    assert RELEASE_CMD in hand_off
    # 130: a plain-branch merge names its pull request body file instead of a summary.
    assert RELEASE_CMD.replace("<merge sha>`", "<merge sha> --notes-file <body file>`") in hand_off
    assert "docs/.tmp/daedalus/releases/v<version>/release-notes.md" in hand_off
    # 0282: the plain path has no run tip, so it checks only that the sha is on the base.
    assert (
        "This path checks only that the sha is on the base branch, because a plain branch has "
        "no recorded run tip."
    ) in hand_off
    assert "After the operator reports the merge" in hand_off
    assert "`Version class: <version> <X, Y or Z>: <one-line reason>`" in hand_off
    assert "`Migration: <what an operator edits>`" in hand_off
    assert "`release: skipped`" in hand_off
    assert "It runs none of them." in hand_off
    # 0093: the main session runs them only in the plugin's own repository; 0089 elsewhere.
    assert (
        "When `<repo>` is the Daedalus plugin repository itself, show them to the operator, "
        "then run them in the printed order yourself. In any other project, show them to the "
        "operator to run from their own shell, and run none of them yourself."
    ) in hand_off
    assert (
        "you run the three commands the release step prints only when `<repo>` is the Daedalus "
        "plugin repository itself; in any other project you show them to the operator to run "
        "from their own shell (0068, 0093)."
    ) in _release().split("## Preconditions", 1)[0]


def test_push_train_proves_the_approved_audit_with_the_script() -> None:
    # 0024: the auditor record checks moved to verify_audit_chain.py --approved.
    step = _release().split("\n9. ", 1)[1].split("\n10. ", 1)[0]
    assert (
        "`python3 ${CLAUDE_PLUGIN_ROOT}/scripts/verify_audit_chain.py --approved <train-id> "
        "--repo <repo>`"
    ) in step
    assert "its `Next:` line is the next action" in step


def test_push_train_stops_on_each_precondition() -> None:
    pre = _release().split("## Preconditions", 1)[1].split("## Push", 1)[0]
    for stop in (
        "No file: stop. Next: build the work first with `/daedalus:run` and the task.",
        "Anything but `daedalus/<train-id>`: stop.",
        "Any `??` line or any change in column two: stop.",
        "the second an empty line, because the releaser's body files must sit under",
    ):
        assert stop in pre, stop


def test_push_train_hands_off_the_contract_commits() -> None:
    # 0011: the contract commits ride the pushed branches; no new conductor command.
    pt = _release()
    assert "the contract path and version from the `Contract:` line" in pt
    assert "when the `charter:` line ends in `(ledger under local_docs_folder)`" in pt
    hand_off = pt.split("## Hand-off", 1)[1]
    assert "its `Lock contract` and `Revise contract` commits are part of the diff" in hand_off
    assert "the contract commits are in this pull request" in hand_off
    assert "contract" not in _section(pt, "## Push", "## Charter branch").lower()


def test_push_train_names_the_charter_pull_request_by_its_content() -> None:
    # Ruling 3: title and body split on where the ledger lives.
    pt = _release()
    body = _section(pt, "## Charter branch", "## Hand-off")
    ledger = body.split("(ledger under local_docs_folder)`:", 1)[1].split("Otherwise:", 1)[0]
    assert "    Contract and ledger entries for run <train-id>.\n" in ledger
    other = body.split("Otherwise:", 1)[1]
    assert "    Contract for run <train-id>.\n" in other
    assert "ledger" not in other.split("The code pull request", 1)[0]
    # issue 13: two literal titles picked by the charter: line, no prose placeholder.
    assert "<title>" not in pt
    messages = [ln for ln in body.splitlines() if ln.startswith("    SendMessage(releaser, ")]
    assert len(messages) == 2
    first, second = messages
    assert '--title "Run <train-id>: contract and ledger" --body-file' in first
    assert '--title "Run <train-id>: contract" --body-file' in second
    assert first.replace(": contract and ledger", ": contract") == second
    pick = body.split(first, 1)[0]
    assert pick.rstrip().endswith("When it ends in `(ledger under local_docs_folder)`:")
    assert body.split(first, 1)[1].split(second, 1)[0].strip() == "Otherwise:"


def test_push_train_checks_the_remote_before_the_conductor() -> None:
    # F5: the conductor's hook refuses git remote, so the main session checks origin.
    text = _release()
    pre = text.split("## Preconditions", 1)[1].split("## Push", 1)[0]
    assert "run `git remote get-url origin` before any releaser dispatch" in pre
    assert "A non-zero exit: stop. Next: add a remote named origin, then rerun." in pre
    dispatch = text.split("## Push", 1)[1].split("\n2. ", 1)[0]
    assert "The remote `origin` exists" in dispatch
    assert "Never repeat the URL it prints to the operator; a remote URL can carry a token." in pre
    assert text.index("git remote get-url origin") < text.index("Agent(`releaser`)")


def test_push_train_dispatch_pins_flags_and_paths() -> None:
    text = _release()
    assert "gitleaks detect --redact --log-opts=<base sha>..daedalus/<train-id>" in text
    for forbidden in (
        "Never run `git commit -a`",
        "`git commit -am`",
        "never `gh pr edit` with any flag but `--body-file`",
        "never `gh pr create --body`",
    ):
        assert forbidden in text, forbidden
    assert '"Use only the commands above. Never run' in text
    # M9: every body file is absolute under <repo>.
    paths = re.findall(r"--body-file (\S+?)`", text)
    # issue 13: the Charter pull request has one command per title.
    assert len(paths) == 5
    for path in paths:
        assert path.startswith("<repo>/docs/.tmp/daedalus/<train-id>"), path


def test_push_train_routes_ci_without_waiting() -> None:
    text = _release()
    assert "`gh run list --branch daedalus/<train-id> --commit <that sha>`" in text
    assert "`[STATUS: CI] run=none conclusion=no workflow runs`" in text
    assert "`run=none`, or a `[STATUS: PUSHED]` reply, means no CI was reported." in text
    # Ruling (CI conclusions): only success, skipped and neutral pass; the rest stop.
    assert "any run whose conclusion is not `success`, `skipped` or `neutral`" in text
    assert "   - Conclusion `success`: go on.\n" in text
    # N5-M3: every non-success conclusion is named, even when a later run succeeded.
    assert (
        "where `<text>` lists every conclusion other than `success` seen across the "
        "listed runs, comma-separated"
    ) in text
    assert (
        "Conclusion `skipped`, `neutral`, or a comma-separated list of only those two: "
        "go on, and name every listed conclusion in hand-off item 2."
    ) in text
    assert "else the last run" not in text
    stop = next(ln for ln in text.splitlines() if "Any other conclusion, known or not" in ln)
    assert "`startup_failure`" in stop and "show them, and stop." in stop
    assert "report it and go on" not in text
    assert "Deviation: CI not observed at push time" in text
    assert "`CI not observed; check the PR's checks before merging`" in text


def test_push_train_reads_the_ledger_sha_from_the_ledger_ids_line() -> None:
    # N5-M1: the summary's `Ledger:` line is the path; the sha is on `Ledger ids:`.
    step = _release().split("\n3. ", 1)[1].split("\n4. ", 1)[0]
    assert "the ledger commit sha from the `Ledger ids:` line," in step
    # 124: one Ledger ids line per ledger commit; step 10 checks each recorded sha.
    assert "one sha from each line" in step and "step 10 checks every one" in step
    check = _release().split("\n10. ", 1)[1].split("\n", 1)[0]
    assert check.startswith("Confirm each ledger commit is on the branch")
    assert "once per sha step 3 recorded" in check


def test_push_train_hands_the_charter_push_to_the_conductor() -> None:
    # 0078: the conductor pushes the Charter branch and opens its pull request; no operator step.
    text = _release()
    hand_off = text.split("## Hand-off", 1)[1]
    assert "push" not in hand_off.split("With a Charter branch", 1)[1].split("\n6. ", 1)[0]
    assert "Push the Charter branch from your own shell" not in text
    assert "open its pull request: `gh pr create" not in text
    assert "gh pr create" not in hand_off and "push -u origin" not in hand_off
    charter = _section(text, "## Charter branch", "## Hand-off")
    push = "When config.json sets local_docs_folder, run `git -C <charter_root> push -u origin "
    assert push + "daedalus/<train-id>`." in charter
    for title in ("contract and ledger", "contract"):
        assert (
            "When config.json sets local_docs_folder, run `gh pr create --repo <charter slug> "
            "--base <charter base> --head daedalus/<train-id> --title "
            f'"Run <train-id>: {title}" --body-file '
            "<repo>/docs/.tmp/daedalus/<train-id>-charter-pr.md`."
        ) in charter, title
    assert charter.index("SendMessage(releaser") < charter.index(push)
    pre = _section(text, "## Preconditions", "## Push")
    assert "`git -C <charter_root> remote get-url origin`" in pre
    assert "The phase does not stop here; go on to the hand-off." in _release()


def test_push_train_marks_the_train_active_and_clears_it() -> None:
    # 0023, 0035: the Push Train marks before the hooks check, since only a marked repo records.
    text = _release()
    pre = _section(text, "## Preconditions", "## Push")
    step7 = pre.split("\n7. ", 1)[1].split("\n8. ", 1)[0]
    assert MARK + "<train-id>`" in step7
    assert pre.index(MARK) < pre.index("--hooks-live") < pre.index("--approved")
    assert pre.index("--approved") < pre.index("merge-base --is-ancestor")
    assert "Preconditions step 7 writes" in text
    rules = text.split("## Preconditions", 1)[0]
    marker = rules.split("- Run marker: ", 1)[1].split("\n", 1)[0]
    assert "every stop that follows" in marker
    assert UNMARK in marker
    hand_off = text.split("## Hand-off", 1)[1]
    assert hand_off.index(UNMARK) < hand_off.index("1. Review the pull request")


@pytest.mark.parametrize("command", _conductor_commands())
def test_push_train_conductor_commands_pass_the_jail(
    repo_cwd: Path, project_data: Path, command: str
) -> None:
    # K1: gh pr edit with --body-file is on the conductor's list.
    d = _conductor_decide(repo_cwd, project_data, command)
    assert d.allow, (command, d.reason)


def test_push_train_names_conductor_commands() -> None:
    commands = _conductor_commands()
    assert "git push -u origin daedalus/<train-id>" in commands
    assert any(c.startswith("gh pr edit daedalus/<train-id> --body-file") for c in commands)
    assert "git -C <charter_root> push -u origin daedalus/<train-id>" in commands
    assert any(c.startswith("gh pr create --repo <charter slug> ") for c in commands)


def test_push_train_checks_gh_beside_gitleaks() -> None:
    step = _release().split("\n5. ", 1)[1].split("\n6. ", 1)[0]
    assert "Then run `gh auth status`. A non-zero exit: stop." in step
    assert "Next: gh auth login" in step
    assert "or `gh` yourself" not in _release()


def test_push_train_runs_the_recovery_round_on_a_moved_tip() -> None:
    # 73, spec 3.3: a step 9 refusal for a moved tip runs reaudit, one round, then step 9 again.
    text = _release()
    step9 = text.split("\n9. ", 1)[1].split("\n10. ", 1)[0]
    moved = step9.split("Exit 1 whose output says the tip moved past the judged tip", 1)[1]
    assert "run the Recovery round below once, then run this step again" in moved
    assert "Any other exit 1: stop and show its output" in moved
    recovery = _section(text, "## Recovery round", "## Push")
    order = [
        REAUDIT_CMD,
        MAIN + "daedalus_workspace.py refresh --repo <repo> --name <train-id>-audit`",
        MAIN + "daedalus_train.py model --repo <repo> --agent auditor`",
        "Agent(`auditor`) with `model: <that word>`",
        "`<repo>/docs/.tmp/daedalus/<train-id>/audit/round<n>/findings.txt`",
        MAIN + "daedalus_train.py verdict --repo <repo> --status approved --round <n> "
        "--findings <findings path> --tip <judged tip>`",
        MAIN + "daedalus_train.py summary --repo <repo>`",
        "Then run Preconditions step 9 again.",
    ]
    places = [recovery.index(part) for part in order]
    assert places == sorted(places)
    assert "the line `Worktree: <audit worktree path>`" in recovery
    # audit_proof._summary_session reads the first Session line; step 8 bound this session.
    step4 = recovery.split("\n4. ", 1)[1].split("\n5. ", 1)[0]
    write = step4.split(MAIN + "daedalus_train.py summary --repo <repo>`", 1)[1]
    assert "never write the summary by hand (0046)" in write
    assert (
        "the first line under `## Audit log` is "
        "`Session <id>: .claude/daedalus/audit/<id>.jsonl` with this session's id from step 8, "
        "the build's session line after it"
    ) in write
    assert "The push proof reads the log of the first `Session <id>:` line" in write
    assert "with one Write" not in step4
    rejected = recovery.split("\n5. `[VERDICT: REJECTED] tip=<sha>`: ", 1)[1]
    assert "with `--status rejected`" in rejected
    assert "the three choices of the per-finding audit prompt" in rejected
    assert "this phase runs no second recovery round" in rejected


def test_push_train_routes_a_ci_reply_at_push_step_two() -> None:
    # issue 20: a conductor that watched CI in its push reply goes straight to the CI rules.
    step2 = _section(_release(), "\n2. Route the reply:", "\n3. SendMessage(releaser")
    route = step2.split("- `[STATUS: CI] run=<id> conclusion=<text>`: ", 1)[1].split("\n", 1)[0]
    assert "route this CI line by the step 3 conclusion rules" in route
    assert "without sending the Watch CI message" in route
    assert "Run `gh pr view daedalus/<train-id> --json url`." in route


def test_release_names_the_conductor_as_the_only_pusher_and_the_operator_as_merger() -> None:
    # 0001, spec 3.7: the conductor alone pushes; the operator merges; main, never the orchestrator.
    _, body = _split(RELEASE)
    flat = " ".join(body.split())
    assert "You never run `git push` or any `gh` command but `gh auth status` yourself" in flat
    assert "the releaser does." in flat
    assert "Nobody here merges" in flat and "the operator merges (0001)" in flat
    evidence = flat.split("## Evidence that ends it", 1)[1].split("## Agents it uses", 1)[0]
    assert "only the releaser pushes (scripts/lib/gh_policy.py:307)" in evidence
    assert "No agent merges (scripts/lib/gh_policy.py:45)" in evidence
    assert "never in the orchestrator" in flat and "(agents/orchestrator.md:36)" in flat
    # 0241: the release phase names the new command; the old one is gone.
    assert "started with `/daedalus:run push`." in flat and "push-train" not in flat


@pytest.mark.parametrize("command", _conductor_commands(RELEASE, "### Push", "### Hand-off"))
def test_release_conductor_commands_pass_the_jail(
    repo_cwd: Path, project_data: Path, command: str
) -> None:
    # spec 3.7: the release phase hands the conductor the same command grammar as the push train.
    d = _conductor_decide(repo_cwd, project_data, command)
    assert d.allow, (command, d.reason)


def test_release_scans_for_secrets_without_the_asset_files() -> None:
    # 0192: gitleaks splits --log-opts on spaces and keeps quotes, so the tail goes unquoted.
    push = " ".join(_section(_release(), "### Push", "### Hand-off").split())
    scan = push.split("gitleaks detect --redact --log-opts=<base sha>", 1)[1]
    assert f"first run {ASSETS_CMD}; exit 1: stop and show its output." in scan
    assert (
        'write the command as `gitleaks detect --redact --log-opts="<base sha>..daedalus/'
        '<train-id> <tail>"`, the tail copied exactly and unquoted inside the double quotes' in scan
    )
    releaser = " ".join((REPO_ROOT / "agents" / "releaser.md").read_text("utf-8").split())
    assert '`"<base>..<branch> -- . :(exclude)assets/"`, run it exactly as given (0192)' in (
        releaser
    )


def test_push_train_validates_the_train_id_against_run_skill() -> None:
    # Ruling M11: the format comes from build-train Preconditions step 6.
    assert "`<train-id>` to the UTC time as `YYYYMMDD-HHMMSS`" in _run_skill()
    text = _release()
    assert "`^[0-9]{8}-[0-9]{6}$`, the UTC `YYYYMMDD-HHMMSS` form" in text
    assert "No match: stop." in text


def test_skill_script_commands_are_allowed_for_main() -> None:
    # M4: every plugin script command in the trains passes the jail as the main session.
    from lib.config import Config
    from lib.jail import decide

    root = str(REPO_ROOT)
    commands = [
        re.sub(r"<[^>]+>", "x", m.replace("${CLAUDE_PLUGIN_ROOT}", root).replace("<repo>", root))
        for path in (REPO_ROOT / "skills" / n for n in ("release",))
        for m in _SKILL_SCRIPT.findall((path / "SKILL.md").read_text(encoding="utf-8"))
    ]
    assert len(commands) >= 4
    for command in commands:
        payload = {"tool_name": "Bash", "tool_input": {"command": command}, "cwd": root}
        d = decide(payload, Config())
        assert d.allow, (command, d.reason)


def test_issue30_skill_script_commands_pass_for_main_during_a_train(
    repo_cwd: Path, project_data: Path
) -> None:
    # issue 30: every skill script command passes the jail for the main session in a train.
    from lib.config import Config
    from lib.jail import decide

    (project_data / "train.active").write_text("20261015-120000\n")
    root, repo = str(REPO_ROOT), str(repo_cwd)
    commands = [
        re.sub(r"<[^>]+>", "x", m.replace("${CLAUDE_PLUGIN_ROOT}", root).replace("<repo>", repo))
        for path in (REPO_ROOT / "skills" / n for n in ("release",))
        for m in _SKILL_SCRIPT.findall((path / "SKILL.md").read_text(encoding="utf-8"))
    ]
    assert len(commands) >= 4
    for command in commands:
        payload = {"tool_name": "Bash", "tool_input": {"command": command}, "cwd": repo}
        d = decide(payload, Config())
        assert d.allow, (command, d.reason)
