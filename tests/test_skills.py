# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import ast
import re
from pathlib import Path
from typing import Any

import pytest

from tests.conftest import REPO_ROOT

SKILLS = sorted((REPO_ROOT / "skills").glob("*/SKILL.md"))
COPYRIGHT = "<!-- Copyright (c) 2026 Brad Duhon. SPDX-License-Identifier: GPL-3.0-or-later -->"
_SCRIPT_REF = re.compile(r"\$\{?CLAUDE_PLUGIN_ROOT\}?/scripts/([^\s`\"')]+?\.py)")


def _split(path: Path) -> tuple[dict[str, str], str]:
    text = path.read_text(encoding="utf-8")
    assert text.startswith("---\n"), path
    block, body = text[4:].split("\n---\n", 1)
    fields: dict[str, str] = {}
    for line in block.splitlines():
        key, _, value = line.partition(":")
        fields[key.strip()] = value.strip()
    return fields, body


def test_skills_exist() -> None:
    assert {p.parent.name for p in SKILLS} >= {
        "doctor",
        "audit-report",
        "build-train",
        "push-train",
    }


@pytest.mark.parametrize("path", SKILLS, ids=lambda p: p.parent.name)
def test_frontmatter_names_the_directory(path: Path) -> None:
    fields, _ = _split(path)
    assert fields.get("name") == path.parent.name
    assert fields.get("description")


@pytest.mark.parametrize("path", SKILLS, ids=lambda p: p.parent.name)
def test_copyright_follows_frontmatter(path: Path) -> None:
    _, body = _split(path)
    assert body.splitlines()[0] == COPYRIGHT


@pytest.mark.parametrize("path", SKILLS, ids=lambda p: p.parent.name)
def test_no_em_or_en_dashes(path: Path) -> None:
    text = path.read_text(encoding="utf-8")
    assert "\u2013" not in text and "\u2014" not in text


@pytest.mark.parametrize("path", SKILLS, ids=lambda p: p.parent.name)
def test_named_scripts_exist(path: Path) -> None:
    for name in _SCRIPT_REF.findall(path.read_text(encoding="utf-8")):
        assert (REPO_ROOT / "scripts" / name).is_file(), f"{path}: {name}"


def test_audit_report_names_its_scripts() -> None:
    text = (REPO_ROOT / "skills" / "audit-report" / "SKILL.md").read_text(encoding="utf-8")
    names = set(_SCRIPT_REF.findall(text))
    assert {"audit_report.py", "verify_audit_chain.py"} <= names


def test_script_ref_stops_at_py() -> None:
    # N2: a sentence-ending period after the script name is not part of the name.
    text = "run ${CLAUDE_PLUGIN_ROOT}/scripts/audit_report.py. Then"
    assert _SCRIPT_REF.findall(text) == ["audit_report.py"]


BUILD_TRAIN = REPO_ROOT / "skills" / "build-train" / "SKILL.md"
_AGENT_REF = re.compile(r"Agent\(`([a-z-]+)`\)")


def _build_train() -> str:
    return BUILD_TRAIN.read_text(encoding="utf-8")


def test_build_train_dispatches_existing_agents() -> None:
    names = set(_AGENT_REF.findall(_build_train()))
    for name in names:
        assert (REPO_ROOT / "agents" / f"{name}.md").is_file(), name
    personas = {p.stem for p in (REPO_ROOT / "agents").glob("*.md")}
    # The Push Train owns pr-train-conductor; the Build Train dispatches every other persona.
    assert names == personas - {"pr-train-conductor"}


def test_build_train_probes_the_ledger_and_asks() -> None:
    text = _build_train()
    pre = text.split("## Preconditions", 1)[1].split("## Phase 1", 1)[0]
    assert "append_ledger.py --probe" in pre
    ledger_step = pre.split("\n4. ", 1)[1].split("\n5. ", 1)[0]
    assert "append_ledger.py --probe" in ledger_step
    none_found = next(line for line in ledger_step.splitlines() if "none declared" in line)
    assert "ask the operator" in none_found
    assert (
        '"This repo has no decision ledger. Options: name an existing file, or let Daedalus '
        'create docs/decisions.md as a table. Which?"'
    ) in none_found


def test_build_train_routes_every_yield_and_the_contradiction_stop() -> None:
    text = _build_train()
    for route in ("YIELD_WEB", "YIELD_CONTRACT", "YIELD_COMPLIANCE", "YIELD_STANDARDS"):
        assert f"[STATUS: {route}]" in text, route
    assert "[STANDARDS: CONTRADICTION]" in text


def test_build_train_never_pushes() -> None:
    text = _build_train()
    assert "git push" not in text
    assert "--no-ff" in text and "daedalus/<train-id>" in text


def test_build_train_writes_summary_under_docs_tmp() -> None:
    # T7 ruling: the conductor's --body-file reads docs/.tmp, never the data dir.
    text = _build_train()
    assert "<repo>/docs/.tmp/daedalus/<train-id>-summary.md" in text
    assert "docs/.tmp/daedalus/.gitignore" in text
    assert "/daedalus:audit-report" in text


def test_build_train_resolves_the_cache_for_specialists() -> None:
    text = _build_train()
    assert "daedalus_doctor.py --print-cache-dir" in text
    assert "<that path>/frameworks" in text


def test_build_train_stops_on_off_contract_replies_and_dead_hooks() -> None:
    text = _build_train()
    assert "does not end with one of its contract lines or contract sections, stop" in text
    assert "ends with its rule list and has no status line" in text
    assert (
        "the jail is not enforcing. Next: run the Daedalus health check (`/daedalus:doctor`)."
    ) in text
    assert "charter: none (repo-local ledger)" in text
    assert "ids=<id>[,<id>]" in text
    assert "Session <id>: .claude/daedalus/audit/<id>.jsonl" in text


@pytest.mark.parametrize("path", SKILLS, ids=lambda p: p.parent.name)
def test_no_plan_or_task_numbers(path: Path) -> None:
    # R1-M3: operator text never names internal plan or task numbers.
    assert not re.search(r"(Task|Plan) [0-9]", path.read_text(encoding="utf-8"))


def test_build_train_switches_back_after_merge_abort() -> None:
    assert re.search(r"`git merge --abort`, then `git switch <base branch>`", _build_train())


def test_build_train_branches_a_clean_charter_and_switches_back() -> None:
    text = _build_train()
    assert "`git -C <charter_root> status --porcelain`" in text
    assert "`git -C <charter_root> switch -c daedalus/<train-id>`" in text
    assert "`git -C <charter_root> switch <recorded branch>`" in text


def test_build_train_checks_the_probe_record_in_the_audit_log() -> None:
    step = _build_train().split("\n5. ", 1)[1].split("\n6. ", 1)[0]
    assert "audit log" in step
    assert '"event":"PreToolUse".*"tool_name":"Bash"' in step
    assert "Grep it again with line numbers for `append_ledger.py --probe`" in step
    assert "a `tool_input.command` containing `append_ledger.py --probe`" in step
    assert "Never Read the whole log." in step


def test_build_train_records_the_charter_branch_and_switches_back_on_every_stop() -> None:
    # R2-M2, R2-M3: record before switch -c; switch back before every later stop.
    text = _build_train()
    record = re.search(r"record the Charter's current branch with `([^`]+)`", text)
    assert record and record.group(1) == "git -C <charter_root> rev-parse --abbrev-ref HEAD"
    assert "Charter switch-back: once Preconditions step 7 has created the Charter branch" in text
    step = text.split("`[STATUS: COMMITTED] <sha>", 1)[1].split("\n5. ", 1)[0]
    for stop in (
        "LEDGER_MISMATCH] expected=<n> ledger=<m>`: Charter switch-back",
        "Any other reply: Charter switch-back",
    ):
        assert stop in step, stop
    assert "Otherwise Charter switch-back, then stop and show the detail." in step
    # M7: the rule's command and the MISMATCH switch-on.
    assert (
        "run `git -C <charter_root> switch <recorded branch>` before every stop that follows"
        in text
    )
    assert "the train runs `git -C <charter_root> switch daedalus/<train-id>`" in step


def test_build_train_keeps_a_dirty_charter_ledger_on_the_train_branch() -> None:
    # Ruling M8: a modified ledger after BLOCKED stays on daedalus/<train-id>.
    step = _build_train().split("`[STATUS: BLOCKED] <detail>`:", 1)[1].split("\n5. ", 1)[0]
    assert step.lstrip().startswith(
        "when you created a Charter branch, run `git -C <charter_root> status --porcelain` first."
    )
    assert "If it lists the ledger file, stop without the switch-back" in step


def test_build_train_summary_names_every_charter_form() -> None:
    text = _build_train()
    assert (
        "charter: <charter name>, branch daedalus/<train-id>, charter base: <recorded branch> "
        "(ledger under charter_root)"
    ) in text
    assert (
        "charter: <charter name>, branch daedalus/<train-id>, charter base: <recorded branch> "
        "(ledger repo-local)"
    ) in text
    assert "no charter branch" not in text
    assert "Ledger: <ledger repo name>/<ledger path relative to that repo>." in text
    # N2: the I2 sentence that defines <charter name>.
    assert "`<charter name>` is the last component of `charter_root`" in text


def test_build_train_summary_carries_no_absolute_path() -> None:
    # I2: the summary is a public PR body.
    shape = _build_train().split("Shape:", 1)[1].split("\n6. ", 1)[0]
    lines = [ln for ln in shape.splitlines() if "charter:" in ln or "Ledger:" in ln]
    assert len(lines) == 4
    lines += [ln for ln in shape.splitlines() if "Contract:" in ln]
    assert len(lines) == 6
    for line in lines:
        assert "<path>" not in line and "<charter_root>" not in line and "/home" not in line


def test_build_train_reads_the_auditor_verdict_first() -> None:
    text = _build_train()
    assert "Read the verdict from the first line of the auditor's reply." in text
    # N2: the off-contract rule names the first-line exception.
    assert (
        "The security-auditor's verdict line is the first line of its reply, not the last; "
        "read it there."
    ) in text
    auditor = (REPO_ROOT / "agents" / "security-auditor.md").read_text(encoding="utf-8")
    contract = auditor.split("## Status contract", 1)[1]
    assert "starts with exactly one of these verdict lines as its first line" in contract


PUSH_TRAIN = REPO_ROOT / "skills" / "push-train" / "SKILL.md"


def _push_train() -> str:
    return PUSH_TRAIN.read_text(encoding="utf-8")


def test_push_train_dispatches_only_the_conductor() -> None:
    assert set(_AGENT_REF.findall(_push_train())) == {"pr-train-conductor"}


def test_push_train_leaves_the_merge_to_the_operator() -> None:
    text = _push_train()
    assert "never merge" in text.lower() or "operator merges" in text
    assert "gh pr merge" not in text
    assert "--force" not in text


def test_push_train_uses_the_conductor_push_grammar_and_scan() -> None:
    text = _push_train()
    assert "git push -u origin" in text
    assert "gitleaks detect" in text
    assert "gitleaks version" in text
    assert "--body-file <repo>/docs/.tmp/daedalus/<train-id>-summary.md" in text


def test_push_train_proves_live_hooks_with_the_script() -> None:
    # 0024: the log reading moved to verify_audit_chain.py; test_audit_proof.py holds it.
    text = _push_train()
    step = text.split("\n7. ", 1)[1].split("\n8. ", 1)[0]
    assert (
        "`python3 ${CLAUDE_PLUGIN_ROOT}/scripts/verify_audit_chain.py --hooks-live --repo <repo>`"
    ) in step
    assert "Grep" not in text
    assert "docs/.tmp/daedalus/" in text
    assert "Next: run a Build Train first (`/daedalus:build-train`)." in text


def test_push_train_ends_with_the_operator_checklist() -> None:
    hand_off = _push_train().split("## Hand-off", 1)[1]
    for item in ("1. Review", "2. Check CI", "3. Merge"):
        assert item in hand_off, item
    # M2: leave the train branch before deleting it, in both repos.
    assert (
        "4. Run `git switch <base branch>`, then delete the branch with "
        "`git branch -d daedalus/<train-id>`."
    ) in hand_off
    assert (
        "then run `git -C <charter_root> switch <charter base>` and "
        "`git -C <charter_root> branch -d daedalus/<train-id>`."
    ) in hand_off
    assert "5. Run `/daedalus:audit-report <session>`" in hand_off


def test_build_train_names_the_push_train_in_present_tense() -> None:
    text = _build_train()
    assert "/daedalus:push-train" in text
    assert "Push Train will" not in text and "adds the Push Train" not in text
    assert "A later Daedalus release adds `/daedalus:push-train`" not in text


def test_push_train_proves_the_approved_audit_with_the_script() -> None:
    # 0024: the auditor record checks moved to verify_audit_chain.py --approved.
    step = _push_train().split("\n8. ", 1)[1].split("\n9. ", 1)[0]
    assert (
        "`python3 ${CLAUDE_PLUGIN_ROOT}/scripts/verify_audit_chain.py --approved <train-id> "
        "--repo <repo>`"
    ) in step
    assert "its `Next:` line is the next action" in step


def test_push_train_stops_on_each_precondition() -> None:
    pre = _push_train().split("## Preconditions", 1)[1].split("## Push", 1)[0]
    for stop in (
        "No file: stop. Next: run a Build Train first (`/daedalus:build-train`).",
        "Anything but `daedalus/<train-id>`: stop.",
        "Any `??` line or any change in column two: stop.",
        "the second an empty line, because the conductor's body files must sit under",
    ):
        assert stop in pre, stop


def _section(text: str, head: str, nxt: str) -> str:
    return text.split(head, 1)[1].split(nxt, 1)[0]


def test_build_train_saves_and_commits_the_contract() -> None:
    # 0011: the packet is saved and committed; the summary records path and version.
    text = _build_train()
    phase1 = _section(text, "## Phase 1", "## Phase 2")
    assert '"Save the packet to <contract path>, then end the reply with the packet."' in phase1
    assert "Run `git switch -c daedalus/<train-id>`: the integration branch" in phase1
    assert phase1.index("git switch -c daedalus/<train-id>") < phase1.index(
        "Agent(`contract-spec`)"
    )
    assert "The main session owns this commit; contract-spec never commits." in phase1
    assert '`git commit -m "Lock contract <name> v<packet_version>"`' in phase1
    assert '`git -C <charter_root> commit -m "Lock contract <name> v<packet_version>"`' in phase1
    assert "Glob the contract path. No file: stop. Next: rerun `/daedalus:build-train`" in phase1
    phase2 = _section(text, "## Phase 2", "## Phase 3")
    assert '"Save the revised packet to <contract path>, overwriting it,' in phase2
    assert "with the message `Revise contract <name> v<N>`" in phase2
    assert "       Contract: contracts/<name>.md v<packet_version>\n" in text
    assert "Contract: <charter name>/specs/<name>.md v<packet_version>\n" in text
    rule = (
        "The Build Train saves the Locked Contract Packet to a file and the main session commits it"
    )
    assert rule in text
    assert "a Build Train keeps the packet in the reply" not in text
    # R3-M2: the howto carries the same sentence.
    howto = (REPO_ROOT / "docs" / "howto" / "README.md").read_text(encoding="utf-8")
    assert (
        "saves the Locked Contract Packet to a file, and the train's main session commits it"
        in (howto)
    )
    assert "committed on the integration branch `daedalus/<train-id>` before any coder starts" in (
        howto
    )
    assert "a Build Train keeps the packet in the reply" not in howto


def test_build_train_skips_the_commit_for_an_unchanged_contract() -> None:
    # Ruling 2: file exists, add, then diff --cached --quiet; rc 0 skips the commit.
    phase1 = _section(_build_train(), "## Phase 1", "## Phase 2")
    repo = phase1.split("   - In this repo:", 1)[1].split("\n", 1)[0]
    order = [
        "Glob the contract path",
        "`git add contracts/<name>.md`",
        "`git diff --cached --quiet -- contracts/<name>.md`",
        "Exit 0: the file is unchanged; skip the commit and note `contract unchanged, no commit`.",
        '`git commit -m "Lock contract <name> v<packet_version>"`',
    ]
    assert [repo.index(s) for s in order] == sorted(repo.index(s) for s in order)
    charter = phase1.split("   - In the Charter:", 1)[1].split("\n", 1)[0]
    order = [
        "`git -C <charter_root> add specs/<name>.md`",
        "`git -C <charter_root> diff --cached --quiet -- specs/<name>.md`",
        "Exit 0: skip the commit with the same note.",
        '`git -C <charter_root> commit -m "Lock contract <name> v<packet_version>"`',
    ]
    assert [charter.index(s) for s in order] == sorted(charter.index(s) for s in order)
    assert "git status --porcelain -- contracts/<name>.md`. No output" not in phase1


def test_build_train_refuses_a_revision_that_does_not_raise_the_version() -> None:
    # R4-M2: N must exceed the recorded packet_version before the Revise commit.
    phase2 = _section(_build_train(), "## Phase 2", "## Phase 3")
    # R5-I2: one retry, then the second non-increasing version stops.
    stop = (
        "When <N> is not greater than the State Block packet_version <n>, "
        'SendMessage(contract-spec, "packet_version must exceed <n>; revise and save again") '
        "once. A second reply whose <N> is still not greater stops the train: the worktree "
        "teardown listing first, then the uncommitted-contract Next:."
    )
    assert stop in phase2
    assert phase2.index(stop) < phase2.index("`Revise contract <name> v<N>`")


def test_build_train_branches_the_charter_in_preconditions() -> None:
    # 0011: every Charter write of the train lands on the train branch.
    text = _build_train()
    pre = _section(text, "## Preconditions", "## Phase 1")
    step7 = pre.split("\n7. ", 1)[1]
    assert step7.startswith("When `charter_root` is declared, run `git -C <charter_root> status")
    assert "`git -C <charter_root> switch -c daedalus/<train-id>`" in step7
    assert step7.index("rev-parse --abbrev-ref HEAD") < step7.index("switch -c")
    phase3 = _section(text, "## Phase 3", "\n5. The summary")
    assert "switch -c" not in phase3
    assert "it is empty when the contract commit landed" in phase3
    assert "Integration switch-back: once Phase 1 step 2 has created" in text
    # R4-M3: the howto says where the Charter branch comes from.
    howto = (REPO_ROOT / "docs" / "howto" / "README.md").read_text(encoding="utf-8")
    assert (
        "The train creates the Charter's `daedalus/<train-id>` branch in its checks, for the "
        "contract and ledger commits"
    ) in howto


def test_build_train_audits_from_the_integration_branch() -> None:
    # R4-C1: the contract commits sit on daedalus/<train-id>, outside every unit diff.
    phase3 = _section(_build_train(), "## Phase 3", "\n3. ")
    step2 = phase3.split("\n2. ", 1)[1]
    dispatch = step2.split("Then Agent(`security-auditor`) with:", 1)[1].split(". Read", 1)[0]
    assert dispatch.startswith(" the diff base `daedalus/<train-id>`, so each diff leaves out")
    assert "base commit" not in dispatch and "base sha" not in dispatch
    step1 = phase3.split("\n2. ", 1)[0]
    assert "(`git diff daedalus/<train-id>...<branch>`)" in step1
    assert "<base sha>" not in step1
    auditor = (REPO_ROOT / "agents" / "security-auditor.md").read_text(encoding="utf-8")
    assert "For each branch run `git diff <diff base>...<branch>`" in auditor


def test_build_train_keeps_dirty_trees_on_the_train_branch() -> None:
    # Ruling 1, R4-I1: a dirty Charter or an uncommitted contract takes no switch-back.
    text = _build_train()
    rules = text.split("## Preconditions", 1)[0]
    assert (
        "The exception: any stop while the Charter tree is dirty (`git -C <charter_root> status "
        "--porcelain` prints anything) takes no Charter switch-back"
    ) in rules
    assert "The one exception is a charter-docs BLOCKED" not in rules
    assert (
        "- Uncommitted contract: any stop while the contract file is uncommitted "
        "(`git status --porcelain -- contracts/<name>.md`, or `git -C <charter_root> status "
        "--porcelain -- specs/<name>.md`, prints its path) takes neither switch-back."
    ) in rules
    assert "The stop names the file and says it sits on `daedalus/<train-id>` in its repo." in rules
    phase3 = _section(text, "## Phase 3", "\n5. The summary")
    assert (
        "Any output: stop without the Charter switch-back, because the Charter tree is dirty"
        in (phase3)
    )
    assert "Any output: Charter switch-back" not in phase3
    # R5-I1: the dirty-Charter stop overrides the global Next: and resumes on the train branch.
    dirty = phase3.split("Any output: stop without the Charter switch-back", 1)[1].split("\n", 1)[0]
    assert "This Next: overrides the dirty-Charter Next: in the rules above." in dirty
    assert (
        "leave the Charter on that branch, then say continue; the train runs "
        "`git -C <charter_root> switch daedalus/<train-id>` and resumes at this step."
    ) in dirty
    assert (
        "Any other reply: Charter switch-back, none while the Charter tree is dirty, then the "
        "off-contract stop."
    ) in phase3


def test_build_train_keeps_worktrees_out_of_git_and_the_train() -> None:
    # R3-O1, R4-I3, R4-M1: worktrees are ignored, listed, force-removed on every exit.
    text = _build_train()
    # 0022: daedalus_workspace.py create writes the worktrees ignore marker itself.
    assert "<repo>/.claude/worktrees/.gitignore" not in text
    rules = text.split("## Preconditions", 1)[0]
    teardown = rules.split("- Worktree teardown: ", 1)[1].split("\n", 1)[0]
    assert teardown.startswith(
        "worktrees never outlive the train. Before every stop once Phase 2 has begun, and after "
        "the merges in Phase 3 step 4,"
    )
    order = [
        "show `git -C <path> status --porcelain` (the changes being discarded)",
        "run `python3 ${CLAUDE_PLUGIN_ROOT}/scripts/daedalus_workspace.py remove --repo <repo> "
        "--name <train-id>-<unit-slug>`",
        "it removes the worktree, keeps its branch, and prunes",
    ]
    assert [teardown.index(s) for s in order] == sorted(teardown.index(s) for s in order)
    assert "they are discarded, never committed." in teardown
    assert teardown.rstrip().endswith(
        "Next: run `git worktree remove --force <path>` and `git worktree prune` from your own "
        "shell."
    )
    # R5-C1: only the State Block's unit branches are torn down.
    assert (
        "the scope is only the unit branches recorded in the State Block, each matched by its "
        "branch name in `git worktree list --porcelain`. Any other worktree under "
        "`<repo>/.claude/worktrees/` is left untouched and never listed for discard."
    ) in teardown
    phase3 = _section(text, "## Phase 3", "\n5. The summary")
    assert "After the merges succeed, run the worktree teardown." in phase3
    assert phase3.index("worktree teardown") < phase3.index("Agent(`charter-docs`)")
    assert "A remove failure: Charter switch-back, then stop" in phase3
    assert "commit or discard the changes in the worktree" not in text


def test_push_train_hands_off_the_contract_commits() -> None:
    # 0011: the contract commits ride the pushed branches; no new conductor command.
    pt = _push_train()
    assert "the contract path and version from the `Contract:` line" in pt
    assert "when the `charter:` line ends in `(ledger under charter_root)`" in pt
    hand_off = pt.split("## Hand-off", 1)[1]
    assert "its `Lock contract` and `Revise contract` commits are part of the diff" in hand_off
    assert "the contract commits are in this pull request" in hand_off
    assert "contract" not in _section(pt, "## Push", "## Charter branch").lower()


def test_push_train_names_the_charter_pull_request_by_its_content() -> None:
    # Ruling 3: title and body split on where the ledger lives.
    pt = _push_train()
    body = _section(pt, "## Charter branch", "## Hand-off")
    ledger = body.split("(ledger under charter_root)`:", 1)[1].split("Otherwise:", 1)[0]
    assert "    Contract and ledger entries for Build Train <train-id>.\n" in ledger
    other = body.split("Otherwise:", 1)[1]
    assert "    Contract for Build Train <train-id>.\n" in other
    assert "ledger" not in other.split("The conductor", 1)[0]
    hand_off = pt.split("## Hand-off", 1)[1]
    assert (
        "where `<title>` is `Build Train <train-id>: contract and ledger` when the `charter:` line "
        "ends in `(ledger under charter_root)`, else `Build Train <train-id>: contract`."
    ) in hand_off


def test_push_train_checks_the_remote_before_the_conductor() -> None:
    # F5: the conductor's hook refuses git remote, so the main session checks origin.
    text = _push_train()
    pre = text.split("## Preconditions", 1)[1].split("## Push", 1)[0]
    assert "run `git remote get-url origin` before any conductor dispatch" in pre
    assert "A non-zero exit: stop. Next: add a remote named origin, then rerun." in pre
    dispatch = text.split("## Push", 1)[1].split("\n2. ", 1)[0]
    assert "The remote `origin` exists" in dispatch
    assert "Never repeat the URL it prints to the operator; a remote URL can carry a token." in pre
    assert text.index("git remote get-url origin") < text.index("Agent(`pr-train-conductor`)")


def test_push_train_validates_the_train_id_against_build_train() -> None:
    # Ruling M11: the format comes from build-train Preconditions step 6.
    assert "`<train-id>` to the UTC time as `YYYYMMDD-HHMMSS`" in _build_train()
    text = _push_train()
    assert "`^[0-9]{8}-[0-9]{6}$`, the UTC `YYYYMMDD-HHMMSS` form" in text
    assert "No match: stop." in text


def test_push_train_dispatch_pins_flags_and_paths() -> None:
    text = _push_train()
    assert "gitleaks detect --redact --log-opts=<base sha>..daedalus/<train-id>" in text
    for forbidden in (
        "Never run `git commit -a`",
        "`git commit -am`",
        "never `gh pr edit --base`",
        "never `gh pr create --body`",
    ):
        assert forbidden in text, forbidden
    assert '"Use only the commands above. Never run' in text
    # M9: every body file is absolute under <repo>.
    paths = re.findall(r"--body-file (\S+?)`", text)
    assert len(paths) == 4
    for path in paths:
        assert path.startswith("<repo>/docs/.tmp/daedalus/<train-id>-"), path


def test_push_train_routes_ci_without_waiting() -> None:
    text = _push_train()
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


def test_both_trains_carry_the_pending_ledger_line() -> None:
    # Ruling N3: the summary exists before charter-docs; push-train refuses it pending.
    bt = _build_train()
    assert "with the line `Ledger ids: pending. Codes: --repo <R> --type <T>.`" in bt
    assert "replace the summary's `Ledger ids: pending` line with" in bt
    assert bt.index("Write the summary now") < bt.index("Agent(`charter-docs`)")
    pt = _push_train()
    assert "A `Ledger ids: pending` line means the Build Train stopped before" in pt
    assert "run `git -C <charter_root> switch daedalus/<train-id>` first." in pt
    assert "A later Daedalus release adds a Build Train resume for this step." in pt
    # N5-M4: the pending Next: writes the same line build-train writes, period included.
    assert "replace that line with `Ledger ids: <ids> in commit <sha>.`, switch" in pt
    assert "with `Ledger ids: <ids> in commit <sha>.` using the Edit tool" in bt
    # N5-M2: the Charter dirty-tree stop precedes the summary write.
    assert "Every stop after this point leaves a summary." in bt
    assert "Every stop after the merge" not in bt


def test_push_train_reads_the_ledger_sha_from_the_ledger_ids_line() -> None:
    # N5-M1: the summary's `Ledger:` line is the path; the sha is on `Ledger ids:`.
    step = _push_train().split("\n3. ", 1)[1].split("\n4. ", 1)[0]
    assert "the ledger commit sha from the `Ledger ids:` line," in step


def test_push_train_sandbox_check_uses_the_repo() -> None:
    # 0020: the sandbox check runs against <repo>, never the session's working directory.
    text = _push_train()
    assert "--repo ." not in text
    step = text.split("\n1. ", 1)[1].split("\n2. ", 1)[0]
    assert f"`{SANDBOX_STATE_CMD} --repo <repo>`" in step


def test_push_train_hands_the_charter_to_the_operator() -> None:
    hand_off = _push_train().split("## Hand-off", 1)[1]
    assert "`git -C <charter_root> push -u origin daedalus/<train-id>`" in hand_off
    assert (
        "`gh pr create --base <charter base> --head daedalus/<train-id> --title "
        '"<title>" --body-file '
        "<repo>/docs/.tmp/daedalus/<train-id>-charter-pr.md`"
    ) in hand_off
    assert hand_off.rstrip().endswith(
        "Execution Train readiness: a later Daedalus release adds the readiness checklist."
    )
    assert "The train does not stop here; go on to the hand-off." in _push_train()


# 0022: the train makes the worktrees; the merge-base check stays as a defence.
DESCENT_STOP = (
    '"Unit <b> does not descend from the integration branch. Next: rerun the train; if it '
    'repeats, file an issue with the train summary."'
)


def test_build_train_checks_each_unit_descends_from_the_lock() -> None:
    text = _build_train()
    assert "packet_version: <n>  contract: <contract path>  lock: <sha>" in text
    phase1 = text.split("## Phase 1", 1)[1].split("## Phase 2", 1)[0]
    assert "Run `git rev-parse daedalus/<train-id>` and record it as `lock: <sha>`" in phase1
    assert "Phase 2 creates every coder worktree from it" in phase1
    assert "baseRef" not in text
    complete = next(line for line in text.splitlines() if line.startswith("| `[STATUS: COMPLETE]"))
    check = (
        "Then run `git merge-base --is-ancestor <lock sha> <b>` with the State Block `lock:` sha."
    )
    assert check in complete
    assert f"A non-zero exit: stop with {DESCENT_STOP} Otherwise record packet_version" in complete
    assert "Otherwise record branch" not in complete


BRANCH_STOP = (
    '"Unit <unit> reported branch <b>; the train created daedalus-unit/<train-id>-<unit-slug>. '
    'Next: rerun the train; if it repeats, file an issue with the train summary."'
)


def test_build_train_requires_the_reported_branch_to_be_the_created_one() -> None:
    # 0022: daedalus/<train-id> is its own ancestor and would merge as a no-op.
    complete = next(
        line for line in _build_train().splitlines() if line.startswith("| `[STATUS: COMPLETE]")
    )
    compare = (
        "First compare `<b>` with the branch the State Block recorded for that unit in Phase 2. "
        f"A mismatch: stop with {BRANCH_STOP}"
    )
    assert compare in complete
    assert complete.index(compare) < complete.index("git merge-base --is-ancestor")
    assert "the unit's branch stays the one Phase 2 recorded" in complete


def test_build_train_creates_each_coder_worktree() -> None:
    phase2 = _section(_build_train(), "## Phase 2", "## Phase 3")
    assert (
        "`python3 ${CLAUDE_PLUGIN_ROOT}/scripts/daedalus_workspace.py create --repo <repo> "
        "--name <train-id>-<unit-slug> --base daedalus/<train-id>`"
    ) in phase2
    assert (
        "`git worktree add -q -b daedalus-unit/<train-id>-<unit-slug> "
        "<repo>/.claude/worktrees/<train-id>-<unit-slug> daedalus/<train-id>`"
    ) in phase2
    assert "the line `Worktree: <path>` naming its working directory" in phase2
    # 0022: the coder prompt binds file paths and git pathspecs to the worktree.
    assert (
        "every file path and every git pathspec you use is absolute or goes through `git -C <path>`"
    ) in phase2
    assert phase2.index("daedalus_workspace.py create") < phase2.index("Agent(`repo-coder`)")


def test_build_train_guards_the_main_checkout_before_merging() -> None:
    phase3 = _section(_build_train(), "## Phase 3", "\n5. The summary")
    merge = phase3.split("\n4. ", 1)[1]
    assert merge.index("Run `git status --porcelain`.") < merge.index("git merge --no-ff")
    assert "a coder changed the main checkout instead of its worktree" in merge


MARK = "`python3 ${CLAUDE_PLUGIN_ROOT}/scripts/daedalus_workspace.py mark --repo <repo> --train "
UNMARK = "`python3 ${CLAUDE_PLUGIN_ROOT}/scripts/daedalus_workspace.py unmark --repo <repo>`"


def test_build_train_marks_the_train_active_and_clears_it() -> None:
    # 0023: written once Preconditions pass, removed at the end and on every stop after it.
    text = _build_train()
    pre = _section(text, "## Preconditions", "**State Block**")
    step9 = pre.split("\n9. ", 1)[1]
    assert MARK + "<train-id>`" in step9
    assert "<repo>/.claude/daedalus/train.active" in step9
    rules = text.split("## Preconditions", 1)[0]
    marker = rules.split("- Train marker: ", 1)[1].split("\n", 1)[0]
    assert "every stop that follows" in marker
    assert UNMARK in marker
    assert "writes the marker again with the Preconditions step 9 command" in marker
    assert UNMARK in text.split("\n6. Print the State Block", 1)[1]


def test_push_train_marks_the_train_active_and_clears_it() -> None:
    # 0023: the Push Train writes the marker after its preconditions and removes it at its end.
    text = _push_train()
    pre = _section(text, "## Preconditions", "## Push")
    step10 = pre.split("\n10. ", 1)[1]
    assert MARK + "<train-id>`" in step10
    rules = text.split("## Preconditions", 1)[0]
    marker = rules.split("- Train marker: ", 1)[1].split("\n", 1)[0]
    assert "every stop that follows" in marker
    assert UNMARK in marker
    hand_off = text.split("## Hand-off", 1)[1]
    assert hand_off.index(UNMARK) < hand_off.index("1. Review the pull request")


def test_build_train_never_respawns_a_coder() -> None:
    text = _build_train()
    assert "Continue on branch" not in text
    assert (
        '"Coder for unit <b> cannot be resumed. Next: rerun the train; the unit branch <b> is '
        'kept for reference."'
    ) in text
    assert (
        "If SendMessage to a coder fails, never start a replacement coder; a replacement coder "
        "would start without the first coder's context and the unit's half-done state."
    ) in text
    assert "cannot move to <b>" not in text


def test_build_train_liveness_uses_no_bash() -> None:
    # M4: a Bash call here would become the newest Bash record and void the check.
    step = _build_train().split("\n5. ", 1)[1].split("\n6. ", 1)[0]
    assert "Use only the Glob, Grep and Read tools here, no Bash" in step


_SKILL_SCRIPT = re.compile(r"`(python3 \$\{CLAUDE_PLUGIN_ROOT\}/scripts/[^`]+)`")


def test_skill_script_commands_are_allowed_for_main() -> None:
    # M4: every plugin script command in the trains passes the jail as the main session.
    from lib.config import Config
    from lib.jail import decide

    root = str(REPO_ROOT)
    commands = [
        re.sub(r"<[^>]+>", "x", m.replace("${CLAUDE_PLUGIN_ROOT}", root).replace("<repo>", root))
        for path in (REPO_ROOT / "skills" / "build-train", REPO_ROOT / "skills" / "push-train")
        for m in _SKILL_SCRIPT.findall((path / "SKILL.md").read_text(encoding="utf-8"))
    ]
    assert len(commands) >= 4
    for command in commands:
        payload = {"tool_name": "Bash", "tool_input": {"command": command}, "cwd": root}
        d = decide(payload, Config())
        assert d.allow, (command, d.reason)


_CONDUCTOR_CMD = re.compile(r"(?:[Rr]un|then) `((?:git|gh|gitleaks) [^`]+)`")


def _conductor_commands() -> list[Any]:
    # 0028: every command the Push section hands the conductor, minus its never-run list.
    push = _section(PUSH_TRAIN.read_text(encoding="utf-8"), "## Push", "## Charter branch")
    allowed = "\n".join(ln for ln in push.splitlines() if "Use only the commands above" not in ln)
    commands = sorted(set(_CONDUCTOR_CMD.findall(allowed)))
    return [
        pytest.param(c, marks=pytest.mark.xfail(reason="waits on K1", strict=True))
        if c.startswith("gh pr edit")
        else c
        for c in commands
    ]


@pytest.mark.parametrize("command", _conductor_commands())
def test_push_train_conductor_commands_pass_the_jail(
    repo_cwd: Path, project_data: Path, command: str
) -> None:
    # K1: gh pr edit is refused until ruled; strict xfail turns green-on-ruling into a failure.
    from lib.config import Config
    from lib.jail import decide

    (project_data / "train.active").write_text("20261016-120000\n", encoding="utf-8")
    concrete = re.sub(r"<[^>]+>", "x", command.replace("<repo>", str(repo_cwd)))
    payload = {
        "tool_name": "Bash",
        "tool_input": {"command": concrete},
        "cwd": str(repo_cwd),
        "session_id": "s",
        "agent_type": "pr-train-conductor",
        "agent_id": "a-1",
    }
    d = decide(payload, Config())
    assert d.allow, (concrete, d.reason)


def test_push_train_names_conductor_commands() -> None:
    commands = [p if isinstance(p, str) else p.values[0] for p in _conductor_commands()]
    assert "git push -u origin daedalus/<train-id>" in commands
    assert any(c.startswith("gh pr edit daedalus/<train-id> --body-file") for c in commands)


SETUP = REPO_ROOT / "skills" / "setup" / "SKILL.md"


def test_setup_skill_runs_the_setup_script_only_when_asked() -> None:
    # 0020: setup is never automatic; the operator types it.
    fields, body = _split(SETUP)
    assert fields["disable-model-invocation"] == "true"
    assert "`python3 ${CLAUDE_PLUGIN_ROOT}/scripts/daedalus_setup.py`" in body
    assert "never run it on your own" in body
    assert "Restart Claude Code to apply" in body


def test_setup_skill_names_the_repo_local_file() -> None:
    # 0027, 0029: setup writes the repo's .claude/settings.local.json and no user-level file.
    fields, body = _split(SETUP)
    for text in (fields["description"], body):
        assert ".claude/settings.local.json" in text
        assert "~/.claude/settings.json" not in text
    assert "`OK   sandbox: on (.claude/settings.local.json)`" in body
    assert "from their own shell" in body


DOCTOR = REPO_ROOT / "skills" / "doctor" / "SKILL.md"
DOCTOR_CMD = "python3 ${CLAUDE_SKILL_DIR}/../../scripts/daedalus_doctor.py"


def test_doctor_preapproves_only_its_own_script() -> None:
    # 0007: allowed-tools expands CLAUDE_SKILL_DIR, not CLAUDE_PLUGIN_ROOT; rule and step match.
    fields, body = _split(DOCTOR)
    assert fields["allowed-tools"] == f"Bash({DOCTOR_CMD} *)"
    assert f'`{DOCTOR_CMD} --repo "<path>"`' in body
    assert (DOCTOR.parent / "../../scripts/daedalus_doctor.py").resolve().is_file()


def test_doctor_asks_once_and_hands_setup_to_the_operator() -> None:
    _, body = _split(DOCTOR)
    assert "Ask once, in a single message" in body and "Never ask per line." in body
    assert "Do not run any other command to investigate" in body
    assert "tell the operator to type `/daedalus:setup` themselves" in body


TRAIN_SKILLS = [p for p in SKILLS if p.parent.name.endswith("-train")]
SANDBOX_NEXT_LINE = "Next: run /daedalus:setup, restart, rerun the train."
SANDBOX_STATE_CMD = "python3 ${CLAUDE_PLUGIN_ROOT}/scripts/daedalus_doctor.py --sandbox-state"


@pytest.mark.parametrize("path", TRAIN_SKILLS, ids=lambda p: p.parent.name)
def test_every_train_declares_a_sandbox_class(path: Path) -> None:
    # 0020: per train class, never hard-wired to one train (0022).
    assert _split(path)[0].get("sandbox") in {"optional", "required"}


def test_train_sandbox_classes() -> None:
    classes = {p.parent.name: _split(p)[0].get("sandbox") for p in TRAIN_SKILLS}
    assert classes == {"build-train": "optional", "push-train": "required"}


def test_build_train_records_the_sandbox_state() -> None:
    text = _build_train()
    step = _section(text, "## Preconditions", "## Phase 1").split("\n8. ", 1)[1]
    assert f"`{SANDBOX_STATE_CMD} --repo <repo>`" in step
    assert "The Build Train runs in every state." in step
    assert "    sandbox: <on, off or configured-unavailable>" in text
    assert "       Sandbox: <on, off or configured-unavailable>" in text


def test_build_train_stops_infrastructure_units_without_the_sandbox() -> None:
    phase3 = _section(_build_train(), "## Phase 3", "\n5. The summary")
    gate = phase3.split("\n1. ", 1)[1].split("\n2. ", 1)[0]
    assert (
        "When the State Block `sandbox:` is not `on` and any unit touched IAM, KMS, mTLS, "
        "key custody or infrastructure config, stop before the security audit and before any "
        "merge, naming those units. " + SANDBOX_NEXT_LINE
    ) in gate
    assert gate.index("`sandbox:` is not `on`") < gate.index("Agent(`nist-specialist`)")


def test_push_train_requires_the_sandbox_first() -> None:
    step = _section(_push_train(), "\n1. ", "\n2. ")
    assert step.index("`<repo>` is the parent") < step.index(SANDBOX_STATE_CMD)
    refusal = "Any word but `on`: stop. The Push Train needs the OS sandbox. "
    assert refusal + SANDBOX_NEXT_LINE in step


def test_push_train_checks_gh_beside_gitleaks() -> None:
    step = _push_train().split("\n5. ", 1)[1].split("\n6. ", 1)[0]
    assert "Then run `gh auth status`. A non-zero exit: stop." in step
    assert "Next: gh auth login" in step
    assert "or `gh` yourself" not in _push_train()


def test_build_train_runs_without_config_json() -> None:
    step = _build_train().split("\n3. ", 1)[1].split("\n4. ", 1)[0]
    assert "Missing: defaults are in use" in step
    assert "Not valid JSON: stop." in step
    assert "Missing or not valid JSON" not in step


# 0031: operator lines name things in words; ids, paths and code trail and are not counted.
_DROP_SPANS = re.compile(r"`[^`]*`|<[^<>]*>|\{[^{}]*\}|\([^()]*\)|https?://\S+")
_WORD = re.compile(r"[A-Za-z][A-Za-z'-]*")
_EDGE = ".,;:!?\"'[]"
_NEXT_CONST = re.compile(r"_?[A-Z_]*NEXT")
_SENTENCE_END = re.compile(r"\.\s+(?=[A-Z])")
_SKILL_NEXT = re.compile(r"(?:^|(?<=[.:;]\s))Next:")
# 0031: jail refusals are messages to the refused agent, which may use ids alone.
AGENT_FACING = {"scripts/lib/jail.py"}
MIN_WORDS = 4


def _words(text: str) -> list[str]:
    from lib.jail import KNOWN_AGENTS

    out = []
    for raw in _DROP_SPANS.sub(" ", text).split():
        token = raw.strip(_EDGE)
        if token in KNOWN_AGENTS or any(c in token for c in "/\\~$_:.*=@#"):
            continue
        if _WORD.fullmatch(token):
            out.append(token)
    return out


def _forward_only(text: str) -> bool:
    return not _DROP_SPANS.sub("", text).strip(" " + _EDGE)


def _render(node: ast.AST, consts: dict[str, str]) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        parts = []
        for value in node.values:
            if isinstance(value, ast.Constant):
                parts.append(str(value.value))
            elif isinstance(value, ast.FormattedValue):
                name = value.value.id if isinstance(value.value, ast.Name) else ""
                parts.append(consts.get(name, "{x}"))
        return "".join(parts)
    return None


def _script_lines(path: Path) -> list[tuple[int, str, str]]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    consts: dict[str, str] = {}
    found: list[tuple[int, str, str]] = []
    for node in tree.body:
        if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name):
            name = node.targets[0].id
            text = _render(node.value, consts)
            if text is not None:
                consts[name] = text
            if _NEXT_CONST.fullmatch(name):
                values = node.value.values if isinstance(node.value, ast.Dict) else [node.value]
                for value in values:
                    rendered = _render(value, consts)
                    if rendered is not None and "Next:" not in rendered:
                        found.append((node.lineno, "next", rendered))
    inner = {id(v) for n in ast.walk(tree) if isinstance(n, ast.JoinedStr) for v in n.values}
    for node in ast.walk(tree):
        text = None if id(node) in inner else _render(node, consts)
        if text is None or "Next:" not in text:
            continue
        message, *nexts = text.split("Next:")
        if "{x}" not in message and not message.startswith("usage:"):
            found.append((node.lineno, "stop", message))
        found.extend((node.lineno, "next", part) for part in nexts)
    return found


def _skill_lines(path: Path) -> list[tuple[int, str, str]]:
    found: list[tuple[int, str, str]] = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        flat = re.sub(r"`[^`]*`", "`x`", line)
        for part in _SKILL_NEXT.split(flat)[1:]:
            found.append((number, "next", _SENTENCE_END.split(part, 1)[0]))
        for quoted in re.findall(r'stop with "([^"]+)"', line):
            found.append((number, "stop", quoted.split("Next:", 1)[0]))
    return found


def _operator_lines() -> list[tuple[str, int, str, str]]:
    out = []
    for path in sorted((REPO_ROOT / "scripts").rglob("*.py")):
        if str(path.relative_to(REPO_ROOT)) in AGENT_FACING:
            continue
        for number, kind, text in _script_lines(path):
            out.append((str(path.relative_to(REPO_ROOT)), number, kind, text))
    for path in SKILLS:
        for number, kind, text in _skill_lines(path):
            out.append((str(path.relative_to(REPO_ROOT)), number, kind, text))
    return out


def test_operator_lines_are_not_bare_ids() -> None:
    bare = [
        f"{name}:{number} {kind}: {' '.join(text.split())}"
        for name, number, kind, text in _operator_lines()
        if text.strip() and not _forward_only(text) and len(_words(text)) < MIN_WORDS
    ]
    assert bare == []


HUMAN_TEXT_RULE = (
    "Text a human reads names each item in words: a short label or one line on what it is and "
    "what it does. Ids (ruling ids, issue numbers, task codes, agent names, snake_case keys) may "
    "trail in parentheses, never replace the description. Logs, status lines and messages to "
    "other agents may use ids alone. Documents carry both."
)


@pytest.mark.parametrize("path", SKILLS, ids=lambda p: p.parent.name)
def test_operator_skills_carry_the_human_text_rule(path: Path) -> None:
    # 0031: every skill speaks to the operator, so each carries the rule verbatim.
    assert HUMAN_TEXT_RULE in path.read_text(encoding="utf-8")


def test_requirements_carry_the_human_text_rule() -> None:
    text = (REPO_ROOT / "docs" / "project-requirements.md").read_text(encoding="utf-8")
    section = text.split("\n## Text a person reads\n", 1)[1].split("\n## ", 1)[0]
    assert HUMAN_TEXT_RULE in section


def test_operator_line_scanner_flags_bare_ids() -> None:
    # 0031: the scanner itself; a command or id alone is not a description.
    assert len(_words("run /daedalus:doctor.")) < MIN_WORDS
    assert len(_words("rerun `/daedalus:build-train` (0024)")) < MIN_WORDS
    assert len(_words("run the Daedalus health check (/daedalus:doctor).")) >= MIN_WORDS
    lines = _skill_lines(SKILLS[0])
    assert all(kind in {"next", "stop"} for _, kind, _ in lines)
