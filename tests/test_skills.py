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


BEGIN = "`python3 ${CLAUDE_PLUGIN_ROOT}/scripts/daedalus_workspace.py begin --repo <repo>`"
STOP_CMD = (
    "`python3 ${CLAUDE_PLUGIN_ROOT}/scripts/daedalus_workspace.py stop "
    '--repo <repo> --reason "<what happened>" --next "<next action>"`'
)


def test_build_train_dispatches_existing_agents() -> None:
    names = set(_AGENT_REF.findall(_build_train()))
    for name in names:
        assert (REPO_ROOT / "agents" / f"{name}.md").is_file(), name
    personas = {p.stem for p in (REPO_ROOT / "agents").glob("*.md")}
    # The Push Train owns pr-train-conductor; the Build Train dispatches every other persona.
    assert names == personas - {"pr-train-conductor"}


def test_build_train_probes_the_ledger_and_asks() -> None:
    # 0004: begin probes; test_begin_asks_the_ledger_question_with_exit_three holds the rest.
    pre = _section(_build_train(), "## Preconditions", "## Phase 1")
    exit3 = next(line for line in pre.splitlines() if "Exit 3" in line)
    assert "ask the operator the question it prints, exactly" in exit3
    assert "append_ledger.py --probe" in pre


def test_build_train_hands_the_pack_path_to_the_standards_specialist() -> None:
    # 0019: a declared pack has no path in config.json; begin prints it, every dispatch carries it.
    text = _build_train()
    assert "    standards packs: <name> at <path>, or none declared\n" in text
    assert "The first six lines are begin's output" in text
    rules = text.split("## Preconditions", 1)[0]
    dispatch = next(ln for ln in rules.splitlines() if "standards-rules-specialist dispatch" in ln)
    assert "the `standards packs:` line" in dispatch
    phase1 = _section(text, "## Phase 1", "## Phase 2")
    assert "the `standards packs:` line" in phase1.split("\n2. ", 1)[0]
    agent = (REPO_ROOT / "agents" / "standards-rules-specialist.md").read_text(encoding="utf-8")
    assert "`standards packs:` line" in agent


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
    # 0024: the dead-hooks stop is begin's; test_begin_refuses_dead_hooks holds it.
    text = _build_train()
    assert "does not end with one of its contract lines or contract sections, stop" in text
    assert "ends with its rule list and has no status line" in text
    assert "charter: none (repo-local ledger)" in text
    assert "ids=<id>[,<id>]" in text
    assert "Session <id>: .claude/daedalus/audit/<id>.jsonl" in text


@pytest.mark.parametrize("path", SKILLS, ids=lambda p: p.parent.name)
def test_no_plan_or_task_numbers(path: Path) -> None:
    # R1-M3: operator text never names internal plan or task numbers.
    assert not re.search(r"(Task|Plan) [0-9]", path.read_text(encoding="utf-8"))


def test_build_train_branches_a_clean_charter_and_switches_back() -> None:
    # 0024: test_begin_branches_a_clean_charter and test_stop_switches_the_charter_back.
    text = _build_train()
    assert "charter_root: <path or none>  charter base: <recorded branch or none>" in text
    assert "`git -C <charter_root> switch <recorded branch>`" in text


def test_build_train_runs_every_stop_through_the_script() -> None:
    # 0024: the five stop rules are the test_stop_* set in test_workspace_train.py.
    text = _build_train()
    rules = text.split("## Preconditions", 1)[0]
    stop = rules.split("- Every stop: ", 1)[1].split("\n", 1)[0]
    assert stop.startswith("run " + STOP_CMD)
    assert "`python3 ${CLAUDE_PLUGIN_ROOT}/scripts/daedalus_workspace.py resume --repo <repo>`" in (
        stop
    )
    for gone in ("Charter switch-back", "Integration switch-back", "Uncommitted contract:"):
        assert gone not in text, gone
    assert "- Worktree teardown:" not in rules and "- Train marker:" not in rules
    assert "unmark" not in text
    step = text.split("`[STATUS: COMMITTED] <sha>", 1)[1].split("\n5. ", 1)[0]
    assert "after `resume`" in step


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
    # 41, C7: the verdict line opens and closes every auditor reply.
    text = _build_train()
    assert (
        "Read the verdict from the last line of the auditor's reply; "
        "its first line carries the same verdict."
    ) in text
    assert "Read the verdict from the first line of the auditor's reply." not in text
    assert (
        "The security-auditor's verdict line is both the first line and the last line of every "
        "reply, fix rounds included; read it from the last line, and a reply whose first line is "
        "not the same verdict is off-contract."
    ) in text
    auditor = (REPO_ROOT / "agents" / "security-auditor.md").read_text(encoding="utf-8")
    contract = auditor.split("## Status contract", 1)[1]
    assert "starts with exactly one of these verdict lines as its first line" in contract


def _phase1_step(text: str, number: int) -> str:
    phase1 = _section(text, "## Phase 1", "## Phase 2")
    return phase1.split(f"\n{number}. ", 1)[1].split(f"\n{number + 1}. ", 1)[0]


def test_build_train_keeps_personas_warm() -> None:
    # 0059, C1: the roster rule sits in the whole-train rules.
    rules = _build_train().split("## Preconditions", 1)[0]
    roster = rules.split("- Warm roster (0059): ", 1)[1].split("\n", 1)[0]
    assert "a persona stays warm after its first use" in roster
    assert "The security-auditor stays warm only after its first verdict" in roster
    cold = next(ln for ln in rules.splitlines() if "standards-rules-specialist dispatch" in ln)
    assert cold.startswith("- The first standards-rules-specialist dispatch of a train carries")
    assert "Every later standards question resumes that same specialist by SendMessage" in cold


def test_build_train_dispatches_the_standards_specialist_once() -> None:
    # 0059, C2, C3: one first dispatch; the State Block records its handle.
    text = _build_train()
    assert text.count("Agent(`standards-rules-specialist`)") == 1
    assert "    standards specialist: <agent handle>  last read: <UTC time>" in text
    seed = text.split("**State Block**", 1)[1].split("\n\n", 2)[1].splitlines()
    assert seed[6].startswith("    standards specialist: ")


def test_build_train_asks_each_contradiction_as_a_brief() -> None:
    # 0057, C4: the stop is replaced by the prompt, the pick record and the re-check.
    text = _build_train()
    step1 = _phase1_step(text, 1)
    for item in (
        "AskUserQuestion",
        "at most four questions per call",
        "`Follow Global`",
        "`Follow Plugin`",
        "`Follow Plugin + amend global`",
        "(Recommended)",
        '"RECHECK. Picks:',
        "a plain question ending in `?`",
        "No tracked-risk issue is filed.",
        "A plugin agent never makes this edit.",
        'The word "Global" appears in a label only when one side is the operator\'s global',
    ):
        assert item in step1, item
    assert "Agent(`charter-docs`)" in step1
    phase1 = _section(text, "## Phase 1", "## Phase 2")
    assert phase1.index("Agent(`charter-docs`)") < phase1.index("\n2. ")
    assert "stops the train. Show the operator both sides" not in text
    assert "Next: reword the task, or change the standard in its source" not in text


def test_build_train_resumes_the_specialist_with_changed_rule_files() -> None:
    # 0059, C5: the coder yield route and the auditor brief resume the warm specialist.
    text = _build_train()
    route = next(ln for ln in text.splitlines() if ln.startswith("| `[STATUS: YIELD_STANDARDS]"))
    assert "SendMessage(standards specialist," in route
    assert "Rule files changed since your last read" in route
    step2 = _section(text, "## Phase 3", "\n3. ").split("\n2. ", 1)[1]
    assert step2.startswith("SendMessage(standards specialist,")
    assert "Rule files changed since your last read" in step2
    assert "resumes the same auditor by SendMessage" in step2


def test_build_train_summary_carries_rulings_and_deviations() -> None:
    # 0057, C6: one line per pick, a deviation line per keep-the-plugin pick.
    shape = _build_train().split("Shape:", 1)[1].split("\n6. ", 1)[0]
    assert "       ## Rulings\n" in shape
    assert "       Deviation: " in shape
    assert shape.index("[POLICY: none declared]") < shape.index("## Rulings")


def test_build_train_records_picks_before_any_coder() -> None:
    # 0057, C9: both ledger locations record picks before a coder starts.
    text = _build_train()
    step1 = _phase1_step(text, 1)
    assert "Ledger under `charter_root`: record the picks right after the last pick" in step1
    assert "Repo-local ledger: record the picks right after the step 3 `lock`" in step1
    assert "No coder starts before `[STATUS: COMMITTED]`." in step1
    step3 = _phase1_step(text, 3)
    assert "With a repo-local ledger and picks from step 1, record the picks now" in step3


def test_build_train_hands_coders_the_pick_ledger_ids() -> None:
    # 0057, C10: the ids line follows the two packets and precedes the worktree line.
    phase2 = _section(_build_train(), "## Phase 2", "## Phase 3")
    dispatch = phase2.split("Then Agent(`repo-coder`) with: both packets", 1)[1]
    assert dispatch.index("`Pick ledger ids:`") < dispatch.index("`Worktree: <path>`")


def test_build_train_phase1_has_no_branch_switch() -> None:
    # 0024, C11: the lock script owns every branch move in Phase 1.
    phase1 = _section(_build_train(), "## Phase 1", "## Phase 2")
    assert "git switch" not in phase1 and "git checkout" not in phase1


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
    step = text.split("\n8. ", 1)[1].split("\n9. ", 1)[0]
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
    step = _push_train().split("\n9. ", 1)[1].split("\n10. ", 1)[0]
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
    # 0011: lock commits the packet (test_lock_* set); the summary records path and version.
    text = _build_train()
    phase1 = _section(text, "## Phase 1", "## Phase 2")
    assert '"Save the packet to <contract path>, then end the reply with the packet."' in phase1
    assert "The main session owns this commit; contract-spec never commits." in phase1
    lock = (
        "`python3 ${CLAUDE_PLUGIN_ROOT}/scripts/daedalus_workspace.py lock --repo <repo> "
        "--contract <contract path> --version <packet_version>`"
    )
    assert lock in phase1
    assert phase1.index("Agent(`contract-spec`)") < phase1.index(lock)
    assert "`contract unchanged, no commit`" in phase1
    assert "git commit" not in phase1 and "git switch -c" not in phase1
    phase2 = _section(text, "## Phase 2", "## Phase 3")
    assert '"Save the revised packet to <contract path>, overwriting it,' in phase2
    assert "it commits `Revise contract <name> v<N>`" in phase2
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


def test_build_train_refuses_a_revision_that_does_not_raise_the_version() -> None:
    # R4-M2: N must exceed the recorded packet_version; lock refuses it too.
    phase2 = _section(_build_train(), "## Phase 2", "## Phase 3")
    # R5-I2: one retry, then the second non-increasing version stops.
    stop = (
        "When <N> is not greater than the State Block packet_version <n>, "
        'SendMessage(contract-spec, "packet_version must exceed <n>; revise and save again") '
        "once. A second reply whose <N> is still not greater stops the train."
    )
    assert stop in phase2
    assert phase2.index(stop) < phase2.index("`Revise contract <name> v<N>`")


def test_build_train_branches_the_charter_in_preconditions() -> None:
    # 0011: begin branches the Charter (test_begin_branches_a_clean_charter).
    text = _build_train()
    pre = _section(text, "## Preconditions", "## Phase 1")
    assert BEGIN in pre
    assert "branches a declared Charter" in pre
    phase3 = _section(text, "## Phase 3", "\n5. The summary")
    assert "switch -c" not in phase3
    assert "it is empty when the contract commit landed" in phase3
    # R4-M3: the howto says where the Charter branch comes from.
    howto = (REPO_ROOT / "docs" / "howto" / "README.md").read_text(encoding="utf-8")
    assert (
        "The train creates the Charter's `daedalus/<train-id>` branch in its checks, for the "
        "contract and ledger commits"
    ) in howto


def test_build_train_proves_live_hooks_after_begin() -> None:
    # 0035: begin creates the data dir; the next command proves hooks live, as in the Push Train.
    pre = _section(_build_train(), "## Preconditions", "## Phase 1")
    step = pre.split("\n3. ", 1)[1]
    hooks = (
        "`python3 ${CLAUDE_PLUGIN_ROOT}/scripts/verify_audit_chain.py --hooks-live --repo <repo>`"
    )
    assert step.startswith(f"Run {hooks}.")
    assert pre.index(BEGIN) < pre.index(hooks)
    assert "record `<id>` in the State Block as `audit session: <id>`" in step
    assert "ends in `audit session: pending`" in pre


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
    # Ruling 1, R4-I1: test_stop_keeps_a_dirty_charter and test_stop_keeps_an_uncommitted_contract.
    phase3 = _section(_build_train(), "## Phase 3", "\n5. The summary")
    dirty = phase3.split("   - Charter ledger:", 1)[1].split("\n", 1)[0]
    assert "the stop keeps the Charter on `daedalus/<train-id>` while it is dirty" in dirty
    assert "resume at this step" in dirty
    assert "Any other reply: the off-contract stop." in phase3


def test_build_train_keeps_worktrees_out_of_git_and_the_train() -> None:
    # 0024: teardown is the scripts' (test_stop_tears_down_only_recorded_units, test_finish_*).
    text = _build_train()
    # 0022: daedalus_workspace.py create writes the worktrees ignore marker itself.
    assert "<repo>/.claude/worktrees/.gitignore" not in text
    assert "daedalus_workspace.py remove" not in text
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
        "never `gh pr edit` with any flag but `--body-file`",
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
    # 0057: Phase 1 records picks first, so compare against the Phase 3 dispatch.
    phase3 = bt.index("## Phase 3")
    assert bt.index("Write the summary now") < bt.index("Agent(`charter-docs`)", phase3)
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
    assert "record its `lock:` line as `lock: <sha>` in the State Block" in phase1
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


def test_build_train_merges_through_the_script() -> None:
    # 0024: test_finish_* holds the dirty-checkout guard, the merges and the conflict abort.
    phase3 = _section(_build_train(), "## Phase 3", "\n5. The summary")
    merge = phase3.split("\n4. ", 1)[1]
    finish = "`python3 ${CLAUDE_PLUGIN_ROOT}/scripts/daedalus_workspace.py finish --repo <repo>`"
    assert finish in merge
    assert merge.index(finish) < merge.index("Agent(`charter-docs`)")
    assert "git merge --no-ff" not in _build_train()


MARK = "`python3 ${CLAUDE_PLUGIN_ROOT}/scripts/daedalus_workspace.py mark --repo <repo> --train "
UNMARK = "`python3 ${CLAUDE_PLUGIN_ROOT}/scripts/daedalus_workspace.py unmark --repo <repo>`"


def test_build_train_marks_the_train_active_and_clears_it() -> None:
    # 0023: begin marks (test_begin_prints_the_state_block_seed); stop clears.
    text = _build_train()
    end = text.split("\n6. Print the State Block", 1)[1]
    assert (
        "`python3 ${CLAUDE_PLUGIN_ROOT}/scripts/daedalus_workspace.py stop --repo <repo> "
        '--reason "train complete"'
    ) in end
    assert "marks the train active" in _section(text, "## Preconditions", "## Phase 1")


def test_push_train_marks_the_train_active_and_clears_it() -> None:
    # 0023, 0035: the Push Train marks before the hooks check, since only a marked repo records.
    text = _push_train()
    pre = _section(text, "## Preconditions", "## Push")
    step7 = pre.split("\n7. ", 1)[1].split("\n8. ", 1)[0]
    assert MARK + "<train-id>`" in step7
    assert pre.index(MARK) < pre.index("--hooks-live") < pre.index("--approved")
    assert pre.index("--approved") < pre.index("merge-base --is-ancestor")
    assert "Preconditions step 7 writes" in text
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


_SKILL_SCRIPT = re.compile(r"`(python3 \$\{CLAUDE_PLUGIN_ROOT\}/scripts/[^`]+)`")


def test_skill_script_commands_are_allowed_for_main() -> None:
    # M4: every plugin script command in the trains passes the jail as the main session.
    from lib.config import Config
    from lib.jail import decide

    root = str(REPO_ROOT)
    commands = [
        re.sub(r"<[^>]+>", "x", m.replace("${CLAUDE_PLUGIN_ROOT}", root).replace("<repo>", root))
        for path in (REPO_ROOT / "skills" / n for n in ("build-train", "push-train"))
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
        for path in (REPO_ROOT / "skills" / n for n in ("build-train", "push-train"))
        for m in _SKILL_SCRIPT.findall((path / "SKILL.md").read_text(encoding="utf-8"))
    ]
    assert len(commands) >= 4
    for command in commands:
        payload = {"tool_name": "Bash", "tool_input": {"command": command}, "cwd": repo}
        d = decide(payload, Config())
        assert d.allow, (command, d.reason)


_CONDUCTOR_CMD = re.compile(r"(?:[Rr]un|then) `((?:git|gh|gitleaks) [^`]+)`")


def _conductor_commands() -> list[str]:
    # 0028: every command the Push section hands the conductor, minus its never-run list.
    push = _section(PUSH_TRAIN.read_text(encoding="utf-8"), "## Push", "## Charter branch")
    allowed = "\n".join(ln for ln in push.splitlines() if "Use only the commands above" not in ln)
    return sorted(set(_CONDUCTOR_CMD.findall(allowed)))


@pytest.mark.parametrize("command", _conductor_commands())
def test_push_train_conductor_commands_pass_the_jail(
    repo_cwd: Path, project_data: Path, command: str
) -> None:
    # K1: gh pr edit with --body-file is on the conductor's list.
    d = _conductor_decide(repo_cwd, project_data, command)
    assert d.allow, (command, d.reason)


def _conductor_decide(repo_cwd: Path, project_data: Path, command: str) -> Any:
    from lib.config import Config

    from tests.hook_chain import judge as decide

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
    return decide(payload, Config())


def test_push_train_conductor_pr_edit_title_refused(repo_cwd: Path, project_data: Path) -> None:
    # K1: the conductor's pr edit changes the body only.
    command = "gh pr edit daedalus/<train-id> --title t --body-file <repo>/docs/.tmp/pr.md"
    d = _conductor_decide(repo_cwd, project_data, command)
    assert not d.allow and "Next: edit only the body with --body-file" in str(d.reason)


def test_push_train_names_conductor_commands() -> None:
    commands = _conductor_commands()
    assert "git push -u origin daedalus/<train-id>" in commands
    assert any(c.startswith("gh pr edit daedalus/<train-id> --body-file") for c in commands)


DOCTOR = REPO_ROOT / "skills" / "doctor" / "SKILL.md"
DOCTOR_CMD = "python3 ${CLAUDE_SKILL_DIR}/../../scripts/daedalus_doctor.py"


def test_doctor_preapproves_only_its_own_script() -> None:
    # 0007: allowed-tools expands CLAUDE_SKILL_DIR, not CLAUDE_PLUGIN_ROOT; rule and step match.
    fields, body = _split(DOCTOR)
    assert fields["allowed-tools"] == f"Bash({DOCTOR_CMD} *)"
    assert f'`{DOCTOR_CMD} --repo "<path>"`' in body
    assert (DOCTOR.parent / "../../scripts/daedalus_doctor.py").resolve().is_file()


def test_doctor_asks_once() -> None:
    _, body = _split(DOCTOR)
    assert "Ask once, in a single message" in body and "Never ask per line." in body
    assert "Do not run any other command to investigate" in body


def test_push_train_checks_gh_beside_gitleaks() -> None:
    step = _push_train().split("\n5. ", 1)[1].split("\n6. ", 1)[0]
    assert "Then run `gh auth status`. A non-zero exit: stop." in step
    assert "Next: gh auth login" in step
    assert "or `gh` yourself" not in _push_train()


def test_build_train_runs_without_config_json() -> None:
    # 0020: test_begin_invalid_config_stops_with_its_next; absent config is the empty config.
    pre = _section(_build_train(), "## Preconditions", "## Phase 1")
    assert "an absent config.json means the defaults" in pre


# 0031: operator lines name things in words; ids, paths and code trail and are not counted.
_DROP_SPANS = re.compile(r"`[^`]*`|<[^<>]*>|\{[^{}]*\}|\([^()]*\)|https?://\S+")
_WORD = re.compile(r"[A-Za-z][A-Za-z'-]*")
_EDGE = ".,;:!?\"'[]"
_NEXT_CONST = re.compile(r"_?[A-Z_]*NEXT")
_SENTENCE_END = re.compile(r"\.\s+(?=[A-Z])")
_SKILL_NEXT = re.compile(r"(?:^|(?<=[.:;]\s))Next:")
# 0031: jail refusals are messages to the refused agent, which may use ids alone.
AGENT_FACING = {"scripts/lib/jail.py", "scripts/lib/shell.py", "scripts/lib/dispatch_binding.py"}
AGENT_FACING |= {"scripts/lib/router.py"} | {
    str(p.relative_to(REPO_ROOT)) for p in (REPO_ROOT / "scripts" / "checks").glob("*.py")
}
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
