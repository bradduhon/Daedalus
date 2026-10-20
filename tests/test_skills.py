# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import ast
import json
import re
import subprocess
from pathlib import Path
from typing import Any

import pytest
from lib.human_text import DROP_SPANS, EDGE, MIN_WORDS, plain_words

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
    # 0060: the skill is the main session's relay; the recipe is the orchestrator's agent file.
    return BUILD_TRAIN.read_text(encoding="utf-8")


ORCHESTRATOR = REPO_ROOT / "agents" / "orchestrator.md"


def _recipe() -> str:
    return ORCHESTRATOR.read_text(encoding="utf-8")


def _rules() -> str:
    return _recipe().split("## Phase 1", 1)[0]


BEGIN = "`python3 ${CLAUDE_PLUGIN_ROOT}/scripts/daedalus_workspace.py begin --repo <repo>`"
STOP_CMD = (
    "`python3 ${CLAUDE_PLUGIN_ROOT}/scripts/daedalus_workspace.py stop "
    '--repo <repo> --reason "<what happened>" --next "<next action>"`'
)
# 0060: the orchestrator writes the plugin root out in full; the hook refuses the variable.
PLUGIN = "`python3 <plugin root>/scripts/"


def test_build_train_dispatches_existing_agents() -> None:
    relay = set(_AGENT_REF.findall(_build_train()))
    names = set(_AGENT_REF.findall(_recipe()))
    for name in relay | names:
        assert (REPO_ROOT / "agents" / f"{name}.md").is_file(), name
    personas = {p.stem for p in (REPO_ROOT / "agents").glob("*.md")}
    # The Push Train owns pr-train-conductor; the relay starts only the orchestrator (0060).
    assert relay == {"orchestrator"}
    assert names == personas - {"pr-train-conductor", "orchestrator"}
    assert "`/daedalus:plan " in _recipe()
    assert "${CLAUDE_PLUGIN_ROOT}" not in _recipe().split("\n---\n", 1)[1]


def test_build_train_probes_the_ledger_and_asks() -> None:
    # 0004: begin probes; test_begin_asks_the_ledger_question_with_exit_three holds the rest.
    pre = _section(_build_train(), "## Preconditions", "## Phase 1")
    exit3 = next(line for line in pre.splitlines() if "Exit 3" in line)
    assert "ask the operator the question it prints, exactly" in exit3
    assert "append_ledger.py --probe" in pre


def test_build_train_hands_the_pack_path_to_the_standards_specialist() -> None:
    # 0019: a declared pack has no path in config.json; begin prints it, every dispatch carries it.
    relay, text = _build_train(), _recipe()
    for part in (relay, text):
        assert "    standards packs: <name> at <path>, or none declared\n" in part
    assert "The first six lines of the **State Block** are begin's output" in relay
    assert "The first six lines come from your brief." in text
    dispatch = next(
        ln for ln in _rules().splitlines() if "standards-rules-specialist dispatch" in ln
    )
    assert "the `standards packs:` line" in dispatch
    phase1 = _section(text, "## Phase 1", "## Phase 2")
    assert "the `standards packs:` line" in phase1.split("\n2. ", 1)[0]
    agent = (REPO_ROOT / "agents" / "standards-rules-specialist.md").read_text(encoding="utf-8")
    assert "`standards packs:` line" in agent


def test_build_train_routes_every_yield_and_the_contradiction_stop() -> None:
    text = _recipe()
    for route in ("YIELD_WEB", "YIELD_CONTRACT", "YIELD_COMPLIANCE", "YIELD_STANDARDS"):
        assert f"[STATUS: {route}]" in text, route
    assert "[STANDARDS: CONTRADICTION]" in text


def test_build_train_never_pushes() -> None:
    text = _recipe()
    assert "git push" not in text and "git push" not in _build_train()
    assert "--no-ff" in text and "daedalus/<train-id>" in text


def test_build_train_writes_summary_under_docs_tmp() -> None:
    # T7 ruling: the conductor's --body-file reads docs/.tmp, never the data dir.
    assert "<repo>/docs/.tmp/daedalus/<train-id>-summary.md" in _recipe()
    assert "docs/.tmp/daedalus/.gitignore" in _build_train()
    assert "/daedalus:audit-report" in _build_train()


def test_build_train_resolves_the_cache_for_specialists() -> None:
    text = _recipe()
    assert "daedalus_doctor.py --print-cache-dir" in text
    assert "<that path>/frameworks" in text


def test_build_train_stops_on_off_contract_replies_and_dead_hooks() -> None:
    # 0024: the dead-hooks stop is begin's; test_begin_refuses_dead_hooks holds it.
    text = _recipe()
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
    for text in (_build_train(), _recipe()):
        assert "charter_root: <path or none>  charter base: <recorded branch or none>" in text
    # 0060: the orchestrator runs no git switch; the final stop switches the Charter back.
    assert "switches this repo and the Charter back to their base branches" in _build_train()
    assert "The final stop switches a created Charter branch back" in _recipe()
    assert "git -C <charter_root> switch" not in _recipe()


def test_build_train_runs_every_stop_through_the_script() -> None:
    # 0024: the five stop rules are the test_stop_* set in test_workspace_train.py.
    text, recipe = _build_train(), _recipe()
    rules = text.split("## Preconditions", 1)[0]
    stop = rules.split("- Every stop: ", 1)[1].split("\n", 1)[0]
    assert stop.startswith("run " + STOP_CMD)
    assert "`python3 ${CLAUDE_PLUGIN_ROOT}/scripts/daedalus_workspace.py resume --repo <repo>`" in (
        stop
    )
    # 0060: the orchestrator returns each stop; the main session runs the stop command.
    own = _rules().split("- Every stop: ", 1)[1].split("\n", 1)[0]
    assert own.startswith("end your reply with `[STATUS: STOP] reason=<what happened>")
    assert "daedalus_workspace.py stop" not in recipe and "daedalus_workspace.py resume" not in (
        recipe
    )
    for gone in ("Charter switch-back", "Integration switch-back", "Uncommitted contract:"):
        assert gone not in text + recipe, gone
    assert "- Worktree teardown:" not in rules and "- Train marker:" not in rules
    assert "unmark" not in text + recipe
    step = recipe.split("`[STATUS: COMMITTED] <sha>", 1)[1].split("\n6. ", 1)[0]
    assert "after the resume" in step


def test_build_train_summary_names_every_charter_form() -> None:
    text = _recipe()
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
    shape = _recipe().split("Shape:", 1)[1].split("\n7. ", 1)[0]
    lines = [ln for ln in shape.splitlines() if "charter:" in ln or "Ledger:" in ln]
    assert len(lines) == 4
    lines += [ln for ln in shape.splitlines() if "Contract:" in ln]
    assert len(lines) == 6
    for line in lines:
        assert "<path>" not in line and "<charter_root>" not in line and "/home" not in line


def test_build_train_reads_the_auditor_verdict_first() -> None:
    # 41, C7: the verdict line opens and closes every auditor reply.
    text = _recipe()
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
    # 0059, 0086, C1: the warm dispatch rule sits in the whole-train rules.
    rules = _rules()
    roster = rules.split("- Warm dispatch (0086): ", 1)[1].split("\n", 1)[0]
    assert "a persona stays warm after its first use" in roster
    # spec 8: the hook rebinds a warm coder as the resume goes out.
    assert "the hook rebinds the coder to the new unit as the message goes out" in roster
    assert "The security-auditor stays warm only after its first verdict" in roster
    assert "goes to that coder by SendMessage as a resume" in roster
    assert "A cold coder starts only when no warm coder built a dependency of the unit." in roster
    cold = next(ln for ln in rules.splitlines() if "standards-rules-specialist dispatch" in ln)
    assert cold.startswith("- The first standards-rules-specialist dispatch of a train carries")
    assert "Every later standards question resumes that same specialist by SendMessage" in cold


def test_build_train_dispatches_the_standards_specialist_once() -> None:
    # 0059, C2, C3: one first dispatch; the State Block records its handle.
    text = _recipe()
    assert text.count("Agent(`standards-rules-specialist`)") == 1
    assert "    standards specialist: <agent handle>  last read: <UTC time>" in text
    seed = text.split("**State Block**", 1)[1].split("\n\n", 2)[1].splitlines()
    assert seed[6].startswith("    standards specialist: ")


def test_build_train_asks_each_contradiction_as_a_brief() -> None:
    # 0057, C4: the stop is replaced by the prompt, the pick record and the re-check.
    text = _recipe()
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
    text = _recipe()
    route = next(ln for ln in text.splitlines() if ln.startswith("| `[STATUS: YIELD_STANDARDS]"))
    assert "SendMessage(standards specialist," in route
    assert "Rule files changed since your last read" in route
    step3 = _section(text, "## Phase 3", "\n4. ").split("\n3. ", 1)[1]
    assert step3.startswith("SendMessage(standards specialist,")
    assert "Rule files changed since your last read" in step3
    assert "resumes the same auditor by SendMessage" in step3


def test_build_train_summary_carries_rulings_and_deviations() -> None:
    # 0057, C6: one line per pick, a deviation line per keep-the-plugin pick.
    shape = _recipe().split("Shape:", 1)[1].split("\n7. ", 1)[0]
    assert "       ## Rulings\n" in shape
    assert "       Deviation: " in shape
    assert shape.index("[POLICY: none declared]") < shape.index("## Rulings")


def test_build_train_records_picks_before_any_coder() -> None:
    # 0057, C9: both ledger locations record picks before a coder starts.
    text = _recipe()
    step1 = _phase1_step(text, 1)
    assert "Ledger under `charter_root`: record the picks right after the last pick" in step1
    assert "Repo-local ledger: record the picks right after the step 3 `lock`" in step1
    assert "No coder starts before `[STATUS: COMMITTED]`." in step1
    step3 = _phase1_step(text, 3)
    assert "With a repo-local ledger and picks from step 1, record the picks now" in step3


def test_build_train_hands_coders_the_pick_ledger_ids() -> None:
    # 0057, 0083, C10: the ids line follows the two packet lines and precedes the worktree line.
    phase2 = _section(_recipe(), "## Phase 2", "## Phase 3")
    brief = phase2.split("holding: the two packet lines", 1)[1]
    assert brief.index("`Pick ledger ids:`") < brief.index("`Worktree: <path>`")
    assert brief.index("`Worktree: <path>`") < brief.index("Agent(`repo-coder`)")


ESCALATION_START = (
    "Put it to the operator with AskUserQuestion, in the decision-brief shape (0103):"
)
ESCALATION_END = "Never run a third round and never stop the train on your own authority."


def _escalation(text: str) -> str:
    flat = " ".join(text.split())
    assert flat.count(ESCALATION_START) == 1, "one escalation prompt"
    return flat.split(ESCALATION_START, 1)[1].split(ESCALATION_END, 1)[0]


def test_build_train_has_no_unit_cap_or_warm_roster_line() -> None:
    # B5, row 17: the planner and max_concurrent_builders govern; warm dispatch replaces the roster.
    text = _recipe()
    for gone in (
        "at most 5 work units",
        "Divide the task into",
        "Warm roster (0059)",
        "Each repo-coder is warm for its own unit only.",
    ):
        assert gone not in text, gone
    phase2 = _section(text, "## Phase 2", "## Phase 3")
    assert "`max_concurrent_builders`" in phase2
    assert "one per unit line of its plan block" in phase2


def test_build_train_has_no_three_round_cap() -> None:
    # 0096, row 17: after the second rejection the operator decides.
    text = _recipe()
    assert "After 3 rejected rounds" not in text and "3 rejected rounds" not in text
    step4 = _section(text, "## Phase 3", "\n5. ").split("\n4. ", 1)[1]
    assert "After the second rejected round, do not start a third" in step4
    assert ESCALATION_END in " ".join(step4.split())


VERDICT_CMD = PLUGIN + "daedalus_train.py verdict --repo <repo> --status {status} --round <n>`"


def test_build_train_records_each_verdict_for_the_push_gate() -> None:
    # 0089: the push gate reads the verdict record; approved is recorded on the merged tip.
    text = _recipe()
    phase3 = _section(text, "## Phase 3", "\n6. The summary")
    step4 = phase3.split("\n4. ", 1)[1].split("\n5. ", 1)[0]
    rejected = VERDICT_CMD.replace("{status}", "rejected")
    assert rejected in step4
    assert step4.index(rejected) < step4.index("SendMessage(each responsible coder")
    step5 = phase3.split("\n5. ", 1)[1]
    approved = VERDICT_CMD.replace("{status}", "approved")
    # spec 8: finish runs before the auditor; the ledger commit moves the tip, so record last.
    finish = "daedalus_workspace.py finish --repo <repo>"
    assert phase3.index(finish) < phase3.index("Agent(`security-auditor`)")
    committed = "   - `[STATUS: COMMITTED] <sha> ids=<id>[,<id>]`: record the sha"
    assert step5.index("Agent(`charter-docs`)") < step5.index(committed) < step5.index(approved)
    assert "- Verdict record, last: after `[STATUS: COMMITTED]` on `[VERDICT: APPROVED]`" in step5
    assert (
        "The push gate reads this record: it refuses an agent's push or pull request for any tip "
        "that moved after it, and asks the operator before the main session's own (0106)."
    ) in step5
    assert "    verdict: <the verdict command's printed line, or pending>\n" in text


def test_build_train_carries_the_escalation_prompt() -> None:
    # 0103: the decision-brief shape, held equal between the catalog and the recipe.
    catalog = (REPO_ROOT / "skills" / "catalog" / "SKILL.md").read_text(encoding="utf-8")
    step4 = _section(_recipe(), "## Phase 3", "\n5. ").split("\n4. ", 1)[1]
    prompt = _escalation(step4)
    assert prompt == _escalation(catalog)
    # 0060: the orchestrator returns the prompt as a decision brief; the session asks it.
    assert "into a decision brief and return `[STATUS: DECISION]`" in step4
    order = [
        "a plain question ending in a question mark",
        "Two or three context sentences in the operator's words",
        "what it protects and why the fix fell short",
        "One more fix-and-audit round:",
        "Merge with each finding as a tracked-risk issue:",
        "Stop with the branches kept:",
        "The recommendation and its reason",
    ]
    places = [prompt.index(item) for item in order]
    assert places == sorted(places)
    assert "`python3 ${CLAUDE_PLUGIN_ROOT}/scripts/" not in prompt
    assert PLUGIN + "daedalus_train.py exception --repo <repo> --ledger-id <id>`" in step4


def test_build_train_prints_progress_not_the_state_block() -> None:
    # 0085: the operator reads the progress note; the State Block prints at stop, resume, summary.
    text = _recipe()
    assert "print it after Preconditions and after each phase" not in text
    note = _rules().split("- Progress (0085): ", 1)[1].split("\n", 1)[0]
    assert PLUGIN + "daedalus_train.py progress --repo <repo>`" in note
    assert "after each phase" in note
    assert "Print the State Block only at a stop, at a resume, and in the summary." in note
    block = text.split("**State Block**", 1)[1].split("\n\n", 1)[0]
    assert "Print it only at a stop, at a resume, and in the summary" in block
    relay = _build_train().split("## Preconditions", 1)[0]
    relay_note = relay.split("- Progress (0085): ", 1)[1].split("\n", 1)[0]
    progress = "`python3 ${CLAUDE_PLUGIN_ROOT}/scripts/daedalus_train.py progress --repo <repo>`"
    assert progress in relay_note and "after Preconditions" in relay_note
    assert "Print the State Block only at a stop, at a resume, and in the summary." in relay_note


def test_build_train_records_choices_plan_packets_and_controls() -> None:
    # 0083, 0086, 0088, 0089, spec 5.2, 5.3, 6.3: the recipe's composition steps.
    text = _recipe()
    flat = " ".join(text.split())
    rules = _rules()
    choice = rules.split("- Choices (0088): ", 1)[1].split("\n", 1)[0]
    assert (
        PLUGIN + 'daedalus_train.py choice --repo <repo> --chose "<what>" --over "<alternative>" '
        '--cost "<time or tokens>"`'
    ) in choice
    for kind in ("warm or cold", "parallel or serial", "weight", "agent"):
        assert kind in choice, kind
    assert "`/daedalus:catalog`" in rules and "`/daedalus:catalog`" in _build_train()
    # 0105: the jail warns and asks, never blocks, the main session's own writes.
    relay = _build_train().split("## Preconditions", 1)[0]
    assert "the jail blocks writes under `src/` and `tests/` for you" not in text + relay
    assert "it never blocks the main session" in relay and "unit worktrees" in relay
    phase1 = " ".join(_section(text, "## Phase 1", "## Phase 2").split())
    assert "`/daedalus:plan <spec path>`" in phase1
    assert (
        PLUGIN + "daedalus_train.py plan --repo <repo> --path "
        "<repo>/docs/.tmp/daedalus/<train-id>/plan.md`"
    ) in phase1
    assert "`wire: none`" in phase1 and "validate-only" in phase1
    assert "starts the moment the last pick is made" in phase1
    assert "the lock waits on both" in phase1
    assert "byte-identical" not in flat
    assert "`<repo>/docs/.tmp/daedalus/<train-id>/standards-packet.md`" in phase1
    assert "`Contract: <contract path> sha256=<hex>`" in phase1
    assert "`Standards: <standards path> sha256=<hex>`" in phase1
    phase2 = " ".join(_section(text, "## Phase 2", "## Phase 3").split())
    for line in ("`Dispatch: repo-coder`", "`Prompt file: <brief path>`", "`Expect: "):
        assert line in phase2, line
    complete = next(ln for ln in text.splitlines() if ln.startswith("| `[STATUS: COMPLETE]"))
    assert "contract=<12 hex> standards=<12 hex>`" in complete
    assert "compare its `contract=` and `standards=` values" in complete
    phase3 = " ".join(_section(text, "## Phase 3", "\n6. The summary").split())
    controls = PLUGIN + "audit_report.py --repo <repo> --session <id> --controls`"
    assert controls in phase3
    assert phase3.index(controls) < phase3.index("Write the summary now")
    for word in ("friction", "habit"):
        assert word in phase3, word
    # spec 8, pin B2 -> B6: a blocking hook with `failure: none` is the contradiction item.
    item = phase3.split("Contradiction item (spec 8):", 1)[1].split("Write the summary now", 1)[0]
    assert "`failure: none`" in item
    for option in ("keep it", "redesign it", "remove it"):
        assert option in item, option
    # pin B3 -> B6: the final audit round comes before the summary Write.
    assert phase3.index("Agent(`security-auditor`)") < phase3.index("Write the summary now")
    assert "       ## Blocks\n" in text.split("Shape:", 1)[1]
    # O7: every charter-docs dispatch names append_ledger.py by its absolute path.
    for part in (phase1, phase3):
        dispatch = part.split("Agent(`charter-docs`) with:", 1)[1].split(". ", 1)[0]
        assert "the absolute path of append_ledger.py" in dispatch


def test_build_train_phase1_has_no_branch_switch() -> None:
    # 0024, C11: the lock script owns every branch move in Phase 1.
    phase1 = _section(_recipe(), "## Phase 1", "## Phase 2")
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


RELEASE_CMD = (
    "`python3 ${CLAUDE_PLUGIN_ROOT}/scripts/daedalus_workspace.py release --repo <repo> "
    "--merge-sha <merge sha>`"
)


def test_push_skill_hand_off_names_the_release_step() -> None:
    # 0068, 0071, 0075: the hand-off names the release step; the main session alone publishes.
    hand_off = _push_train().split("## Hand-off", 1)[1]
    assert RELEASE_CMD in hand_off
    assert "after the operator reports the merge" in hand_off
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
    ) in _push_train().split("## Preconditions", 1)[0]


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
    text = _recipe()
    phase1 = _section(text, "## Phase 1", "## Phase 2")
    assert '"Save the packet to <contract path>, then end the reply with the packet."' in phase1
    assert "The lock script owns this commit; contract-spec never commits." in phase1
    lock = (
        PLUGIN + "daedalus_workspace.py lock --repo <repo> "
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
    # 0060: the orchestrator runs the lock script; the commit is the script's, not an agent's.
    rule = (
        "The Build Train saves the Locked Contract Packet to a file and the train commits it "
        "through the lock script"
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
    phase2 = _section(_recipe(), "## Phase 2", "## Phase 3")
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
    pre = _section(_build_train(), "## Preconditions", "## Relay")
    assert BEGIN in pre
    assert "branches a declared Charter" in pre
    phase3 = _section(_recipe(), "## Phase 3", "\n6. The summary")
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
    pre = _section(_build_train(), "## Preconditions", "## Relay")
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
    # spec 8: audit after finish; the auditor judges the merged tip against the train's base.
    phase3 = _section(_recipe(), "## Phase 3", "\n4. ")
    step3 = phase3.split("\n3. ", 1)[1]
    dispatch = step3.split("Then Agent(`security-auditor`) with:", 1)[1].split(". Read", 1)[0]
    assert dispatch.startswith(" the diff base `<base sha>`, the State Block `base:` sha")
    assert "the one branch `daedalus/<train-id>`" in dispatch
    assert "the merged integration tip the Push Train pushes" in dispatch
    assert phase3.index("daedalus_workspace.py finish") < phase3.index("\n3. ")
    step2 = phase3.split("\n2. ", 1)[1].split("\n3. ", 1)[0]
    assert "(`git diff <base sha>...daedalus/<train-id>`" in step2
    auditor = (REPO_ROOT / "agents" / "security-auditor.md").read_text(encoding="utf-8")
    assert "For each branch run `git diff <diff base>...<branch>`" in auditor
    inputs = " ".join(auditor.split("Inputs:", 1)[1].split("## Procedure", 1)[0].split())
    assert "the diff base is the commit the train started from" in inputs
    assert "the merged integration branch `daedalus/<train-id>`" in inputs


def test_build_train_keeps_dirty_trees_on_the_train_branch() -> None:
    # Ruling 1, R4-I1: test_stop_keeps_a_dirty_charter and test_stop_keeps_an_uncommitted_contract.
    phase3 = _section(_recipe(), "## Phase 3", "\n6. The summary")
    dirty = phase3.split("   - Charter ledger:", 1)[1].split("\n", 1)[0]
    assert "the stop keeps the Charter on `daedalus/<train-id>` while it is dirty" in dirty
    assert "resume at this step" in dirty
    assert "Any other reply: the off-contract stop." in phase3


def test_build_train_keeps_worktrees_out_of_git_and_the_train() -> None:
    # 0024: teardown is the scripts' (test_stop_tears_down_only_recorded_units, test_finish_*).
    text = _recipe()
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
    assert "ledger" not in other.split("The code pull request", 1)[0]
    assert (
        "where `<title>` is `Build Train <train-id>: contract and ledger` when the `charter:` line "
        "ends in `(ledger under charter_root)`, else `Build Train <train-id>: contract`."
    ) in body


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
    bt = _recipe()
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


def test_push_train_hands_the_charter_push_to_the_conductor() -> None:
    # 0078: the conductor pushes the Charter branch and opens its pull request; no operator step.
    text = _push_train()
    hand_off = text.split("## Hand-off", 1)[1]
    assert "push" not in hand_off.split("With a Charter branch", 1)[1].split("\n6. ", 1)[0]
    assert "Push the Charter branch from your own shell" not in text
    assert "open its pull request: `gh pr create" not in text
    assert "gh pr create" not in hand_off and "push -u origin" not in hand_off
    charter = _section(text, "## Charter branch", "## Hand-off")
    push = "When charter_root is declared, run `git -C <charter_root> push -u origin "
    assert push + "daedalus/<train-id>`." in charter
    assert (
        "When charter_root is declared, run `gh pr create --repo <charter slug> "
        "--base <charter base> --head daedalus/<train-id> --title "
        '"<title>" --body-file <repo>/docs/.tmp/daedalus/<train-id>-charter-pr.md`.'
    ) in charter
    assert charter.index("SendMessage(conductor") < charter.index(push)
    pre = _section(text, "## Preconditions", "## Push")
    assert "`git -C <charter_root> remote get-url origin`" in pre
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
    text = _recipe()
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
        line for line in _recipe().splitlines() if line.startswith("| `[STATUS: COMPLETE]")
    )
    compare = (
        "First compare `<b>` with the branch the State Block recorded for that unit in Phase 2. "
        f"A mismatch: stop with {BRANCH_STOP}"
    )
    assert compare in complete
    assert complete.index(compare) < complete.index("git merge-base --is-ancestor")
    assert "the unit's branch stays the one Phase 2 recorded" in complete


def test_build_train_creates_each_coder_worktree() -> None:
    phase2 = _section(_recipe(), "## Phase 2", "## Phase 3")
    assert (
        PLUGIN + "daedalus_workspace.py create --repo <repo> "
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
    phase3 = _section(_recipe(), "## Phase 3", "\n6. The summary")
    merge = phase3.split("\n1. ", 1)[1].split("\n2. ", 1)[0]
    finish = PLUGIN + "daedalus_workspace.py finish --repo <repo>`"
    assert finish in merge
    assert phase3.index(finish) < phase3.index("Agent(`charter-docs`)")
    assert "git merge --no-ff" not in _recipe()
    # spec 8: a fix round is a fix unit cut from the integration branch, merged by a second finish.
    fix = phase3.split("\n4. ", 1)[1].split("\n5. ", 1)[0]
    assert "--name <train-id>-fix<n>-<unit-slug> --base daedalus/<train-id>" in fix
    assert "Then run the step 1 finish again" in fix
    assert "The hook rebinds that coder from its merged unit to the fix unit" in fix


MARK = "`python3 ${CLAUDE_PLUGIN_ROOT}/scripts/daedalus_workspace.py mark --repo <repo> --train "
UNMARK = "`python3 ${CLAUDE_PLUGIN_ROOT}/scripts/daedalus_workspace.py unmark --repo <repo>`"


def test_build_train_marks_the_train_active_and_clears_it() -> None:
    # 0023: begin marks (test_begin_prints_the_state_block_seed); stop clears.
    # 0060: the orchestrator reports the train complete; the relay runs the final stop.
    text = _build_train()
    end = text.split("- `[STATUS: TRAIN_COMPLETE] summary=<path> audit_log=<path>`", 1)[1]
    assert (
        "`python3 ${CLAUDE_PLUGIN_ROOT}/scripts/daedalus_workspace.py stop --repo <repo> "
        '--reason "train complete"'
    ) in end
    assert "marks the train active" in _section(text, "## Preconditions", "## Relay")
    last = _recipe().split("\n7. Print the State Block", 1)[1]
    assert (
        "`[STATUS: TRAIN_COMPLETE] summary=<repo>/docs/.tmp/daedalus/<train-id>-summary.md" in last
    )


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
    text = _recipe()
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
    # 0028, 0078: every command Push and Charter branch hand the conductor, minus never-run lines.
    text = PUSH_TRAIN.read_text(encoding="utf-8")
    push = _section(text, "## Push", "## Hand-off")
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
    from tests.test_checks_git_push import audited_train

    # spec 4.2: an audited train, so the push and pr create meet an approved verdict.
    audited_train(repo_cwd, "20261016-120000")
    # 0078: a declared charter root whose origin names the <charter slug> the skill records.
    charter = repo_cwd.parent / "Charter"
    if not charter.exists():
        subprocess.run(["git", "init", "-q", str(charter)], check=True)
        url = "https://github.com/acme/charter.git"
        subprocess.run(["git", "-C", str(charter), "remote", "add", "origin", url], check=True)
    config = json.dumps({"charter_root": str(charter)})
    (project_data / "config.json").write_text(config, encoding="utf-8")
    for name, value in (
        ("<repo>", str(repo_cwd)),
        ("<train-id>", "20261016-120000"),
        ("<charter_root>", str(charter)),
        ("<charter slug>", "acme/charter"),
    ):
        command = command.replace(name, value)
    concrete = re.sub(r"<[^>]+>", "x", command)
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
    assert "git -C <charter_root> push -u origin daedalus/<train-id>" in commands
    assert any(c.startswith("gh pr create --repo <charter slug> ") for c in commands)


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


# 0031: operator lines name things in words; lib.human_text holds the one word counter.
_NEXT_CONST = re.compile(r"_?[A-Z_]*NEXT")
_SENTENCE_END = re.compile(r"\.\s+(?=[A-Z])")
_SKILL_NEXT = re.compile(r"(?:^|(?<=[.:;]\s))Next:")
# 0031: jail refusals are messages to the refused agent, which may use ids alone.
AGENT_FACING = {"scripts/lib/jail.py", "scripts/lib/shell.py", "scripts/lib/dispatch_binding.py"}
AGENT_FACING |= {"scripts/lib/router.py"} | {
    str(p.relative_to(REPO_ROOT)) for p in (REPO_ROOT / "scripts" / "checks").glob("*.py")
}
_words = plain_words


def _forward_only(text: str) -> bool:
    return not DROP_SPANS.sub("", text).strip(" " + EDGE)


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
