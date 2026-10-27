# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0127, 0128, 0136: the verifier judges a unit's diff against its brief and counts corrections.
from __future__ import annotations

from pathlib import Path

import pytest
from lib.agent_files import Hook, frontmatter, load
from lib.train_summary import Reply
from lib.workspace import VERIFIED_LINE

from tests.conftest import REPO_ROOT
from tests.test_train_state_print import RECORDS, _section, _stop, _text

VERIFIER = REPO_ROOT / "agents" / "verifier.md"
ORCHESTRATOR = REPO_ROOT / "agents" / "orchestrator.md"
CATALOG = REPO_ROOT / "skills" / "catalog" / "SKILL.md"
HOOKS = (
    "credential_paths",
    "workspace_integrity",
    "tool_bound",
    "shell_tripwires",
    "network_tools",
    "read_only_bash",
    "gh_classes",
)


def _flat(text: str) -> str:
    return " ".join(text.split())


def _body(head: str, end: str) -> str:
    return _flat(VERIFIER.read_text(encoding="utf-8")).split(head, 1)[1].split(end, 1)[0]


def test_frontmatter_keeps_its_tools_model_and_hooks() -> None:
    # VER 9: the body changes; tools, model, shape, phases and hooks stay as they were.
    fields = frontmatter(VERIFIER)
    assert fields["tools"] == "Read, Grep, Glob, Bash"
    assert fields["disallowedTools"] == (
        "Write, Edit, MultiEdit, NotebookEdit, WebFetch, WebSearch, Agent, Task, SendMessage"
    )
    agent = load(VERIFIER)
    assert (agent.model, agent.shape, agent.phases) == ("opus", "judge", ("implementation",))
    assert tuple(h.script for h in agent.hooks) == HOOKS
    assert Hook("read_only_bash", ("--git", "read-only", "--test-runner", "unit")) in agent.hooks


def test_procedure_takes_its_claims_from_the_brief_not_the_report() -> None:
    # VER 1, 0128: requirement section, files list, pins and Standards Packet are the claims.
    head = _body("You are the Verifier.", "## Procedure")
    assert (
        "you judge a unit's diff against its brief, never against the coder's report (0128)" in head
    )
    assert "The coder's report is receipts only." in head
    assert "a `Brief: <path>` line naming the unit's brief file" in head
    procedure = _body("## Procedure", "## Claims mode")
    assert "List the claims from the brief, never from the report." in procedure
    assert (
        "the line reading exactly `Requirements:` is followed by lines `<n>. <requirement>`"
        in procedure
    )
    assert "Each numbered line is one claim (pin REQ -> VER)." in procedure
    assert "The `files:` list of the unit line is one claim".lower() in procedure.lower()
    assert (
        "each `pin:` line of the brief that names the unit on either side is one claim"
        in procedure.lower()
    )
    assert "each Standards Packet rule that a changed line falls under is one claim" in procedure
    # V1 req 3, spec 9.2: step 1 reads the named ranges first; prepush-2026-10-27 finding 3:
    # the full diff with its removed lines is a required read, so the ranges never bound it.
    assert "a `Read: <file>:<first>-<last>[, ...]` line" in _body("Inputs:", "## Procedure")
    step1 = procedure.split("1. ", 1)[1].split(" 2. ", 1)[0]
    assert step1.startswith("Read the brief, the packets, the full diff and the named ranges:")
    assert "`git -C <unit worktree> diff <diff base>...<branch>` with every removed `-` line" in (
        step1
    )
    assert "The full diff is a required read for every unit" in step1
    assert "The `Read:` ranges guide your attention and never bound it" in step1
    assert "Without a `Read:` line, read the full diff instead." not in procedure
    assert "each range of the `Read:` line through the `git show` pipe of step 3" in step1
    assert "Open another file only to settle a named claim" in step1
    assert "list each extra file in the verdict's receipts" in step1
    assert "then the full diff. Read all of it." not in procedure


def test_lint_receipts_are_judged_from_the_receipts_block_with_the_jail_unchanged() -> None:
    # V1 req 4, spec 6.4: ruff stays refused; the verifier judges lint from the coder's receipts.
    jail = _body("The jail refuses these:", "\0")
    assert (
        "Any other test runner or lint command, `ruff` included, and `pytest --basetemp`. "
        "Typecheck and lint receipts are judged from the coder's receipts block, never rerun; "
        "only the pytest run above is reproduced." in jail
    )
    assert Hook("read_only_bash", ("--git", "read-only", "--test-runner", "unit")) in (
        load(VERIFIER).hooks
    )


def test_refuted_rows_are_code_or_scope_and_a_deviation_excuses_scope() -> None:
    # VER 2: a file outside the list or an unasked change is scope unless a deviation names it.
    procedure = _body("## Procedure", "## Claims mode")
    assert "Its row is `code` or `scope`, never anything else" in procedure
    assert (
        "`scope`: a changed file outside the files list, or a behaviour change no requirement "
        "asks for." in procedure
    )
    assert "`- deviation <file or behaviour> | <reason>`" in procedure
    assert "makes the claim MATCH" in procedure
    # Contract FLAG E: a missing typecheck receipt is a scope row, not a hand-back refusal.
    assert (
        "such as the typecheck command, with no receipt line for it is a `scope` row" in procedure
    )
    contract = _body("## Status contract", "\0")
    assert (
        "A refuted row is `<class> | <claim> | <verdict> | <branch quote> | <brief quote>`"
        in contract
    )
    assert "REFUTED needs at least one `code` or `scope` row." in contract


def test_wrong_receipts_are_corrected_and_counted_above_the_closing_line() -> None:
    # VER 3, 0127: a correction is counted on corrected=<k>, never refuted, never sent back.
    procedure = _body("## Procedure", "## Claims mode")
    assert "is a report correction (0127)" in procedure and "never refute for it" in procedure
    assert "the coder is not resumed for a correction" in procedure
    contract = _body("## Status contract", "\0")
    assert "The line directly above the closing verdict line reads `corrected=<k>`" in contract
    assert "`corrected=0` when none" in contract
    assert load(VERIFIER).status_lines == (
        "[VERDICT: VERIFIED] claims=<n>",
        "[VERDICT: REFUTED] <rows>",
    )
    lines = VERIFIER.read_text(encoding="utf-8").splitlines()
    shapes = [ln for ln in lines if ln.startswith("- `[VERDICT: ")]
    assert all(
        ln.endswith("then `corrected=<k>` then " + ln.split(" then ")[0][2:]) for ln in shapes
    )


def test_a_verified_reply_with_a_corrected_line_still_ends_on_the_merge_line() -> None:
    # VER 3: the merge proof keeps matching the closing line (scripts/lib/workspace.py).
    reply = Reply(
        1,
        "verifier",
        "v",
        "[VERDICT: VERIFIED] claims=4\n| r |\ncorrected=2\n[VERDICT: VERIFIED] claims=4\n",
    )
    assert VERIFIED_LINE.fullmatch(reply.last) is not None
    assert reply.corrected == 2


def test_the_map_feeds_the_subtracted_and_added_rows() -> None:
    # VER 4, pin MAP -> VER: fan_in is the subtracted checklist, duplicates the added source.
    procedure = _body("## Procedure", "## Claims mode")
    assert "a `Map: <path>` line" in _body("Inputs:", "## Procedure")
    assert (
        "Subtracted: the map's `imports.<module path>.fan_in` lists the modules that import"
        in procedure
    )
    assert "(pin MAP -> VER)" in procedure
    assert (
        "Added: each `duplicates` entry of the map lists the file:line ranges of one "
        "near-duplicate block" in procedure
    )
    # V1 req 5, spec 5.2 item 2: a copied test body is a scope row unless the brief names it.
    added = procedure.split("Added: ", 1)[1].split("Without a `Map:` line", 1)[0]
    assert (
        "A new test function whose body, with constants replaced, matches an existing test's "
        "body is a `scope` refutation unless the brief names it." in added
    )


def test_claims_mode_checks_only_the_listed_claims_and_samples_later_rounds() -> None:
    # VER 5, pin VER -> DOCT, 0136 items 2 and 3.
    mode = _body("## Claims mode", "Never write U+2013")
    assert (
        "A prompt whose first line is `CLAIMS MODE.` lists one "
        "`Claim: <output path>:<line> <claim>` line per claim" in mode
    )
    assert "check only the listed claims" in mode
    assert "In rounds 2 and 3" in mode
    assert (
        "every claim you rejected in the prior round, plus a random 20 percent sample of the rest"
        in mode
    )
    assert (
        "Reply with the usual first and last verdict lines over the claims checked this round only."
        in mode
    )
    assert "in claims mode every claim checked this round" in _body("## Status contract", "\0")


def test_claims_mode_checks_attachment_beside_existence() -> None:
    # Train 10 audit-miss diagnosis V1 and V1b: a check claim needs a caller, not a definition.
    mode = _body("## Claims mode", "Never write U+2013")
    assert "existence (its definition) and attachment (a caller on the path it governs)" in mode
    assert "existence alone is OVERSTATED" in mode
    writer = _flat((REPO_ROOT / "agents" / "docs-writer.md").read_text(encoding="utf-8"))
    assert "carries a receipt that includes the caller grep" in writer


def test_a_clause_number_beside_a_receipt_gets_two_checks() -> None:
    # VER 6, 0136 item 6: the line holds the claim, and the number names that line's clause.
    procedure = _body("## Procedure", "## Claims mode")
    assert "when a clause number sits beside a receipt or a cited `file:line`" in procedure
    assert "run two checks and print both. First, the line holds the claim." in procedure
    assert "Second, the number names that line's clause" in procedure


def test_orchestrator_sends_the_brief_and_counts_only_code_and_scope_rows() -> None:
    # VER 7: the verifier step and the two VERDICT route rows of Phase 2.
    # 0165: the verifier step is the verify phase skill the orchestrator runs per unit.
    assert "skills/verify/SKILL.md` in unit mode" in ORCHESTRATOR.read_text(encoding="utf-8")
    phase2 = (REPO_ROOT / "skills" / "verify" / "SKILL.md").read_text(encoding="utf-8")
    phase2 = (
        phase2.split("### Unit mode", 1)[0]
        + phase2.split("### Unit mode", 1)[1].split("### Claims mode", 1)[0]
    )
    step = _flat(phase2)
    assert (
        "The verifier judges each unit's diff against its brief, never against the coder's "
        "report (0128)" in step
    )
    assert "the line `Brief: <the unit's brief path from the build phase>`" in step
    assert (
        "the line `Map: <repo>/docs/.tmp/daedalus/<train-id>/map/map.json` when that file exists"
        in step
    )
    assert "the `## Receipts` block above it, as receipts only" in step
    # V1 reqs 1 and 2, spec 9.2 and 6.4: named ranges, and lint judged from the receipts.
    assert "the line `Read: <file>:<first>-<last>[, ...]` from step 3" in step
    assert (
        "Then, for each changed module, add the line of each importer its map entry "
        "`imports.<module path>.fan_in` names that imports it"
    ) in step
    assert "`git -C <repo> diff -U0 <lock sha>...<b>`" in step
    assert (
        "Typecheck and lint receipts are judged from the coder's receipts block, not rerun; "
        "only a pytest run is reproduced." in step
    )
    rows = phase2.splitlines()
    verified = next(ln for ln in rows if ln.startswith("   - `[VERDICT: VERIFIED] claims=<n>`"))
    assert "the `<k>` of the `corrected=<k>` line above the verdict" in verified
    assert "never counts as a refutation (0127)" in verified
    refuted = next(ln for ln in rows if ln.startswith("   - `[VERDICT: REFUTED]"))
    assert "only rows of class `code` or `scope` count (0127)" in refuted
    assert '"FIX. The verifier refuted: <code and scope rows>"' in refuted


def test_catalog_rule_sends_the_brief_and_counts_only_code_and_scope_rows() -> None:
    # VER 7: the verifier rule of the catalog's composition rules.
    rules = CATALOG.read_text(encoding="utf-8").split("## Composition rules", 1)[1]
    rule = next(ln for ln in rules.splitlines() if ln.startswith("- Verifier step (spec 5): "))
    assert "the orchestrator sends the verifier the unit's brief" in rule
    assert "the coder's reply is receipts only (0128)" in rule
    assert "counted on a `corrected=<k>` line, never refuted (0127)" in rule
    assert "Only `code` and `scope` rows count" in rule


def _with_verdict(text: str) -> list[dict[str, object]]:
    return [_stop(7, "verifier", text, "v1") if r.get("seq") == 7 else r for r in RECORDS]


@pytest.mark.parametrize(
    ("reply", "want"),
    [
        (
            "[VERDICT: VERIFIED] claims=12\nrows\ncorrected=2\n[VERDICT: VERIFIED] claims=12",
            "- u1: \\[VERDICT: VERIFIED\\] claims=12 corrected=2",
        ),
        (
            "[VERDICT: VERIFIED] claims=12\nrows\n  corrected=0  \n\n[VERDICT: VERIFIED] claims=12",
            "- u1: \\[VERDICT: VERIFIED\\] claims=12 corrected=0",
        ),
        (
            "[VERDICT: REFUTED] code | R1 | MISSING | - | x\nrows\ncorrected=1\n"
            "[VERDICT: REFUTED] code | R1 | MISSING | - | x",
            "- u1: \\[VERDICT: REFUTED\\] code \\| R1 \\| MISSING \\| - \\| x corrected=1",
        ),
    ],
)
def test_summary_prints_the_corrected_count_beside_the_verdict(
    tmp_path: Path, reply: str, want: str
) -> None:
    # VER 8: the Verification section reads the line directly above the closing verdict.
    assert _section(_text(tmp_path, records=_with_verdict(reply)), "Verification") == [want]


@pytest.mark.parametrize(
    "reply",
    [
        "[VERDICT: VERIFIED] claims=12\nrows\n[VERDICT: VERIFIED] claims=12",
        "[VERDICT: VERIFIED] claims=12\ncorrected=2\nrows\n[VERDICT: VERIFIED] claims=12",
        "[VERDICT: VERIFIED] claims=12\nrows\ncorrected=two\n[VERDICT: VERIFIED] claims=12",
    ],
)
def test_summary_prints_no_count_without_a_corrected_line_above_the_verdict(
    tmp_path: Path, reply: str
) -> None:
    # 0127: a reply with no counted line prints the verdict alone, never an invented zero.
    lines = _section(_text(tmp_path, records=_with_verdict(reply)), "Verification")
    assert lines == ["- u1: \\[VERDICT: VERIFIED\\] claims=12"]


VERIFY_SKILL = REPO_ROOT / "skills" / "verify" / "SKILL.md"


def test_verify_skill_carries_the_verifier_step_and_claims_mode() -> None:
    # spec 3.4, 0127, 0128: the verify phase holds the verifier step, its routes and claims mode.
    text = _flat(VERIFY_SKILL.read_text(encoding="utf-8"))
    method = text.split("## What the phase does well", 1)[1].split("## Evidence that ends it", 1)[0]
    assert "never against the coder's report (0128)" in method
    assert "The coder's report is receipts only" in method
    assert "the coder's `[STATUS: COMPLETE]` line with its ledger notes and the `## Receipts`" in (
        method
    )
    assert (
        "Typecheck and lint receipts are judged from the coder's receipts block, not rerun; "
        "only a pytest run is reproduced." in method
    )
    assert "never a `Worktree:` line" in method
    assert "never counts as a refutation (0127)" in method
    assert "only rows of class `code` or `scope` count (0127)" in method
    assert "a prompt whose first line is `CLAIMS MODE.`" in method
    assert "a random 20 percent sample of the rest of the prior round's claims" in method
    # 0161, 0133: a later refutation goes to the operator; no automatic stop.
    step5 = method.split(" 5. Route the verdict.", 1)[1].split("### Claims mode", 1)[0]
    for label in ("`Fix it now (Recommended)`", "`Skip, track or exempt it`", "`Stop the run`"):
        assert label in step5, label
    assert "stops the run" not in step5
    assert "exempt it` pick at a later refutation" in text.split("## Evidence that ends it", 1)[1]
    evidence = text.split("## Evidence that ends it", 1)[1].split("## Agents it uses", 1)[0]
    assert "(scripts/lib/workspace.py:966, :1062)" in evidence
    assert "no recorded VERIFIED reply for its worktree" in evidence
