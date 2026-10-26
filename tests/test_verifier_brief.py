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


def test_a_clause_number_beside_a_receipt_gets_two_checks() -> None:
    # VER 6, 0136 item 6: the line holds the claim, and the number names that line's clause.
    procedure = _body("## Procedure", "## Claims mode")
    assert "when a clause number sits beside a receipt or a cited `file:line`" in procedure
    assert "run two checks and print both. First, the line holds the claim." in procedure
    assert "Second, the number names that line's clause" in procedure


def test_orchestrator_sends_the_brief_and_counts_only_code_and_scope_rows() -> None:
    # VER 7: the verifier step and the two VERDICT route rows of Phase 2.
    text = ORCHESTRATOR.read_text(encoding="utf-8")
    phase2 = text.split("## Phase 2", 1)[1].split("## Phase 3", 1)[0]
    step = _flat(phase2.split("Verifier step (spec 5): ", 1)[1].split("\n", 1)[0])
    assert (
        "the verifier judges the unit's diff against its brief, never against the reply (0128)"
        in step
    )
    assert "the line `Brief: <the unit's brief path from Phase 2>`" in step
    assert (
        "the line `Map: <repo>/docs/.tmp/daedalus/<train-id>/map/map.json` when that file exists"
        in step
    )
    assert "the `## Receipts` block above it as receipts only" in step
    rows = phase2.splitlines()
    verified = next(ln for ln in rows if ln.startswith("| `[VERDICT: VERIFIED] claims=<n>`"))
    assert "the `<k>` of the `corrected=<k>` line above the verdict" in verified
    assert "never counts as a refutation (0127)" in verified
    refuted = next(ln for ln in rows if ln.startswith("| `[VERDICT: REFUTED]"))
    assert "Only rows of class `code` or `scope` count (0127)" in refuted
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
