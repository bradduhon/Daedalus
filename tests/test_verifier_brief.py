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
from tests.helpers import flatten
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


def _body(head: str, end: str) -> str:
    return flatten(VERIFIER.read_text(encoding="utf-8")).split(head, 1)[1].split(end, 1)[0]


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
    assert "every range of the `Read:` line through one claims call of step 3" in step1
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
        "A refuted row is `<class> | <claim> | <verdict> | <branch quote> | <brief quote> | "
        "rule: <the rule broken, in one sentence> | places: <place>[, <place>] | "
        "search: <command>`" in contract
    )
    assert "each place is `<file>:<line>` or `<file>:<named part>`" in contract
    assert "REFUTED needs at least one `code` or `scope` row." in contract


WHOLE_LIST = (
    "What you return is everything in this submission that needs fixing; a second round will "
    "read only what that round changed."
)


@pytest.mark.parametrize(
    ("name", "heading"), [("verifier", "## Claims mode"), ("auditor", "## Severity")]
)
def test_each_judge_searches_every_place_before_the_verdict(name: str, heading: str) -> None:
    # 0278, 0281: one step before the verdict states the rule and searches for every place.
    text = " ".join((VERIFIER.parent / f"{name}.md").read_text(encoding="utf-8").split())
    procedure = text.split("## Procedure", 1)[1].split(heading, 1)[0]
    step = procedure.split("Every place of each rule", 1)[1]
    assert "state the rule it breaks in one sentence" in step
    assert "search the submission" in step and "every other place" in step
    assert "lists them all with that search" in step
    assert "A rule with one place still carries its search" in step
    assert WHOLE_LIST in step
    for word in (" diff", " code ", " function"):
        assert word not in step, word


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
        "[ROWS] n=<count>",
    )
    lines = VERIFIER.read_text(encoding="utf-8").splitlines()
    shapes = [ln for ln in lines if ln.startswith("- `[VERDICT: ")]
    assert all(
        ln.endswith("then `corrected=<k>` then " + ln.split(" then ")[0][2:]) for ln in shapes
    )


def test_every_reply_shape_carries_the_unit_key_line_second() -> None:
    # 0231: the merge gate selects a unit's reply by the key line after the opening line.
    contract = _body("## Status contract", "\0")
    assert (
        "The second line is the key line `Unit worktree: <path>`, the prompt's "
        "`Unit worktree:` line copied verbatim, or `Unit worktree: none` when the prompt has "
        "none (0231)." in contract
    )
    assert "matches no dispatched unit, counts as no reply for any unit." in contract
    lines = VERIFIER.read_text(encoding="utf-8").splitlines()
    shapes = [ln for ln in lines if ln.startswith(("- `[VERDICT: ", "- `[ROWS] "))]
    assert len(shapes) == 3
    assert all(ln.split(" then ")[1] == "`Unit worktree: <path>`" for ln in shapes)


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
    kind = REPO_ROOT / "skills" / "document" / "kinds" / "public-docs" / "SKILL.md"
    writer = flatten(kind.read_text(encoding="utf-8"))
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
    step = flatten(phase2)
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
    text = flatten(VERIFY_SKILL.read_text(encoding="utf-8"))
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
    assert "(scripts/lib/workspace.py:1082, :1275; scripts/lib/train_runner.py:1691)" in evidence
    assert "REFUTED with every row exempted against that reply" in evidence


def test_the_verifier_opens_the_named_set_in_one_turn_and_never_searches_for_it() -> None:
    # item 15: the brief names every file once; a search runs only for a map importer.
    assert "an `Open: <path>[, ...]` line naming once every file to open" in _body(
        "Inputs:", "## Procedure"
    )
    procedure = _body("## Procedure", "## Claims mode")
    step1 = procedure.split("1. ", 1)[1].split(" 2. ", 1)[0]
    assert (
        "first open every path of the `Open:` line in one turn of parallel Read calls (item 15)"
        in step1
    )
    assert (
        "Never search with Grep, Glob or `find` for a file the brief or the `Open:` line names"
        in step1
    )
    assert "search only for an importer the map's `fan_in` names" in step1
    step = flatten(VERIFY_SKILL.read_text(encoding="utf-8"))
    assert (
        "Then build the `Open:` line (item 15), which names once, as absolute paths, every file "
        "the verifier opens" in step
    )
    for part in (
        "the brief file, the Contract and Standards files its packet lines name",
        "each file of the unit's `files:` list in the unit worktree that exists on `<b>`",
        "each test file the coder's `- test` receipts run that is not on that list",
        "- the line `Open: <path>[, ...]` from step 3;",
        "Open every file of the `Open:` line in one turn of parallel Read calls before anything "
        "else, and never search with Grep, Glob or find for a file it names.",
    ):
        assert part in step, part


def test_the_read_line_and_the_full_diff_carry_the_asset_tail() -> None:
    # 0192: the session prints the tail once; the Read line and the verifier's diff copy it.
    step = flatten(VERIFY_SKILL.read_text(encoding="utf-8"))
    assert (
        "first run `python3 ${CLAUDE_PLUGIN_ROOT}/scripts/daedalus_train.py assets --repo <repo> "
        "--base <lock sha> --tip <b>`" in step
    )
    assert (
        "With a tail, the `-U0` command below ends with it, copied exactly, so no asset file "
        "reaches the `Read:` or `Open:` line." in step
    )
    assert (
        "- the `Assets: <tail>` line and its `Over size:` lines from step 3, unchanged, when it "
        "printed a tail; the verifier ends its full diff command with that tail;" in step
    )
    assert "an `Assets: <tail>` line and its `Over size:` lines when the project keeps asset" in (
        _body("Inputs:", "## Procedure")
    )
    step1 = _body("## Procedure", "## Claims mode").split("1. ", 1)[1].split(" 2. ", 1)[0]
    assert "with an `Assets:` line, end the full diff command with its tail exactly as given" in (
        step1
    )
    assert "judge an `Over size:` file by its name" in step1
    assert "The files check of step 2 runs without the tail." in step1


def test_the_verify_step_asks_the_operator_each_check_and_never_fetches_the_site() -> None:
    # 0164, 0192: operator checks and the dev server check become pass, fail or skip questions.
    text = flatten(VERIFY_SKILL.read_text(encoding="utf-8"))
    route = text.split(" 5. Route the verdict.", 1)[1].split("### Claims mode", 1)[0]
    checks = route.split("- Operator checks (0164, 0192).", 1)[1]
    for part in (
        "one operator check per entry of its plan line's `operator_checks:` field",
        "the manifest's `local_testing` check, when `local_testing` is set and the unit touches "
        "web code: the `commands` group declares a `vitest` or `tsc` command, or the unit's "
        "files include a `.ts`, `.tsx` or `.html` file",
        "in the shape of the per-finding audit prompt of the catalog",
        "with the options `Pass`, `Fail` and `Skip`",
        "A local site question names its `local_testing.url` and its "
        "`local_testing.instructions` text",
        "`Fail` is a refuted `code` row routed like a verifier refutation",
        "`Skip` records the operator's reason.",
        # L1: the second and third steps live in the REFUTED bullet below this one.
        "the second and third take the steps of the `[VERDICT: REFUTED]` bullet below.",
        "`operator check | <url or none> | <check text> | <pass, fail or skip> | <the "
        "operator's words>`",
        "Daedalus never starts, polls or fetches the site; the operator hosts it.",
    ):
        assert part in checks, part
    assert "ready for the build phase's merge once its operator checks below are answered" in (
        route
    )
    evidence = text.split("## Evidence that ends it", 1)[1].split("## Agents it uses", 1)[0]
    assert "Each operator check of the unit has an `operator check` evidence row" in evidence


def test_the_second_refutation_escalates_and_the_third_reaches_the_operator() -> None:
    # 0187, issue 115: a fresh coder on the escalated model takes the second refutation.
    text = flatten(VERIFY_SKILL.read_text(encoding="utf-8"))
    nxt = text.split("## Suggested next", 1)[1]
    assert (
        "the first time on its own for one fix pass, the second time by a fresh coder on the "
        "escalated model, a third time on the operator's Fix it now pick (step 5)." in nxt
    )


def test_the_catalog_and_build_skill_send_the_second_refutation_to_a_fresh_coder() -> None:
    # Issue 256, 0187: the catalog row says what the build skill does; no stop on the second.
    rules = flatten(CATALOG.read_text(encoding="utf-8")).split("## Composition rules", 1)[1]
    rule = rules.split("- Verifier step (spec 5): ", 1)[1].split(" - ", 1)[0]
    assert (
        "a second REFUTED on the same unit goes to a fresh coder on the escalated model and the"
        " run goes on (0187); a third goes to the operator." in rule
    )
    assert "stops the train" not in rule
    build = flatten((REPO_ROOT / "skills" / "build" / "SKILL.md").read_text(encoding="utf-8"))
    step5 = build.split("A second refutation (0187, issue 115).", 1)[1].split(" 6. ", 1)[0]
    assert (
        "When the verifier refutes the same unit a second time, the unit goes to a fresh coder"
        " and the run goes on." in step5
    )


def test_refuted_jail_forms_become_corpus_rows_in_every_routing_place() -> None:
    # 0229: the coder writes the row, the verifier checks it, the build skill refuses a fix
    # pass without it, and the auditor's reproductions land the same way.
    verify = flatten(VERIFY_SKILL.read_text(encoding="utf-8"))
    route = verify.split("`[VERDICT: REFUTED] <rows>`: only rows", 1)[1]
    for phrase in (
        "Refutations become corpus (0229): before sending the `FIX.` message for a unit whose"
        " diff names a path of the audit phase's table-diff list",
        "record the unit branch head from `git -C <repo> rev-parse <b>` on its State Block row",
        "The coder adds each refuted form as a named row under `tests/adversarial/` in its own"
        " worktree, in a commit before its fix",
        '"Refuted forms: check that each form you refuted has a named row under'
        ' tests/adversarial, committed before the fix, failing at that commit and passing now."',
        "On any other unit, a refuted requirement becomes a failing test in the unit's own test"
        " file.",
    ):
        assert phrase in route, phrase
    verifier = _body("## Refuted forms (0229)", "## What the jail passes and refuses")
    for phrase in (
        "A message carrying a `Refuted forms:` line, after your refutation of the same unit",
        "A named row under `tests/adversarial/` holds the form with its expected verdict.",
        "Its commit comes before the fix commit",
        "A missing row, or a row first committed with the fix, is a `code` row.",
    ):
        assert phrase in verifier, phrase
    build = flatten((REPO_ROOT / "skills" / "build" / "SKILL.md").read_text(encoding="utf-8"))
    check = build.split("Refuted forms (0229).", 1)[1].split("Then hand the unit", 1)[0]
    for phrase in (
        "run `git diff --name-only <refuted head>...<b>`",
        "When it names no path under `tests/adversarial/`, the fix pass added no row",
        "A second COMPLETE on the unit without one stops the run",
        "The same check runs on an audit fix unit",
    ):
        assert phrase in check, phrase
    coder = flatten((REPO_ROOT / "agents" / "coder.md").read_text(encoding="utf-8"))
    rows = coder.split("**Refuted forms** (0229):", 1)[1].split("`pytest --basetemp`", 1)[0]
    for phrase in (
        "one named row per form in the matching module under `tests/adversarial/` in your worktree",
        "Commit the rows before the fix, run them there and record the failing run as a"
        " `- test` receipt",
        "On any other unit, a refuted requirement gets a failing test in the unit's own test file.",
    ):
        assert phrase in rows, phrase
    auditor = flatten((REPO_ROOT / "agents" / "auditor.md").read_text(encoding="utf-8"))
    item5 = auditor.split("5. **Extend the corpus, not the prose**", 1)[1].split("Return", 1)[0]
    assert (
        "every reproduction you or the operator record on a file of the table-diff list lands"
        " in `tests/adversarial/` as a named row before the fix is accepted" in item5
    )
    audit = flatten((REPO_ROOT / "skills" / "audit" / "SKILL.md").read_text(encoding="utf-8"))
    step8 = audit.split("8. Per-finding step.", 1)[1].split("### Verdict", 1)[0]
    assert (
        '"Add each reproduction as a named row of the matching module under'
        ' `tests/adversarial/` in your worktree, in a commit before the fix."' in step8
    )


def test_a_local_url_is_the_one_web_address_a_decision_brief_may_carry() -> None:
    # 0164: the dev server question names the site; any other web address is still refused.
    from lib.briefs import SITE_HELP, ask_problems, brief_problems

    good = "Question: Open http://localhost:5173 in your browser. Does the scene load?"
    assert brief_problems(good) == []
    assert brief_problems("Question: Open http://localhost:5173/x?y#z now?") == []
    assert brief_problems("Question: Open http://localhost:5173/play?v=1.2 now?") == []
    assert brief_problems("Question: Open https://127.0.0.1:8080/a/b now?") == []
    assert brief_problems("Question: Open `http://localhost:5173` now?") == []
    # 0254: a path with no :// is the project's own name and passes.
    assert brief_problems("Question: Should src/map/loader.py and a/b change?") == []
    # L3: the path or query never carries another url, a host and path, or a user part.
    for url in (
        "http://example.com",
        "file:///tmp/x",
        "http://localhost.evil.com/a",
        "http://localhost:5173/?u=https://evil.com",
        "http://localhost:5173/a@evil.com",
        "http://localhost:5173?u=evil.com/x",
        "`https://example.com/x`",
    ):
        bare = url.strip("`")
        want = f"Question carries the web address {bare}. {SITE_HELP}"
        assert brief_problems(f"Question: Open {url} now?") == [want], url
        context = f"Question: Ready?\nContext: The site is at {url} today."
        assert brief_problems(context) == [want.replace("Question", "Context", 1)], url
        label = f"Question: Ready?\nOptions:\n- Open {url}: opens it."
        assert brief_problems(label) == [want.replace("Question", "Option label", 1)], url
        ask = f"Anchor: The site is {url}.\nQuestion: Ready\nChoices:\nA. Open it: at {url}."
        assert ask_problems(ask) == [
            want.replace("Question", "Anchor", 1),
            want.replace("Question", "Choice A", 1),
        ], url


def test_the_verifier_prints_its_claims_in_one_call_and_runs_in_the_foreground() -> None:
    # 0230: one claims call per claims list; every command in the foreground.
    head = _body("You are the Verifier.", "Inputs:")
    assert (
        "Run the test run and every other command in the foreground, never as a background task,"
        " so the reply is one turn and the main session is woken once." in head
    )
    step3 = _body("3. Print every range you judge", "4. Class every claim")
    assert "in one call per claims list, the script of the prompt's `Claims:` line" in step3
    assert (
        "`python3 <plugin root>/scripts/daedalus_claims.py --worktree <unit worktree> --branch"
        " <branch> --ranges <file>:<first>-<last>[,...]`" in step3
    )
    assert "heads it `== <file>:<first>-<last> ==`" in step3
    assert "call it again only for ranges you find while judging" in step3
    jail = _body("The jail passes these for the verifier:", "The jail refuses these:")
    assert "its three options once each in that order and no other word" in jail


def test_a_rows_unit_runs_the_rows_file_alone() -> None:
    # 0230: the rows file is the one test run; the full suite is judged from the receipts.
    step5 = _body("5. Receipts (pin RCP -> VER)", "6. Clause numbers")
    assert (
        "On a unit whose brief carries a `Rows:` line, the one test run is the rows file alone;"
        " the full suite is the coder's receipt, judged from the receipts block and never rerun."
        " A unit without a `Rows:` line keeps the run above." in step5
    )
    skill = flatten(VERIFY_SKILL.read_text(encoding="utf-8"))
    rows = skill.split("Rows pass (0228).", 1)[1].split("Hunt pass (227).", 1)[0]
    assert (
        "On a unit with a `Rows:` line the test run is the rows file alone: the full suite is the"
        " coder's receipt, judged from the receipts block and never rerun by the verifier." in rows
    )
    assert "as your one test run, in the foreground, and judge each row's result" in rows
    dispatch = skill.split("4. Dispatch.", 1)[1].split("Rows pass (0228).", 1)[0]
    assert "the line `Claims: python3 ${CLAUDE_PLUGIN_ROOT}/scripts/daedalus_claims.py`" in dispatch


def test_the_coder_runs_its_suite_in_the_foreground() -> None:
    # 0230: a background suite wakes the main session twice.
    coder = flatten((REPO_ROOT / "agents" / "coder.md").read_text(encoding="utf-8"))
    step6 = coder.split("6. Finish with receipts", 1)[1].split("## Project priorities", 1)[0]
    assert (
        "Run every suite command in the foreground, never as a background task, so the main"
        " session is woken once; a background suite wakes it twice." in step6
    )
