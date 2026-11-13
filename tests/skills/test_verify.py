# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

from tests.conftest import REPO_ROOT
from tests.skill_helpers import (
    _flat,
    _phase_skill,
    _verify_rows_mode,
    _verify_unit_mode,
)


def test_verify_skill_runs_rows_mode_before_the_coder() -> None:
    # 0228: the verifier writes the rows from the brief alone, before the coder starts.
    text = _flat(_phase_skill("verify"))
    assert text.index("### Rows mode") < text.index("### Unit mode")
    rows = _verify_rows_mode()
    for item in (
        "once per unit of the build-only-the-ask class",
        "before its coder is dispatched",
        "A unit outside the class skips it.",
        "Run the model command for the verifier as unit mode does (step 4).",
        "the first line `ROWS MODE.`",
        "the line `Unit worktree: <unit worktree path>`",
        "the line `Brief: <brief path>`",
        "the line `Spec: <each path the brief's Contract line names>`",
        "the line `Packs: <the brief's Packs: line>`",
        "the line `Base: <lock sha>`, the tree the rows are judged against",
        "Each row is one line `<req n> | <agent> | <admitted|refused> | <command>`.",
        "Reply with `[ROWS] n=<count>` as your first and last line and the rows between.",
    ):
        assert item in rows, item


def test_verify_skill_has_the_main_session_write_and_commit_the_rows() -> None:
    # 0228: the verifier cannot write, so the main session writes the rows file.
    rows = _verify_rows_mode()
    for item in (
        "The orchestrator hands the rows text back, and the main session writes the file.",
        "`<unit worktree>/tests/adversarial/test_<unit-slug>_rows.py`",
        "one case per row with the row text as its id",
        "`assert_denied` of `tests/adversarial/corpus.py`",
        "`decide(<hook input>, CFG).allow` from `tests/hook_chain.py`",
        "with the subject `Add the verifier's rows for <unit id> (0228)`",
        "adds the line `Rows: <that path>` to the brief file, directly after the `Packs:` line",
        "A reply whose first and last lines differ, or that reads `n=0`, is off its contract:"
        " stop and show its last 10 lines.",
    ):
        assert item in rows, item
    for path in ("corpus.py", "test_brace_glob.py"):
        assert (REPO_ROOT / "tests" / "adversarial" / path).is_file(), path
    assert (REPO_ROOT / "tests" / "hook_chain.py").is_file()


def test_verify_unit_mode_runs_the_rows_file_in_place_of_the_hunt() -> None:
    # 0228: the post-build pass judges the rows' result and hunts only over a changed row.
    unit = _flat(_phase_skill("verify")).split("### Unit mode", 1)[1].split("### Claims mode")[0]
    assert (
        "For a unit with a `Rows:` line, run the rows file as the one test run and judge each"
        " row's result; hunt again only over a row the coder's diff changed or deleted, and a"
        " changed or deleted row is a `scope` refutation unless the brief names it."
    ) in unit
    assert "A unit without a `Rows:` line keeps the hunt pass as before." in unit
    assert "the rows pass below when it carries a `Rows:` line, else the hunt pass below" in unit
    opened = unit.split("Then build the `Open:` line", 1)[1].split("4. Dispatch.", 1)[0]
    assert "the rows file of the brief's `Rows:` line" in opened


def test_verify_skill_dispatches_one_verifier_per_unit() -> None:
    # 0231: a fresh verifier per unit, in parallel under the builders cap.
    unit = _verify_unit_mode()
    for sentence in (
        "4. Dispatch. Each unit gets a fresh verifier (0231).",
        "A unit with a `Rows:` line goes to the verifier rows mode started for it, by the"
        " orchestrator's message.",
        "Before each fresh dispatch, run `python3 ${CLAUDE_PLUGIN_ROOT}/scripts/daedalus_train.py"
        " model --repo <repo> --agent verifier --unit <unit id>`",
        "The unit's class picks the verifier's model, the same model its coder gets (0267).",
        "One verifier per unit (0231, amends 0086): a later unit never goes to an earlier unit's"
        " verifier.",
        "The verifiers run in parallel, up to `limits.parallel_coders` coders plus verifiers at"
        " once, the same cap the build phase's step 1 uses.",
        "The verifier stays warm only for a fix pass on the same unit: after a `FIX.` round, the"
        " unit's next verdict goes to the verifier that refuted it, by the orchestrator's message"
        " with the same items, the `Range:` and `Place:` lines of that round's step 3 call"
        " included unchanged.",
    ):
        assert sentence in unit, sentence
    assert "The first time, run" not in unit
    assert "every later unit goes to it" not in unit
    # 0231: the route step expects the key line the merge gate selects by.
    assert (
        "The reply's second line is the key line `Unit worktree: <unit worktree path>`, copied "
        "from the dispatch; a reply without it, or naming another worktree, counts as no reply "
        "for any unit and is off its contract the same way (0231)."
    ) in unit


def test_verify_rows_mode_verifier_is_the_units_verifier() -> None:
    # 0231: the rows verifier judges the same unit's diff later.
    assert (
        "The verifier this dispatch starts is the unit's verifier from rows mode on, and it later"
        " judges the unit's diff (0231)."
    ) in _verify_rows_mode()
    uses = _flat(_phase_skill("verify")).split("## Agents it uses", 1)[1].split("## ", 1)[0]
    assert "verifier, one per unit from rows mode through its fix passes" in uses
    assert "warm across rows mode, units" not in uses


def test_verify_skill_keeps_stays_warm_only_in_the_fix_pass_sentence() -> None:
    # 0231: the warm rule survives only for a fix pass on the same unit.
    text = _flat(_phase_skill("verify"))
    assert text.count("stays warm") == 1
    sentence = text.split("stays warm", 1)[1].split(". ", 1)[0]
    assert sentence.startswith(" only for a fix pass on the same unit")
