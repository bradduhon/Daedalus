# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

from tests.conftest import REPO_ROOT
from tests.helpers import phase_text
from tests.skill_helpers import (
    BRANCH_STOP,
    CODER_PACKS,
    PLUGIN,
    _build_step4,
    _flat,
    _phase_row,
    _phase_step,
)


def test_build_train_hands_coders_the_pick_ledger_ids() -> None:
    # 0057, 0083, C10: the ids line follows the two packet lines and precedes the worktree line.
    phase2 = phase_text("build")
    brief = phase2.split("holding: the two packet lines", 1)[1]
    assert brief.index("`Pick ledger ids:`") < brief.index("`Worktree: <path>`")
    assert brief.index("`Worktree: <path>`") < brief.index("dispatch `coder`")


def test_complete_check_requires_adversarial_pass_for_jail_check_units() -> None:
    # spec 3.3: the reply check reads the unit's changed files from git diff --name-only.
    jail = "   - Jail check units (spec 3.3)."
    complete = next(ln for ln in phase_text("build").splitlines() if ln.startswith(jail))
    assert "`git diff --name-only <lock sha>...<b>`" in complete
    for path in (
        "`scripts/checks/`",
        "`scripts/lib/jail.py`",
        "`scripts/lib/shell.py`",
        "`scripts/enforce_agent_jail.py`",
    ):
        assert path in complete, path
    assert "the line must carry ` adversarial=pass`" in complete
    assert "`python3 -m pytest tests/adversarial -q`" in complete
    assert "A second COMPLETE on the unit without it stops the run" in complete


def test_build_train_refuses_a_revision_that_does_not_raise_the_version() -> None:
    # R4-M2: N must exceed the recorded packet_version; lock refuses it too.
    phase2 = _phase_row("build", "STATUS: YIELD_CONTRACT]")
    # R5-I2: one retry, then the second non-increasing version stops.
    stop = (
        "When its `packet_version` is not greater than the recorded one, ask contract-spec once "
        "to revise and save again; a second reply that is still not greater stops the run."
    )
    assert stop in phase2
    assert phase2.index(stop) < phase2.index("`Revise contract <name> v<N>`")


def test_build_train_requires_the_reported_branch_to_be_the_created_one() -> None:
    # 0022: daedalus/<train-id> is its own ancestor and would merge as a no-op.
    complete = _phase_step("build", 7)
    compare = (
        "Branch. Compare `<b>` with the branch recorded for that unit in step 2. "
        f"A mismatch: stop with {BRANCH_STOP}"
    )
    assert compare in complete
    assert complete.index(compare) < complete.index("git merge-base --is-ancestor")
    assert "the unit's branch stays the one step 2 recorded" in complete


def test_build_train_creates_each_coder_worktree() -> None:
    phase2 = phase_text("build")
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
    assert phase2.index("daedalus_workspace.py create") < phase2.index("dispatch `coder`")


def test_build_skill_gives_a_class_unit_the_packs_line_after_hunt() -> None:
    # 227 part 2: the `Packs:` bullet follows the `Hunt:` bullet and names both packs in full.
    step4 = _build_step4()
    bullet = step4.split("- Coder packs (227). ", 1)[1]
    assert step4.index("- Hunt: ") < step4.index("- Coder packs (227). ")
    assert "one line directly after the `Hunt:` line" in bullet
    assert f"`Packs: {CODER_PACKS[0]}, {CODER_PACKS[1]}`" in bullet
    assert "written with the plugin root out in full" in bullet
    for path in CODER_PACKS:
        assert (REPO_ROOT / path.removeprefix("<plugin root>/")).is_file(), path


def test_build_skill_gives_no_packs_line_outside_the_class() -> None:
    bullet = _build_step4().split("- Coder packs (227). ", 1)[1]
    assert (
        "A unit outside the class carries no `Packs:` line unless its plan line names a pack."
    ) in bullet


def test_build_skill_hands_the_shell_semantics_pack_to_its_class_only() -> None:
    # 0226: the class pack rides the `Packs:` line only for the shell and check files.
    bullet = _build_step4().split("- Coder packs (227). ", 1)[1]
    path = "<plugin root>/packs/coder/shell-semantics/rules.md"
    assert f"the line also carries `{path}`" in bullet
    for name in (
        "scripts/lib/jail.py",
        "scripts/lib/shell.py",
        "scripts/lib/shparse.py",
        "scripts/lib/admit.py",
        "scripts/checks/",
    ):
        assert f"`{name}`" in bullet, name
    assert (REPO_ROOT / path.removeprefix("<plugin root>/")).is_file()


def test_build_skill_runs_rows_mode_after_the_packs_line() -> None:
    # 0228, 0230: a class unit gets its rows before its coder dispatch, from the dispatch lines.
    step4 = _build_step4()
    assert step4.index("- Coder packs (227). ") < step4.index("- Rows (0228). ")
    bullet = step4.split("- Rows (0228). ", 1)[1]
    for sentence in (
        "For a unit of the class, the dispatch call ends its line with `rows=needed`",
        "Run the verify phase's rows mode",
        "with those lines pasted unchanged, before the coder dispatch of step 5.",
        "It adds the `Rows:` line to the brief directly after the `Packs:` line.",
        "The coder never edits the rows file.",
    ):
        assert sentence in bullet, sentence


def test_build_skill_routes_a_unit_without_green_rows_as_refuted() -> None:
    # 0228: step 7 checks the coder's test line for the rows file before the verifier runs.
    text = _flat(REPO_ROOT / "skills" / "build" / "SKILL.md")
    step7 = text.split("7. Check each COMPLETE line", 1)[1].split("8. A coder that", 1)[0]
    hunt, rows, hand = (
        step7.index("- Build-only-the-ask units (227)."),
        step7.index("- Rows (0228). "),
        step7.index("- Then hand the unit to the verify phase"),
    )
    assert hunt < rows < hand
    check = step7[rows:hand]
    assert (
        "For a unit with a `Rows:` line, the coder's receipts carry a `- test` line for that"
        " rows file with zero failures."
    ) in check
    assert 'routed as a REFUTED with one `code` row "rows file not green"' in check


def test_build_schedule_shares_the_cap_with_verifiers() -> None:
    # 0231, 0245: coders and verifiers share limits.parallel_coders.
    text = _flat(REPO_ROOT / "skills" / "build" / "SKILL.md")
    step1 = text.split("1. Schedule.", 1)[1].split("2. ", 1)[0]
    assert (
        "At most `limits.parallel_coders` coders plus verifiers run at once (the config setting,"
        " default 5, 0231). A verifier counts from its dispatch to its verdict."
    ) in step1
    hand = text.split("- Then hand the unit to the verify phase", 1)[1].split("8. ", 1)[0]
    assert "The unit gets its own verifier, inside the cap of step 1 (0231)." in hand
