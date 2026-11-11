# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

from tests.conftest import REPO_ROOT
from tests.helpers import TABLE_DIFF_PATHS, table_diff_list
from tests.skill_helpers import (
    ASSETS_CMD,
    _flat,
    _phase_step,
    _section,
)


def test_audit_with_no_decisions_file_named_skips_the_ledger_step() -> None:
    # 0247: the audit phase ends with no ledger step, no ledger question and no error.
    audit = _flat(REPO_ROOT / "skills" / "audit" / "SKILL.md")
    step = audit.split("9. `[VERDICT: APPROVED] tip=<sha>`", 1)[1].split("### Recovery", 1)[0]
    rule = step.split("- No decisions file named (0247):", 1)[1].split(" - Codes:", 1)[0]
    for part in (
        "Skip the codes, the Charter ledger check, the charter-docs dispatch and the ledger record",
        "ask the operator nothing about decisions",
        "the verdict record follows the approved verdict directly",
    ):
        assert part in rule, part


def test_build_train_keeps_dirty_trees_on_the_train_branch() -> None:
    # Ruling 1, R4-I1: test_stop_keeps_a_dirty_charter and test_stop_keeps_an_uncommitted_contract.
    phase3 = _phase_step("audit", 9)
    dirty = phase3.split("   - Charter ledger:", 1)[1].split("\n", 1)[0]
    assert "the stop keeps the Charter on `daedalus/<train-id>` while it is dirty" in dirty
    assert "the run resumes at this step" in dirty
    assert "Any other reply is off its contract." in phase3


def test_audit_judges_read_the_merged_diff_without_the_asset_files() -> None:
    # 0192: one assets run; every content diff and stat carries the tail, a name list never.
    text = " ".join((REPO_ROOT / "skills" / "audit" / "SKILL.md").read_text("utf-8").split())
    intro = _section(text, "Asset exclusion (0192).", "### Compliance rulebooks")
    assert f"Before the first judge, run {ASSETS_CMD}." in intro
    assert "every content diff and `--stat` command of this phase ends with it" in intro
    assert "a `--name-only` list never carries it" in intro
    assert "Every auditor dispatch carries the `Assets:`" in intro
    # H1, 0128: a source ending is never excluded; a source file under a root is a finding.
    assert "A file with a source ending is never excluded." in intro
    assert "Run it again before each later auditor round" in intro
    auditor_text = " ".join((REPO_ROOT / "agents" / "auditor.md").read_text("utf-8").split())
    assert "Each `Asset root source:` line names a source file under an asset root" in (
        auditor_text
    )
    assert "and file it as a finding, because an asset root is no place for source" in (
        auditor_text
    )
    short = _section(text, "### Short form", "## ")
    assert "With an asset tail, the `--stat` command ends with it" in short
    auditor = " ".join((REPO_ROOT / "agents" / "auditor.md").read_text("utf-8").split())
    assert "the stat command ends with its tail" in auditor
    assert "the name list never carries the tail" in auditor
    specialist = (REPO_ROOT / "packs" / "judges" / "frameworks.md").read_text("utf-8")
    assert "end the diff command with that tail exactly as given" in " ".join(specialist.split())


def test_audit_names_three_forms_and_the_table_diff_trigger() -> None:
    # 0232: full, short and table-diff forms; the trigger is a file list the diff can test.
    text = " ".join((REPO_ROOT / "skills" / "audit" / "SKILL.md").read_text("utf-8").split())
    assert (
        "in one of three forms: the full procedure, the short form for a small change, and"
        " the table-diff form for a change to the jail or a command parser" in text
    )
    for path in TABLE_DIFF_PATHS:
        assert (REPO_ROOT / path).exists(), path
    form = _section(text, "### Table-diff form", "### A rejected round")
    assert "Run `git diff --name-only <base sha>...daedalus/<train-id>`." in form
    assert f"names any of {table_diff_list()}." in form
    assert "Such a change never takes the short form." in form
    assert "no path of the table-diff list below, and no protected path" in text
    assert "Put a `Form: table diff` line in the auditor's dispatch of step 5." in form
    assert "the short form and the table-diff form skip it" in text
    for phrase in (
        "The auditor runs the adversarial corpus on the merged tip in the audit worktree. "
        "Every failing row is a blocking finding.",
        "`Table diff: <table> | <added, widened, narrowed or removed> | <row> | <corpus row "
        "that pins it>`",
        "the role table and the option sets of `scripts/lib/admit.py`",
        "`_GIT_GRAMMAR` in `scripts/lib/jail.py`, `READ_GIT_GRAMMAR` in "
        "`scripts/checks/read_only_bash.py`",
        "The auditor judges each added or widened row and names each removed row. An added or "
        "widened row with no corpus row is a blocking finding.",
        "is a claim to check, never the table: the auditor derives its own from the diff.",
        "It drops the rank by readers, the reachable scope and the hunt lines.",
    ):
        assert phrase in form, phrase
