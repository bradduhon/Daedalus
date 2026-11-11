# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

from tests.helpers import phase_text
from tests.skill_helpers import (
    _phase_step,
)


def test_build_train_records_picks_before_any_coder() -> None:
    # 0057, C9: both ledger locations record picks before a coder starts.
    step1 = _phase_step("plan", 12)
    assert (
        "With the decisions file in the local docs folder (`local_docs_folder`, the "
        "`<charter_root>` of the commands), record the picks right after the last pick"
    ) in step1
    # 0247: with no decisions file named, nothing records the picks and nothing is asked.
    assert "No decisions file named (0247): when the ledger line reads `decisions: none`" in step1
    assert "With a repo-local ledger, record the picks right after the step 14 lock" in step1
    assert "No coder starts before `[STATUS: COMMITTED]`." in step1
    step3 = _phase_step("plan", 14)
    assert "With a repo-local ledger and picks from step 12, record the picks now" in step3


def test_build_train_phase1_has_no_branch_switch() -> None:
    # 0024, C11: the lock script owns every branch move in the plan phase.
    phase1 = phase_text("plan")
    assert "git switch" not in phase1 and "git checkout" not in phase1
