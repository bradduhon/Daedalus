# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

from tests.conftest import REPO_ROOT


def test_catalog_names_the_rebind_rule_and_the_verifier_step() -> None:
    # 0086, spec 6: only the orchestrator's SendMessage rebinds; spec 5: one FIX pass.
    catalog = (REPO_ROOT / "skills" / "catalog" / "SKILL.md").read_text(encoding="utf-8")
    rules = catalog.split("## Composition rules", 1)[1].split("\n## ", 1)[0]
    assert (
        "a warm resume onto a new unit rebinds the coder only through the orchestrator's "
        "SendMessage"
    ) in rules
    assert "The main session's SendMessage does not rebind" in rules
    assert "a recipe the main session drives by hand cold-dispatches each new unit" in rules
    assert "`[VERDICT: REFUTED] <rows>` sends the coder one FIX pass" in rules
    assert "fast-forwards the audit branch" in rules and "` adversarial=pass`" in rules
    # 0231: one verifier per unit, warm only for that unit's fix pass.
    assert (
        "One verifier per unit (0231): each unit gets a fresh verifier, which stays warm only "
        "for a fix pass on the same unit."
    ) in rules
    assert "stays warm across units" not in catalog


def test_catalog_names_the_recovery_commands_and_lines() -> None:
    # pin D1 -> D5, 0119: reaudit and resume are main-session commands; ledger is the recipe's.
    catalog = (REPO_ROOT / "skills" / "catalog" / "SKILL.md").read_text(encoding="utf-8")
    rules = catalog.split("## Composition rules", 1)[1].split("\n## ", 1)[0]
    assert "`REAUDIT. <the reaudit line>`" in rules
    assert "`RESUME LEDGER. <the resume line>`" in rules
    assert "the push proof anchors on that command's record" in rules
    commands = catalog.split("## Commands and reply lines", 1)[1].split("\n## ", 1)[0]
    for line in (
        "`reaudit round=<n> tip=<40 hex>`",
        "`resume ledger train=<train-id> summary=<repo-relative path>`",
        "`ledger recorded sha=<sha> ids=<ids>`",
        "both run from the main session only",
    ):
        assert line in commands, line
