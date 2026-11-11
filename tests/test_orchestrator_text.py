# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

from tests.conftest import REPO_ROOT
from tests.skill_helpers import (
    _orchestrator,
    _rules,
)


def test_build_train_keeps_personas_warm() -> None:
    # 0059, 0086, C1: the warm dispatch rule sits in the whole-train rules.
    rules = _rules()
    roster = rules.split("- Warm dispatch (0086): ", 1)[1].split("\n", 1)[0]
    assert "a persona stays warm after its first use" in roster
    # spec 8: the hook rebinds a warm coder as the resume goes out.
    assert "the hook rebinds the coder to the new unit as the message goes out" in roster
    assert "The auditor stays warm only after its first verdict" in roster
    assert "goes to that coder by SendMessage as a resume" in roster
    assert "A cold coder starts only when no warm coder built a dependency of the unit." in roster
    # 0186: no agent holds the standards; the orchestrator rereads changed rule files itself.
    standards = next(ln for ln in rules.splitlines() if ln.startswith("- Standards (0186): "))
    assert "no agent holds the standards" in standards
    assert "Every later standards question reads again the rule files changed" in standards


def test_coder_bash_section_opens_with_the_credential_habit_line() -> None:
    # spec 7.1: the habit block is the first line of the coder's Bash section.
    coder = (REPO_ROOT / "agents" / "coder.md").read_text(encoding="utf-8")
    section = coder.split("## Shell rules (0022, spec 7)\n", 1)[1]
    first = section.splitlines()[0]
    assert first.startswith("- Credential stores are never read, from any path:"), first


def test_orchestrator_keeps_one_verifier_per_unit() -> None:
    # 0231: the warm rule's verifier exception and the State Block's verifier column.
    roster = _rules().split("- Warm dispatch (0086): ", 1)[1].split("\n", 1)[0]
    assert (
        "The verifier is one per unit (0231): each unit gets a fresh verifier, run in parallel"
        " inside the build phase's cap, and that verifier stays warm only for a fix pass on its"
        " own unit."
    ) in roster
    row = next(ln for ln in _orchestrator().splitlines() if ln.strip().startswith("units: "))
    assert row.rstrip().endswith("| verifier <agent id, or pending>")
