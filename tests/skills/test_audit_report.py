# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

from tests.conftest import REPO_ROOT
from tests.skill_helpers import (
    _SCRIPT_REF,
)


def test_audit_report_names_its_scripts() -> None:
    text = (REPO_ROOT / "skills" / "audit-report" / "SKILL.md").read_text(encoding="utf-8")
    names = set(_SCRIPT_REF.findall(text))
    assert {"audit_report.py", "verify_audit_chain.py"} <= names


def test_audit_report_saves_without_asking() -> None:
    # 0252: a settings file naming the docs folder decides the save; no yes-or-no question.
    text = (REPO_ROOT / "skills" / "audit-report" / "SKILL.md").read_text(encoding="utf-8")
    assert "audit_report.py --session <session> --save" in text
    assert "Render this session's report again" not in text
    assert "(yes/no)" not in text and "offer to create" not in text
    assert "no docs folder is set" in text
