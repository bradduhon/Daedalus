# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

from tests.conftest import REPO_ROOT


def test_token_report_saves_without_asking() -> None:
    # 0252: a settings file naming the docs folder decides the save; no yes-or-no question.
    text = (REPO_ROOT / "skills" / "token-report" / "SKILL.md").read_text(encoding="utf-8")
    assert "report --run <id> --save" in text
    assert "Save this run's token table" not in text
    assert "(yes/no)" not in text and "offer to create it" not in text
    assert "in the plugin data folder" in text and "`history` reads that folder" in text
