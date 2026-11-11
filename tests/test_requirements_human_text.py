# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

from tests.conftest import REPO_ROOT
from tests.skill_helpers import (
    HUMAN_TEXT_RULE,
)


def test_requirements_carry_the_human_text_rule() -> None:
    text = (REPO_ROOT / "docs" / "project-requirements.md").read_text(encoding="utf-8")
    section = text.split("\n## Text a person reads\n", 1)[1].split("\n## ", 1)[0]
    assert HUMAN_TEXT_RULE in section
