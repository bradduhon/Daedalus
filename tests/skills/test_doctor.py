# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

from tests.skill_helpers import (
    DOCTOR,
    DOCTOR_CMD,
    _split,
)


def test_doctor_preapproves_only_its_own_script() -> None:
    # 0007: allowed-tools expands CLAUDE_SKILL_DIR, not CLAUDE_PLUGIN_ROOT; rule and step match.
    fields, body = _split(DOCTOR)
    assert fields["allowed-tools"] == f"Bash({DOCTOR_CMD} *)"
    assert f'`{DOCTOR_CMD} --repo "<path>"`' in body
    assert (DOCTOR.parent / "../../scripts/daedalus_doctor.py").resolve().is_file()


def test_doctor_asks_once() -> None:
    _, body = _split(DOCTOR)
    assert "Ask once, in a single message" in body and "Never ask per line." in body
    assert "Do not run any other command to investigate" in body
