# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

from pathlib import Path

from tests.test_live_plugin import RECEIPT_NAME, _append_result, receipt_path


def test_receipt_uses_private_verification_when_present(tmp_path: Path) -> None:
    private = tmp_path / "docs" / "private" / "verification"
    private.mkdir(parents=True)
    assert receipt_path(tmp_path) == private / RECEIPT_NAME


def test_receipt_falls_back_to_ignored_scratch_dir(tmp_path: Path) -> None:
    expected = tmp_path / "docs" / ".tmp" / "verification" / RECEIPT_NAME
    assert receipt_path(tmp_path) == expected


def test_append_creates_the_fallback_receipt(tmp_path: Path) -> None:
    _append_result("- first", tmp_path)
    _append_result("- second", tmp_path)
    text = receipt_path(tmp_path).read_text()
    assert text == "## Appended results\n- first\n- second\n"


def test_append_keeps_an_existing_private_receipt(tmp_path: Path) -> None:
    private = tmp_path / "docs" / "private" / "verification"
    private.mkdir(parents=True)
    (private / RECEIPT_NAME).write_text("# Receipt\n")
    _append_result("- first", tmp_path)
    assert (private / RECEIPT_NAME).read_text() == "# Receipt\n\n## Appended results\n- first\n"
