# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from textkit import word_count  # noqa: E402


class WordCountTest(unittest.TestCase):
    def test_single_spaces(self) -> None:
        self.assertEqual(word_count("one two three"), 3)


if __name__ == "__main__":
    unittest.main()
