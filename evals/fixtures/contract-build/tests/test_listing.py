# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from storefront.listing import render  # noqa: E402


class RenderTest(unittest.TestCase):
    def test_name_and_sku(self) -> None:
        self.assertEqual(render("A1", "Lamp"), "Lamp (A1)")


if __name__ == "__main__":
    unittest.main()
