#!/usr/bin/env python3
# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0252: thin entry point for the Developer Profile store; all logic is in lib/developer_profile.py.
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from lib.developer_profile import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
