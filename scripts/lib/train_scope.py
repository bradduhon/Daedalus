# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# Standard library only: the jail's entry script imports this before the rest of lib.
from __future__ import annotations

# 0035: the begin command's own hook record is the one write that may create the data dir.
BEGIN_NEEDLE = "daedalus_workspace.py begin"
