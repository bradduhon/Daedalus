# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations


def to_slug(text: str) -> str:
    return "-".join(text.lower().split())
