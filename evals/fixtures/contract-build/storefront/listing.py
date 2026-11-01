# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations


def render(sku: str, name: str) -> str:
    return f"{name} ({sku})"
