# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations


def build_headers(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}
