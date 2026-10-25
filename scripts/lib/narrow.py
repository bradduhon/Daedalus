# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# W1.3: one set of readers that narrow parsed JSON values to typed Python values.
# A value of the wrong type reads as the empty value or the default; nothing raises.
from __future__ import annotations

from collections.abc import Mapping


def text(block: Mapping[str, object], key: str) -> str:
    value = block.get(key)
    return value if isinstance(value, str) else ""


def _keyed(value: Mapping[object, object]) -> dict[str, object]:
    # W1.3: dict keys are coerced with str(), so every caller sees string keys.
    return {str(k): v for k, v in value.items()}


def obj(block: Mapping[str, object], key: str) -> dict[str, object]:
    value = block.get(key)
    return _keyed(value) if isinstance(value, dict) else {}


def objects(block: Mapping[str, object], key: str) -> list[dict[str, object]]:
    value = block.get(key)
    items = value if isinstance(value, list) else []
    return [_keyed(item) for item in items if isinstance(item, dict)]


def strings(value: object) -> list[str]:
    return [item for item in value if isinstance(item, str)] if isinstance(value, list) else []


def integer(block: Mapping[str, object], key: str, default: int) -> int:
    # W1.3: bool is an int subclass and is refused.
    value = block.get(key)
    return value if isinstance(value, int) and not isinstance(value, bool) else default
