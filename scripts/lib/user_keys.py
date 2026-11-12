# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0260: a settings key that starts with an underscore is the user's own; no reader looks at it.
from __future__ import annotations

from collections.abc import Iterable

USER_KEY_CLAUSE = "a key that starts with an underscore is your own and is ignored"
USER_KEY_NOTE = f"A {USER_KEY_CLAUSE[2:]}."


def is_user_key(key: object) -> bool:
    # 0260: the one rule; JSON has no comments, so a user key may hold any value.
    return isinstance(key, str) and key.startswith("_")


def without_user_keys(block: dict[str, object]) -> dict[str, object]:
    return {key: value for key, value in block.items() if not is_user_key(key)}


def unknown_keys(block: dict[str, object], known: Iterable[str]) -> list[str]:
    # 0260: the keys a reader refuses; user keys are never among them.
    names = set(known)
    return sorted(str(key) for key in block if key not in names and not is_user_key(key))
