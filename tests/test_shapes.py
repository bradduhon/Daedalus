# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0044: scripts/checks/shapes.json names each shape's hooks; every name is a shipped script.
from __future__ import annotations

import json

from tests.conftest import SCRIPTS_DIR

SHAPES = SCRIPTS_DIR / "checks" / "shapes.json"


def _entries() -> list[str]:
    data = json.loads(SHAPES.read_text(encoding="utf-8"))
    flat: list[str] = []
    for entries in data.values():
        for entry in entries:
            flat += entry if isinstance(entry, list) else [entry]
    return flat


def test_shape_lists_name_only_shipped_hooks() -> None:
    names = {entry.split()[0] for entry in _entries()}
    assert names, "shapes.json names no hooks"
    for name in sorted(names):
        assert (SCRIPTS_DIR / "checks" / f"{name}.py").is_file(), name


def test_shapes_name_the_five_shapes() -> None:
    data = json.loads(SHAPES.read_text(encoding="utf-8"))
    assert list(data) == ["producer", "judge", "finder", "mover", "shaper"]
    assert SHAPES.read_bytes().endswith(b"}\n")
