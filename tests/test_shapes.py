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
    # 0060: the five worker shapes lead the file unchanged; the dispatcher follows them.
    data = json.loads(SHAPES.read_text(encoding="utf-8"))
    assert list(data)[:5] == ["producer", "judge", "finder", "mover", "shaper"]
    assert SHAPES.read_bytes().endswith(b"}\n")


def test_shapes_add_only_the_dispatcher() -> None:
    data = json.loads(SHAPES.read_text(encoding="utf-8"))
    assert list(data)[5:] == ["dispatcher"]


def test_only_the_dispatcher_carries_the_dispatch_gate() -> None:
    # 0060: the dispatch gate judges Agent and SendMessage, which only the dispatcher is granted.
    data = json.loads(SHAPES.read_text(encoding="utf-8"))
    carriers = [shape for shape, entries in data.items() if "dispatch_gate" in entries]
    assert carriers == ["dispatcher"]
    for entry in ("shell_tripwires", "git_push", "command_allowlist --allow train,inspect"):
        assert entry in data["dispatcher"], entry
    assert not any(e.startswith(("git_grammar", "network_tools --")) for e in data["dispatcher"])


def test_judge_shape_names_no_write_hook() -> None:
    # 0109: the auditor's audit write rides its agent file; the judge list grants no write.
    data = json.loads(SHAPES.read_text(encoding="utf-8"))
    flat = [e for entry in data["judge"] for e in (entry if isinstance(entry, list) else [entry])]
    assert not any(e.startswith(("root_writes", "unit_writes")) for e in flat)
    assert "read_only_bash" in flat
