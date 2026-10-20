# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# spec 8, pin B2: the failure each control prevents and the test that goes red if its premise falls.
# One fragment per unit under scripts/checks/controls/, keyed "<module stem>.<R_ constant>" or
# "checks/<script stem>"; load() merges them and refuses a key named twice.
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

CONTROLS_DIR = Path(__file__).resolve().parents[1] / "checks" / "controls"
HOOK_PREFIX = "checks/"
FIELDS = ("failure", "premise_test")
# 6.1: these record prefixes are decided inside enforce_agent_jail itself, not a checks script.
_JAIL_HOOKS = frozenset({"jail", "config", "router"})
_NEXT = "Next: fix the fragment under scripts/checks/controls/ and rerun."


class ControlsError(Exception):
    pass


@dataclass(frozen=True)
class Control:
    failure: str
    premise_test: str


def _unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
    out: dict[str, object] = {}
    for key, value in pairs:
        if key in out:
            raise ControlsError(f"key {key!r} is named twice")
        out[key] = value
    return out


def _row(name: str, key: str, value: object) -> Control:
    if not isinstance(value, dict) or sorted(value) != sorted(FIELDS):
        raise ControlsError(f"{name}: {key} must hold exactly {', '.join(FIELDS)}. {_NEXT}")
    fields = [value[f] for f in FIELDS]
    if not all(isinstance(f, str) for f in fields):
        raise ControlsError(f"{name}: {key} fields must be strings. {_NEXT}")
    return Control(*fields)


def load(folder: Path = CONTROLS_DIR) -> dict[str, Control]:
    rows: dict[str, Control] = {}
    origin: dict[str, str] = {}
    for path in sorted(folder.glob("*.json")):
        try:
            doc = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_unique)
        except (OSError, UnicodeDecodeError, ValueError, ControlsError) as exc:
            raise ControlsError(f"{path.name}: {exc}. {_NEXT}") from exc
        if not isinstance(doc, dict):
            raise ControlsError(f"{path.name}: the fragment is not a JSON object. {_NEXT}")
        for key, value in doc.items():
            if key in rows:
                raise ControlsError(f"{key} is in both {origin[key]} and {path.name}. {_NEXT}")
            rows[key] = _row(path.name, key, value)
            origin[key] = path.name
    return rows


def hook_key(hook: str) -> str:
    # 0105: an ask row names the same hook as its blocks.
    name = hook.removesuffix(" (ask)")
    return f"{HOOK_PREFIX}enforce_agent_jail" if name in _JAIL_HOOKS else f"{HOOK_PREFIX}{name}"


def failure_line(hook: str, rows: dict[str, Control]) -> str:
    row = rows.get(hook_key(hook))
    return f"failure: {row.failure}" if row is not None and row.failure.strip() else "failure: none"
