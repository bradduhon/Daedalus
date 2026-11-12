# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0257: carries the values of an older settings file onto the starter shape. A value moves only
# to the same place, only under a name the key table still has, and only when the file's own
# reader accepts the result; every other old entry is returned to be listed, never mapped.
from __future__ import annotations

import copy
import json
import re
from collections.abc import Callable
from dataclasses import dataclass

from lib import settings_edit
from lib.redact import redact, redact_text

GONE = "no longer a setting"
REFUSED = "this version refuses its value"
WITHHELD = "<value withheld>"
NAME_WITHHELD = "<name withheld>"
_PLAIN = re.compile(r"[A-Za-z0-9_-]+")


@dataclass(frozen=True)
class Moved:
    path: tuple[str, ...]
    value: object
    why: str | None = None


@dataclass
class Outcome:
    doc: dict[str, object]
    carried: list[Moved]
    dropped: list[Moved]


def _segments(key: str) -> tuple[str, ...]:
    # 0257: "a[].b" is ("a", "[]", "b"); a "<name>" segment stands for any entry name.
    out: list[str] = []
    for part in key.split("."):
        if part.endswith("[]"):
            out += [part.removesuffix("[]"), "[]"]
        else:
            out.append(part)
    return tuple(out)


def known(path: tuple[str, ...], keys: tuple[str, ...]) -> bool:
    # 0257: a name the key table holds, or a name inside the value of one of its leaf keys.
    # A list row is never walked by name, so a "[]" segment never matches a path segment.
    return any(
        all(k.startswith("<") or k == p for k, p in zip(key, path, strict=False))
        for key in map(_segments, keys)
    )


class _Walk:
    def __init__(self, starter: dict[str, object], accepts: Callable[[object], bool]) -> None:
        self.doc: dict[str, object] = copy.deepcopy(starter)
        self.accepts = accepts
        self.carried: list[Moved] = []
        self.dropped: list[Moved] = []

    def _try(self, path: tuple[str, ...], value: object) -> bool:
        candidate = settings_edit.with_value(self.doc, path, value)
        if not isinstance(candidate, dict) or not self.accepts(candidate):
            return False
        self.doc = candidate
        return True

    def _settle(self, path: tuple[str, ...], pending: dict[str, object]) -> None:
        # 0257: retried until nothing moves, so a value needing a sibling lands after it.
        moved = True
        while moved:
            moved = False
            for name, value in list(pending.items()):
                if self._try((*path, name), value):
                    self.carried.append(Moved((*path, name), value))
                    del pending[name]
                    moved = True

    def walk(self, path: tuple[str, ...], old: dict[str, object], keys: tuple[str, ...]) -> None:
        pending: dict[str, object] = {}
        for name, value in old.items():
            if known((*path, name), keys):
                pending[name] = value
            else:
                self.dropped.append(Moved((*path, name), value, GONE))
        self._settle(path, pending)
        for name, value in list(pending.items()):
            if isinstance(value, dict) and value:
                del pending[name]
                self.walk((*path, name), value, keys)
            elif isinstance(value, list) and value:
                del pending[name]
                self.rows((*path, name), value)
        self._settle(path, pending)
        self.dropped += [Moved((*path, n), v, REFUSED) for n, v in pending.items()]

    def rows(self, path: tuple[str, ...], old: list[object]) -> None:
        # 0257: a list carries each row the reader accepts whole, in the old order.
        present, now = settings_edit.lookup(self.doc, path)
        kept = list(now) if present and isinstance(now, list) else []
        for index, row in enumerate(old):
            if self._try(path, [*kept, row]):
                kept.append(row)
                self.carried.append(Moved((*path, f"[{index}]"), row))
            else:
                self.dropped.append(Moved((*path, f"[{index}]"), row, REFUSED))


def carry(
    old: dict[str, object],
    starter: dict[str, object],
    keys: tuple[str, ...],
    accepts: Callable[[object], bool],
) -> Outcome:
    walk = _Walk(starter, accepts)
    walk.walk((), old, keys)
    return Outcome(walk.doc, walk.carried, walk.dropped)


def _name(segment: str) -> str:
    if redact_text(segment) != segment:
        return NAME_WITHHELD
    if segment.startswith("[") or _PLAIN.fullmatch(segment):
        return segment
    return json.dumps(segment, ensure_ascii=True)


def shown_path(path: tuple[str, ...]) -> str:
    text = ""
    for segment in path:
        text += _name(segment) if segment.startswith("[") or not text else f".{_name(segment)}"
    return text


def secret_like(path: tuple[str, ...], value: object) -> bool:
    # 0257: the audit log's redaction decides; a settings file should hold no secret at all.
    leaf = next((s for s in reversed(path) if not s.startswith("[")), "")
    named = any(redact_text(s) != s for s in path)
    return named or redact({leaf: value}) != {leaf: value} or redact(value) != value


def shown_value(path: tuple[str, ...], value: object) -> str:
    if secret_like(path, value):
        return WITHHELD
    # 0257: shown whole, never cut, so a dropped value can be typed again; escaped to one line.
    return json.dumps(value, ensure_ascii=True)
