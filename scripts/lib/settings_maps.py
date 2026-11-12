# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0264: a schema change ships a map. To add one: raise the kind's current number in KINDS, append a
# Step(from, from + 1, rows) to its steps, and record the new key-table hash in FINGERPRINTS.
from __future__ import annotations

import copy
from collections.abc import Callable
from dataclasses import dataclass

SCHEMA_KEY = "schema"
Path = tuple[str, ...]


@dataclass(frozen=True)
class Move:
    old: Path
    new: Path


@dataclass(frozen=True)
class Drop:
    path: Path
    why: str


@dataclass(frozen=True)
class Set:
    path: Path
    value: object


@dataclass(frozen=True)
class Convert:
    path: Path
    func: str


Row = Move | Drop | Set | Convert


@dataclass(frozen=True)
class Step:
    start: int
    end: int
    rows: tuple[Row, ...]


@dataclass(frozen=True)
class Kind:
    current: int
    steps: tuple[Step, ...]


# 0264: the three settings files by form; schema 1 is the first, so every list is empty.
KINDS: dict[str, Kind] = {
    "manifest": Kind(1, ()),
    "config": Kind(1, ()),
    "operator": Kind(1, ()),
}
# 0264: small pure functions a Convert row names; each maps one old value to the new one.
CONVERTERS: dict[str, Callable[[object], object]] = {}
# 0264: per form and schema number, the hash of that schema's key table (project_keys.fingerprint).
FINGERPRINTS: dict[str, dict[int, str]] = {
    "manifest": {1: "88107e513568dbdc04c4a82e139cafa545a53f1d11d7c0152cce403173d98e80"},
    "config": {1: "bdc56bcde7810f1a4ecf06bff5dd033f03b5621cde6ba2c5bc097d426a6bd1a0"},
    "operator": {1: "229b044e0ee950a61af48e9a66f2ae3ab6478ee769b1f5dc4a762eb4e47b9fa9"},
}


class SchemaError(ValueError):
    pass


@dataclass(frozen=True)
class Action:
    start: int
    end: int
    verb: str
    text: str


@dataclass(frozen=True)
class Upgrade:
    doc: dict[str, object]
    actions: list[Action]


def current(form: str) -> int:
    return KINDS[form].current


def number_problem(value: object, top: int) -> str | None:
    # 0264: the plain refusal for a schema number the reader will not accept, else None.
    shown = repr(value)[:40]
    if isinstance(value, bool) or not isinstance(value, int):
        return (
            f"schema must be a whole number, and it is {shown}. "
            f"Next: set schema to {top}, or remove the key."
        )
    if value < 1:
        return (
            f"schema is {value}, and the lowest schema number is 1. "
            f"Next: set schema to a number from 1 to {top}, or remove the key."
        )
    if value > top:
        return (
            f"schema is {value}, but this version of Daedalus reads schema {top} at most, so a "
            "newer version wrote this file. Next: update the Daedalus plugin, then run it again."
        )
    return None


def _split(path: str) -> Path:
    return tuple(path.split("."))


def _get(doc: object, path: Path) -> tuple[bool, object]:
    node = doc
    for part in path:
        if not isinstance(node, dict) or part not in node:
            return False, None
        node = node[part]
    return True, node


def _put(doc: dict[str, object], path: Path, value: object) -> None:
    node = doc
    for part in path[:-1]:
        child = node.setdefault(part, {})
        if not isinstance(child, dict):
            raise SchemaError(
                f"a map row needs {'.'.join(path)}, but {part} holds a value, not an object. "
                "Next: report this with the file; the old file is unchanged."
            )
        node = child
    node[path[-1]] = value


def _remove(doc: dict[str, object], path: Path) -> None:
    parents: list[dict[str, object]] = [doc]
    for part in path[:-1]:
        parents.append(parents[-1][part])  # type: ignore[arg-type]
    del parents[-1][path[-1]]
    # 0264: an object the removal left empty goes with it, so a moved group leaves no shell.
    for parent, part in zip(reversed(parents[:-1]), reversed(path[:-1]), strict=True):
        if parent[part]:
            break
        del parent[part]


def _step_from(kind: Kind, start: int) -> Step:
    found = [s for s in kind.steps if s.start == start]
    if len(found) != 1 or found[0].end != start + 1:
        raise SchemaError(
            f"this version has no map from schema {start} to schema {start + 1}, so the file "
            f"cannot be upgraded. Next: report this; the file is unchanged."
        )
    return found[0]


def _apply(
    doc: dict[str, object], step: Step, converters: dict[str, Callable[[object], object]]
) -> list[Action]:
    actions: list[Action] = []

    def note(verb: str, text: str) -> None:
        actions.append(Action(step.start, step.end, verb, text))

    for row in step.rows:
        if isinstance(row, Move):
            old, new = ".".join(row.old), ".".join(row.new)
            there, value = _get(doc, row.old)
            if not there:
                continue
            if _get(doc, row.new)[0]:
                raise SchemaError(
                    f"schema {step.start} to {step.end} moves {old} to {new}, but {new} is "
                    f"already in the file. Next: remove {new} or {old} from the file by hand, "
                    "then run the same command again."
                )
            _remove(doc, row.old)
            _put(doc, row.new, value)
            note("move", f"{old} -> {new}")
        elif isinstance(row, Drop):
            if _get(doc, row.path)[0]:
                _remove(doc, row.path)
                note("drop", f"{'.'.join(row.path)} ({row.why})")
        elif isinstance(row, Set):
            if not _get(doc, row.path)[0]:
                _put(doc, row.path, copy.deepcopy(row.value))
                note("set", f"{'.'.join(row.path)} = {row.value!r}")
        else:
            there, value = _get(doc, row.path)
            func = converters.get(row.func)
            if func is None:
                raise SchemaError(
                    f"schema {step.start} to {step.end} names a converter {row.func!r} that "
                    "this version does not have. Next: report this; the file is unchanged."
                )
            if there:
                try:
                    converted = func(value)
                except (ValueError, TypeError) as exc:
                    raise SchemaError(
                        f"the value of {'.'.join(row.path)} cannot be converted to schema "
                        f"{step.end} ({exc}). Next: correct that value by hand, then run the "
                        "same command again."
                    ) from exc
                _put(doc, row.path, converted)
                note("convert", f"{'.'.join(row.path)} ({row.func})")
    return actions


def upgrade(
    doc: dict[str, object],
    form: str,
    accepts: Callable[[object], bool],
    kinds: dict[str, Kind] = KINDS,
    converters: dict[str, Callable[[object], object]] = CONVERTERS,
) -> Upgrade:
    # 0264: every step from the file's number to the current one, in order; writes nothing.
    kind = kinds[form]
    if SCHEMA_KEY not in doc:
        raise SchemaError(
            "the file holds no schema number, so no map applies. Next: use the replace form "
            "without a map, which carries values whose names are unchanged."
        )
    problem = number_problem(doc[SCHEMA_KEY], kind.current)
    if problem is not None:
        raise SchemaError(problem)
    number = doc[SCHEMA_KEY]
    assert isinstance(number, int)
    out = copy.deepcopy(doc)
    actions: list[Action] = []
    for start in range(number, kind.current):
        step = _step_from(kind, start)
        actions += _apply(out, step, converters)
        out[SCHEMA_KEY] = step.end
    if not accepts(out):
        raise SchemaError(
            "the upgraded file failed its own check, so nothing was written. Next: report this "
            "with the plan's lines; the old file is unchanged."
        )
    return Upgrade(out, actions)
