# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0242: one key of an existing JSON settings file, changed in place. The new value's text
# replaces the old value's text, so every other byte stays; the write is a temp file and a rename.
from __future__ import annotations

import copy
import json
import os
import stat
from dataclasses import dataclass, field
from pathlib import Path

from lib import atomic

MAX_BYTES = 1024 * 1024
_WS = " \t\n\r"
_DECODER = json.JSONDecoder()
_BOM = chr(0xFEFF)


class EditError(ValueError):
    pass


def _unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
    # 0242: a key written twice has no single value to keep, so the file is refused.
    out: dict[str, object] = {}
    for key, value in pairs:
        if key in out:
            raise EditError(f"holds the key {key!r} twice")
        out[key] = value
    return out


def parse(text: str) -> object:
    try:
        return json.loads(text.removeprefix(_BOM), object_pairs_hook=_unique)
    except EditError:
        raise
    except (ValueError, RecursionError) as exc:
        raise EditError(f"is not valid JSON ({getattr(exc, 'msg', type(exc).__name__)})") from exc


def read_text(path: Path, limit: int = MAX_BYTES) -> str:
    # 0242: opened as the personal file's reader opens it: never through a link, never blocking.
    atomic.refuse_links(path)
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except OSError as exc:
        raise EditError(f"could not be opened ({exc.strerror})") from exc
    if not stat.S_ISREG(os.fstat(fd).st_mode):
        os.close(fd)
        raise EditError("is not a regular file")
    with os.fdopen(fd, "rb") as handle:
        data = handle.read(limit + 1)
    if len(data) > limit:
        raise EditError(f"is larger than {limit // 1024} KiB")
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise EditError("is not UTF-8 text") from exc


def lookup(doc: object, path: tuple[str, ...]) -> tuple[bool, object]:
    for segment in path:
        if not isinstance(doc, dict) or segment not in doc:
            return False, None
        doc = doc[segment]
    return True, doc


def same(first: object, second: object) -> bool:
    # 0242: JSON equality, so true never equals 1 and key order never matters.
    return json.dumps(first, sort_keys=True) == json.dumps(second, sort_keys=True)


def _skip(text: str, index: int) -> int:
    while index < len(text) and text[index] in _WS:
        index += 1
    return index


@dataclass
class _Object:
    start: int
    end: int
    # (key, key start, value start, value end) per member, in file order.
    members: list[tuple[str, int, int, int]] = field(default_factory=list)


def _object_at(text: str, start: int) -> _Object:
    found = _Object(start, start)
    index = _skip(text, start + 1)
    if text[index] == "}":
        found.end = index
        return found
    while True:
        key, after = _DECODER.raw_decode(text, index)
        if not isinstance(key, str):
            raise EditError("holds an object member with no name")
        value_start = _skip(text, _skip(text, after) + 1)
        _, value_end = _DECODER.raw_decode(text, value_start)
        found.members.append((key, index, value_start, value_end))
        index = _skip(text, value_end)
        if text[index] == "}":
            found.end = index
            return found
        index = _skip(text, index + 1)


def _dump(value: object) -> str:
    return json.dumps(value, ensure_ascii=False)


def _nest(path: tuple[str, ...], value: object) -> object:
    for segment in reversed(path):
        value = {segment: value}
    return value


def _insert(text: str, obj: _Object, key: str, value: object) -> str:
    member = f"{_dump(key)}: {_dump(value)}"
    if not obj.members:
        return text[: obj.start + 1] + member + text[obj.end :]
    _, key_start, _, value_end = obj.members[-1]
    line_start = text.rfind("\n", 0, key_start) + 1
    indent = text[line_start:key_start]
    # 0242: a member on its own line gets a new line at the same indent; inline stays inline.
    multiline = line_start > obj.start and not indent.strip(" \t")
    sep = ",\n" + indent if multiline else ", "
    return text[:value_end] + sep + member + text[value_end:]


def splice(text: str, path: tuple[str, ...], value: object) -> str:
    # 0242: the text of one value is replaced or one member inserted; nothing else is reprinted.
    start = _skip(text, len(_BOM) if text.startswith(_BOM) else 0)
    if text[start : start + 1] != "{":
        raise EditError("is not one JSON object")
    obj = _object_at(text, start)
    for depth, segment in enumerate(path):
        rest = path[depth + 1 :]
        member = next((m for m in obj.members if m[0] == segment), None)
        if member is None:
            return _insert(text, obj, segment, _nest(rest, value))
        _, _, value_start, value_end = member
        if not rest:
            return text[:value_start] + _dump(value) + text[value_end:]
        if text[value_start] == "{":
            obj = _object_at(text, value_start)
        elif text[value_start:value_end] == "null":
            return text[:value_start] + _dump(_nest(rest, value)) + text[value_end:]
        else:
            where = ".".join(path[: depth + 1])
            raise EditError(f"holds {where} as a value that is not an object")
    raise EditError("names no key")


def with_value(doc: object, path: tuple[str, ...], value: object) -> object:
    # 0242: the document splice must produce, built the plain way to cross-check the text.
    out = copy.deepcopy(doc)
    node = out
    for segment in path[:-1]:
        if not isinstance(node, dict):
            raise EditError("is not one JSON object")
        if not isinstance(node.get(segment), dict):
            node[segment] = {}
        node = node[segment]
    if not isinstance(node, dict):
        raise EditError("is not one JSON object")
    node[path[-1]] = value
    return out


def write(path: Path, before: str, text: str, limit: int = MAX_BYTES) -> None:
    # 0242: a file changed since it was read is refused, so a second writer's change is not lost.
    if read_text(path, limit) != before:
        raise EditError("changed while this command ran")
    atomic.write_atomic(path, text)
