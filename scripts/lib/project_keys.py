# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0076: the keys the manifest and config readers accept, as JSON paths, derived from the
# readers' own dataclasses; the setup script and the README key reference test both read them.
from __future__ import annotations

from dataclasses import fields

from lib.config import LEDGER_FIELDS, Config, LedgerDecl, PolicyDecl, StandardsSource
from lib.manifest import (
    FEATURE_KEYS,
    MANIFEST_NAME,
    NARROWING_KEYS,
    STACK_COMMANDS,
    Features,
    Manifest,
)

MANIFEST_FILE = MANIFEST_NAME
CONFIG_FILE = ".claude/daedalus/config.json"
# 0054, 0073, B2: the JSON object each flat Manifest field is read from.
_MANIFEST_PARENT = {key: "jail_narrowing" for key in NARROWING_KEYS} | {
    key: "stack" for key in STACK_COMMANDS
}
# 0004: lib.ledger reads a manifest ledger block with the config ledger's four fields.
MANIFEST_LEDGER = "ledger"
_Nested = type[LedgerDecl] | type[PolicyDecl] | type[StandardsSource]
_CONFIG_NESTED: dict[str, tuple[str, _Nested]] = {
    "ledger": ("ledger", LedgerDecl),
    "policy": ("policy", PolicyDecl),
    "standards_sources": ("standards_sources[]", StandardsSource),
}


def manifest_keys() -> tuple[str, ...]:
    keys: list[str] = []
    for item in fields(Manifest):
        if item.name == "features":
            keys.extend(f"features.{key}" for key in FEATURE_KEYS)
        elif item.name in _MANIFEST_PARENT:
            keys.append(f"{_MANIFEST_PARENT[item.name]}.{item.name}")
        else:
            keys.append(item.name)
    keys.extend(f"{MANIFEST_LEDGER}.{key}" for key in LEDGER_FIELDS)
    return tuple(keys)


def _json(value: object) -> object:
    if isinstance(value, tuple):
        return list(value)
    if value is None or isinstance(value, bool | int | str):
        return value
    raise TypeError(f"a reader default of type {type(value).__name__} has no JSON form")


def starter_manifest() -> dict[str, object]:
    # 0076: every feature off (a switch false, any other feature null); the rest at reader defaults.
    base = Manifest()
    doc: dict[str, object] = {}
    blocks: dict[str, dict[str, object]] = {}
    for item in fields(Manifest):
        if item.name == "features":
            doc["features"] = {
                f.name: False if "bool" in str(f.type) else None for f in fields(Features)
            }
        elif item.name in _MANIFEST_PARENT:
            parent = _MANIFEST_PARENT[item.name]
            doc[parent] = block = blocks.setdefault(parent, {})
            block[item.name] = _json(getattr(base, item.name))
        else:
            doc[item.name] = _json(getattr(base, item.name))
    doc[MANIFEST_LEDGER] = None
    return doc


def starter_config() -> dict[str, object]:
    # 0072, 0076: every top-level key at the reader default; null means not declared.
    base = Config()
    return {item.name: _json(getattr(base, item.name)) for item in fields(Config)}


def config_keys() -> tuple[str, ...]:
    keys: list[str] = []
    for item in fields(Config):
        nested = _CONFIG_NESTED.get(item.name)
        if nested is None:
            keys.append(item.name)
        else:
            prefix, shape = nested
            keys.extend(f"{prefix}.{sub.name}" for sub in fields(shape))
    return tuple(keys)
