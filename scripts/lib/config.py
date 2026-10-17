# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from lib.audit import check_project_data_dir

POLICY_ENGINES = ("cfn-guard", "conftest")
LEDGER_FORMATS = ("markdown-table-row", "heading-entry")
LEDGER_FIELDS = ("path", "format", "id_scheme", "sequence_source")
PACKS_DIR = Path(__file__).resolve().parents[2] / "packs"
_PACK_NAME = re.compile(r"[a-z0-9][a-z0-9-]*")


class ConfigError(ValueError):
    pass


@dataclass(frozen=True)
class LedgerDecl:
    path: Path
    format: str
    id_scheme: str
    sequence_source: str


@dataclass(frozen=True)
class PolicyDecl:
    engine: str
    path: Path


@dataclass(frozen=True)
class StandardsSource:
    kind: str
    path: Path
    name: str | None = None


@dataclass(frozen=True)
class Config:
    charter_root: Path | None = None
    ledger: LedgerDecl | None = None
    policy: PolicyDecl | None = None
    standards_sources: tuple[StandardsSource, ...] = field(default_factory=tuple)
    operator_signing_keys: tuple[str, ...] = field(default_factory=tuple)


def _require_str(raw: dict[str, Any], key: str, where: str) -> str:
    name = f"{where}.{key}" if where else key
    value = raw.get(key)
    if not isinstance(value, str) or not value:
        raise ConfigError(
            f"config.json {name} must be a non-empty string. Next: set {name} to a string value."
        )
    return value


def _signing_keys(raw: dict[str, Any]) -> tuple[str, ...]:
    if "operator_signing_keys" not in raw:
        return ()
    keys = raw["operator_signing_keys"]
    if not isinstance(keys, list) or not all(isinstance(k, str) and k for k in keys):
        raise ConfigError(
            "config.json operator_signing_keys must be a list of non-empty strings. "
            'Next: write it as ["KEYID", ...].'
        )
    return tuple(keys)


def _ledger(raw: Any) -> LedgerDecl:
    if not isinstance(raw, dict):
        raise ConfigError(
            "config.json ledger must be an object. "
            "Next: write the ledger block as an object, as docs/project-requirements.md shows."
        )
    missing = [key for key in LEDGER_FIELDS if key not in raw]
    if missing:
        names = ", ".join(f"ledger.{key}" for key in missing)
        raise ConfigError(f"config.json is missing {names}. Next: declare all four ledger fields.")
    path, fmt, id_scheme, sequence_source = (_require_str(raw, k, "ledger") for k in LEDGER_FIELDS)
    if fmt not in LEDGER_FORMATS:
        raise ConfigError(
            f"config.json ledger.format must be one of {LEDGER_FORMATS}. "
            "Next: pick the one matching your ledger file."
        )
    return LedgerDecl(Path(path), fmt, id_scheme, sequence_source)


def _policy(raw: Any) -> PolicyDecl:
    if not isinstance(raw, dict) or "engine" not in raw or "path" not in raw:
        raise ConfigError(
            "config.json policy needs engine and path. "
            "Next: add the engine and path keys, as docs/project-requirements.md shows."
        )
    engine = _require_str(raw, "engine", "policy")
    path = _require_str(raw, "path", "policy")
    if engine not in POLICY_ENGINES:
        raise ConfigError(
            f"config.json policy.engine must be one of {POLICY_ENGINES}. "
            "Next: install that engine and name it here."
        )
    return PolicyDecl(engine, Path(path))


def _sources(raw: Any) -> tuple[StandardsSource, ...]:
    if raw is None:
        return ()
    if not isinstance(raw, list):
        raise ConfigError(
            "config.json standards_sources must be a list. Next: wrap the entry in [ ]."
        )
    out: list[StandardsSource] = []
    for item in raw:
        if isinstance(item, dict) and item.get("kind") == "pack":
            out.append(_pack(item.get("name")))
            continue
        if not isinstance(item, dict) or "kind" not in item or "path" not in item:
            raise ConfigError(
                "each standards_sources entry needs kind and path. "
                "Next: add both the kind and path keys."
            )
        kind = _require_str(item, "kind", "standards_sources[]")
        out.append(StandardsSource(kind, Path(_require_str(item, "path", "standards_sources[]"))))
    return tuple(out)


def _pack(name: Any) -> StandardsSource:
    # 0019, 0026: a shipped pack resolves under the plugin root; the name never walks out of it.
    if isinstance(name, str) and _PACK_NAME.fullmatch(name):
        path = PACKS_DIR / name
        if (path / "rules.md").is_file():
            return StandardsSource("pack", path, name)
    raise ConfigError(
        f"config.json standards_sources[] pack {name!r} is not a pack Daedalus ships. "
        'Next: name the shipped baseline pack, "baseline".'
    )


def load_config(cwd: str | None = None, path: Path | None = None) -> Config:
    if path is None:
        if not cwd or not os.path.isabs(cwd):
            raise ConfigError(
                f"config lookup needs an absolute cwd (got {cwd!r}). "
                "Next: report the hook input; config.json is found from cwd."
            )
    # 0010: config.json is project-scoped, at <repo>/.claude/daedalus/config.json.
    target = path or (check_project_data_dir(str(cwd)) / "config.json")
    if not target.exists():
        return Config()
    try:
        text = target.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise ConfigError(
            f"{target} could not be read ({exc}). Next: make it a readable UTF-8 file."
        ) from exc
    try:
        raw = json.loads(text)
    except (ValueError, RecursionError) as exc:
        detail = getattr(exc, "msg", str(exc))
        raise ConfigError(
            f"{target} is not valid JSON ({detail}). Next: fix the syntax or delete the file."
        ) from exc
    if not isinstance(raw, dict):
        raise ConfigError(
            f"{target} must contain a JSON object. "
            "Next: make the file one JSON object, as docs/project-requirements.md shows."
        )
    charter = _require_str(raw, "charter_root", "") if "charter_root" in raw else None
    return Config(
        charter_root=Path(charter) if charter is not None else None,
        ledger=_ledger(raw["ledger"]) if "ledger" in raw else None,
        policy=_policy(raw["policy"]) if "policy" in raw else None,
        standards_sources=_sources(raw.get("standards_sources")),
        operator_signing_keys=_signing_keys(raw),
    )
