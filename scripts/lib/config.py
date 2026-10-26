# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path

from lib.agent_models import MODELS
from lib.audit import check_project_data_dir
from lib.train_scope import KNOWN_AGENTS

POLICY_ENGINES = ("cfn-guard", "conftest")
# 0072: how many coders a parallel stage runs at once when the config names no number.
DEFAULT_MAX_CONCURRENT_BUILDERS = 5
# 0133: the audit round budget is retired; a config that still sets it is refused.
RETIRED_ROUND_BUDGET = "audit_round_budget"
# AU-11, AU-6: a declared audit retention keeps at least this many days of session logs.
AUDIT_RETENTION_FLOOR_DAYS = 90
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
    max_concurrent_builders: int = DEFAULT_MAX_CONCURRENT_BUILDERS
    audit_retention_days: int | None = None
    agent_models: dict[str, str] = field(default_factory=dict)


def _require_str(raw: dict[str, object], key: str, where: str) -> str:
    name = f"{where}.{key}" if where else key
    value = raw.get(key)
    if not isinstance(value, str) or not value:
        raise ConfigError(
            f"config.json {name} must be a non-empty string. Next: set {name} to a string value."
        )
    return value


def _signing_keys(raw: dict[str, object]) -> tuple[str, ...]:
    if "operator_signing_keys" not in raw:
        return ()
    keys = raw["operator_signing_keys"]
    if not isinstance(keys, list) or not all(isinstance(k, str) and k for k in keys):
        raise ConfigError(
            "config.json operator_signing_keys must be a list of non-empty strings. "
            'Next: write it as ["KEYID", ...].'
        )
    return tuple(str(k) for k in keys)


def _max_builders(raw: dict[str, object]) -> int:
    # 0072: a whole number of at least 1; bool is refused, though Python counts it an int.
    value = raw.get("max_concurrent_builders", DEFAULT_MAX_CONCURRENT_BUILDERS)
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ConfigError(
            f"config.json max_concurrent_builders must be a whole number of at least 1 "
            f"(got {value!r}). Next: set max_concurrent_builders to 1 or more, or remove it "
            "to run five coders at once."
        )
    return value


def _retention_days(raw: dict[str, object]) -> int | None:
    # issue 50, AU-11: null keeps every log; a number is whole and at least the floor.
    value = raw.get("audit_retention_days")
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or value < AUDIT_RETENTION_FLOOR_DAYS:
        raise ConfigError(
            f"config.json audit_retention_days must be a whole number of at least "
            f"{AUDIT_RETENTION_FLOOR_DAYS} (got {value!r}). Next: set it to "
            f"{AUDIT_RETENTION_FLOOR_DAYS} or more, or to null to keep every audit log."
        )
    return value


def _refuse_round_budget(raw: dict[str, object]) -> None:
    # 0133: every failing gate goes to the operator, so no number of rounds is configured.
    if RETIRED_ROUND_BUDGET in raw:
        raise ConfigError(
            f"config.json sets {RETIRED_ROUND_BUDGET}, which Daedalus removed: the operator now "
            "decides each audit finding, with no round budget. "
            f"Next: delete the {RETIRED_ROUND_BUDGET} line from .claude/daedalus/config.json."
        )


def _agent_models(raw: dict[str, object]) -> dict[str, str]:
    # spec 4: names come from agents/*.md through KNOWN_AGENTS, so no name is hard-coded here.
    value = raw.get("agent_models")
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ConfigError(
            "config.json agent_models must be an object. "
            'Next: write agent_models as {"<agent>": "<model>"}, or remove it.'
        )
    agents = KNOWN_AGENTS - {"main"}
    for name, model in value.items():
        if name not in agents:
            raise ConfigError(
                f"config.json agent_models names {name!r}, which is not a catalog agent. "
                "Next: key agent_models by an agent name the catalog lists, one of "
                f"{', '.join(sorted(agents))}."
            )
        if model not in MODELS:
            raise ConfigError(
                f"config.json agent_models.{name} is {model!r}. "
                f"Next: set agent_models.{name} to one of {', '.join(MODELS)}."
            )
    return {str(name): str(model) for name, model in value.items()}


def _ledger(raw: object) -> LedgerDecl:
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


def _policy(raw: object) -> PolicyDecl:
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


def _sources(raw: object) -> tuple[StandardsSource, ...]:
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


def _pack(name: object) -> StandardsSource:
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
        raw: object = json.loads(text)
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
    _refuse_round_budget(raw)
    # 0076: null is not declared, the same as an absent key; the setup starter writes null.
    charter = _require_str(raw, "charter_root", "") if raw.get("charter_root") is not None else None
    return Config(
        charter_root=Path(charter) if charter is not None else None,
        ledger=_ledger(raw["ledger"]) if raw.get("ledger") is not None else None,
        policy=_policy(raw["policy"]) if raw.get("policy") is not None else None,
        standards_sources=_sources(raw.get("standards_sources")),
        operator_signing_keys=_signing_keys(raw),
        max_concurrent_builders=_max_builders(raw),
        audit_retention_days=_retention_days(raw),
        agent_models=_agent_models(raw),
    )
