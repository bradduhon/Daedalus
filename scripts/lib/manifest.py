# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# The one reader of <repo>/service-manifest.json; ledger.py, the jail and the trains use it.
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field, fields
from pathlib import Path
from typing import Literal

from lib.project_root import project_root
from lib.train_scope import KNOWN_AGENTS

MANIFEST_NAME = "service-manifest.json"
NARROWING_KEYS = ("forbidden_paths", "forbidden_extensions")
SCOPE_KINDS = ("repository", "folder")
_GLOB = frozenset("*?[]")


class ManifestError(ValueError):
    pass


class PrioritiesError(ManifestError):
    # 0129, F.6: the doctor names the key reference row a malformed priorities block broke.
    def __init__(self, message: str, row: str) -> None:
        super().__init__(message)
        self.row = row


@dataclass(frozen=True)
class Features:
    # 0069: spec 3.9 absent defaults; a field typed None-able keeps null as its absent value.
    scope: Literal["repository", "folder"] | None = None
    secrets_scan: bool = False
    scrub_file: str | None = None
    ledger: bool | None = None
    # issue 48: true, false or null; absent reads false, and only true makes the gh lines a MISS.
    github: bool | None = False
    # 0132: true, false or null; only false turns the dependency auditor's web lookup off.
    dependency_web_lookup: bool | None = None
    # 0132: true, false or null; only false turns off terraform fmt -check and validate.
    terraform_tools: bool | None = None


# 0073: the one list of feature names; validator check 13 and the key reference import it.
FEATURE_KEYS = tuple(f.name for f in fields(Features))
# 0134: a docs.literacy value is a level word or profile:<project-relative path>.
LITERACY_LEVELS = ("plain", "standard", "expert")
LITERACY_PROFILE = "profile:"


@dataclass(frozen=True)
class Docs:
    # 0134: null lets the docs writer keep the register the public docs already use.
    literacy: str | None = None


DOCS_KEYS = tuple(f.name for f in fields(Docs))
# 0129, Addendum F.2: the four drivers, the closed reason vocabulary and the surface outcome.
DRIVERS = ("security", "trust", "ops", "cost")
REASONS = (
    "certification",
    "framework",
    "best-practice",
    "incident",
    "shape",
    "domain-separation",
    "ownership",
    "convenience",
    "latency",
    "margin",
    "running-cost",
)
SURFACE = "surface"
# 0129, F.6: one key reference row per field, in table order, and each field's limits.
PRIORITY_ROWS = (
    "drivers",
    "rules[].when.conflict",
    "rules[].when.reason",
    "rules[].then",
    "rules[].note",
    "principles[].id",
    "principles[].driver",
    "principles[].text",
    "principles[].source",
    "agents.<name>.drivers",
)
MAX_RULES, MAX_PRINCIPLES, NOTE_MAX, TEXT_MAX = 32, 64, 200, 300
PRINCIPLE_ID = re.compile(r"P[0-9]+")
NOT_OVERRIDABLE = "security-auditor"
R_PRIORITIES = (
    "{target} {key} {detail} (0129). Next: correct {key} against its row in the key reference, "
    "then rerun."
)


@dataclass(frozen=True)
class Rule:
    conflict: tuple[str, str]
    reason: tuple[str, ...]
    then: str
    note: str


@dataclass(frozen=True)
class Principle:
    id: str
    driver: str
    text: str
    source: str | None = None


@dataclass(frozen=True)
class Priorities:
    # 0137: rules and principles are global; only the ranking varies per agent.
    drivers: tuple[str, ...]
    rules: tuple[Rule, ...] = ()
    principles: tuple[Principle, ...] = ()
    agents: tuple[tuple[str, tuple[str, ...]], ...] = ()

    def ranking(self, agent: str) -> tuple[str, ...]:
        return dict(self.agents).get(agent, self.drivers)


@dataclass(frozen=True)
class Manifest:
    forbidden_paths: tuple[str, ...] = ()
    forbidden_extensions: tuple[str, ...] = ()
    features: Features = field(default_factory=Features)
    trains_dir: str | None = None
    unit_test_cmd: str | None = None
    typecheck_cmd: str | None = None
    lint_cmd: str | None = None
    docs: Docs = field(default_factory=Docs)
    priorities: Priorities | None = None


# 0073, B2: the stack keys that hold a command the coder may run verbatim.
STACK_COMMANDS = ("unit_test_cmd", "typecheck_cmd", "lint_cmd")


def declared_commands(manifest: Manifest) -> tuple[str, ...]:
    values = (getattr(manifest, key) for key in STACK_COMMANDS)
    return tuple(value for value in values if isinstance(value, str))


def manifest_path(repo: Path) -> Path:
    # 0077: the manifest sits at the project root found from repo, never at HOME or the plugin.
    return project_root(repo) / MANIFEST_NAME


def read_raw(repo: Path) -> object:
    # 0054: None when absent; unreadable or malformed JSON raises with a Next line.
    target = manifest_path(repo)
    if not target.is_file():
        return None
    try:
        parsed: object = json.loads(target.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise ManifestError(
            f"{target} could not be read as JSON ({exc}). Next: fix the manifest syntax."
        ) from exc
    return parsed


def _shape_error(target: Path, detail: str) -> ManifestError:
    return ManifestError(
        f"{target} jail_narrowing {detail}. Next: fix jail_narrowing to match the example "
        "in docs/project-requirements.md."
    )


def _key_error(target: Path, key: str, detail: str) -> ManifestError:
    return ManifestError(
        f"{target} {key} {detail}. Next: correct the {key} value in the service manifest, "
        "then rerun."
    )


def repo_relative(entry: str) -> bool:
    # 0054: repo-relative, forward slashes, no glob; a trailing slash marks a folder prefix.
    if not entry or entry.startswith("/") or "\\" in entry or _GLOB & set(entry):
        return False
    parts = entry.removesuffix("/").split("/")
    return all(part not in {"", ".", ".."} for part in parts)


def _extension_ok(entry: str) -> bool:
    banned = {"/", "\\"} | _GLOB
    return entry.startswith(".") and bool(entry.strip(".")) and not banned & set(entry)


def _strings(target: Path, block: dict[str, object], key: str) -> tuple[str, ...]:
    value = block.get(key, [])
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise _shape_error(target, f"{key} must be a list of strings")
    return tuple(str(item) for item in value)


def _narrowing(target: Path, raw: dict[str, object]) -> tuple[tuple[str, ...], tuple[str, ...]]:
    block = raw.get("jail_narrowing", {})
    if not isinstance(block, dict):
        raise _shape_error(target, "must be an object")
    unknown = sorted(set(block) - set(NARROWING_KEYS))
    if unknown:
        raise _shape_error(target, f"has unknown keys {', '.join(unknown)}")
    paths = _strings(target, block, "forbidden_paths")
    extensions = _strings(target, block, "forbidden_extensions")
    bad_paths = [p for p in paths if not repo_relative(p)]
    if bad_paths:
        raise _shape_error(
            target,
            f"forbidden_paths entries {bad_paths} are not repo-relative forward-slash paths "
            "without a leading slash, '..' or glob characters",
        )
    bad_ext = [e for e in extensions if not _extension_ok(e)]
    if bad_ext:
        raise _shape_error(
            target,
            f"forbidden_extensions entries {bad_ext} must each start with a dot and hold no "
            "slash or glob characters",
        )
    return paths, extensions


def _features(target: Path, raw: dict[str, object]) -> Features:
    # 0073: an unknown key or a value outside its field's type is refused, never ignored.
    block = raw.get("features", {})
    if not isinstance(block, dict):
        raise _key_error(target, "features", "must be an object")
    unknown = sorted(str(key) for key in set(block) - set(FEATURE_KEYS))
    if unknown:
        known = ", ".join(FEATURE_KEYS)
        raise _key_error(target, "features", f"has unknown keys {unknown} (known: {known})")
    scope = block.get("scope")
    if scope is not None and scope not in SCOPE_KINDS:
        raise _key_error(target, "features.scope", f"must be one of {SCOPE_KINDS} or null")
    secrets = block.get("secrets_scan", False)
    if not isinstance(secrets, bool):
        raise _key_error(target, "features.secrets_scan", "must be true or false")
    scrub = block.get("scrub_file")
    if scrub is not None and not (isinstance(scrub, str) and repo_relative(scrub)):
        raise _key_error(
            target,
            "features.scrub_file",
            "must be null or a project-relative path without a leading slash, '..' or globs",
        )
    kind: Literal["repository", "folder"] | None = (
        "repository" if scope == "repository" else "folder" if scope == "folder" else None
    )
    return Features(
        kind,
        secrets,
        scrub,
        _switch(target, block, "ledger", None),
        _switch(target, block, "github", False),
        _switch(target, block, "dependency_web_lookup", None),
        _switch(target, block, "terraform_tools", None),
    )


def _switch(target: Path, block: dict[str, object], key: str, absent: bool | None) -> bool | None:
    # 0069, 0132: a true, false or null feature; absent reads as the field's default.
    value = block.get(key, absent)
    if value is not None and not isinstance(value, bool):
        raise _key_error(target, f"features.{key}", "must be true, false or null")
    return value


def _literacy_ok(value: object) -> bool:
    if value is None or value in LITERACY_LEVELS:
        return True
    if not isinstance(value, str) or not value.startswith(LITERACY_PROFILE):
        return False
    return repo_relative(value.removeprefix(LITERACY_PROFILE))


def _docs(target: Path, raw: dict[str, object]) -> Docs:
    # 0134: the docs block holds the docs writer's literacy; unknown keys are refused.
    block = raw.get("docs", {})
    if not isinstance(block, dict):
        raise _key_error(target, "docs", "must be an object")
    unknown = sorted(str(key) for key in set(block) - set(DOCS_KEYS))
    if unknown:
        raise _key_error(
            target, "docs", f"has unknown keys {unknown} (known: {', '.join(DOCS_KEYS)})"
        )
    literacy = block.get("literacy")
    if not _literacy_ok(literacy):
        levels = ", ".join(f'"{level}"' for level in LITERACY_LEVELS)
        raise _key_error(
            target,
            "docs.literacy",
            f"must be null, one of {levels}, or {LITERACY_PROFILE}<project-relative path to a "
            "voice profile without a leading slash, '..' or globs>",
        )
    return Docs(literacy if isinstance(literacy, str) else None)


def _bad(target: Path, row: str, detail: str) -> PrioritiesError:
    key = f"priorities.{row}" if row else "priorities"
    return PrioritiesError(R_PRIORITIES.format(target=target, key=key, detail=detail), row)


def _object(
    target: Path, value: object, row: str, keys: set[str], need: set[str]
) -> dict[str, object]:
    # 0129, F.6: an object with only its table's keys and every required one.
    if not isinstance(value, dict):
        raise _bad(target, row, "must be an object")
    unknown = sorted(str(key) for key in set(value) - keys)
    if unknown:
        raise _bad(target, row, f"has unknown keys {unknown} (known: {', '.join(sorted(keys))})")
    missing = sorted(need - set(value))
    if missing:
        raise _bad(target, row, f"lacks {', '.join(missing)}")
    return {str(key): item for key, item in value.items()}


def _line(target: Path, value: object, row: str, limit: int) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= limit or not value.isprintable():
        raise _bad(target, row, f"must be one printable line of 1 to {limit} characters")
    return value


def _ranking(target: Path, value: object, row: str) -> tuple[str, ...]:
    # 0129, F.6: exactly the four driver names, each once.
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise _bad(target, row, f"must be a list of the driver names {list(DRIVERS)}")
    repeated = sorted({item for item in value if value.count(item) > 1})
    if repeated:
        raise _bad(target, row, f"repeats the driver {repeated[0]!r}")
    if sorted(value) != sorted(DRIVERS):
        raise _bad(target, row, f"must name each of {list(DRIVERS)} once, in rank order")
    return tuple(str(item) for item in value)


def _rule(target: Path, value: object) -> Rule:
    rule = _object(
        target, value, "rules[].then", {"when", "then", "note"}, {"when", "then", "note"}
    )
    when = _object(
        target,
        rule["when"],
        "rules[].when.conflict",
        {"conflict", "reason"},
        {"conflict", "reason"},
    )
    conflict = when["conflict"]
    if not (
        isinstance(conflict, list)
        and len(conflict) == 2
        and all(item in DRIVERS for item in conflict)
        and conflict[0] != conflict[1]
    ):
        raise _bad(
            target, "rules[].when.conflict", f"must name two distinct drivers of {list(DRIVERS)}"
        )
    reason = when["reason"]
    if not isinstance(reason, list) or not reason or len(set(map(str, reason))) != len(reason):
        raise _bad(target, "rules[].when.reason", "must list one or more reasons, each once")
    outside = [item for item in reason if item not in REASONS]
    if outside:
        raise _bad(
            target,
            "rules[].when.reason",
            f"names {outside[0]!r}, outside the reason vocabulary {list(REASONS)}",
        )
    then = rule["then"]
    if then not in (*DRIVERS, SURFACE):
        raise _bad(target, "rules[].then", f"must be a driver of {list(DRIVERS)} or {SURFACE!r}")
    note = _line(target, rule["note"], "rules[].note", NOTE_MAX)
    return Rule((str(conflict[0]), str(conflict[1])), tuple(map(str, reason)), str(then), note)


def _principle(target: Path, value: object, seen: set[str]) -> Principle:
    item = _object(
        target,
        value,
        "principles[].id",
        {"id", "driver", "text", "source"},
        {"id", "driver", "text"},
    )
    ident = item["id"]
    if not isinstance(ident, str) or not PRINCIPLE_ID.fullmatch(ident) or ident in seen:
        raise _bad(target, "principles[].id", "must be P followed by digits, unique in the block")
    seen.add(ident)
    if item["driver"] not in DRIVERS:
        raise _bad(target, "principles[].driver", f"must be a driver of {list(DRIVERS)}")
    text = _line(target, item["text"], "principles[].text", TEXT_MAX)
    source = item.get("source")
    if source is not None and not (isinstance(source, str) and repo_relative(source)):
        raise _bad(
            target,
            "principles[].source",
            "must be a repo-relative path or a ledger id without a leading slash, '..' or globs",
        )
    return Principle(ident, str(item["driver"]), text, source)


def _overrides(target: Path, value: object) -> tuple[tuple[str, tuple[str, ...]], ...]:
    # 0129, F.2: the security auditor's ranking is never overridable.
    row = "agents.<name>.drivers"
    if not isinstance(value, dict):
        raise _bad(target, row, "agents must be an object keyed by agent name")
    out: list[tuple[str, tuple[str, ...]]] = []
    for name, entry in value.items():
        if name == NOT_OVERRIDABLE:
            raise _bad(target, row, f"names {NOT_OVERRIDABLE}, whose ranking no project overrides")
        if name not in KNOWN_AGENTS - {"main"}:
            raise _bad(target, row, f"names {name!r}, which is not a Daedalus agent file name")
        body = _object(target, entry, row, {"drivers"}, {"drivers"})
        out.append((str(name), _ranking(target, body["drivers"], row)))
    return tuple(out)


def _bounded_list(target: Path, value: object, row: str, limit: int) -> list[object]:
    if not isinstance(value, list) or len(value) > limit:
        raise _bad(target, row, f"must be a list of at most {limit} entries")
    return value


def _priorities(target: Path, raw: dict[str, object]) -> Priorities | None:
    # 0129, F.6: absent is none declared; anything off the field table is refused.
    if "priorities" not in raw:
        return None
    keys = {"drivers", "rules", "principles", "agents"}
    block = _object(target, raw["priorities"], "", keys, {"drivers"})
    drivers = _ranking(target, block["drivers"], "drivers")
    rules = _bounded_list(target, block.get("rules", []), "rules[].then", MAX_RULES)
    principles = _bounded_list(
        target, block.get("principles", []), "principles[].id", MAX_PRINCIPLES
    )
    seen: set[str] = set()
    return Priorities(
        drivers,
        tuple(_rule(target, rule) for rule in rules),
        tuple(_principle(target, item, seen) for item in principles),
        _overrides(target, block.get("agents", {})),
    )


def _trains_dir(target: Path, raw: dict[str, object]) -> str | None:
    value = raw.get("trains_dir")
    if value is None:
        return None
    if not isinstance(value, str) or not repo_relative(value):
        raise _key_error(
            target,
            "trains_dir",
            "must be a project-relative folder path without a leading slash, '..' or globs",
        )
    return value


def _stack_commands(target: Path, raw: dict[str, object]) -> dict[str, str | None]:
    stack = raw.get("stack", {})
    if not isinstance(stack, dict):
        raise _key_error(target, "stack", "must be an object")
    out: dict[str, str | None] = {}
    for key in STACK_COMMANDS:
        value = stack.get(key)
        if value is not None and (not isinstance(value, str) or not value.strip()):
            raise _key_error(target, f"stack.{key}", "must be null or a non-empty string")
        out[key] = value
    return out


def load(repo: Path) -> Manifest | None:
    raw = read_raw(repo)
    if raw is None:
        return None
    target = manifest_path(repo)
    if not isinstance(raw, dict):
        raise ManifestError(
            f"{target} is not a JSON object. Next: start from the example in "
            "docs/project-requirements.md."
        )
    paths, extensions = _narrowing(target, raw)
    commands = _stack_commands(target, raw)
    return Manifest(
        paths,
        extensions,
        features=_features(target, raw),
        trains_dir=_trains_dir(target, raw),
        unit_test_cmd=commands["unit_test_cmd"],
        typecheck_cmd=commands["typecheck_cmd"],
        lint_cmd=commands["lint_cmd"],
        docs=_docs(target, raw),
        priorities=_priorities(target, raw),
    )


def features(repo: Path) -> Features:
    # 0069: no manifest means every feature at its absent default.
    loaded = load(repo)
    return loaded.features if loaded is not None else Features()


def path_hit(manifest: Manifest, rel: str) -> bool:
    # 0054: casefolded, so a case-insensitive mount cannot dodge an entry by case.
    folded = rel.casefold().removesuffix("/")
    for entry in manifest.forbidden_paths:
        want = entry.casefold()
        bare = want.removesuffix("/")
        # 0054: an ancestor is hit too; rm -r or mv on it would take the entry along.
        if folded == bare or bare.startswith(f"{folded}/"):
            return True
        if want.endswith("/") and folded.startswith(want):
            return True
    return False


def extension_hit(manifest: Manifest, rel: str) -> bool:
    name = rel.rsplit("/", 1)[-1].casefold()
    return any(name.endswith(ext.casefold()) for ext in manifest.forbidden_extensions)
