# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import json
import os
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from lib import git
from lib.agent_aliases import current as current_name
from lib.agent_models import MODELS
from lib.audit import check_project_data_dir
from lib.credential_paths import credential_roots
from lib.project_root import in_git_work_tree
from lib.train_scope import KNOWN_AGENTS

POLICY_ENGINES = ("cfn-guard", "conftest")
# D.2.1, 0136: the excluded root kinds this release resolves, and what a gitignore root takes.
EXCLUDED_ROOT_KINDS = ("path", "gitignore")
GITIGNORE_MATCHES = ("directories", "all")
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
class ExcludedRootDecl:
    kind: str
    path: str | None = None
    match: str = "directories"


@dataclass(frozen=True)
class ExcludedRoot:
    # D.2.1: ignored is True for a gitignore root and None until git check-ignore is asked.
    path: str
    ignored: bool | None = None


@dataclass(frozen=True)
class Config:
    charter_root: Path | None = None
    standing_rules: str | None = None
    excluded_roots: tuple[ExcludedRootDecl, ...] = field(default_factory=tuple)
    ledger: LedgerDecl | None = None
    policy: PolicyDecl | None = None
    standards_sources: tuple[StandardsSource, ...] = field(default_factory=tuple)
    operator_signing_keys: tuple[str, ...] = field(default_factory=tuple)
    max_concurrent_builders: int = DEFAULT_MAX_CONCURRENT_BUILDERS
    audit_retention_days: int | None = None
    wrapper_read_roots: tuple[str, ...] = field(default_factory=tuple)
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
    out: dict[str, str] = {}
    for name, model in value.items():
        # 0190: an old agent name keys its new name for one release; the doctor warns.
        new = current_name(str(name))
        if new not in agents:
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
        if out.get(new, model) != model:
            raise ConfigError(
                f"config.json agent_models gives {new} two models under its old and new names. "
                "Next: delete one of the two entries, so that one model is left for it."
            )
        out[new] = str(model)
    return out


def _expand_root(entry: str) -> str:
    # 0164: a ~/ entry names a folder under the operator's home, never a project file there.
    return os.path.normpath(os.path.expanduser(entry))


def overlaps(first: str, second: str) -> bool:
    # 0164: either path holds the other; the filesystem root holds every path.
    a, b = (os.path.realpath(p).rstrip(os.sep) + os.sep for p in (first, second))
    return a.startswith(b) or b.startswith(a)


def _wrapper_read_roots(raw: dict[str, object], dot_claude: Path) -> tuple[str, ...]:
    # 0164: folders the kernel wrapper lets a runner row read and run; never a credential store
    # and never the project's .claude folder, which holds the train's reply key.
    value = raw.get("wrapper_read_roots")
    if value is None:
        return ()
    if not isinstance(value, list) or not all(isinstance(v, str) and v for v in value):
        raise ConfigError(
            "config.json wrapper_read_roots must be a list of non-empty strings. "
            'Next: write it as ["~/.local/share/pnpm/store"], or remove it.'
        )
    guarded = [*credential_roots(), str(dot_claude)]
    out: list[str] = []
    for entry in value:
        path = _expand_root(entry)
        if not os.path.isabs(path):
            raise ConfigError(
                f"config.json wrapper_read_roots entry {entry!r} is not an absolute path. "
                "Next: write it as an absolute path or a path starting with ~/."
            )
        for store in guarded:
            if overlaps(path, store):
                raise ConfigError(
                    f"config.json wrapper_read_roots entry {entry!r} holds or sits inside "
                    f"{store}, a credential store or the project's .claude folder, and the "
                    "kernel wrapper never grants either. Next: name a folder that holds "
                    "neither, such as ~/.local/share/pnpm/store, or remove the entry."
                )
        out.append(path)
    return tuple(out)


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


def _excluded_roots(raw: object) -> tuple[ExcludedRootDecl, ...]:
    # D.2.1, 0136: a literal folder or the repository's ignored paths; the plugin names none.
    if raw is None:
        return ()
    if not isinstance(raw, list):
        raise ConfigError(
            "config.json excluded_roots must be a list. "
            'Next: write it as [{"kind": "path", "path": "<repo_root>/private/"}], or remove it.'
        )
    out: list[ExcludedRootDecl] = []
    for item in raw:
        kind = item.get("kind") if isinstance(item, dict) else None
        if not isinstance(item, dict) or kind not in EXCLUDED_ROOT_KINDS:
            raise ConfigError(
                f"each excluded_roots entry needs a kind of {' or '.join(EXCLUDED_ROOT_KINDS)} "
                f"(got {item!r}). Next: give the entry a kind of path or gitignore."
            )
        if kind == "path":
            out.append(ExcludedRootDecl("path", _require_str(item, "path", "excluded_roots[]")))
            continue
        match = item.get("match", "directories")
        if match not in GITIGNORE_MATCHES:
            raise ConfigError(
                f"config.json excluded_roots[].match must be one of {GITIGNORE_MATCHES} "
                f"(got {match!r}). Next: set match to directories or all, or remove it."
            )
        out.append(ExcludedRootDecl("gitignore", None, str(match)))
    return tuple(out)


def _root_path(raw: str, repo_root: Path, charter_root: Path | None) -> str:
    if "<charter_root>" in raw:
        if charter_root is None:
            raise ConfigError(
                f"excluded root {raw} uses <charter_root> but no charter_root is set. "
                "Next: set charter_root in .claude/daedalus/config.json, or write the path."
            )
        raw = raw.replace("<charter_root>", str(charter_root))
    path = Path(raw.replace("<repo_root>", str(repo_root)))
    # D.2.1: a relative root is read against the project root, never the process cwd.
    return os.path.normpath(path if path.is_absolute() else repo_root / path)


def standing_rules_path(config: Config, repo_root: Path) -> Path | None:
    # 0090: relative to charter_root when one is declared, else to the project root.
    if config.standing_rules is None:
        return None
    base = repo_root / config.charter_root if config.charter_root else repo_root
    return Path(os.path.normpath(base / config.standing_rules))


def _git_lines(args: list[str], repo_root: Path) -> list[str]:
    try:
        out = git.run(args, repo_root, 5)
    except (OSError, subprocess.SubprocessError) as exc:
        raise ConfigError(
            f"git {args[0]} failed in {repo_root} ({exc}). Next: fix git there, then rerun."
        ) from exc
    if out.returncode != 0:
        first = (out.stderr.strip().splitlines() or ["no stderr"])[0]
        raise ConfigError(
            f"git {args[0]} failed in {repo_root} ({first}). "
            "Next: fix git in that folder, then rerun."
        )
    return [line for line in out.stdout.split("\0" if "-z" in args else "\n") if line]


def _ignored_paths(repo_root: Path, match: str) -> list[str]:
    # D.2.1: a folder holding a linked worktree is another checkout, not excluded content.
    if not in_git_work_tree(repo_root):
        return []
    args = ["ls-files", "-z", "--others", "--ignored", "--exclude-standard", "--directory"]
    entries = _git_lines(args, repo_root)
    listed = _git_lines(["worktree", "list", "--porcelain"], repo_root)
    trees = [os.path.normpath(line[9:]) for line in listed if line.startswith("worktree ")]
    out: list[str] = []
    for entry in entries:
        if match == "directories" and not entry.endswith("/"):
            continue
        path = os.path.normpath(repo_root / entry)
        if not any(t == path or t.startswith(path + os.sep) for t in trees):
            out.append(path)
    return out


def resolve_excluded_roots(config: Config, repo_root: Path) -> tuple[ExcludedRoot, ...]:
    # D.2.1: resolved on each call from project metadata; no block resolves to none.
    found: dict[str, ExcludedRoot] = {}
    for decl in config.excluded_roots:
        if decl.kind == "path":
            path = _root_path(str(decl.path), repo_root, config.charter_root)
            found.setdefault(path, ExcludedRoot(path))
            continue
        for path in _ignored_paths(repo_root, decl.match):
            found[path] = ExcludedRoot(path, True)
    return tuple(found.values())


def root_ignored(root: ExcludedRoot, tree: Path) -> bool:
    # D.7: git check-ignore on the folder; an error or a tracked path reads as not ignored.
    if root.ignored is not None:
        return root.ignored
    rel = os.path.relpath(root.path, tree)
    if rel == "." or rel.startswith(".." + os.sep) or not in_git_work_tree(tree):
        return False
    try:
        out = git.run(["check-ignore", "-q", "--", rel + "/"], tree, 5)
    except (OSError, subprocess.SubprocessError):
        return False
    return out.returncode == 0


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
    rules = (
        _require_str(raw, "standing_rules", "") if raw.get("standing_rules") is not None else None
    )
    return Config(
        charter_root=Path(charter) if charter is not None else None,
        standing_rules=rules,
        excluded_roots=_excluded_roots(raw.get("excluded_roots")),
        ledger=_ledger(raw["ledger"]) if raw.get("ledger") is not None else None,
        policy=_policy(raw["policy"]) if raw.get("policy") is not None else None,
        standards_sources=_sources(raw.get("standards_sources")),
        operator_signing_keys=_signing_keys(raw),
        max_concurrent_builders=_max_builders(raw),
        audit_retention_days=_retention_days(raw),
        wrapper_read_roots=_wrapper_read_roots(raw, target.parent.parent),
        agent_models=_agent_models(raw),
    )
