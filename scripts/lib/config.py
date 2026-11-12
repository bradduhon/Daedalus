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
from lib.agent_models import MODELS
from lib.audit import check_project_data_dir
from lib.coder_model import DEFAULT_CODER_MODELS
from lib.credential_paths import credential_roots
from lib.operator_file import OperatorError, validate
from lib.project_root import in_git_work_tree
from lib.settings_maps import SCHEMA_KEY, current, number_problem
from lib.train_scope import KNOWN_AGENTS

POLICY_ENGINES = ("cfn-guard", "conftest")
# D.2.1, 0136: the excluded root kinds this release resolves, and what a gitignore root takes.
EXCLUDED_ROOT_KINDS = ("path", "gitignore")
GITIGNORE_MATCHES = ("directories", "all")
# 0072: how many coders a parallel stage runs at once when the config names no number.
DEFAULT_MAX_CONCURRENT_BUILDERS = 5
# AU-11, AU-6: a declared audit retention keeps at least this many days of session logs.
AUDIT_RETENTION_FLOOR_DAYS = 90
PACKS_DIR = Path(__file__).resolve().parents[2] / "packs"
_PACK_NAME = re.compile(r"[a-z0-9][a-z0-9-]*")
# 0245: the JSON names of config.json, in key-table order; the reader maps them onto Config.
CONFIG_KEYS = (
    SCHEMA_KEY,
    "local_docs_folder",
    "git_excluded_folders",
    "coding_rules",
    "personal_overrides",
    "models",
    "limits",
    "test_readable_folders",
    "policy",
)
MODEL_KEYS = (
    "agents",
    "coder",
    "plugin_file_coder",
    "coder_after_rejection",
    "fable_available",
)
# 0245: each coder model key and the coder tier it sets.
CODER_KEYS = {
    "coder": "default",
    "plugin_file_coder": "control_path",
    "coder_after_rejection": "escalated",
}
LIMIT_KEYS = ("parallel_coders", "task_tokens", "log_retention_days")
# 0245: a coding rules entry's one key and the standards source kind it names.
RULE_SOURCE_KEYS = {"folder": "rules-dir", "file": "file", "builtin": "pack"}
EXCLUDED_KEYS = ("kind", "path", "match")


class ConfigError(ValueError):
    pass


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
    # 0245: read from local_docs_folder, a docs folder kept elsewhere on this machine.
    charter_root: Path | None = None
    excluded_roots: tuple[ExcludedRootDecl, ...] = field(default_factory=tuple)
    policy: PolicyDecl | None = None
    standards_sources: tuple[StandardsSource, ...] = field(default_factory=tuple)
    max_concurrent_builders: int = DEFAULT_MAX_CONCURRENT_BUILDERS
    audit_retention_days: int | None = None
    wrapper_read_roots: tuple[str, ...] = field(default_factory=tuple)
    # 0209: total tokens per unit, coders plus verifiers; None leaves the gate off.
    unit_token_budget: int | None = None
    # 0187: the coder's model per tier, passed per dispatch; agent_models stays the fallback.
    coder_models: dict[str, str] = field(default_factory=lambda: dict(DEFAULT_CODER_MODELS))
    # 0217: true or false settles Fable for the preferring agents; None leaves it to the session.
    fable_available: bool | None = None
    agent_models: dict[str, str] = field(default_factory=dict)
    # 0235: the validated per-repository override of the operator file; {} sets nothing.
    operator: dict[str, object] = field(default_factory=dict)


def _require_str(raw: dict[str, object], key: str, where: str) -> str:
    name = f"{where}.{key}" if where else key
    value = raw.get(key)
    if not isinstance(value, str) or not value:
        raise ConfigError(
            f"config.json {name} must be a non-empty string. Next: set {name} to a string value."
        )
    return value


def _group(
    target: Path, raw: dict[str, object], name: str, keys: tuple[str, ...]
) -> dict[str, object]:
    # 0245: a group is an object of its own keys; null reads as absent; an unknown key is refused.
    block = raw.get(name)
    if block is None:
        return {}
    if not isinstance(block, dict):
        raise ConfigError(f"config.json {name} must be an object. Next: write {name} as an object.")
    _refuse_unknown_keys(target, block, keys, f"{name} ")
    return block


def _max_builders(raw: dict[str, object]) -> int:
    # 0072: a whole number of at least 1; bool is refused, though Python counts it an int.
    value = raw.get("parallel_coders", DEFAULT_MAX_CONCURRENT_BUILDERS)
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ConfigError(
            f"config.json limits.parallel_coders must be a whole number of at least 1 "
            f"(got {value!r}). Next: set limits.parallel_coders to 1 or more, or remove it "
            "to run five coders at once."
        )
    return value


def _retention_days(raw: dict[str, object]) -> int | None:
    # issue 50, AU-11: null keeps every log; a number is whole and at least the floor.
    value = raw.get("log_retention_days")
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or value < AUDIT_RETENTION_FLOOR_DAYS:
        raise ConfigError(
            f"config.json limits.log_retention_days must be a whole number of at least "
            f"{AUDIT_RETENTION_FLOOR_DAYS} (got {value!r}). Next: set it to "
            f"{AUDIT_RETENTION_FLOOR_DAYS} or more, or to null to keep every audit log."
        )
    return value


def _unit_budget(raw: dict[str, object]) -> int | None:
    # 0209: null or absent leaves the token budget gate off; a number is whole and positive.
    value = raw.get("task_tokens")
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ConfigError(
            f"config.json limits.task_tokens must be a whole number of at least 1 "
            f"(got {value!r}). Next: set it to a token count, or to null to leave the budget "
            "gate off."
        )
    return value


def _refuse_unknown_keys(
    target: Path, raw: dict[str, object], keys: tuple[str, ...] = CONFIG_KEYS, where: str = ""
) -> None:
    # 0241, 0245: a key off the key table, an old name included, is refused with the valid names.
    unknown = sorted(str(key) for key in set(raw) - set(keys))
    if unknown:
        raise ConfigError(
            f"{target} {where}has unknown keys {unknown} (known: {', '.join(keys)}). "
            f"Next: delete or correct those keys in {target}, then rerun."
        )


def _agent_models(raw: dict[str, object]) -> dict[str, str]:
    # spec 4: names come from agents/*.md through KNOWN_AGENTS, so no name is hard-coded here.
    value = raw.get("agents")
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ConfigError(
            "config.json models.agents must be an object. "
            'Next: write models.agents as {"<agent>": "<model>"}, or remove it.'
        )
    agents = KNOWN_AGENTS - {"main"}
    out: dict[str, str] = {}
    for name, model in value.items():
        if name not in agents:
            raise ConfigError(
                f"config.json models.agents names {name!r}, which is not a catalog agent. "
                "Next: key models.agents by an agent name the catalog lists, one of "
                f"{', '.join(sorted(agents))}."
            )
        if model not in MODELS:
            raise ConfigError(
                f"config.json models.agents.{name} is {model!r}. "
                f"Next: set models.agents.{name} to one of {', '.join(MODELS)}."
            )
        out[str(name)] = str(model)
    return out


def _fable_available(raw: dict[str, object]) -> bool | None:
    # 0217: only the two JSON booleans or null; a string or a number is refused by name.
    value = raw.get("fable_available")
    if value is None or isinstance(value, bool):
        return value
    raise ConfigError(
        f"config.json models.fable_available must be true, false or null (got {value!r}). "
        "Next: set models.fable_available to true when your plan offers Fable, to false to "
        "keep the planner and the auditor on their default model, or remove it."
    )


def _operator(raw: dict[str, object]) -> dict[str, object]:
    # 0235: the personal overrides go through operator_file's one validator, never a second schema.
    value = raw.get("personal_overrides")
    if value is None:
        return {}
    try:
        return validate(value, "config.json", "personal_overrides.")
    except OperatorError as exc:
        raise ConfigError(str(exc)) from exc


def _local_docs_folder(raw: dict[str, object]) -> Path | None:
    # 0245: an absolute folder path, never a link; it keeps charter_root's rules.
    value = raw.get("local_docs_folder")
    if value is None:
        return None
    if not isinstance(value, str) or not value or not os.path.isabs(value):
        raise ConfigError(
            f"config.json local_docs_folder must be an absolute folder path (got {value!r}). "
            "Next: write the full path of the docs folder kept on this machine, or null."
        )
    if os.path.islink(value.rstrip(os.sep) or os.sep):
        raise ConfigError(
            f"config.json local_docs_folder {value} is a symlink. Next: name the real folder "
            "the link points at, or null."
        )
    # 0245: a folder inside the project is kept, as charter_root allowed it: a git-ignored clone.
    return Path(value)


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
    value = raw.get("test_readable_folders")
    if value is None:
        return ()
    if not isinstance(value, list) or not all(isinstance(v, str) and v for v in value):
        raise ConfigError(
            "config.json test_readable_folders must be a list of non-empty strings. "
            'Next: write it as ["~/.local/share/pnpm/store"], or remove it.'
        )
    guarded = [*credential_roots(), str(dot_claude)]
    out: list[str] = []
    for entry in value:
        path = _expand_root(entry)
        if not os.path.isabs(path):
            raise ConfigError(
                f"config.json test_readable_folders entry {entry!r} is not an absolute path. "
                "Next: write it as an absolute path or a path starting with ~/."
            )
        for store in guarded:
            if overlaps(path, store):
                raise ConfigError(
                    f"config.json test_readable_folders entry {entry!r} holds or sits inside "
                    f"{store}, a credential store or the project's .claude folder, and the "
                    "kernel wrapper never grants either. Next: name a folder that holds "
                    "neither, such as ~/.local/share/pnpm/store, or remove the entry."
                )
        out.append(path)
    return tuple(out)


def _coder_models(raw: dict[str, object]) -> dict[str, str]:
    # 0187, 0245: each coder model key sets one coder tier; a key left out keeps its default.
    out = dict(DEFAULT_CODER_MODELS)
    for key, tier in CODER_KEYS.items():
        model = raw.get(key)
        if model is None:
            continue
        if model not in MODELS:
            raise ConfigError(
                f"config.json models.{key} is {model!r}. "
                f"Next: set models.{key} to one of {', '.join(MODELS)}, or remove it."
            )
        out[tier] = str(model)
    return out


def _policy(raw: object) -> PolicyDecl:
    if not isinstance(raw, dict) or "engine" not in raw or "path" not in raw:
        raise ConfigError(
            "config.json policy needs engine and path. "
            "Next: add the engine and path keys, as docs/project-requirements.md shows."
        )
    unknown = sorted(str(key) for key in set(raw) - {"engine", "path"})
    if unknown:
        raise ConfigError(
            f"config.json policy has unknown keys {unknown} (known: engine, path). "
            "Next: delete or correct those keys, then rerun."
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
    # 0245: each coding rules entry is an object with exactly one of folder, file or builtin.
    if raw is None:
        return ()
    if not isinstance(raw, list):
        raise ConfigError("config.json coding_rules must be a list. Next: wrap the entry in [ ].")
    out: list[StandardsSource] = []
    known = ", ".join(RULE_SOURCE_KEYS)
    for item in raw:
        if not isinstance(item, dict) or len(item) != 1 or next(iter(item)) not in RULE_SOURCE_KEYS:
            raise ConfigError(
                f"each coding_rules entry must be an object with exactly one of {known} "
                f"(got {item!r}). Next: write the entry as one key, such as "
                '{"folder": "/work/rules"}.'
            )
        key, value = next(iter(item.items()))
        if key == "builtin":
            out.append(_pack(value))
            continue
        out.append(
            StandardsSource(RULE_SOURCE_KEYS[key], Path(_require_str(item, key, "coding_rules[]")))
        )
    return tuple(out)


def _pack(name: object) -> StandardsSource:
    # 0019, 0026: a shipped pack resolves under the plugin root; the name never walks out of it.
    if isinstance(name, str) and _PACK_NAME.fullmatch(name):
        path = PACKS_DIR / name
        if (path / "rules.md").is_file():
            return StandardsSource("pack", path, name)
    raise ConfigError(
        f"config.json coding_rules[].builtin {name!r} is not a rule set Daedalus ships. "
        'Next: name the shipped baseline rules, "baseline".'
    )


def _excluded_roots(raw: object) -> tuple[ExcludedRootDecl, ...]:
    # D.2.1, 0136: a literal folder or the repository's ignored paths; the plugin names none.
    if raw is None:
        return ()
    if not isinstance(raw, list):
        raise ConfigError(
            "config.json git_excluded_folders must be a list. "
            'Next: write it as [{"kind": "path", "path": "<repo_root>/private/"}], or remove it.'
        )
    out: list[ExcludedRootDecl] = []
    for item in raw:
        kind = item.get("kind") if isinstance(item, dict) else None
        if not isinstance(item, dict) or kind not in EXCLUDED_ROOT_KINDS:
            raise ConfigError(
                f"each git_excluded_folders entry needs a kind of "
                f"{' or '.join(EXCLUDED_ROOT_KINDS)} (got {item!r}). Next: give the entry a "
                "kind of path or gitignore."
            )
        unknown = sorted(str(key) for key in set(item) - set(EXCLUDED_KEYS))
        if unknown:
            raise ConfigError(
                f"config.json git_excluded_folders[] has unknown keys {unknown} (known: "
                f"{', '.join(EXCLUDED_KEYS)}). Next: delete or correct those keys, then rerun."
            )
        if kind == "path":
            out.append(
                ExcludedRootDecl("path", _require_str(item, "path", "git_excluded_folders[]"))
            )
            continue
        match = item.get("match", "directories")
        if match not in GITIGNORE_MATCHES:
            raise ConfigError(
                f"config.json git_excluded_folders[].match must be one of {GITIGNORE_MATCHES} "
                f"(got {match!r}). Next: set match to directories or all, or remove it."
            )
        out.append(ExcludedRootDecl("gitignore", None, str(match)))
    return tuple(out)


def _root_path(raw: str, repo_root: Path, charter_root: Path | None) -> str:
    if "<charter_root>" in raw:
        if charter_root is None:
            raise ConfigError(
                f"excluded folder {raw} uses <charter_root> but no local_docs_folder is set. "
                "Next: set local_docs_folder in .claude/daedalus/config.json, or write the path."
            )
        raw = raw.replace("<charter_root>", str(charter_root))
    path = Path(raw.replace("<repo_root>", str(repo_root)))
    # D.2.1: a relative root is read against the project root, never the process cwd.
    return os.path.normpath(path if path.is_absolute() else repo_root / path)


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
    return parse_config(raw, target)


def parse_config(raw: object, target: Path) -> Config:
    # 0242: the one check of a parsed config; setup runs it on a changed document before writing.
    if not isinstance(raw, dict):
        raise ConfigError(
            f"{target} must contain a JSON object. "
            "Next: make the file one JSON object, as docs/project-requirements.md shows."
        )
    _refuse_unknown_keys(target, raw)
    # 0264: no schema number reads as today; one outside 1 to the current number is refused.
    problem = number_problem(raw[SCHEMA_KEY], current("config")) if SCHEMA_KEY in raw else None
    if problem is not None:
        raise ConfigError(f"{target} {problem}")
    models = _group(target, raw, "models", MODEL_KEYS)
    limits = _group(target, raw, "limits", LIMIT_KEYS)
    # 0076: null is not declared, the same as an absent key; the setup starter writes null.
    return Config(
        charter_root=_local_docs_folder(raw),
        excluded_roots=_excluded_roots(raw.get("git_excluded_folders")),
        policy=_policy(raw["policy"]) if raw.get("policy") is not None else None,
        standards_sources=_sources(raw.get("coding_rules")),
        max_concurrent_builders=_max_builders(limits),
        audit_retention_days=_retention_days(limits),
        wrapper_read_roots=_wrapper_read_roots(raw, target.parent.parent),
        unit_token_budget=_unit_budget(limits),
        coder_models=_coder_models(models),
        fable_available=_fable_available(models),
        agent_models=_agent_models(models),
        operator=_operator(raw),
    )
