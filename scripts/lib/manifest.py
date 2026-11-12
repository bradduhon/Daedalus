# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# The one reader of <repo>/service-manifest.json; ledger.py, the jail and the trains use it.
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field, fields
from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit

from lib.project_root import in_git_work_tree, project_root
from lib.settings_maps import SCHEMA_KEY, current, number_problem
from lib.train_scope import KNOWN_AGENTS

MANIFEST_NAME = "service-manifest.json"
SCOPE_KINDS = ("repository", "folder")
_GLOB = frozenset("*?[]")
_PATHSPEC_WORD = re.compile(r"[A-Za-z0-9._/-]+")


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
    # 0247: true exactly when docs.decisions_filename names a file.
    ledger: bool = False
    # 0132: true, false or null; only false turns the auditor's dependency web lookup off.
    dependency_web_lookup: bool | None = None
    # 0132: true, false or null; only false turns off terraform fmt -check and validate.
    terraform_tools: bool | None = None
    # 0158: true or false; absent reads false, and only true admits terraform validate.
    terraform_validate: bool = False


# 0073: the one list of feature names; validator check 13 and the key reference import it.
FEATURE_KEYS = tuple(f.name for f in fields(Features))
# 0134, 0245: a docs.reading_level value is a level word or profile:<project-relative path>.
LITERACY_LEVELS = ("standard", "expert")
# 0255: the retired level word still loads, so a set project keeps working; it reads standard.
LITERACY_RETIRED = "plain"
LITERACY_PROFILE = "profile:"


@dataclass(frozen=True)
class Docs:
    # 0134: null lets the docs writer keep the register the public docs already use.
    literacy: str | None = None
    # 0245: the project's docs folder, relative to its root.
    folder: str = "docs"
    # 0247: the decisions file's name in the docs folder; null records no decisions.
    decisions_filename: str | None = None
    # 0245: the branch the decisions file's checkout must be on, when one is named.
    git_branch: str | None = None


DOCS_DEFAULT_FOLDER = "docs"
# 0245: the JSON names of each manifest group, in key-table order; tests hold the table to them.
TOP_KEYS = (
    SCHEMA_KEY,
    "commands",
    "docs",
    "checks",
    "prohibited_writes",
    "code_review_exemptions",
    "packages",
    "run_output_priority",
    "local_testing",
    "compliance_rules",
    "custom_workflows_folder",
    "code_areas",
)
COMMAND_KEYS = {"unit_test": "unit_test_cmd", "typecheck": "typecheck_cmd", "lint": "lint_cmd"}
DOCS_KEYS = ("folder", "decisions_filename", "reading_level", "git_branch")
CHECK_KEYS = {
    "secret_scan": "secrets_scan",
    "online_advisory_lookup": "dependency_web_lookup",
    "terraform_format": "terraform_tools",
    "terraform_validate": "terraform_validate",
    "release_banned_terms": "scrub_file",
}
PROHIBITED_KEYS = ("paths", "file_types")
EXEMPTION_KEYS = ("folders", "file_types", "report_over_bytes")
PACKAGE_KEYS = ("allowed_installers", "minimum_age_days", "minimum_age_reason")
PRIORITY_KEYS = ("order", "rules", "principles", "agent_order")
RULE_KEYS = ("between", "reasons", "outcome", "note")
PRINCIPLE_KEYS = ("name", "category", "text")
LOCAL_TESTING_KEYS = ("url", "instructions")
COMPLIANCE_KEYS = ("folder", "use_builtin", "extra_builtin")


@dataclass(frozen=True)
class Frameworks:
    # 0157 (12.1): no pack folder named reads the shipped packs; false reads only pack_dir.
    pack_dir: str | None = None
    default_packs: bool = True
    # 0192: shipped packs whose pack.json says default false, read only when named here.
    packs: tuple[str, ...] = ()


# 0192: the shape of a pack id, as lib.packs.PACK_ID checks it.
_PACK_ID = re.compile(r"[a-z0-9-]{1,40}")
# 0129, Addendum F.2: the four drivers, the closed reason vocabulary and the surface outcome.
DRIVERS = ("security", "trust", "ops", "cost")
# 0245: the file's words for the drivers and the surface outcome, translated here only.
PRIORITY_WORDS = {"security": "security", "trust": "trust", "operations": "ops", "cost": "cost"}
ASK_ME = "ask_me"
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
    "order",
    "rules[].between",
    "rules[].reasons",
    "rules[].outcome",
    "rules[].note",
    "principles[].name",
    "principles[].category",
    "principles[].text",
    "agent_order.<name>",
)
MAX_RULES, MAX_PRINCIPLES, NOTE_MAX, TEXT_MAX = 32, 64, 200, 300
PRINCIPLE_ID = re.compile(r"P[0-9]+")
NOT_OVERRIDABLE = "auditor"
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
class Assets:
    # 0192: asset files kept out of the judges' diffs and the secret scan; never a source file.
    roots: tuple[str, ...] = ()
    extensions: tuple[str, ...] = ()
    max_bytes: int | None = None


# 0128, 0192: endings the judges always read; never an asset ending, never excluded.
SOURCE_EXTENSIONS = (
    *(".sh", ".bash", ".zsh", ".mjs", ".cjs", ".ts", ".tsx", ".js", ".jsx", ".html", ".css"),
    *(".toml", ".ini", ".cfg", ".env", ".txt", ".md", ".json", ".yaml", ".yml", ".tf"),
    *(".tfvars", ".py", ".pyi", ".go", ".rs", ".java", ".kt", ".c", ".h", ".cpp", ".hpp"),
    *(".cs", ".rb", ".php", ".sql"),
)


def is_source(path: str) -> bool:
    # 0192: casefolded, so a case change never turns a source file into an asset.
    return path.casefold().endswith(SOURCE_EXTENSIONS)


@dataclass(frozen=True)
class DevServer:
    # 0164: the operator hosts the site; the plugin only names the url and the check.
    url: str
    check: str


DEV_SERVER_HOSTS = ("localhost", "127.0.0.1")
# 0196: the ecosystems whose frozen, scripts-off install a coder may run when listed.
INSTALL_ECOSYSTEMS = ("npm", "python", "cargo", "go")


# 0197: the release age floor; a lower value needs a reason of at least this many characters.
RELEASE_AGE_DEFAULT = 7
RELEASE_AGE_REASON_MIN = 20


@dataclass(frozen=True)
class Dependencies:
    # 0196: the ecosystems the coder's frozen install is enabled for; none by default.
    installs: tuple[str, ...] = ()
    # 0197: the youngest a resolved version may be, in days, and why it sits below the default.
    minimum_release_age_days: int = RELEASE_AGE_DEFAULT
    minimum_release_age_reason: str | None = None


@dataclass(frozen=True)
class Manifest:
    forbidden_paths: tuple[str, ...] = ()
    forbidden_extensions: tuple[str, ...] = ()
    features: Features = field(default_factory=Features)
    trains_dir: str | None = None
    # 0192: each stack command reads as its commands in order; null is not declared.
    unit_test_cmd: tuple[str, ...] | None = None
    typecheck_cmd: tuple[str, ...] | None = None
    lint_cmd: tuple[str, ...] | None = None
    docs: Docs = field(default_factory=Docs)
    priorities: Priorities | None = None
    frameworks: Frameworks = field(default_factory=Frameworks)
    assets: Assets = field(default_factory=Assets)
    dev_server: DevServer | None = None
    dependencies: Dependencies = field(default_factory=Dependencies)


# 0073, B2: the Manifest fields that hold a command the coder may run verbatim.
STACK_COMMANDS = tuple(COMMAND_KEYS.values())


def declared_commands(manifest: Manifest) -> tuple[str, ...]:
    # 0192: every declared command, flat, in key order then list order.
    return tuple(cmd for key in STACK_COMMANDS for cmd in getattr(manifest, key) or ())


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


def _group(
    target: Path, raw: dict[str, object], name: str, keys: tuple[str, ...] | dict[str, str]
) -> dict[str, object]:
    # 0245: a group is an object of its own keys; null reads as absent; anything else is refused.
    block = raw.get(name)
    if block is None:
        return {}
    if not isinstance(block, dict):
        raise _key_error(target, name, "must be an object")
    unknown = sorted(str(key) for key in set(block) - set(keys))
    if unknown:
        raise _key_error(target, name, f"has unknown keys {unknown} (known: {', '.join(keys)})")
    return block


def _strings(target: Path, block: dict[str, object], group: str, key: str) -> tuple[str, ...]:
    value = block.get(key, [])
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise _key_error(target, f"{group}.{key}", "must be a list of strings")
    return tuple(str(item) for item in value)


def _narrowing(target: Path, raw: dict[str, object]) -> tuple[tuple[str, ...], tuple[str, ...]]:
    block = _group(target, raw, "prohibited_writes", PROHIBITED_KEYS)
    paths = _strings(target, block, "prohibited_writes", "paths")
    extensions = _strings(target, block, "prohibited_writes", "file_types")
    bad_paths = [p for p in paths if not repo_relative(p)]
    if bad_paths:
        raise _key_error(
            target,
            "prohibited_writes.paths",
            f"entries {bad_paths} are not repo-relative forward-slash paths "
            "without a leading slash, '..' or glob characters",
        )
    bad_ext = [e for e in extensions if not _extension_ok(e)]
    if bad_ext:
        raise _key_error(
            target,
            "prohibited_writes.file_types",
            f"entries {bad_ext} must each start with a dot and hold no slash or glob characters",
        )
    return paths, extensions


def _features(target: Path, raw: dict[str, object], docs: Docs) -> Features:
    # 0073, 0245: the checks group; a value outside its type is refused, never ignored.
    block = _group(target, raw, "checks", CHECK_KEYS)
    secrets = block.get("secret_scan", False)
    if not isinstance(secrets, bool):
        raise _key_error(target, "checks.secret_scan", "must be true or false")
    scrub = block.get("release_banned_terms")
    if scrub is not None and not (isinstance(scrub, str) and repo_relative(scrub)):
        raise _key_error(
            target,
            "checks.release_banned_terms",
            "must be null or a project-relative path without a leading slash, '..' or globs",
        )
    validate = block.get("terraform_validate", False)
    if not isinstance(validate, bool):
        raise _key_error(target, "checks.terraform_validate", "must be true or false")
    # 0247: naming a decisions file is the switch; scope is detected, never declared (0245).
    return Features(
        None,
        secrets,
        scrub,
        docs.decisions_filename is not None,
        _switch(target, block, "online_advisory_lookup"),
        _switch(target, block, "terraform_format"),
        validate,
    )


def _switch(target: Path, block: dict[str, object], key: str) -> bool | None:
    # 0069, 0132: a true, false or null check; absent reads as null, and only false is off.
    value = block.get(key)
    if value is not None and not isinstance(value, bool):
        raise _key_error(target, f"checks.{key}", "must be true, false or null")
    return value


def _literacy_ok(value: object) -> bool:
    if value is None or value in (*LITERACY_LEVELS, LITERACY_RETIRED):
        return True
    if not isinstance(value, str) or not value.startswith(LITERACY_PROFILE):
        return False
    return repo_relative(value.removeprefix(LITERACY_PROFILE))


def file_name_ok(value: object) -> bool:
    # 0247: a plain file name, never a path, a glob or a dot name.
    return (
        isinstance(value, str)
        and bool(value.strip())
        and value.isprintable()
        and not ({"/", "\\"} | _GLOB) & set(value)
        and value not in {".", ".."}
    )


def branch_ok(value: object) -> bool:
    # issue 186: a branch name with no spaces or control characters.
    return isinstance(value, str) and value.isprintable() and value.split() == [value]


def _docs(target: Path, raw: dict[str, object]) -> Docs:
    # 0134, 0245: the docs group; unknown keys are refused.
    block = _group(target, raw, "docs", DOCS_KEYS)
    literacy = block.get("reading_level")
    if not _literacy_ok(literacy):
        levels = ", ".join(f'"{level}"' for level in LITERACY_LEVELS)
        raise _key_error(
            target,
            "docs.reading_level",
            f"must be null, one of {levels}, or {LITERACY_PROFILE}<project-relative path to a "
            "voice profile without a leading slash, '..' or globs>",
        )
    folder = block.get("folder", DOCS_DEFAULT_FOLDER)
    if folder is None:
        folder = DOCS_DEFAULT_FOLDER
    if not (isinstance(folder, str) and repo_relative(folder)):
        raise _key_error(
            target,
            "docs.folder",
            "must be a project-relative folder path without a leading slash, '..' or globs",
        )
    name = block.get("decisions_filename")
    if name is not None and not file_name_ok(name):
        raise _key_error(
            target, "docs.decisions_filename", "must be null or a plain file name, not a path"
        )
    branch = block.get("git_branch")
    if branch is not None and not branch_ok(branch):
        raise _key_error(target, "docs.git_branch", "must be null or a branch name with no spaces")
    return Docs(
        literacy if isinstance(literacy, str) else None,
        folder.removesuffix("/"),
        name if isinstance(name, str) else None,
        branch if isinstance(branch, str) else None,
    )


def _frameworks(target: Path, raw: dict[str, object]) -> Frameworks:
    # 0157, 0245: the compliance rules group; unknown keys are refused.
    block = _group(target, raw, "compliance_rules", COMPLIANCE_KEYS)
    pack_dir = block.get("folder")
    if pack_dir is not None and not (isinstance(pack_dir, str) and repo_relative(pack_dir)):
        raise _key_error(
            target,
            "compliance_rules.folder",
            "must be null or a project-relative folder path without a leading slash, '..' or globs",
        )
    default_packs = block.get("use_builtin", True)
    if not isinstance(default_packs, bool):
        raise _key_error(target, "compliance_rules.use_builtin", "must be true or false")
    named = block.get("extra_builtin", [])
    if not (
        isinstance(named, list)
        and all(isinstance(n, str) and _PACK_ID.fullmatch(n) for n in named)
        and len(set(named)) == len(named)
    ):
        raise _key_error(
            target,
            "compliance_rules.extra_builtin",
            "must be a list of distinct built-in rule set ids, each of lowercase letters, digits "
            "and hyphens",
        )
    return Frameworks(pack_dir, default_packs, tuple(named))


def _bad(target: Path, row: str, detail: str) -> PrioritiesError:
    key = f"run_output_priority.{row}" if row else "run_output_priority"
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


_WORDS = list(PRIORITY_WORDS)


def _priority(value: object) -> str | None:
    # 0245: the file's priority word to the internal driver name, or None when it is not one.
    return PRIORITY_WORDS.get(value) if isinstance(value, str) else None


def _ranking(target: Path, value: object, row: str) -> tuple[str, ...]:
    # 0129, F.6: exactly the four priority words, each once.
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise _bad(target, row, f"must be a list of the priority words {_WORDS}")
    repeated = sorted({item for item in value if value.count(item) > 1})
    if repeated:
        raise _bad(target, row, f"repeats {repeated[0]!r}")
    if sorted(value) != sorted(_WORDS):
        raise _bad(target, row, f"must name each of {_WORDS} once, in rank order")
    return tuple(PRIORITY_WORDS[str(item)] for item in value)


def _rule(target: Path, value: object) -> Rule:
    rule = _object(target, value, "rules[].outcome", set(RULE_KEYS), set(RULE_KEYS))
    between = rule["between"]
    pair = [_priority(item) for item in between] if isinstance(between, list) else []
    if len(pair) != 2 or None in pair or pair[0] == pair[1]:
        raise _bad(target, "rules[].between", f"must name two different priorities of {_WORDS}")
    reason = rule["reasons"]
    if not isinstance(reason, list) or not reason or len(set(map(str, reason))) != len(reason):
        raise _bad(target, "rules[].reasons", "must list one or more reasons, each once")
    outside = [item for item in reason if item not in REASONS]
    if outside:
        raise _bad(
            target,
            "rules[].reasons",
            f"names {outside[0]!r}, outside the reason vocabulary {list(REASONS)}",
        )
    outcome = rule["outcome"]
    then = SURFACE if outcome == ASK_ME else _priority(outcome)
    if then is None:
        raise _bad(target, "rules[].outcome", f"must be a priority of {_WORDS} or {ASK_ME!r}")
    note = _line(target, rule["note"], "rules[].note", NOTE_MAX)
    return Rule((str(pair[0]), str(pair[1])), tuple(map(str, reason)), then, note)


def _principle(target: Path, value: object, seen: set[str]) -> Principle:
    item = _object(target, value, "principles[].name", set(PRINCIPLE_KEYS), set(PRINCIPLE_KEYS))
    ident = item["name"]
    if not isinstance(ident, str) or not PRINCIPLE_ID.fullmatch(ident) or ident in seen:
        raise _bad(target, "principles[].name", "must be P followed by digits, unique in the list")
    seen.add(ident)
    driver = _priority(item["category"])
    if driver is None:
        raise _bad(target, "principles[].category", f"must be one of {_WORDS}")
    text = _line(target, item["text"], "principles[].text", TEXT_MAX)
    return Principle(ident, driver, text)


def _overrides(target: Path, value: object) -> tuple[tuple[str, tuple[str, ...]], ...]:
    # 0129, F.2: the security auditor's ranking is never overridable.
    row = "agent_order.<name>"
    if not isinstance(value, dict):
        raise _bad(target, row, "agent_order must be an object keyed by agent name")
    out: list[tuple[str, tuple[str, ...]]] = []
    for raw_name, entry in value.items():
        name = str(raw_name)
        if name == NOT_OVERRIDABLE:
            raise _bad(target, row, f"names {NOT_OVERRIDABLE}, whose ranking no project overrides")
        if name not in KNOWN_AGENTS - {"main"}:
            raise _bad(target, row, f"names {name!r}, which is not a Daedalus agent file name")
        out.append((name, _ranking(target, entry, row)))
    return tuple(out)


def _bounded_list(target: Path, value: object, row: str, limit: int) -> list[object]:
    if not isinstance(value, list) or len(value) > limit:
        raise _bad(target, row, f"must be a list of at most {limit} entries")
    return value


def _priorities(target: Path, raw: dict[str, object]) -> Priorities | None:
    # 0129, F.6, 0076: absent or null is none declared; anything off the field table is refused.
    if raw.get("run_output_priority") is None:
        return None
    block = _object(target, raw["run_output_priority"], "", set(PRIORITY_KEYS), {"order"})
    drivers = _ranking(target, block["order"], "order")
    rules = _bounded_list(target, block.get("rules", []), "rules[].outcome", MAX_RULES)
    principles = _bounded_list(
        target, block.get("principles", []), "principles[].name", MAX_PRINCIPLES
    )
    seen: set[str] = set()
    return Priorities(
        drivers,
        tuple(_rule(target, rule) for rule in rules),
        tuple(_principle(target, item, seen) for item in principles),
        _overrides(target, block.get("agent_order", {})),
    )


def _trains_dir(target: Path, raw: dict[str, object]) -> str | None:
    # 0245: the folder of the project's own run definitions, an override.
    value = raw.get("custom_workflows_folder")
    if value is None:
        return None
    if not isinstance(value, str) or not repo_relative(value):
        raise _key_error(
            target,
            "custom_workflows_folder",
            "must be a project-relative folder path without a leading slash, '..' or globs",
        )
    return value


def _command_list(value: object) -> tuple[str, ...] | None:
    # 0192: a non-empty string, or a non-empty list of non-empty strings; None when neither.
    if isinstance(value, str):
        return (value,) if value.strip() else None
    if not isinstance(value, list) or not value:
        return None
    if not all(isinstance(item, str) and item.strip() for item in value):
        return None
    return tuple(str(item) for item in value)


def _stack_commands(target: Path, raw: dict[str, object]) -> dict[str, tuple[str, ...] | None]:
    # 0192, 0245: the commands group, each JSON name read onto its Manifest field.
    group = _group(target, raw, "commands", COMMAND_KEYS)
    out: dict[str, tuple[str, ...] | None] = {}
    for key, attr in COMMAND_KEYS.items():
        value = group.get(key)
        commands = None if value is None else _command_list(value)
        if value is not None and commands is None:
            raise _key_error(
                target,
                f"commands.{key}",
                "must be null, a non-empty string, or a non-empty list of non-empty strings",
            )
        # 93: a line break or other control character could forge a line wherever it prints.
        if commands is not None and not all(cmd.isprintable() for cmd in commands):
            raise _key_error(
                target,
                f"commands.{key}",
                "holds a control character, such as a line break; each command must be one "
                "printable line (93)",
            )
        out[attr] = commands
    return out


def pathspec_safe(entry: str) -> bool:
    # 0192: a word that renders unquoted in gitleaks --log-opts and single-quoted in git diff.
    return bool(_PATHSPEC_WORD.fullmatch(entry))


def _assets(target: Path, raw: dict[str, object]) -> Assets:
    # 0192, 0245: folders and file types as prohibited writes checks them, as pathspec words.
    block = _group(target, raw, "code_review_exemptions", EXEMPTION_KEYS)
    roots = block.get("folders", [])
    if not isinstance(roots, list) or not all(
        isinstance(r, str) and repo_relative(r) and pathspec_safe(r) for r in roots
    ):
        raise _key_error(
            target,
            "code_review_exemptions.folders",
            "must be a list of project-relative folder paths of letters, digits, dots, dashes, "
            "underscores and slashes, without a leading slash, '..' or globs",
        )
    extensions = block.get("file_types", [])
    if not isinstance(extensions, list) or not all(
        isinstance(e, str) and _extension_ok(e) and pathspec_safe(e) for e in extensions
    ):
        raise _key_error(
            target,
            "code_review_exemptions.file_types",
            "must be a list of endings that each start with a dot and hold only letters, "
            "digits, dots, dashes and underscores",
        )
    sources = [str(e) for e in extensions if is_source(str(e))]
    if sources:
        raise _key_error(
            target,
            "code_review_exemptions.file_types",
            f"names the source endings {sources}, which the judges always read and the secret "
            "scan always covers",
        )
    size = block.get("report_over_bytes")
    if size is not None and (isinstance(size, bool) or not isinstance(size, int) or size < 1):
        raise _key_error(
            target,
            "code_review_exemptions.report_over_bytes",
            "must be null or a whole number of at least 1",
        )
    return Assets(tuple(map(str, roots)), tuple(map(str, extensions)), size)


def _dependencies(target: Path, raw: dict[str, object]) -> Dependencies:
    # 0196, 0197, 0245: the packages group; each installer named once; a lowered age has a reason.
    block = _group(target, raw, "packages", PACKAGE_KEYS)
    installs = block.get("allowed_installers", [])
    if (
        not isinstance(installs, list)
        or not all(isinstance(e, str) and e in INSTALL_ECOSYSTEMS for e in installs)
        or len(set(installs)) != len(installs)
    ):
        names = ", ".join(INSTALL_ECOSYSTEMS)
        raise _key_error(
            target,
            "packages.allowed_installers",
            f"must be a list naming each of {names} at most once (0196)",
        )
    days = block.get("minimum_age_days", RELEASE_AGE_DEFAULT)
    if isinstance(days, bool) or not isinstance(days, int) or days < 0:
        raise _key_error(target, "packages.minimum_age_days", "must be a whole number of 0 or more")
    reason = block.get("minimum_age_reason")
    if reason is not None and (not isinstance(reason, str) or not reason.isprintable()):
        raise _key_error(
            target, "packages.minimum_age_reason", "must be null or one printable line"
        )
    if days < RELEASE_AGE_DEFAULT and len((reason or "").strip()) < RELEASE_AGE_REASON_MIN:
        raise _key_error(
            target,
            "packages.minimum_age_days",
            f"is below {RELEASE_AGE_DEFAULT} days, which needs a packages.minimum_age_reason "
            f"of at least {RELEASE_AGE_REASON_MIN} characters (0197)",
        )
    return Dependencies(tuple(map(str, installs)), days, reason)


def _local_url(url: object) -> bool:
    # 0164: http or https on this machine, a port of 1 to 65535 or none, no user part.
    if not isinstance(url, str) or not url.isprintable() or any(c.isspace() for c in url):
        return False
    parts = urlsplit(url)
    try:
        port = parts.port  # urlsplit raises here on a port outside 0 to 65535.
    except ValueError:
        return False
    return (
        port != 0
        and parts.scheme in ("http", "https")
        and parts.hostname in DEV_SERVER_HOSTS
        and parts.username is None
        and parts.password is None
    )


def _dev_server(target: Path, raw: dict[str, object]) -> DevServer | None:
    # 0164: the plugin names the operator's local site; it never starts or fetches it.
    if raw.get("local_testing") is None:
        return None
    block = _group(target, raw, "local_testing", LOCAL_TESTING_KEYS)
    missing = sorted(set(LOCAL_TESTING_KEYS) - set(block))
    if missing:
        known = ", ".join(LOCAL_TESTING_KEYS)
        raise _key_error(target, "local_testing", f"lacks {', '.join(missing)} (known: {known})")
    url = block["url"]
    if not _local_url(url):
        hosts = " or ".join(DEV_SERVER_HOSTS)
        raise _key_error(target, "local_testing.url", f"must be an http or https url on {hosts}")
    check = block["instructions"]
    if not isinstance(check, str) or not check.strip() or not check.isprintable() or "`" in check:
        raise _key_error(
            target,
            "local_testing.instructions",
            "must be one printable line of plain words without backticks",
        )
    return DevServer(str(url), check)


def _entrypoints(target: Path, raw: dict[str, object]) -> None:
    # 0245: the project's file areas the planner reads; an object of names to paths.
    value = raw.get("code_areas")
    if value is not None and not (
        isinstance(value, dict) and all(isinstance(v, str) for v in value.values())
    ):
        raise _key_error(target, "code_areas", "must be an object of area names to paths")


def load(repo: Path) -> Manifest | None:
    raw = read_raw(repo)
    if raw is None:
        return None
    return parse(raw, manifest_path(repo))


def parse(raw: object, target: Path) -> Manifest:
    # 0242: the one check of a parsed manifest; setup runs it on a changed document before writing.
    if not isinstance(raw, dict):
        raise ManifestError(
            f"{target} is not a JSON object. Next: start from the example in "
            "docs/project-requirements.md."
        )
    # 0245: an unknown top-level key, an old name included, is refused with the valid names.
    unknown = sorted(str(key) for key in set(raw) - set(TOP_KEYS))
    if unknown:
        raise ManifestError(
            f"{target} has unknown keys {unknown} (known: {', '.join(TOP_KEYS)}). "
            "Next: delete or rename those keys in the service manifest, then rerun."
        )
    # 0264: no schema number reads as today; one outside 1 to the current number is refused.
    problem = number_problem(raw[SCHEMA_KEY], current("manifest")) if SCHEMA_KEY in raw else None
    if problem is not None:
        raise ManifestError(f"{target} {problem}")
    _entrypoints(target, raw)
    paths, extensions = _narrowing(target, raw)
    commands = _stack_commands(target, raw)
    docs = _docs(target, raw)
    return Manifest(
        paths,
        extensions,
        features=_features(target, raw, docs),
        trains_dir=_trains_dir(target, raw),
        unit_test_cmd=commands["unit_test_cmd"],
        typecheck_cmd=commands["typecheck_cmd"],
        lint_cmd=commands["lint_cmd"],
        docs=docs,
        priorities=_priorities(target, raw),
        frameworks=_frameworks(target, raw),
        assets=_assets(target, raw),
        dev_server=_dev_server(target, raw),
        dependencies=_dependencies(target, raw),
    )


def features(repo: Path) -> Features:
    # 0069: no manifest means every feature at its absent default.
    loaded = load(repo)
    return loaded.features if loaded is not None else Features()


def scope_kind(root: Path, declared: Features) -> Literal["repository", "folder"]:
    # 0074: a declared scope key wins; else a git work tree is repository scope, else folder.
    return declared.scope or ("repository" if in_git_work_tree(root) else "folder")


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
