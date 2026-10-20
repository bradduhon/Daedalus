# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0076: the keys the manifest and config readers accept, as JSON paths, derived from the
# readers' own dataclasses; the setup script and the README key reference test both read them.
from __future__ import annotations

from dataclasses import dataclass, fields

from lib.config import (
    AUDIT_RETENTION_FLOOR_DAYS,
    LEDGER_FIELDS,
    Config,
    LedgerDecl,
    PolicyDecl,
    StandardsSource,
)
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


@dataclass(frozen=True)
class KeyRow:
    governs: str
    kind: str
    values: str
    default: str
    example: str


_LEDGER_PATH_VALUES = (
    "A path; `<repo_root>` and `<charter_root>` are filled in, and a relative path is read "
    "from the project root"
)
_LEDGER_FORMAT = KeyRow(
    "How each ruling is written to the ledger (0004)",
    "string",
    '`"markdown-table-row"` (one table row per ruling) or `"heading-entry"` (one `## Entry N` '
    "section per ruling)",
    "Required once the block exists",
    '`"markdown-table-row"`',
)
_LEDGER_ID_SCHEME = KeyRow(
    "The pattern each new ruling id follows (0004)",
    "string",
    "A pattern such as `{seq:04d}-{repo}-{type}`; a heading ledger uses `{seq}`",
    "Required once the block exists",
    '`"{seq:04d}-{repo}-{type}"`',
)
_LEDGER_SEQUENCE = KeyRow(
    "Where the next ruling number comes from (0004)",
    "string",
    '`"last-row-id"` or `"frontmatter:<key>"`',
    "Required once the block exists",
    '`"last-row-id"`',
)
_COMMAND_VALUES = "A non-empty command string, or `null`"
# 0076, B7: one row per reader key; tests hold the README table equal to reference_table().
KEY_ROWS: dict[tuple[str, str], KeyRow] = {
    (MANIFEST_FILE, "jail_narrowing.forbidden_paths"): KeyRow(
        "Paths in your project no coding agent may write, on top of the paths the jail always "
        "protects (0054)",
        "list of strings",
        "Project-relative paths with forward slashes and no leading slash, `..` or glob "
        "characters; a trailing slash covers the whole folder, and matching ignores case",
        "`[]`",
        '`["infra/", "scripts/release.sh"]`',
    ),
    (MANIFEST_FILE, "jail_narrowing.forbidden_extensions"): KeyRow(
        "File endings no coding agent may write (0054)",
        "list of strings",
        "Endings that each start with a dot and hold no slash or glob characters; matching "
        "ignores case",
        "`[]`",
        '`[".pem", ".tfstate"]`',
    ),
    (MANIFEST_FILE, "features.scope"): KeyRow(
        "Whether a train treats the project as a git repository or as a plain folder (0074)",
        "string or null",
        '`"repository"`, `"folder"` or `null`',
        "`null`: a git work tree is a repository, anything else is a plain folder",
        '`"repository"`',
    ),
    (MANIFEST_FILE, "features.secrets_scan"): KeyRow(
        "Turns on the Push Train's gitleaks scan of the commits a push sends; with the scan on, "
        "the Push Train stops when gitleaks is missing or finds a secret, and the doctor's "
        "gitleaks line is a `MISS` (0069)",
        "boolean",
        "`true` or `false`",
        "`false`: no scan, and gitleaks need not be installed",
        "`true`",
    ),
    (MANIFEST_FILE, "features.scrub_file"): KeyRow(
        "A file of terms, one per line, that the release step checks the release notes against; "
        "a hit stops the release and names how many terms it found, never the terms (0069)",
        "string or null",
        "A project-relative path without a leading slash, `..` or glob characters, or `null`",
        "`null`: nothing is checked",
        '`"docs/scrub-terms.txt"`',
    ),
    (MANIFEST_FILE, "features.ledger"): KeyRow(
        "Turns the decision ledger steps on or off (0069)",
        "boolean or null",
        "`true`: the ledger is used, and a train asks before creating one; `false`: no ledger "
        "step and no ledger question; `null`: the default",
        "`null`: a ledger the config declares or the probe finds is used, and none is created",
        "`true`",
    ),
    (MANIFEST_FILE, "trains_dir"): KeyRow(
        "The project folder that holds its own train definitions; a train is looked up there "
        "first, as `<trains_dir>/<name>.json`, and then in the plugin's own trains folder (0073)",
        "string or null",
        "A project-relative folder path without a leading slash, `..` or glob characters, or "
        "`null`",
        "`null`: only the plugin's trains are used",
        '`"trains"`',
    ),
    (MANIFEST_FILE, "stack.unit_test_cmd"): KeyRow(
        "The command that runs the project's unit tests; a coding agent may run it exactly as "
        "written, as one command (0073, 0098)",
        "string or null",
        _COMMAND_VALUES,
        "`null`: no declared command",
        '`"pytest -q"`',
    ),
    (MANIFEST_FILE, "stack.typecheck_cmd"): KeyRow(
        "The command that type-checks the project; a coding agent may run it exactly as "
        "written, as one command (0098)",
        "string or null",
        _COMMAND_VALUES,
        "`null`: no declared command",
        '`"mypy src"`',
    ),
    (MANIFEST_FILE, "stack.lint_cmd"): KeyRow(
        "The command that lints the project; a coding agent may run it exactly as written, as "
        "one command (0098)",
        "string or null",
        _COMMAND_VALUES,
        "`null`: no declared command",
        '`"ruff check ."`',
    ),
    (MANIFEST_FILE, "ledger.path"): KeyRow(
        "Where rulings are appended, declared for everyone who works on the project; it wins "
        "over the config's ledger block (0004)",
        "string",
        _LEDGER_PATH_VALUES,
        "No block, or `ledger: null`: the config's ledger block or the ledger probe is used",
        '`"docs/decisions.md"`',
    ),
    (MANIFEST_FILE, "ledger.format"): _LEDGER_FORMAT,
    (MANIFEST_FILE, "ledger.id_scheme"): _LEDGER_ID_SCHEME,
    (MANIFEST_FILE, "ledger.sequence_source"): _LEDGER_SEQUENCE,
    (CONFIG_FILE, "charter_root"): KeyRow(
        "The repository where your decisions and specs live; the contract and ledger agents "
        "may write there, and a Build Train branches it as `daedalus/<train-id>` (0011)",
        "string or null",
        "A non-empty path to a git repository, written absolute",
        "`null`: those agents write only inside the project, and the contract lives in "
        "`contracts/`",
        '`"/work/decisions"`',
    ),
    (CONFIG_FILE, "ledger.path"): KeyRow(
        "Where rulings are appended on this machine, used when the manifest declares no "
        "ledger (0004)",
        "string",
        _LEDGER_PATH_VALUES,
        "`null`: the ledger probe looks for one",
        '`"<charter_root>/decision-log.md"`',
    ),
    (CONFIG_FILE, "ledger.format"): _LEDGER_FORMAT,
    (CONFIG_FILE, "ledger.id_scheme"): _LEDGER_ID_SCHEME,
    (CONFIG_FILE, "ledger.sequence_source"): _LEDGER_SEQUENCE,
    (CONFIG_FILE, "policy.engine"): KeyRow(
        "The tool for a deterministic policy check on infrastructure changes; no train runs it yet",
        "string",
        '`"cfn-guard"` or `"conftest"`',
        "`policy: null`: none declared",
        '`"conftest"`',
    ),
    (CONFIG_FILE, "policy.path"): KeyRow(
        "The folder that holds your policy rules; no train reads it yet",
        "string",
        "A non-empty path",
        "Required once the block exists",
        '`"/work/decisions/policy"`',
    ),
    (CONFIG_FILE, "standards_sources[].kind"): KeyRow(
        "What one source of your standards is; the standards specialist reads only these "
        "entries (0019)",
        "string",
        '`"rules-dir"` (a folder of rule files), `"file"` (one file) or `"pack"` (a pack '
        "shipped inside the plugin)",
        "`[]`: the Standards Packet is empty",
        '`"rules-dir"`',
    ),
    (CONFIG_FILE, "standards_sources[].path"): KeyRow(
        "Where a rules folder or rules file lives",
        "string",
        "A non-empty path, written absolute; a pack entry carries none",
        "Required for a `rules-dir` or `file` entry",
        '`"/work/rules"`',
    ),
    (CONFIG_FILE, "standards_sources[].name"): KeyRow(
        "Which pack shipped with Daedalus to use (0019)",
        "string",
        "The name of a folder under the plugin's `packs/` that holds a `rules.md`; any other "
        "name is refused",
        "Required for a `pack` entry",
        '`"baseline"`',
    ),
    (CONFIG_FILE, "operator_signing_keys"): KeyRow(
        "Reserved for the key fingerprints allowed to sign merges; no check reads it yet",
        "list of strings",
        "Non-empty strings",
        "`[]`",
        '`["ABCD1234EF567890"]`',
    ),
    (CONFIG_FILE, "max_concurrent_builders"): KeyRow(
        "How many coding agents a parallel stage runs at once, and the cap on the plan width "
        "the plan validator prints (0072)",
        "integer",
        "A whole number of at least 1; `true` and `false` are refused",
        "`5`",
        "`3`",
    ),
    (CONFIG_FILE, "audit_retention_days"): KeyRow(
        "How many days a session's audit log is kept after its last record. When a new session "
        "starts writing, older logs are deleted, each named with its final record in the new "
        "session's own log. A log named on a train summary's `Session` line, the log of a train "
        "not yet merged, and the current session's log are never deleted (issue 50)",
        "integer or null",
        f"A whole number of at least {AUDIT_RETENTION_FLOOR_DAYS}, or `null`",
        "`null`: every log is kept",
        "`365`",
    ),
}
REFERENCE_HEADER = (
    "Key",
    "File",
    "What it governs",
    "Type",
    "Allowed values",
    "Default",
    "Example",
)


def reference_keys() -> tuple[tuple[str, str], ...]:
    manifest = tuple((MANIFEST_FILE, key) for key in manifest_keys())
    return manifest + tuple((CONFIG_FILE, key) for key in config_keys())


def reference_table() -> str:
    # B7: a reader key without a KEY_ROWS entry raises KeyError, so the README test fails.
    lines = [
        "| " + " | ".join(REFERENCE_HEADER) + " |",
        "|" + "---|" * len(REFERENCE_HEADER),
    ]
    for file, key in reference_keys():
        row = KEY_ROWS[(file, key)]
        cells = (
            f"`{key}`",
            f"`{file}`",
            row.governs,
            row.kind,
            row.values,
            row.default,
            row.example,
        )
        lines.append("| " + " | ".join(cell.replace("|", "\\|") for cell in cells) + " |")
    return "\n".join(lines) + "\n"
