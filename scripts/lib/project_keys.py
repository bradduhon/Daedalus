# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0076: the keys the manifest and config readers accept, as JSON paths, derived from the
# readers' own dataclasses; the setup script and the README key reference test both read them.
from __future__ import annotations

from dataclasses import dataclass, fields

from lib.agent_models import MODELS
from lib.config import (
    AUDIT_RETENTION_FLOOR_DAYS,
    LEDGER_FIELDS,
    Config,
    LedgerDecl,
    PolicyDecl,
    StandardsSource,
)
from lib.manifest import (
    ASSETS_KEYS,
    DEV_SERVER_KEYS,
    DOCS_KEYS,
    DRIVERS,
    FEATURE_KEYS,
    FRAMEWORKS_KEYS,
    LITERACY_LEVELS,
    LITERACY_PROFILE,
    MANIFEST_NAME,
    MAX_PRINCIPLES,
    MAX_RULES,
    NARROWING_KEYS,
    NOT_OVERRIDABLE,
    NOTE_MAX,
    PACKAGE_MANAGERS,
    PRIORITY_ROWS,
    REASONS,
    STACK_KEYS,
    SURFACE,
    TEXT_MAX,
    Assets,
    Docs,
    Features,
    Manifest,
)

MANIFEST_FILE = MANIFEST_NAME
CONFIG_FILE = ".claude/daedalus/config.json"
# 0054, 0073, B2, 0192: the JSON object each flat Manifest field is read from.
_MANIFEST_PARENT = {key: "jail_narrowing" for key in NARROWING_KEYS} | {
    key: "stack" for key in STACK_KEYS
}
# 0158: opt-in feature switches setup never writes; each reads false until the operator sets it.
SETUP_OMITS = frozenset({"terraform_validate"})
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
        elif item.name == "docs":
            keys.extend(f"docs.{key}" for key in DOCS_KEYS)
        elif item.name == "priorities":
            keys.extend(f"priorities.{row}" for row in PRIORITY_ROWS)
        elif item.name == "frameworks":
            keys.extend(f"frameworks.{key}" for key in FRAMEWORKS_KEYS)
        elif item.name == "assets":
            keys.extend(f"assets.{key}" for key in ASSETS_KEYS)
        elif item.name == "dev_server":
            keys.extend(f"dev_server.{key}" for key in DEV_SERVER_KEYS)
        elif item.name in _MANIFEST_PARENT:
            keys.append(f"{_MANIFEST_PARENT[item.name]}.{item.name}")
        else:
            keys.append(item.name)
    keys.extend(f"{MANIFEST_LEDGER}.{key}" for key in LEDGER_FIELDS)
    return tuple(keys)


def _json(value: object) -> object:
    if isinstance(value, tuple):
        return list(value)
    if isinstance(value, dict):
        return {str(k): _json(v) for k, v in value.items()}
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
                f.name: False if "bool" in str(f.type) else None
                for f in fields(Features)
                if f.name not in SETUP_OMITS
            }
        elif item.name == "docs":
            doc["docs"] = {f.name: _json(getattr(Docs(), f.name)) for f in fields(Docs)}
        elif item.name in ("priorities", "frameworks"):
            # 0129, 0157: no priorities or frameworks key; absent is none declared, shipped packs.
            continue
        elif item.name == "assets":
            # 0192, 0076: every key present and empty, so the key reference explains each one.
            doc["assets"] = {f.name: _json(getattr(Assets(), f.name)) for f in fields(Assets)}
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
    "How each ruling is written to the ledger; see the requirements page, the section on "
    "ledger formats",
    "string",
    '`"markdown-table-row"` (one table row per ruling) or `"heading-entry"` (one `## Entry N` '
    "section per ruling)",
    "Required once the block exists",
    '`"markdown-table-row"`',
)
_LEDGER_ID_SCHEME = KeyRow(
    "The pattern each new ruling id follows",
    "string",
    "A pattern such as `{seq:04d}-{repo}-{type}`; a heading ledger uses `{seq}`",
    "Required once the block exists",
    '`"{seq:04d}-{repo}-{type}"`',
)
_LEDGER_SEQUENCE = KeyRow(
    "Where the next ruling number comes from",
    "string",
    '`"last-row-id"` or `"frontmatter:<key>"`',
    "Required once the block exists",
    '`"last-row-id"`',
)
_COMMAND_VALUES = (
    "A non-empty command string, a non-empty list of non-empty command strings run one after "
    "another, or `null`"
)
_COMMAND_KIND = "string, list of strings or null"
_DRIVER_NAMES = ", ".join(f"`{driver}`" for driver in DRIVERS)
# 0134: the docs.literacy values the key reference and the setup command show.
LITERACY_EXAMPLES = (
    *(f'"{level}"' for level in LITERACY_LEVELS),
    f'"{LITERACY_PROFILE}docs/voice-profile.md"',
)
# 0076, B7: one row per reader key; tests hold the README table equal to reference_table().
KEY_ROWS: dict[tuple[str, str], KeyRow] = {
    (MANIFEST_FILE, "jail_narrowing.forbidden_paths"): KeyRow(
        "Paths in your project no coding agent may write, on top of the paths the jail always "
        "protects; see the requirements page, the section on the coder write boundary",
        "list of strings",
        "Project-relative paths with forward slashes and no leading slash, `..` or glob "
        "characters; a trailing slash covers the whole folder, and matching ignores case",
        "`[]`",
        '`["infra/", "scripts/release.sh"]`',
    ),
    (MANIFEST_FILE, "jail_narrowing.forbidden_extensions"): KeyRow(
        "File endings no coding agent may write",
        "list of strings",
        "Endings that each start with a dot and hold no slash or glob characters; matching "
        "ignores case",
        "`[]`",
        '`[".pem", ".tfstate"]`',
    ),
    (MANIFEST_FILE, "features.scope"): KeyRow(
        "Whether a train treats the project as a git repository or as a plain folder",
        "string or null",
        '`"repository"`, `"folder"` or `null`',
        "`null`: a git work tree is a repository, anything else is a plain folder",
        '`"repository"`',
    ),
    (MANIFEST_FILE, "features.secrets_scan"): KeyRow(
        "Turns on the Push Train's gitleaks scan of the commits a push sends; with the scan on, "
        "the Push Train stops when gitleaks is missing or finds a secret, and the doctor's "
        "gitleaks line is a `MISS`",
        "boolean",
        "`true` or `false`",
        "`false`: no scan, and gitleaks need not be installed",
        "`true`",
    ),
    (MANIFEST_FILE, "features.scrub_file"): KeyRow(
        "A file of terms, one per line, that the release step checks the release notes against; "
        "a hit stops the release and names how many terms it found, never the terms",
        "string or null",
        "A project-relative path without a leading slash, `..` or glob characters, or `null`",
        "`null`: nothing is checked",
        '`"docs/scrub-terms.txt"`',
    ),
    (MANIFEST_FILE, "features.ledger"): KeyRow(
        "Turns the decision ledger steps on or off",
        "boolean or null",
        "`true`: the ledger is used, and a train asks before creating one; `false`: no ledger "
        "step and no ledger question; `null`: the default",
        "`null`: a ledger the config declares or the probe finds is used, and none is created",
        "`true`",
    ),
    (MANIFEST_FILE, "features.dependency_web_lookup"): KeyRow(
        "Lets the dependency auditor ask for security advisories on the web; the train sends "
        "its questions to the web researcher. With it off, the auditor judges from the lockfile "
        "and any advisory export the project supplies",
        "boolean or null",
        "`true`, `false` or `null`; only `false` turns the lookup off",
        "`null`: the lookup is on",
        "`false`",
    ),
    (MANIFEST_FILE, "features.terraform_tools"): KeyRow(
        "Lets the Terraform reviewer run `terraform fmt -check` and `terraform validate` on the "
        "Terraform files a train changes; validate also needs `features.terraform_validate`. "
        "With it off, the reviewer judges by reading the files",
        "boolean or null",
        "`true`, `false` or `null`; only `false` turns both commands off; validate also needs "
        "`features.terraform_validate`",
        "`null`: `fmt -check` may run",
        "`false`",
    ),
    (MANIFEST_FILE, "features.terraform_validate"): KeyRow(
        "Lets the Terraform reviewer run `terraform validate`, which starts the provider "
        "programs in a module's `.terraform` folder. Setup never writes it, and "
        "`features.terraform_tools` set to `false` still turns it off",
        "boolean",
        "`true` or `false`",
        "`false`: the reviewer runs no validate and marks that check N/A",
        "`true`",
    ),
    (MANIFEST_FILE, "trains_dir"): KeyRow(
        "The project folder that holds its own train definitions; a train is looked up there "
        "first, as `<trains_dir>/<name>.json`, and then in the plugin's own trains folder; see the "
        "requirements page, the section on project train definitions",
        "string or null",
        "A project-relative folder path without a leading slash, `..` or glob characters, or "
        "`null`",
        "`null`: only the plugin's trains are used",
        '`"trains"`',
    ),
    (MANIFEST_FILE, "stack.unit_test_cmd"): KeyRow(
        "The commands that run the project's unit tests; a coding agent may run each exactly as "
        "written, as one command",
        _COMMAND_KIND,
        _COMMAND_VALUES,
        "`null`: no declared command",
        '`["pytest -q", "pnpm vitest run"]`',
    ),
    (MANIFEST_FILE, "stack.typecheck_cmd"): KeyRow(
        "The commands that type-check the project; a coding agent may run each exactly as "
        "written, as one command",
        _COMMAND_KIND,
        _COMMAND_VALUES,
        "`null`: no declared command",
        '`["mypy src", "pnpm tsc --noEmit"]`',
    ),
    (MANIFEST_FILE, "stack.lint_cmd"): KeyRow(
        "The commands that lint the project; a coding agent may run each exactly as written, as "
        "one command",
        _COMMAND_KIND,
        _COMMAND_VALUES,
        "`null`: no declared command",
        '`"ruff check ."`',
    ),
    (MANIFEST_FILE, "stack.package_manager"): KeyRow(
        "The package manager the project installs with; the doctor prints it on its stack line",
        "string or null",
        ", ".join(f'`"{name}"`' for name in PACKAGE_MANAGERS[:-1])
        + f' or `"{PACKAGE_MANAGERS[-1]}"`, or `null`; any other name is refused',
        "`null`: none declared",
        '`"pnpm"`',
    ),
    (MANIFEST_FILE, "docs.literacy"): KeyRow(
        "How plainly the docs writer writes the public docs at the end of a Build Train, as a "
        "reader level or a voice profile the project declares; a brief may override it",
        "string or null",
        ", ".join(f"`{example}`" for example in LITERACY_EXAMPLES[:-1])
        + f" or `{LITERACY_EXAMPLES[-1]}`, a project-relative path to the profile file without "
        "a leading slash, `..` or glob characters",
        "`null`: the writer keeps the register the public docs already use",
        f"`{LITERACY_EXAMPLES[0]}`",
    ),
    (MANIFEST_FILE, "priorities.drivers"): KeyRow(
        "Which concern wins when two conflict and no rule below matches, for every agent in "
        "every train, never the operator's own session; see the guardrails page, the row on "
        "project priorities",
        "list of strings",
        f"Each of {_DRIVER_NAMES} exactly once, highest first",
        "No `priorities` key: none declared, and agents follow no project ranking",
        '`["security", "trust", "ops", "cost"]`',
    ),
    (MANIFEST_FILE, "priorities.rules[].when.conflict"): KeyRow(
        "The two concerns a rule settles; rules are tried in order and the first match decides",
        "list of two strings",
        f"Two different names of {_DRIVER_NAMES}; at most {MAX_RULES} rules",
        "`rules` absent: no rule, so the ranking decides",
        '`["security", "cost"]`',
    ),
    (MANIFEST_FILE, "priorities.rules[].when.reason"): KeyRow(
        "Why the conflict arises; the rule matches only these reasons",
        "list of strings",
        "One or more of " + ", ".join(f"`{reason}`" for reason in REASONS) + ", each once",
        "Required in each rule",
        '`["certification", "framework"]`',
    ),
    (MANIFEST_FILE, "priorities.rules[].then"): KeyRow(
        f"What a matching rule does: a concern named here wins and the agent decides alone; "
        f"`{SURFACE}` puts the decision to the operator",
        "string",
        f"One of {_DRIVER_NAMES}, or `{SURFACE}`",
        "Required in each rule",
        f'`"{SURFACE}"`',
    ),
    (MANIFEST_FILE, "priorities.rules[].note"): KeyRow(
        "The one line a choice record or a decision brief quotes when the rule applies",
        "string",
        f"One printable line of 1 to {NOTE_MAX} characters",
        "Required in each rule",
        '`"a control a certification asks for wins over its running cost"`',
    ),
    (MANIFEST_FILE, "priorities.principles[].id"): KeyRow(
        "The name an agent cites when a decision rests on one of the project's principles",
        "string",
        f"`P` followed by digits, unique in the block; at most {MAX_PRINCIPLES} principles",
        "`principles` absent: none declared",
        '`"P1"`',
    ),
    (MANIFEST_FILE, "priorities.principles[].driver"): KeyRow(
        "The concern a principle serves",
        "string",
        f"One of {_DRIVER_NAMES}",
        "Required in each principle",
        '`"security"`',
    ),
    (MANIFEST_FILE, "priorities.principles[].text"): KeyRow(
        "The principle itself, as one sentence a decision brief quotes",
        "string",
        f"One printable line of 1 to {TEXT_MAX} characters",
        "Required in each principle",
        '`"Each tenant keeps its own key."`',
    ),
    (MANIFEST_FILE, "priorities.principles[].source"): KeyRow(
        "Where the principle is written down, so a reader can follow it",
        "string",
        "A repo-relative path or a ruling id of the project's own ledger, without a leading "
        "slash, `..` or glob characters",
        "Absent: no source named",
        '`"docs/design.md"`',
    ),
    (MANIFEST_FILE, "priorities.agents.<name>.drivers"): KeyRow(
        "A different ranking for one agent; rules and principles still apply to it",
        "list of strings",
        f"Each of {_DRIVER_NAMES} exactly once; `<name>` is a Daedalus agent file name other "
        f"than `{NOT_OVERRIDABLE}`, which is refused",
        "Absent: the agent follows `priorities.drivers`",
        '`{"coder": {"drivers": ["cost", "security", "ops", "trust"]}}`',
    ),
    (MANIFEST_FILE, "frameworks.pack_dir"): KeyRow(
        "The project folder that holds its own control packs; each subfolder holding a "
        "`pack.json` is one pack; see the requirements page, the section on framework control "
        "packs",
        "string or null",
        "A project-relative folder path without a leading slash, `..` or glob characters, or "
        "`null`",
        "No `frameworks` key: only the packs Daedalus ships are read",
        '`"compliance/packs"`',
    ),
    (MANIFEST_FILE, "frameworks.default_packs"): KeyRow(
        "Whether the packs Daedalus ships are read beside the project's own packs",
        "boolean",
        "`true` or `false`; `false` reads only the packs under `frameworks.pack_dir`",
        "`true`: the shipped packs are read",
        "`false`",
    ),
    (MANIFEST_FILE, "assets.roots"): KeyRow(
        "Folders of asset files, such as models, textures, sounds and shaders, kept out of the "
        "diffs the verifier and the auditor read and out of the secret scan; the doctor warns "
        "about a source file inside one",
        "list of strings",
        "Project-relative folder paths of letters, digits, dots, dashes, underscores and "
        "slashes, without a leading slash, `..` or glob characters",
        "`[]`: no folder is kept out",
        '`["assets/", "public/models/"]`',
    ),
    (MANIFEST_FILE, "assets.extensions"): KeyRow(
        "File endings kept out of those diffs and the secret scan wherever the file sits; "
        "matching keeps case",
        "list of strings",
        "Endings that each start with a dot and hold only letters, digits, dots, dashes and "
        "underscores",
        "`[]`: no ending is kept out",
        '`[".glb", ".png", ".wav"]`',
    ),
    (MANIFEST_FILE, "assets.max_bytes"): KeyRow(
        "The largest changed file the judges read in full; a larger one is listed by name and "
        "size only, and kept out of the diffs and the secret scan",
        "integer or null",
        "A whole number of at least 1, or `null`",
        "`null`: no size limit",
        "`1048576`",
    ),
    (MANIFEST_FILE, "dev_server.url"): KeyRow(
        "The address of the site you host on your own machine for testing; the verify step "
        "asks you to open it, and Daedalus never starts, polls or fetches it",
        "string",
        # 0065: the loopback address reads as a version literal, so the row names it in words.
        "An `http` or `https` address on `localhost` or the IPv4 loopback address, with any "
        "port; any other host is refused",
        "`dev_server: null`: no site is named",
        '`"http://localhost:5173"`',
    ),
    (MANIFEST_FILE, "dev_server.check"): KeyRow(
        "What you check on that site after a unit that changes web code; your answer of pass, "
        "fail or skip goes into the unit's evidence",
        "string",
        "One printable line of plain words",
        "Required once the block exists",
        '`"the scene loads and the player can move"`',
    ),
    (MANIFEST_FILE, "ledger.path"): KeyRow(
        "Where rulings are appended, declared for everyone who works on the project; it wins "
        "over the config's ledger block",
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
        "may write there, and a Build Train branches it as `daedalus/<train-id>`",
        "string or null",
        "A non-empty path to a git repository, written absolute",
        "`null`: those agents write only inside the project, and the contract lives in "
        "`contracts/`",
        '`"/work/decisions"`',
    ),
    (CONFIG_FILE, "standing_rules"): KeyRow(
        "The standing-rules file the planner reads as the rules every plan must satisfy, "
        "derived from the ledger by `scripts/standing_rules.py`; see the requirements page, the "
        "section on the standing-rules backfill file",
        "string or null",
        "A non-empty path; a relative path is read from `charter_root` when one is declared, "
        "else from the project root",
        "`null`: the repository has no standing-rules file",
        '`"standing-rules.md"`',
    ),
    (CONFIG_FILE, "excluded_roots"): KeyRow(
        "Folders whose files must never reach git, GitHub or a redirect. A Daedalus agent is "
        "refused such a command in every session, and the main session is warned during a "
        "train. A document train records the resolved folders in its frozen sources file. "
        "See the guardrails page, the row on excluded roots",
        "list of objects",
        '`{"kind": "path", "path": "<folder>"}`, a folder with `<repo_root>` and '
        "`<charter_root>` filled in and a relative path read from the project root; or "
        '`{"kind": "gitignore", "match": "directories"}` (every folder git ignores) or '
        '`"match": "all"` (every ignored path); a folder holding a linked worktree is skipped',
        "`[]`: no folder is excluded",
        '`[{"kind": "path", "path": "<repo_root>/private/"}]`',
    ),
    (CONFIG_FILE, "ledger.path"): KeyRow(
        "Where rulings are appended on this machine, used when the manifest declares no ledger",
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
        "entries; see the requirements page, the section on standards_sources kinds",
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
        "Which pack shipped with Daedalus to use",
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
        "the plan validator prints",
        "integer",
        "A whole number of at least 1; `true` and `false` are refused",
        "`5`",
        "`3`",
    ),
    (CONFIG_FILE, "audit_retention_days"): KeyRow(
        "How many days a session's audit log is kept after its last record. When a new session "
        "starts writing, older logs are deleted, each named with its final record in the new "
        "session's own log. A log named on a train summary's `Session` line, the log of a train "
        "not yet merged, and the current session's log are never deleted",
        "integer or null",
        f"A whole number of at least {AUDIT_RETENTION_FLOOR_DAYS}, or `null`",
        "`null`: every log is kept",
        "`365`",
    ),
    (CONFIG_FILE, "agent_models"): KeyRow(
        "Which model each catalog agent runs on, in place of the `model:` line of its agent "
        "file; a model a skill is given for one run still comes first",
        "object",
        "Keys are agent names the catalog lists; values are "
        + ", ".join(f'`"{model}"`' for model in MODELS[:-1])
        + f' or `"{MODELS[-1]}"`; any other name or value is refused',
        "`{}`: every agent runs on its agent file's model",
        '`{"coder": "sonnet"}`',
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
