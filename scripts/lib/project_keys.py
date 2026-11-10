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
    LEDGER_OPTIONAL,
    Config,
    LedgerDecl,
    PolicyDecl,
    StandardsSource,
)
from lib.manifest import (
    ASSETS_KEYS,
    DEPENDENCIES_KEYS,
    DEV_SERVER_KEYS,
    DOCS_KEYS,
    DRIVERS,
    FEATURE_KEYS,
    FRAMEWORKS_KEYS,
    INSTALL_ECOSYSTEMS,
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
    RELEASE_AGE_DEFAULT,
    RELEASE_AGE_REASON_MIN,
    STACK_KEYS,
    SURFACE,
    TEXT_MAX,
    Assets,
    Dependencies,
    Docs,
    Features,
    Manifest,
)
from lib.operator_file import MAIN_REFUSAL_CLASSES, OPERATOR_FILE, PROFILE_KEYS

MANIFEST_FILE = MANIFEST_NAME
CONFIG_FILE = ".claude/daedalus/config.json"
# 0235: the user-scope operator file, shown as written in a shell.
OPERATOR_FILE_NAME = "~/" + OPERATOR_FILE.as_posix()
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
        elif item.name == "dependencies":
            keys.extend(f"dependencies.{key}" for key in DEPENDENCIES_KEYS)
        elif item.name in _MANIFEST_PARENT:
            keys.append(f"{_MANIFEST_PARENT[item.name]}.{item.name}")
        else:
            keys.append(item.name)
    keys.extend(f"{MANIFEST_LEDGER}.{key}" for key in (*LEDGER_FIELDS, *LEDGER_OPTIONAL))
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
        elif item.name == "dependencies":
            # 0196: every key present at its default, so the key reference explains each one.
            doc["dependencies"] = {
                f.name: _json(getattr(Dependencies(), f.name)) for f in fields(Dependencies)
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
    # 0235: the operator override is opt-in and never written by setup.
    return {
        item.name: _json(getattr(base, item.name))
        for item in fields(Config)
        if item.name != "operator"
    }


def operator_keys() -> tuple[str, ...]:
    # 0235: the operator file's keys as JSON paths, from operator_file's own tables.
    return ("main_refusals", *(f"profile.{key}" for key in PROFILE_KEYS))


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
    # 0242: one plain sentence on what changes for the user; no key name, path or id in it.
    affects: str
    # 0242: the files that act on the value, never its validator alone; () means not active.
    readers: tuple[str, ...]


# 0242: the opening of every affects sentence whose key no code acts on yet.
NOT_ACTIVE = "Nothing acts on it yet"
_LEDGER_READERS = ("scripts/lib/ledger.py", "scripts/append_ledger.py")
_STANDARDS = "skills/plan/standards/SKILL.md"


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
    "Each new ruling is written to the ledger in this shape.",
    _LEDGER_READERS,
)
_LEDGER_ID_SCHEME = KeyRow(
    "The pattern each new ruling id follows",
    "string",
    "A pattern such as `{seq:04d}-{repo}-{type}`; a heading ledger uses `{seq}`",
    "Required once the block exists",
    '`"{seq:04d}-{repo}-{type}"`',
    "Each new ruling id follows this pattern.",
    _LEDGER_READERS,
)
_LEDGER_SEQUENCE = KeyRow(
    "Where the next ruling number comes from",
    "string",
    '`"last-row-id"` or `"frontmatter:<key>"`',
    "Required once the block exists",
    '`"last-row-id"`',
    "The next ruling number is read from this place.",
    _LEDGER_READERS,
)
_LEDGER_BRANCH = KeyRow(
    "The branch the ledger's checkout must be on; an append or a probe on any other branch, or "
    "on a detached HEAD, is refused, and Daedalus never switches the branch itself",
    "string or null",
    "A branch name with no spaces; refused beside a ledger path holding `<charter_root>`, "
    "because a run branches that repository as `daedalus/<train-id>`",
    "Absent or `null`: the ledger is written on whatever branch its checkout is on",
    '`"main"`',
    "A ruling written while the ledger's checkout is on any other branch is refused.",
    _LEDGER_READERS,
)
_COMMAND_VALUES = (
    "A non-empty command string, a non-empty list of non-empty command strings run one after "
    "another, or `null`; a command holding a line break or other control character is refused"
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
        "A coding agent is refused every write to these paths, and the health check counts them.",
        ("scripts/lib/manifest.py", "scripts/daedalus_doctor.py"),
    ),
    (MANIFEST_FILE, "jail_narrowing.forbidden_extensions"): KeyRow(
        "File endings no coding agent may write",
        "list of strings",
        "Endings that each start with a dot and hold no slash or glob characters; matching "
        "ignores case",
        "`[]`",
        '`[".pem", ".tfstate"]`',
        "A coding agent is refused every write to a file with one of these endings.",
        ("scripts/lib/manifest.py", "scripts/daedalus_doctor.py"),
    ),
    (MANIFEST_FILE, "features.scope"): KeyRow(
        "Whether a train treats the project as a git repository or as a plain folder",
        "string or null",
        '`"repository"`, `"folder"` or `null`',
        "`null`: a git work tree is a repository, anything else is a plain folder",
        '`"repository"`',
        "A run works on the project as a git repository it can push, or as a plain folder.",
        ("scripts/lib/workspace.py", "scripts/daedalus_doctor.py"),
    ),
    (MANIFEST_FILE, "features.secrets_scan"): KeyRow(
        "Turns on the Push Train's gitleaks scan of the commits a push sends; with the scan on, "
        "the Push Train stops when gitleaks is missing or finds a secret, and the doctor's "
        "gitleaks line is a `MISS`",
        "boolean",
        "`true` or `false`",
        "`false`: no scan, and gitleaks need not be installed",
        "`true`",
        "The push step scans the commits it sends for secrets and stops on a hit.",
        ("scripts/daedalus_doctor.py", "skills/release/SKILL.md"),
    ),
    (MANIFEST_FILE, "features.scrub_file"): KeyRow(
        "A file of terms, one per line, that the release step checks the release notes against; "
        "a hit stops the release and names how many terms it found, never the terms",
        "string or null",
        "A project-relative path without a leading slash, `..` or glob characters, or `null`",
        "`null`: nothing is checked",
        '`"docs/scrub-terms.txt"`',
        "The release step checks the release notes against your list of terms.",
        ("scripts/lib/scrub.py",),
    ),
    (MANIFEST_FILE, "features.ledger"): KeyRow(
        "Turns the decision ledger steps on or off",
        "boolean or null",
        "`true`: the ledger is used, and a train asks before creating one; `false`: no ledger "
        "step and no ledger question; `null`: the default",
        "`null`: a ledger the config declares or the probe finds is used, and none is created",
        "`true`",
        "A run records each ruling in a decision ledger, or skips every ledger step.",
        ("scripts/lib/workspace.py", "scripts/lib/train_runner.py"),
    ),
    (MANIFEST_FILE, "features.dependency_web_lookup"): KeyRow(
        "Lets the auditor ask for security advisories on the web; the train sends "
        "its questions to the web researcher. With it off, the auditor judges from the lockfile "
        "and any advisory export the project supplies",
        "boolean or null",
        "`true`, `false` or `null`; only `false` turns the lookup off",
        "`null`: the lookup is on",
        "`false`",
        "The audit looks up security advisories on the web, or judges from the lockfile alone.",
        ("skills/audit/SKILL.md", "agents/auditor.md"),
    ),
    (MANIFEST_FILE, "features.terraform_tools"): KeyRow(
        "Lets the auditor run `terraform fmt -check` and `terraform validate` on the "
        "Terraform files a train changes; validate also needs `features.terraform_validate`. "
        "With it off, the auditor judges by reading the files",
        "boolean or null",
        "`true`, `false` or `null`; only `false` turns both commands off; validate also needs "
        "`features.terraform_validate`",
        "`null`: `fmt -check` may run",
        "`false`",
        "The audit may run the Terraform format check on changed Terraform files, or only reads "
        "them.",
        ("skills/audit/SKILL.md", "agents/auditor.md", "scripts/checks/command_allowlist.py"),
    ),
    (MANIFEST_FILE, "features.terraform_validate"): KeyRow(
        "Lets the auditor run `terraform validate`, which starts the provider "
        "programs in a module's `.terraform` folder. Setup never writes it, and "
        "`features.terraform_tools` set to `false` still turns it off",
        "boolean",
        "`true` or `false`",
        "`false`: the auditor runs no validate and marks that check N/A",
        "`true`",
        "The audit may also run the Terraform validate check, which starts provider programs.",
        ("scripts/checks/command_allowlist.py", "packs/judges/terraform.md"),
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
        "A run looks for its run definitions in this folder before the plugin's own.",
        ("scripts/lib/train_runner.py",),
    ),
    (MANIFEST_FILE, "stack.unit_test_cmd"): KeyRow(
        "The commands that run the project's unit tests; a coding agent may run each exactly as "
        "written, as one command",
        _COMMAND_KIND,
        _COMMAND_VALUES,
        "`null`: no declared command",
        '`["pytest -q", "pnpm vitest run"]`',
        "A coding agent may run these test commands as written, inside the test wrapper.",
        ("agents/coder.md", "scripts/checks/confine.py", "scripts/daedalus_doctor.py"),
    ),
    (MANIFEST_FILE, "stack.typecheck_cmd"): KeyRow(
        "The commands that type-check the project; a coding agent may run each exactly as "
        "written, as one command",
        _COMMAND_KIND,
        _COMMAND_VALUES,
        "`null`: no declared command",
        '`["mypy src", "pnpm tsc --noEmit"]`',
        "A coding agent may run these type-check commands as written.",
        ("agents/coder.md", "scripts/daedalus_doctor.py"),
    ),
    (MANIFEST_FILE, "stack.lint_cmd"): KeyRow(
        "The commands that lint the project; a coding agent may run each exactly as written, as "
        "one command",
        _COMMAND_KIND,
        _COMMAND_VALUES,
        "`null`: no declared command",
        '`"ruff check ."`',
        "A coding agent may run these lint commands as written.",
        ("agents/coder.md", "scripts/daedalus_doctor.py"),
    ),
    (MANIFEST_FILE, "stack.package_manager"): KeyRow(
        "The package manager the project installs with; the doctor prints it on its stack line",
        "string or null",
        ", ".join(f'`"{name}"`' for name in PACKAGE_MANAGERS[:-1])
        + f' or `"{PACKAGE_MANAGERS[-1]}"`, or `null`; any other name is refused',
        "`null`: none declared",
        '`"pnpm"`',
        "The health check names this package manager on its stack line.",
        ("scripts/daedalus_doctor.py",),
    ),
    (MANIFEST_FILE, "docs.literacy"): KeyRow(
        "How plainly Daedalus writes for people, as a reader level or a voice profile the "
        "project declares. The docs writer writes the public docs at the end of a run at this "
        "level, and a brief may override it. The orchestrator's decision briefs and the "
        "questions the plan and verify phases put to you are written at this level, and the "
        "decision brief check holds each brief to it, reading a voice profile as `plain`. "
        "Brainstorm questions are always plain, whatever this key says",
        "string or null",
        ", ".join(f"`{example}`" for example in LITERACY_EXAMPLES[:-1])
        + f" or `{LITERACY_EXAMPLES[-1]}`, a project-relative path to the profile file without "
        "a leading slash, `..` or glob characters",
        "`null`: the writer keeps the register the public docs already use; decision briefs are "
        "written and checked at `standard`, and the plan and verify questions are written at "
        "`standard`",
        f"`{LITERACY_EXAMPLES[0]}`",
        "The public docs, the decision briefs and the questions a run asks you are written at "
        "this reading level.",
        (
            "scripts/lib/briefs.py",
            "skills/document/kinds/public-docs/SKILL.md",
            "skills/plan/SKILL.md",
            "skills/verify/SKILL.md",
            "agents/orchestrator.md",
        ),
    ),
    (MANIFEST_FILE, "priorities.drivers"): KeyRow(
        "Which concern wins when two conflict and no rule below matches, for every agent in "
        "every train, never the operator's own session; see the guardrails page, the row on "
        "project priorities",
        "list of strings",
        f"Each of {_DRIVER_NAMES} exactly once, highest first",
        "No `priorities` key: none declared, and agents follow no project ranking",
        '`["security", "trust", "ops", "cost"]`',
        "Every agent in a run settles a clash between two concerns by this ranking.",
        (_STANDARDS, "scripts/daedalus_doctor.py"),
    ),
    (MANIFEST_FILE, "priorities.rules[].when.conflict"): KeyRow(
        "The two concerns a rule settles; rules are tried in order and the first match decides",
        "list of two strings",
        f"Two different names of {_DRIVER_NAMES}; at most {MAX_RULES} rules",
        "`rules` absent: no rule, so the ranking decides",
        '`["security", "cost"]`',
        "A rule applies only to a clash between these two concerns.",
        ("agents/orchestrator.md",),
    ),
    (MANIFEST_FILE, "priorities.rules[].when.reason"): KeyRow(
        "Why the conflict arises; the rule matches only these reasons",
        "list of strings",
        "One or more of " + ", ".join(f"`{reason}`" for reason in REASONS) + ", each once",
        "Required in each rule",
        '`["certification", "framework"]`',
        "A rule applies only when the clash arises for one of these reasons.",
        (_STANDARDS, "agents/orchestrator.md"),
    ),
    (MANIFEST_FILE, "priorities.rules[].then"): KeyRow(
        f"What a matching rule does: a concern named here wins and the agent decides alone; "
        f"`{SURFACE}` puts the decision to the operator",
        "string",
        f"One of {_DRIVER_NAMES}, or `{SURFACE}`",
        "Required in each rule",
        f'`"{SURFACE}"`',
        "A matching rule lets the agent decide alone, or puts the choice to you.",
        (_STANDARDS, "scripts/lib/train_summary.py"),
    ),
    (MANIFEST_FILE, "priorities.rules[].note"): KeyRow(
        "The one line a choice record or a decision brief quotes when the rule applies",
        "string",
        f"One printable line of 1 to {NOTE_MAX} characters",
        "Required in each rule",
        '`"a control a certification asks for wins over its running cost"`',
        "Choice records and decision briefs quote this line when the rule applies.",
        (_STANDARDS,),
    ),
    (MANIFEST_FILE, "priorities.principles[].id"): KeyRow(
        "The name an agent cites when a decision rests on one of the project's principles",
        "string",
        f"`P` followed by digits, unique in the block; at most {MAX_PRINCIPLES} principles",
        "`principles` absent: none declared",
        '`"P1"`',
        "Agents cite the principle by this name when a decision rests on it.",
        (_STANDARDS,),
    ),
    (MANIFEST_FILE, "priorities.principles[].driver"): KeyRow(
        "The concern a principle serves",
        "string",
        f"One of {_DRIVER_NAMES}",
        "Required in each principle",
        '`"security"`',
        "The run's standards list the principle under this concern.",
        (_STANDARDS,),
    ),
    (MANIFEST_FILE, "priorities.principles[].text"): KeyRow(
        "The principle itself, as one sentence a decision brief quotes",
        "string",
        f"One printable line of 1 to {TEXT_MAX} characters",
        "Required in each principle",
        '`"Each tenant keeps its own key."`',
        "Decision briefs quote this sentence when a decision rests on the principle.",
        (_STANDARDS,),
    ),
    (MANIFEST_FILE, "priorities.principles[].source"): KeyRow(
        "Where the principle is written down, so a reader can follow it",
        "string",
        "A repo-relative path or a ruling id of the project's own ledger, without a leading "
        "slash, `..` or glob characters",
        "Absent: no source named",
        '`"docs/design.md"`',
        f"{NOT_ACTIVE}: the run's standards list each principle without its source.",
        (),
    ),
    (MANIFEST_FILE, "priorities.agents.<name>.drivers"): KeyRow(
        "A different ranking for one agent; rules and principles still apply to it",
        "list of strings",
        f"Each of {_DRIVER_NAMES} exactly once; `<name>` is a Daedalus agent file name other "
        f"than `{NOT_OVERRIDABLE}`, which is refused",
        "Absent: the agent follows `priorities.drivers`",
        '`{"coder": {"drivers": ["cost", "security", "ops", "trust"]}}`',
        "That one agent ranks the concerns in this order instead.",
        (_STANDARDS,),
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
        "The audit also judges each change against the control packs in this folder.",
        ("scripts/lib/packs.py",),
    ),
    (MANIFEST_FILE, "frameworks.default_packs"): KeyRow(
        "Whether the packs Daedalus ships are read beside the project's own packs",
        "boolean",
        "`true` or `false`; `false` reads only the packs under `frameworks.pack_dir` and the "
        "packs named in `frameworks.packs`",
        "`true`: the shipped packs that are on by default are read",
        "`false`",
        "The audit reads the control packs Daedalus ships, or only your own and the named ones.",
        ("scripts/lib/packs.py",),
    ),
    (MANIFEST_FILE, "frameworks.packs"): KeyRow(
        "Shipped packs that are off until a project names them, such as the cost-tier pack; "
        "a named pack is read even when `frameworks.default_packs` is `false`",
        "list of strings",
        "Pack ids of lowercase letters, digits and hyphens, each named once",
        "`[]`: only the shipped packs that are on by default are read",
        '`["cost-tier"]`',
        "The audit also reads these shipped control packs that are off by default.",
        ("scripts/lib/packs.py",),
    ),
    (MANIFEST_FILE, "assets.roots"): KeyRow(
        "Folders of asset files, such as models, textures, sounds and shaders, kept out of the "
        "diffs the verifier and the auditor read and out of the secret scan. A source file "
        "inside one, such as a `.py` or `.ts` file, is never kept out, and the doctor and the "
        "auditor report it",
        "list of strings",
        "Project-relative folder paths of letters, digits, dots, dashes, underscores and "
        "slashes, without a leading slash, `..` or glob characters",
        "`[]`: no folder is kept out",
        '`["assets/", "public/models/"]`',
        "The checks and the secret scan skip asset files in these folders.",
        ("scripts/lib/assets.py",),
    ),
    (MANIFEST_FILE, "assets.extensions"): KeyRow(
        "File endings kept out of those diffs and the secret scan wherever the file sits; "
        "matching keeps case",
        "list of strings",
        "Endings that each start with a dot and hold only letters, digits, dots, dashes and "
        "underscores; a source ending such as `.py`, `.ts`, `.json` or `.env` is refused",
        "`[]`: no ending is kept out",
        '`[".glb", ".png", ".wav"]`',
        "The checks and the secret scan skip files with these endings.",
        ("scripts/lib/assets.py",),
    ),
    (MANIFEST_FILE, "assets.max_bytes"): KeyRow(
        "The size above which a kept-out asset file is listed by name and size, so the judges "
        "know it changed; it never keeps out a file that is not an asset",
        "integer or null",
        "A whole number of at least 1, or `null`",
        "`null`: no asset file is listed by size",
        "`1048576`",
        "The checks list each skipped asset file above this size by name and size.",
        ("scripts/lib/assets.py",),
    ),
    (MANIFEST_FILE, "dependencies.installs"): KeyRow(
        "The ecosystems whose frozen, scripts-off install a coding agent may run, such as "
        "`npm ci --ignore-scripts` or `uv sync --frozen --no-build`; every other install, update, "
        "add or "
        "resolve command stays refused for every agent, and no other agent gets this exception",
        "list of strings",
        "Each of "
        + ", ".join(f"`{name}`" for name in INSTALL_ECOSYSTEMS)
        + " at most once; `npm` covers npm, pnpm, yarn and bun, `python` covers pip and uv",
        "`[]`: no agent runs any install",
        '`["npm", "python"]`',
        "A coding agent may run a locked, scripts-off install for these ecosystems.",
        ("scripts/lib/admit.py", "agents/coder.md"),
    ),
    (MANIFEST_FILE, "dependencies.minimum_release_age_days"): KeyRow(
        "The youngest a package version a change adds or updates may be, in days since it was "
        "published; the auditor fails a younger version. A security fix this holds "
        "back is tracked as a risk, never exempted silently",
        "integer",
        f"A whole number of 0 or more; below {RELEASE_AGE_DEFAULT} it needs "
        "`dependencies.minimum_release_age_reason`, else the manifest is refused",
        f"`{RELEASE_AGE_DEFAULT}`",
        "`14`",
        "The audit fails a package version published fewer than this many days ago.",
        ("skills/audit/SKILL.md",),
    ),
    (MANIFEST_FILE, "dependencies.minimum_release_age_reason"): KeyRow(
        f"Why the project sets the release age below {RELEASE_AGE_DEFAULT} days; the doctor "
        "prints it",
        "string or null",
        f"One printable line of at least {RELEASE_AGE_REASON_MIN} characters, or `null`",
        "`null`: no reason, so the age may not go below the default",
        '`"internal registry mirrors with its own quarantine"`',
        "The health check prints this reason beside a lowered package age.",
        ("scripts/daedalus_doctor.py",),
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
        "The verify step asks you to open this address after a change to web code.",
        ("skills/verify/SKILL.md",),
    ),
    (MANIFEST_FILE, "dev_server.check"): KeyRow(
        "What you check on that site after a unit that changes web code; your answer of pass, "
        "fail or skip goes into the unit's evidence",
        "string",
        "One printable line of plain words",
        "Required once the block exists",
        '`"the scene loads and the player can move"`',
        "The verify step asks you to check this on your site and records your answer.",
        ("skills/verify/SKILL.md",),
    ),
    (MANIFEST_FILE, "ledger.path"): KeyRow(
        "Where rulings are appended, declared for everyone who works on the project; it wins "
        "over the config's ledger block",
        "string",
        _LEDGER_PATH_VALUES,
        "No block, or `ledger: null`: the config's ledger block or the ledger probe is used",
        '`"docs/decisions.md"`',
        "Rulings are appended to this file for everyone who works on the project.",
        _LEDGER_READERS,
    ),
    (MANIFEST_FILE, "ledger.format"): _LEDGER_FORMAT,
    (MANIFEST_FILE, "ledger.id_scheme"): _LEDGER_ID_SCHEME,
    (MANIFEST_FILE, "ledger.sequence_source"): _LEDGER_SEQUENCE,
    (MANIFEST_FILE, "ledger.branch"): _LEDGER_BRANCH,
    (CONFIG_FILE, "charter_root"): KeyRow(
        "The repository where your decisions and specs live; the contract and ledger agents "
        "may write there, and a Build Train branches it as `daedalus/<train-id>`",
        "string or null",
        "A non-empty path to a git repository, written absolute",
        "`null`: those agents write only inside the project, and the contract lives in "
        "`contracts/`",
        '`"/work/decisions"`',
        "The contract and ledger agents may write in this repository, and a run branches it.",
        ("scripts/lib/jail.py", "scripts/lib/workspace.py", "scripts/lib/ledger.py"),
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
        "The planner holds every plan to the rules in this file.",
        ("skills/plan/SKILL.md", "agents/planner.md"),
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
        "Agents are refused any command that sends these folders to git, GitHub or a file.",
        ("scripts/checks/excluded_roots.py", "scripts/lib/jail.py", "scripts/freeze_sources.py"),
    ),
    (CONFIG_FILE, "ledger.path"): KeyRow(
        "Where rulings are appended on this machine, used when the manifest declares no ledger",
        "string",
        _LEDGER_PATH_VALUES,
        "`null`: the ledger probe looks for one",
        '`"<charter_root>/decision-log.md"`',
        "Rulings are appended to this file on this machine when the project names no ledger.",
        _LEDGER_READERS,
    ),
    (CONFIG_FILE, "ledger.format"): _LEDGER_FORMAT,
    (CONFIG_FILE, "ledger.id_scheme"): _LEDGER_ID_SCHEME,
    (CONFIG_FILE, "ledger.sequence_source"): _LEDGER_SEQUENCE,
    (CONFIG_FILE, "ledger.branch"): _LEDGER_BRANCH,
    (CONFIG_FILE, "policy.engine"): KeyRow(
        "The tool for a deterministic policy check on infrastructure changes; no train runs it yet",
        "string",
        '`"cfn-guard"` or `"conftest"`',
        "`policy: null`: none declared",
        '`"conftest"`',
        "A run's opening lines name this tool; no check runs it yet.",
        ("scripts/lib/workspace.py",),
    ),
    (CONFIG_FILE, "policy.path"): KeyRow(
        "The folder that holds your policy rules; no train reads it yet",
        "string",
        "A non-empty path",
        "Required once the block exists",
        '`"/work/decisions/policy"`',
        "A run's opening lines name this folder; no check reads the rules in it yet.",
        ("scripts/lib/workspace.py",),
    ),
    (CONFIG_FILE, "standards_sources[].kind"): KeyRow(
        "What one source of your standards is; the run reads only these "
        "entries; see the requirements page, the section on standards_sources kinds",
        "string",
        '`"rules-dir"` (a folder of rule files), `"file"` (one file) or `"pack"` (a pack '
        "shipped inside the plugin)",
        "`[]`: the Standards Packet is empty",
        '`"rules-dir"`',
        "A run reads your standards only from the entries you list.",
        ("scripts/lib/workspace.py", _STANDARDS),
    ),
    (CONFIG_FILE, "standards_sources[].path"): KeyRow(
        "Where a rules folder or rules file lives",
        "string",
        "A non-empty path, written absolute; a pack entry carries none",
        "Required for a `rules-dir` or `file` entry",
        '`"/work/rules"`',
        "A run reads the rules folder or rules file at this place.",
        ("scripts/lib/workspace.py", _STANDARDS),
    ),
    (CONFIG_FILE, "standards_sources[].name"): KeyRow(
        "Which pack shipped with Daedalus to use",
        "string",
        "The name of a folder under the plugin's `packs/` that holds a `rules.md`; any other "
        "name is refused",
        "Required for a `pack` entry",
        '`"baseline"`',
        "A run reads this pack of rules that ships with Daedalus.",
        ("scripts/lib/workspace.py",),
    ),
    (CONFIG_FILE, "operator_signing_keys"): KeyRow(
        "Reserved for the key fingerprints allowed to sign merges; no check reads it yet",
        "list of strings",
        "Non-empty strings",
        "`[]`",
        '`["ABCD1234EF567890"]`',
        f"{NOT_ACTIVE}: no check compares a signature against this list.",
        (),
    ),
    (CONFIG_FILE, "max_concurrent_builders"): KeyRow(
        "How many coding agents a parallel stage runs at once, and the cap on the plan width "
        "the plan validator prints",
        "integer",
        "A whole number of at least 1; `true` and `false` are refused",
        "`5`",
        "`3`",
        "A run starts at most this many coding agents at once.",
        ("scripts/lib/train_runner.py", "skills/build/SKILL.md"),
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
        "Session audit logs older than this are deleted when a new session starts writing.",
        ("scripts/lib/audit.py",),
    ),
    (CONFIG_FILE, "wrapper_read_roots"): KeyRow(
        "Folders outside the project that a test runner under the kernel wrapper may read and "
        "run programs from, such as the pnpm package store or a Node.js install; the wrapper "
        "never lets it write there",
        "list of strings",
        "Absolute paths or paths starting with `~/`; a path that holds or sits inside a "
        "credential store, such as `~/.ssh`, is refused",
        "`[]`: the wrapper reads only the project, the system folders and Python",
        '`["~/.local/share/pnpm/store", "~/.nvm"]`',
        "Tests run inside the test wrapper may read and run programs from these folders.",
        ("scripts/daedalus_confine.py",),
    ),
    (CONFIG_FILE, "unit_token_budget"): KeyRow(
        "The most tokens one unit may spend, its coding and checking agents together. The token "
        "report lists every unit over it, and its gate form fails the audit phase's budget check",
        "integer or null",
        "A whole number of at least 1, or `null`; `true` and `false` are refused",
        "`null`: no budget, and the gate never fails",
        "`4000000`",
        "The token report flags each unit over this budget, and the audit's budget check fails.",
        ("scripts/token_economy.py", "skills/audit/SKILL.md"),
    ),
    (CONFIG_FILE, "coder_models"): KeyRow(
        "Which model a coding agent runs on for one unit. `default` is for most units. "
        "`control_path` is for a unit that changes a file under `agents/`, `skills/`, `hooks/` "
        "or `scripts/checks/`, or one of the three jail files. `escalated` is for the fresh "
        "coding agent that takes over a unit after its second failed check",
        "object",
        "Keys are `default`, `control_path` and `escalated`; values are "
        + ", ".join(f'`"{model}"`' for model in MODELS[:-1])
        + f' or `"{MODELS[-1]}"`; any other key or value is refused, and a key left out keeps '
        "its default",
        '`{"default": "sonnet", "control_path": "opus", "escalated": "opus"}`',
        '`{"default": "opus"}`',
        "Each coding agent runs on the model named for its kind of unit.",
        ("scripts/lib/coder_model.py", "scripts/daedalus_train.py"),
    ),
    (CONFIG_FILE, "agent_models"): KeyRow(
        "Which model each catalog agent runs on, in place of the `model:` line of its agent "
        "file; a model a skill is given for one run still comes first. Inside a run the coding "
        "agent takes its model from `coder_models` instead",
        "object",
        "Keys are agent names the catalog lists; values are "
        + ", ".join(f'`"{model}"`' for model in MODELS[:-1])
        + f' or `"{MODELS[-1]}"`; any other name or value is refused',
        "`{}`: every agent runs on its agent file's model",
        '`{"planner": "sonnet"}`',
        "Each agent you name runs on the model you give it instead of its own.",
        ("scripts/lib/agent_models.py", "scripts/daedalus_train.py"),
    ),
    (CONFIG_FILE, "fable_available"): KeyRow(
        "Whether your plan offers the Fable model. When it does, the planner and the auditor run "
        "on Fable unless `agent_models` names them; every other agent keeps its own model",
        "boolean or null",
        "`true`, `false` or `null`; any other value is refused",
        "`null`: Fable is used only when a running train's audit log shows this session "
        "started on it",
        "`true`",
        "The planner and the auditor run on the Fable model when your plan offers it.",
        ("scripts/lib/fable.py",),
    ),
    (CONFIG_FILE, "operator"): KeyRow(
        "A project's own values for the operator file's keys; a key set here replaces the "
        "operator file's value for this project, and a key left out inherits it. Nothing acts on "
        "the operator values yet",
        "object",
        "The same keys as the operator file: `main_refusals` and `profile`, checked the same way; "
        "any other key is refused",
        "Absent: the operator file's values stand",
        '`{"profile": {"literacy": "plain"}}`',
        f"{NOT_ACTIVE}: the personal values are checked and kept for later.",
        (),
    ),
    (OPERATOR_FILE_NAME, "main_refusals"): KeyRow(
        "The warning classes your own session turns into refusals for itself. The file only "
        "lists them; nothing acts on the list yet",
        "list of strings",
        "Each of "
        + ", ".join(f"`{name}`" for name in MAIN_REFUSAL_CLASSES)
        + " at most once; any other name is refused",
        "`[]`: your session is warned and never refused",
        '`["commit_on_main", "credential_read"]`',
        f"{NOT_ACTIVE}: your own session is still only warned.",
        (),
    ),
    (OPERATOR_FILE_NAME, "profile.literacy"): KeyRow(
        "How plainly Daedalus writes for you, for every project that does not set "
        "`docs.literacy` itself. Nothing acts on it yet",
        "string",
        ", ".join(f"`{example}`" for example in LITERACY_EXAMPLES[:-1])
        + f" or `{LITERACY_EXAMPLES[-1]}`, a project-relative path to the profile file without "
        "a leading slash, `..` or glob characters; `null` is refused",
        "Absent: no operator level is set",
        f"`{LITERACY_EXAMPLES[0]}`",
        f"{NOT_ACTIVE}: Daedalus writes for you at the project's level.",
        (),
    ),
    (OPERATOR_FILE_NAME, "profile.dash_ban"): KeyRow(
        "Whether Daedalus text for you avoids long dashes. Nothing acts on it yet",
        "boolean",
        "`true` or `false`; any other value is refused",
        "Absent: no operator choice is set",
        "`true`",
        f"{NOT_ACTIVE}: Daedalus text keeps whatever dashes it has.",
        (),
    ),
}


@dataclass(frozen=True)
class Group:
    id: str
    title: str
    order: int
    file: str
    keys: tuple[str, ...]
    # 0242: asked on the first walk; every day-one key has a reader.
    day_one: tuple[str, ...] = ()


def _ledger_keys() -> tuple[str, ...]:
    return tuple(f"ledger.{key}" for key in (*LEDGER_FIELDS, *LEDGER_OPTIONAL))


_PRIORITY_KEYS = tuple(f"priorities.{row}" for row in PRIORITY_ROWS)
_STACK = tuple(f"stack.{key}" for key in STACK_KEYS)
# 0242: every key of the three files in exactly one group; tests/test_setup_wizard.py holds it.
GROUPS: tuple[Group, ...] = (
    Group(
        "stack",
        "The commands that test, type-check and lint the project, and its package manager",
        1,
        MANIFEST_FILE,
        _STACK,
        _STACK,
    ),
    Group(
        "features",
        "Switches that turn whole steps of a run on or off",
        2,
        MANIFEST_FILE,
        tuple(f"features.{key}" for key in FEATURE_KEYS),
        ("features.secrets_scan", "features.ledger", "features.terraform_tools"),
    ),
    Group(
        "docs",
        "How plainly Daedalus writes for people",
        3,
        MANIFEST_FILE,
        tuple(f"docs.{key}" for key in DOCS_KEYS),
        ("docs.literacy",),
    ),
    Group(
        "jail",
        "Files no coding agent may write",
        4,
        MANIFEST_FILE,
        tuple(f"jail_narrowing.{key}" for key in NARROWING_KEYS),
    ),
    Group(
        "dependencies",
        "Package installs and how new a package may be",
        5,
        MANIFEST_FILE,
        tuple(f"dependencies.{key}" for key in DEPENDENCIES_KEYS),
    ),
    Group(
        "frameworks",
        "Which control packs the audit judges each change against",
        6,
        MANIFEST_FILE,
        tuple(f"frameworks.{key}" for key in FRAMEWORKS_KEYS),
    ),
    Group(
        "assets",
        "Asset files the checks and the secret scan skip",
        7,
        MANIFEST_FILE,
        tuple(f"assets.{key}" for key in ASSETS_KEYS),
    ),
    Group(
        "dev_server",
        "The local site you open to check web changes",
        8,
        MANIFEST_FILE,
        tuple(f"dev_server.{key}" for key in DEV_SERVER_KEYS),
    ),
    Group(
        "priorities",
        "Which concern wins when two clash",
        9,
        MANIFEST_FILE,
        _PRIORITY_KEYS,
    ),
    Group(
        "project_ledger",
        "Where rulings are recorded, for everyone on the project",
        10,
        MANIFEST_FILE,
        _ledger_keys(),
    ),
    Group(
        "trains",
        "A folder of your own run definitions",
        11,
        MANIFEST_FILE,
        ("trains_dir",),
    ),
    Group(
        "charter",
        "Where your decisions and standing rules live",
        12,
        CONFIG_FILE,
        ("charter_root", "standing_rules"),
    ),
    Group(
        "local_ledger",
        "Where rulings are recorded on this machine",
        13,
        CONFIG_FILE,
        _ledger_keys(),
    ),
    Group(
        "excluded",
        "Folders whose files must never reach git or GitHub",
        14,
        CONFIG_FILE,
        ("excluded_roots",),
    ),
    Group(
        "standards",
        "Your own standards and policy rules",
        15,
        CONFIG_FILE,
        (
            *(f"standards_sources[].{f.name}" for f in fields(StandardsSource)),
            *(f"policy.{f.name}" for f in fields(PolicyDecl)),
        ),
    ),
    Group(
        "models",
        "Which model each agent runs on",
        16,
        CONFIG_FILE,
        ("coder_models", "agent_models", "fable_available"),
    ),
    Group(
        "limits",
        "How many coding agents run at once and how many tokens a unit may spend",
        17,
        CONFIG_FILE,
        ("max_concurrent_builders", "unit_token_budget"),
    ),
    Group(
        "machine",
        "Audit log age, test wrapper folders and signing keys on this machine",
        18,
        CONFIG_FILE,
        ("audit_retention_days", "wrapper_read_roots", "operator_signing_keys"),
    ),
    Group(
        "project_operator",
        "This project's own copy of your personal preferences",
        19,
        CONFIG_FILE,
        ("operator",),
    ),
    Group(
        "operator",
        "Your personal preferences across every project",
        20,
        OPERATOR_FILE_NAME,
        operator_keys(),
    ),
)


@dataclass(frozen=True)
class Overlap:
    id: str
    text: str
    # 0242: (path, line, words on that line) the answer rests on; a test rereads each line.
    sources: tuple[tuple[str, int, str], ...]


# 0242: which file wins where two files overlap; the describe output and the README share these.
OVERLAPS: tuple[Overlap, ...] = (
    Overlap(
        "ledger",
        "When the project's manifest and this checkout's config both name a decision ledger, "
        "the manifest's ledger wins. The config's ledger is used only when the manifest names "
        "none.",
        (("scripts/lib/ledger.py", 206, "manifest wins, then config"),),
    ),
    Overlap(
        "literacy",
        "Today only the project's reading level changes how Daedalus writes. Your personal "
        "reading level is checked but nothing reads it yet. Once it is read, it will apply "
        "only to a project that sets no reading level of its own.",
        (
            ("scripts/lib/briefs.py", 281, "manifest.docs.literacy"),
            ("scripts/lib/operator_file.py", 4, "no check or hook acts on it yet"),
        ),
    ),
    Overlap(
        "operator",
        "A project's config can hold its own copy of any personal preference. A value set "
        "there replaces your personal value for that project only, and the rest still come "
        "from your personal file. Nothing acts on those values yet.",
        (("scripts/lib/operator_file.py", 138, "a key the override sets replaces the base value"),),
    ),
)
REFERENCE_HEADER = (
    "Key",
    "File",
    "What it governs",
    "What changes for you",
    "Type",
    "Allowed values",
    "Default",
    "Example",
)


def reference_keys() -> tuple[tuple[str, str], ...]:
    manifest = tuple((MANIFEST_FILE, key) for key in manifest_keys())
    operator = tuple((OPERATOR_FILE_NAME, key) for key in operator_keys())
    return manifest + tuple((CONFIG_FILE, key) for key in config_keys()) + operator


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
            row.affects,
            row.kind,
            row.values,
            row.default,
            row.example,
        )
        lines.append("| " + " | ".join(cell.replace("|", "\\|") for cell in cells) + " |")
    return "\n".join(lines) + "\n"
