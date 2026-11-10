# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0076, 0245: every key of the three settings files by its JSON name, built from the readers'
# own name tables; the starter files, the setup wizard, the README table and the tests read it.
from __future__ import annotations

from dataclasses import dataclass

from lib.agent_models import MODELS
from lib.coder_model import DEFAULT_CODER_MODELS
from lib.config import (
    AUDIT_RETENTION_FLOOR_DAYS,
    CODER_KEYS,
    CONFIG_KEYS,
    DEFAULT_MAX_CONCURRENT_BUILDERS,
    LIMIT_KEYS,
    MODEL_KEYS,
    RULE_SOURCE_KEYS,
)
from lib.manifest import (
    ASK_ME,
    CHECK_KEYS,
    COMMAND_KEYS,
    COMPLIANCE_KEYS,
    DOCS_DEFAULT_FOLDER,
    DOCS_KEYS,
    EXEMPTION_KEYS,
    INSTALL_ECOSYSTEMS,
    LITERACY_LEVELS,
    LITERACY_PROFILE,
    LOCAL_TESTING_KEYS,
    MANIFEST_NAME,
    MAX_PRINCIPLES,
    MAX_RULES,
    NOT_OVERRIDABLE,
    NOTE_MAX,
    PACKAGE_KEYS,
    PRIORITY_ROWS,
    PRIORITY_WORDS,
    PROHIBITED_KEYS,
    REASONS,
    RELEASE_AGE_DEFAULT,
    RELEASE_AGE_REASON_MIN,
    TEXT_MAX,
    TOP_KEYS,
)
from lib.operator_file import GUIDANCE_SOURCES, MAIN_REFUSAL_CLASSES, OPERATOR_FILE
from lib.operator_file import TOP_KEYS as OPERATOR_TOP_KEYS

MANIFEST_FILE = MANIFEST_NAME
CONFIG_FILE = ".claude/daedalus/config.json"
# 0235: the user-scope operator file, shown as written in a shell.
OPERATOR_FILE_NAME = "~/" + OPERATOR_FILE.as_posix()
# 0245: each manifest group and its member names, in key-table order.
_MANIFEST_GROUPS: dict[str, tuple[str, ...]] = {
    "commands": tuple(COMMAND_KEYS),
    "docs": DOCS_KEYS,
    "checks": tuple(CHECK_KEYS),
    "prohibited_writes": PROHIBITED_KEYS,
    "code_review_exemptions": EXEMPTION_KEYS,
    "packages": PACKAGE_KEYS,
    "run_output_priority": PRIORITY_ROWS,
    "local_testing": LOCAL_TESTING_KEYS,
    "compliance_rules": COMPLIANCE_KEYS,
}
_CONFIG_GROUPS: dict[str, tuple[str, ...]] = {
    "coding_rules": tuple(f"[].{key}" for key in RULE_SOURCE_KEYS),
    "models": MODEL_KEYS,
    "limits": LIMIT_KEYS,
    "policy": ("engine", "path"),
}


def _keys(tops: tuple[str, ...], groups: dict[str, tuple[str, ...]]) -> tuple[str, ...]:
    out: list[str] = []
    for top in tops:
        members = groups.get(top)
        if members is None:
            out.append(top)
        else:
            out.extend(f"{top}{m}" if m.startswith("[") else f"{top}.{m}" for m in members)
    return tuple(out)


def manifest_keys() -> tuple[str, ...]:
    return _keys(TOP_KEYS, _MANIFEST_GROUPS)


def config_keys() -> tuple[str, ...]:
    return _keys(CONFIG_KEYS, _CONFIG_GROUPS)


def operator_keys() -> tuple[str, ...]:
    # 0235, 0245: the personal file is flat; its keys are its top-level names.
    return OPERATOR_TOP_KEYS


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
    # 0245: an override has a good default, stays out of the starter files and the first day.
    override: bool = False


# 0242: the opening of every affects sentence whose key no code acts on yet.
NOT_ACTIVE = "Nothing acts on it yet"
_LEDGER = ("scripts/lib/ledger.py", "scripts/append_ledger.py")
_STANDARDS = "skills/plan/standards/SKILL.md"
_COMMAND_VALUES = (
    "A non-empty command string, a non-empty list of non-empty command strings run one after "
    "another, or `null`; a command holding a line break or other control character is refused"
)
_COMMAND_KIND = "string, list of strings or null"
_PRIORITY_NAMES = ", ".join(f"`{word}`" for word in PRIORITY_WORDS)
_MODEL_NAMES = ", ".join(f'`"{model}"`' for model in MODELS[:-1]) + f' or `"{MODELS[-1]}"`'
# 0134: the reading-level values the key reference and the setup command show.
LITERACY_EXAMPLES = (
    *(f'"{level}"' for level in LITERACY_LEVELS),
    f'"{LITERACY_PROFILE}docs/voice-profile.md"',
)
_LEVELS = (
    ", ".join(f"`{example}`" for example in LITERACY_EXAMPLES[:-1])
    + f" or `{LITERACY_EXAMPLES[-1]}`, a project-relative path to the profile file without "
    "a leading slash, `..` or glob characters"
)
_CODER_TIER_TEXT = {
    "default": "most units",
    "control_path": "a unit that changes a file under `agents/`, `skills/`, `hooks/` or "
    "`scripts/checks/`, or one of the three jail files",
    "escalated": "the fresh coding agent that takes over a unit after its second failed check",
}
_CODER_AFFECTS = {
    "default": "Coding agents run on this model for most work.",
    "control_path": "Coding agents run on this model when a change touches the plugin's own "
    "control files.",
    "escalated": "A fresh coding agent runs on this model after a change fails its check twice.",
}


def _coder_row(key: str) -> KeyRow:
    tier = CODER_KEYS[key]
    return KeyRow(
        f"The model a coding agent runs on for {_CODER_TIER_TEXT[tier]}",
        "string or null",
        f"{_MODEL_NAMES}, or `null`; any other value is refused",
        f'`null`: `"{DEFAULT_CODER_MODELS[tier]}"`',
        '`"opus"`',
        _CODER_AFFECTS[tier],
        ("scripts/lib/coder_model.py", "scripts/daedalus_train.py"),
        override=True,
    )


# 0076, B7, 0245: one row per key; tests hold the README table equal to reference_table().
KEY_ROWS: dict[tuple[str, str], KeyRow] = {
    (MANIFEST_FILE, "commands.unit_test"): KeyRow(
        "The commands that run the project's unit tests; a coding agent may run each exactly as "
        "written, as one command",
        _COMMAND_KIND,
        _COMMAND_VALUES,
        "`null`: no declared command",
        '`["python3 -m pytest -q"]`',
        "A coding agent may run these test commands as written, inside the test wrapper.",
        ("agents/coder.md", "scripts/checks/confine.py", "scripts/daedalus_doctor.py"),
    ),
    (MANIFEST_FILE, "commands.typecheck"): KeyRow(
        "The commands that type-check the project; a coding agent may run each exactly as "
        "written, as one command",
        _COMMAND_KIND,
        _COMMAND_VALUES,
        "`null`: no declared command",
        '`["python3 -m mypy ."]`',
        "A coding agent may run these type-check commands as written.",
        ("agents/coder.md", "scripts/daedalus_doctor.py"),
    ),
    (MANIFEST_FILE, "commands.lint"): KeyRow(
        "The commands that lint the project; a coding agent may run each exactly as written, as "
        "one command",
        _COMMAND_KIND,
        _COMMAND_VALUES,
        "`null`: no declared command",
        '`["python3 -m ruff check ."]`',
        "A coding agent may run these lint commands as written.",
        ("agents/coder.md", "scripts/daedalus_doctor.py"),
    ),
    (MANIFEST_FILE, "docs.folder"): KeyRow(
        "The project's docs folder; the decisions file and the decisions-in-force summary live "
        "in it unless `local_docs_folder` names a folder kept elsewhere",
        "string",
        "A project-relative folder path without a leading slash, `..` or glob characters",
        f'`"{DOCS_DEFAULT_FOLDER}"`',
        '`"docs"`',
        "Decisions are written to the named file in this folder.",
        _LEDGER,
    ),
    (MANIFEST_FILE, "docs.decisions_filename"): KeyRow(
        "The file in the docs folder where decisions are recorded; naming it turns recording on. "
        "Its layout, id pattern and numbering are read from the file itself, and a file that does "
        "not exist yet is created as a table when the first decision is recorded",
        "string or null",
        "A plain file name without a slash or glob characters, or `null`",
        "`null`: no decisions are recorded, and a run has no decision step at all",
        '`"decisions.md"`',
        "A run records each decision in this file, or records none and asks nothing about it.",
        ("scripts/lib/ledger.py", "scripts/append_ledger.py"),
    ),
    (MANIFEST_FILE, "docs.reading_level"): KeyRow(
        "How plainly Daedalus writes for people, as a reading level or a voice profile the "
        "project declares. The docs writer writes the public docs at the end of a run at this "
        "level, and a brief may override it. Decision briefs and the questions the plan and "
        "verify phases put to you are written at this level, and the decision brief check holds "
        "each brief to it, reading a voice profile as `plain`. Brainstorm questions are always "
        "plain, whatever this key says",
        "string or null",
        _LEVELS,
        "`null`: the writer keeps the register the public docs already use; decision briefs and "
        "the plan and verify questions are written at `standard`",
        f"`{LITERACY_EXAMPLES[1]}`",
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
    (MANIFEST_FILE, "docs.git_branch"): KeyRow(
        "The branch the decisions file's checkout must be on; a decision written or a probe run "
        "on any other branch, or on a detached HEAD, is refused, and Daedalus never switches the "
        "branch itself",
        "string or null",
        "A branch name with no spaces; refused while `local_docs_folder` is set, because a run "
        "branches that folder as `daedalus/<run id>`",
        "`null`: decisions are written on whatever branch the file's checkout is on",
        '`"main"`',
        "A decision written while the file's checkout is on any other branch is refused.",
        _LEDGER,
        override=True,
    ),
    (MANIFEST_FILE, "checks.secret_scan"): KeyRow(
        "Turns on the push step's gitleaks scan of the commits a push sends; with the scan on, "
        "the push stops when gitleaks is missing or finds a secret, and the doctor's gitleaks "
        "line is a `MISS`",
        "boolean",
        "`true` or `false`",
        "`false`: no scan, and gitleaks need not be installed",
        "`true`",
        "The push step scans the commits it sends for secrets and stops on a hit.",
        ("scripts/daedalus_doctor.py", "skills/release/SKILL.md"),
    ),
    (MANIFEST_FILE, "checks.online_advisory_lookup"): KeyRow(
        "Lets the auditor ask for security advisories on the web; the run sends its questions to "
        "the web researcher. With it off, the auditor judges from the lockfile and any advisory "
        "export the project supplies",
        "boolean or null",
        "`true`, `false` or `null`; only `false` turns the lookup off",
        "`true`: the lookup is on",
        "`false`",
        "The audit looks up security advisories on the web, or judges from the lockfile alone.",
        ("skills/audit/SKILL.md", "agents/auditor.md"),
    ),
    (MANIFEST_FILE, "checks.terraform_format"): KeyRow(
        "Lets the auditor run `terraform fmt -check` on the Terraform files a change touches. "
        "With it off, the auditor judges by reading the files, and validate is off too",
        "boolean or null",
        "`true`, `false` or `null`; only `false` turns it off",
        "`true`: `fmt -check` may run",
        "`false`",
        "The audit may run the Terraform format check on changed Terraform files, or only reads "
        "them.",
        ("skills/audit/SKILL.md", "agents/auditor.md"),
    ),
    (MANIFEST_FILE, "checks.terraform_validate"): KeyRow(
        "Lets the auditor run `terraform validate`, which starts the provider programs in a "
        "module's `.terraform` folder; `checks.terraform_format` set to `false` still turns it off",
        "boolean",
        "`true` or `false`",
        "`false`: the auditor runs no validate and marks that check N/A",
        "`true`",
        "The audit may also run the Terraform validate check, which starts provider programs.",
        ("packs/judges/terraform.md",),
    ),
    (MANIFEST_FILE, "checks.release_banned_terms"): KeyRow(
        "A file of terms, one per line, that the release step checks the release notes against; "
        "a hit stops the release and names how many terms it found, never the terms",
        "string or null",
        "A project-relative path without a leading slash, `..` or glob characters, or `null`",
        "`null`: nothing is checked",
        '`"docs/banned-terms.txt"`',
        "The release step checks the release notes against your list of terms.",
        ("scripts/lib/scrub.py",),
        override=True,
    ),
    (MANIFEST_FILE, "prohibited_writes.paths"): KeyRow(
        "Paths in your project no coding agent may write, on top of the paths Daedalus always "
        "protects",
        "list of strings",
        "Project-relative paths with forward slashes and no leading slash, `..` or glob "
        "characters; a trailing slash covers the whole folder, and matching ignores case",
        "`[]`",
        '`["infra/", "scripts/release.sh"]`',
        "A coding agent is refused every write to these paths, and the health check counts them.",
        ("scripts/lib/manifest.py", "scripts/daedalus_doctor.py"),
    ),
    (MANIFEST_FILE, "prohibited_writes.file_types"): KeyRow(
        "File endings no coding agent may write",
        "list of strings",
        "Endings that each start with a dot and hold no slash or glob characters; matching "
        "ignores case",
        "`[]`",
        '`[".pem", ".tfstate"]`',
        "A coding agent is refused every write to a file with one of these endings.",
        ("scripts/lib/manifest.py",),
    ),
    (MANIFEST_FILE, "code_review_exemptions.folders"): KeyRow(
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
    (MANIFEST_FILE, "code_review_exemptions.file_types"): KeyRow(
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
    (MANIFEST_FILE, "code_review_exemptions.report_over_bytes"): KeyRow(
        "The size above which a kept-out asset file is listed by name and size, so the judges "
        "know it changed; it never keeps out a file that is not an asset",
        "integer or null",
        "A whole number of at least 1, or `null`",
        "`null`: no asset file is listed by size",
        "`1048576`",
        "The checks list each skipped asset file above this size by name and size.",
        ("scripts/lib/assets.py",),
        override=True,
    ),
    (MANIFEST_FILE, "packages.allowed_installers"): KeyRow(
        "The ecosystems whose frozen, scripts-off install a coding agent may run, such as "
        "`npm ci --ignore-scripts` or `uv sync --frozen --no-build`; every other install, update, "
        "add or resolve command stays refused for every agent",
        "list of strings",
        "Each of "
        + ", ".join(f"`{name}`" for name in INSTALL_ECOSYSTEMS)
        + " at most once; `npm` covers npm, pnpm, yarn and bun, `python` covers pip and uv",
        "`[]`: no agent runs any install",
        '`["npm", "python"]`',
        "A coding agent may run a locked, scripts-off install for these ecosystems.",
        ("agents/coder.md",),
    ),
    (MANIFEST_FILE, "packages.minimum_age_days"): KeyRow(
        "The youngest a package version a change adds or updates may be, in days since it was "
        "published; the auditor fails a younger version. A security fix this holds back is "
        "tracked as a risk, never exempted silently",
        "integer",
        f"A whole number of 0 or more; below {RELEASE_AGE_DEFAULT} it needs "
        "`packages.minimum_age_reason`, else the manifest is refused",
        f"`{RELEASE_AGE_DEFAULT}`",
        "`14`",
        "The audit fails a package version published fewer than this many days ago.",
        ("skills/audit/SKILL.md",),
        override=True,
    ),
    (MANIFEST_FILE, "packages.minimum_age_reason"): KeyRow(
        f"Why the project sets the package age below {RELEASE_AGE_DEFAULT} days; the doctor "
        "prints it",
        "string or null",
        f"One printable line of at least {RELEASE_AGE_REASON_MIN} characters, or `null`",
        "`null`: no reason, so the age may not go below the default",
        '`"internal registry mirrors with its own quarantine"`',
        "The health check prints this reason beside a lowered package age.",
        ("scripts/daedalus_doctor.py",),
        override=True,
    ),
    (MANIFEST_FILE, "run_output_priority.order"): KeyRow(
        "Which concern wins when two conflict and no rule below matches, for every agent in a "
        "run, never the operator's own session",
        "list of strings",
        f"Each of {_PRIORITY_NAMES} exactly once, highest first",
        "`run_output_priority: null`: none declared, and agents follow no project ranking",
        '`["security", "trust", "operations", "cost"]`',
        "Every agent in a run settles a clash between two concerns by this ranking.",
        (_STANDARDS, "scripts/daedalus_doctor.py"),
    ),
    (MANIFEST_FILE, "run_output_priority.rules[].between"): KeyRow(
        "The two concerns a rule settles; rules are tried in order and the first match decides",
        "list of two strings",
        f"Two different names of {_PRIORITY_NAMES}; at most {MAX_RULES} rules",
        "`rules` empty: no rule, so the order decides",
        '`["security", "cost"]`',
        "A rule applies only to a clash between these two concerns.",
        (_STANDARDS,),
    ),
    (MANIFEST_FILE, "run_output_priority.rules[].reasons"): KeyRow(
        "Why the conflict arises; the rule matches only these reasons",
        "list of strings",
        "One or more of " + ", ".join(f"`{reason}`" for reason in REASONS) + ", each once",
        "Required in each rule",
        '`["certification", "framework"]`',
        "A rule applies only when the clash arises for one of these reasons.",
        (_STANDARDS,),
    ),
    (MANIFEST_FILE, "run_output_priority.rules[].outcome"): KeyRow(
        f"What a matching rule does: a concern named here wins and the agent decides alone; "
        f"`{ASK_ME}` puts the decision to you",
        "string",
        f"One of {_PRIORITY_NAMES}, or `{ASK_ME}`",
        "Required in each rule",
        f'`"{ASK_ME}"`',
        "A matching rule lets the agent decide alone, or puts the choice to you.",
        (_STANDARDS,),
    ),
    (MANIFEST_FILE, "run_output_priority.rules[].note"): KeyRow(
        "The one line a choice record or a decision brief quotes when the rule applies",
        "string",
        f"One printable line of 1 to {NOTE_MAX} characters",
        "Required in each rule",
        '`"a control a certification asks for wins over its running cost"`',
        "Choice records and decision briefs quote this line when the rule applies.",
        (_STANDARDS,),
    ),
    (MANIFEST_FILE, "run_output_priority.principles[].name"): KeyRow(
        "The name an agent cites when a decision rests on one of the project's principles",
        "string",
        f"`P` followed by digits, unique in the list; at most {MAX_PRINCIPLES} principles",
        "`principles` empty: none declared",
        '`"P1"`',
        "Agents cite the principle by this name when a decision rests on it.",
        (_STANDARDS,),
    ),
    (MANIFEST_FILE, "run_output_priority.principles[].category"): KeyRow(
        "The concern a principle serves",
        "string",
        f"One of {_PRIORITY_NAMES}",
        "Required in each principle",
        '`"security"`',
        "The run's standards list the principle under this concern.",
        (_STANDARDS,),
    ),
    (MANIFEST_FILE, "run_output_priority.principles[].text"): KeyRow(
        "The principle itself, as one sentence a decision brief quotes",
        "string",
        f"One printable line of 1 to {TEXT_MAX} characters",
        "Required in each principle",
        '`"Each tenant keeps its own key."`',
        "Decision briefs quote this sentence when a decision rests on the principle.",
        (_STANDARDS,),
    ),
    (MANIFEST_FILE, "run_output_priority.agent_order.<name>"): KeyRow(
        "A different order for one agent; rules and principles still apply to it",
        "list of strings",
        f"Each of {_PRIORITY_NAMES} exactly once; `<name>` is a Daedalus agent file name other "
        f"than `{NOT_OVERRIDABLE}`, which is refused",
        "Absent: the agent follows `run_output_priority.order`",
        '`{"coder": ["cost", "security", "operations", "trust"]}`',
        "That one agent ranks the concerns in this order instead.",
        (_STANDARDS,),
        override=True,
    ),
    (MANIFEST_FILE, "local_testing.url"): KeyRow(
        "The address of the site you host on your own machine for testing; the verify step "
        "asks you to open it, and Daedalus never starts, polls or fetches it",
        "string",
        # 0065: the loopback address reads as a version literal, so the row names it in words.
        "An `http` or `https` address on `localhost` or the IPv4 loopback address, with any "
        "port; any other host is refused",
        "`local_testing: null`: no site is named",
        '`"http://localhost:5173"`',
        "The verify step asks you to open this address after a change to web code.",
        ("skills/verify/SKILL.md",),
    ),
    (MANIFEST_FILE, "local_testing.instructions"): KeyRow(
        "What you check on that site after a change to web code; your answer of pass, fail or "
        "skip goes into the change's evidence",
        "string",
        "One printable line of plain words",
        "Required once the group exists",
        '`"The level loads and the player can move."`',
        "The verify step asks you to check this on your site and records your answer.",
        ("skills/verify/SKILL.md",),
    ),
    (MANIFEST_FILE, "compliance_rules.folder"): KeyRow(
        "The project folder that holds its own compliance rule sets; each subfolder holding a "
        "`pack.json` is one rule set",
        "string or null",
        "A project-relative folder path without a leading slash, `..` or glob characters, or "
        "`null`",
        "`null`: only the rule sets Daedalus ships are read",
        '`"compliance/rules"`',
        "The audit also judges each change against the rule sets in this folder.",
        ("scripts/lib/packs.py",),
        override=True,
    ),
    (MANIFEST_FILE, "compliance_rules.use_builtin"): KeyRow(
        "Whether the rule sets Daedalus ships are read beside the project's own",
        "boolean",
        "`true` or `false`; `false` reads only the rule sets under `compliance_rules.folder` and "
        "those named in `compliance_rules.extra_builtin`",
        "`true`: the shipped rule sets that are on by default are read",
        "`false`",
        "The audit reads the rule sets Daedalus ships, or only your own and the named ones.",
        ("scripts/lib/packs.py",),
        override=True,
    ),
    (MANIFEST_FILE, "compliance_rules.extra_builtin"): KeyRow(
        "Shipped rule sets that are off until a project names them, such as the cost-tier set; "
        "a named set is read even when `compliance_rules.use_builtin` is `false`",
        "list of strings",
        "Rule set ids of lowercase letters, digits and hyphens, each named once",
        "`[]`: only the shipped rule sets that are on by default are read",
        '`["cost-tier"]`',
        "The audit also reads these shipped rule sets that are off by default.",
        ("scripts/lib/packs.py",),
        override=True,
    ),
    (MANIFEST_FILE, "run_definitions_folder"): KeyRow(
        "The project folder that holds its own run definitions; a run definition is looked up "
        "there first, as `<folder>/<name>.json`, and then in the plugin's own folder",
        "string or null",
        "A project-relative folder path without a leading slash, `..` or glob characters, or "
        "`null`",
        "`null`: only the plugin's run definitions are used",
        '`"runs"`',
        "A run looks for its run definitions in this folder before the plugin's own.",
        ("scripts/lib/train_runner.py",),
        override=True,
    ),
    (MANIFEST_FILE, "entrypoints"): KeyRow(
        "The project's file areas by name; the plan phase pastes this object into the planner's "
        "prompt, and the planner cuts work along these areas",
        "object of strings",
        "Each key names an area, and each value is a project-relative path",
        "Absent: the planner is told `none declared`",
        '`{"handlers": "src/handlers/", "infra": "infra/"}`',
        "The planner cuts the work along these named areas of the project.",
        ("skills/plan/SKILL.md", "agents/planner.md"),
        override=True,
    ),
    (CONFIG_FILE, "local_docs_folder"): KeyRow(
        "A docs folder kept elsewhere on this machine, which may be its own git repository; when "
        "set, the decisions file and its summary live there in place of `docs.folder`, the "
        "contract and decision agents may write there, and a run branches it as "
        "`daedalus/<run id>`",
        "string or null",
        "An absolute folder path outside the project; a relative path, a symlink or a folder "
        "inside the project is refused",
        "`null`: the project's own `docs.folder` is used",
        '`"/work/decisions"`',
        "Decisions are written in this folder kept elsewhere on this machine.",
        ("scripts/lib/ledger.py", "scripts/lib/config.py"),
    ),
    (CONFIG_FILE, "git_excluded_folders"): KeyRow(
        "Folders whose files must never reach git, GitHub or a redirect. A Daedalus agent is "
        "refused such a command in every session, and the main session is warned during a run. "
        "A document run records the resolved folders in its frozen sources file",
        "list of objects",
        '`{"kind": "path", "path": "<folder>"}`, a folder with `<repo_root>` and '
        "`<charter_root>` (the local docs folder) filled in and a relative path read from the "
        'project root; or `{"kind": "gitignore", "match": "directories"}` (every folder git '
        'ignores) or `"match": "all"` (every ignored path); a folder holding a linked worktree '
        "is skipped",
        "`[]`: no folder is excluded",
        '`[{"kind": "path", "path": "<repo_root>/private/"}]`',
        "Agents are refused any command that sends these folders to git, GitHub or a file.",
        ("scripts/freeze_sources.py", "skills/document/SKILL.md"),
    ),
    (CONFIG_FILE, "coding_rules[].folder"): KeyRow(
        "A folder of rule files every run reads as your coding rules",
        "string",
        "A non-empty path, written absolute; an entry holds exactly one of `folder`, `file` or "
        "`builtin`",
        "`[]`: no coding rules are read",
        '`"/work/rules"`',
        "A run reads your coding rules from the rule files in this folder.",
        ("scripts/lib/workspace.py", _STANDARDS),
    ),
    (CONFIG_FILE, "coding_rules[].file"): KeyRow(
        "One file every run reads as your coding rules",
        "string",
        "A non-empty path, written absolute",
        "`[]`: no coding rules are read",
        '`"/work/rules/python.md"`',
        "A run reads your coding rules from this one file.",
        ("scripts/lib/workspace.py", _STANDARDS),
    ),
    (CONFIG_FILE, "coding_rules[].builtin"): KeyRow(
        "A set of coding rules shipped with Daedalus",
        "string",
        "The name of a folder under the plugin's `packs/` that holds a `rules.md`; any other "
        "name is refused",
        "`[]`: no coding rules are read",
        '`"baseline"`',
        "A run reads this set of coding rules that ships with Daedalus.",
        ("scripts/lib/workspace.py", _STANDARDS),
    ),
    (CONFIG_FILE, "personal_overrides"): KeyRow(
        "This project's own values for keys of your personal file; a key set here replaces the "
        "personal file's value for this project, and a key left out inherits it",
        "object",
        "The keys of the personal file, checked the same way; any other key is refused",
        "`{}`: the personal file's values stand",
        '`{"reading_level": "plain"}`',
        f"{NOT_ACTIVE}: the personal values are checked and kept for later.",
        (),
    ),
    (CONFIG_FILE, "models.agents"): KeyRow(
        "Which model each catalog agent runs on, in place of the `model:` line of its agent "
        "file; a model a skill is given for one run still comes first. Inside a run the coding "
        "agent takes its model from the `models.coder` keys instead",
        "object",
        f"Keys are agent names the catalog lists; values are {_MODEL_NAMES}; any other name or "
        "value is refused",
        "`{}`: every agent runs on its agent file's model",
        '`{"planner": "sonnet"}`',
        "Each agent you name runs on the model you give it instead of its own.",
        ("scripts/lib/agent_models.py", "scripts/daedalus_train.py"),
        override=True,
    ),
    **{(CONFIG_FILE, f"models.{key}"): _coder_row(key) for key in CODER_KEYS},
    (CONFIG_FILE, "models.fable_available"): KeyRow(
        "Whether your plan offers the Fable model. When it does, the planner and the auditor run "
        "on Fable unless `models.agents` names them; every other agent keeps its own model",
        "boolean or null",
        "`true`, `false` or `null`; any other value is refused",
        "`null`: Fable is used only when a running train's audit log shows this session "
        "started on it",
        "`true`",
        "The planner and the auditor run on the Fable model when your plan offers it.",
        ("scripts/lib/fable.py",),
        override=True,
    ),
    (CONFIG_FILE, "limits.parallel_coders"): KeyRow(
        "How many coding agents a parallel stage runs at once, and the cap on the plan width "
        "the plan validator prints",
        "integer",
        "A whole number of at least 1; `true` and `false` are refused",
        f"`{DEFAULT_MAX_CONCURRENT_BUILDERS}`",
        "`3`",
        "A run starts at most this many coding agents at once.",
        ("scripts/lib/train_runner.py", "skills/build/SKILL.md"),
        override=True,
    ),
    (CONFIG_FILE, "limits.task_tokens"): KeyRow(
        "The most tokens one task may spend, its coding and checking agents together. The token "
        "report lists every task over it, and its gate form fails the audit phase's budget check",
        "integer or null",
        "A whole number of at least 1, or `null`; `true` and `false` are refused",
        "`null`: no budget, and the gate never fails",
        "`4000000`",
        "The token report flags each task over this budget, and the audit's budget check fails.",
        ("scripts/token_economy.py", "skills/audit/SKILL.md"),
        override=True,
    ),
    (CONFIG_FILE, "limits.log_retention_days"): KeyRow(
        "How many days a session's audit log is kept after its last record. When a new session "
        "starts writing, older logs are deleted, each named with its final record in the new "
        "session's own log. A log named on a run summary's `Session` line, the log of a run not "
        "yet merged, and the current session's log are never deleted",
        "integer or null",
        f"A whole number of at least {AUDIT_RETENTION_FLOOR_DAYS}, or `null`",
        "`null`: every log is kept",
        "`365`",
        "Session audit logs older than this are deleted when a new session starts writing.",
        ("scripts/lib/audit.py",),
        override=True,
    ),
    (CONFIG_FILE, "test_readable_folders"): KeyRow(
        "Folders outside the project that a test run under the kernel wrapper may read and run "
        "programs from, such as the pnpm package store or a Node.js install; the wrapper never "
        "lets it write there",
        "list of strings",
        "Absolute paths or paths starting with `~/`; a path that holds or sits inside a "
        "credential store, such as `~/.ssh`, is refused",
        "`[]`: the wrapper reads only the project, the system folders and Python",
        '`["~/.local/share/pnpm/store", "~/.nvm"]`',
        "Tests run inside the test wrapper may read and run programs from these folders.",
        ("scripts/daedalus_confine.py",),
        override=True,
    ),
    (CONFIG_FILE, "policy.engine"): KeyRow(
        "The tool for a deterministic policy check on infrastructure changes; no run runs it yet",
        "string",
        '`"cfn-guard"` or `"conftest"`',
        "`policy: null`: none declared",
        '`"conftest"`',
        "A run's opening lines name this tool; no check runs it yet.",
        ("scripts/lib/workspace.py",),
        override=True,
    ),
    (CONFIG_FILE, "policy.path"): KeyRow(
        "The folder that holds your policy rules; no run reads it yet",
        "string",
        "A non-empty path",
        "Required once the group exists",
        '`"/work/decisions/policy"`',
        "A run's opening lines name this folder; no check reads the rules in it yet.",
        ("scripts/lib/workspace.py",),
        override=True,
    ),
    (OPERATOR_FILE_NAME, "hard_stops"): KeyRow(
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
    (OPERATOR_FILE_NAME, "reading_level"): KeyRow(
        "How plainly Daedalus writes for you, for every project that does not set "
        "`docs.reading_level` itself. Nothing acts on it yet",
        "string or null",
        _LEVELS + ", or `null`",
        "`null`: no personal level is set",
        f"`{LITERACY_EXAMPLES[0]}`",
        f"{NOT_ACTIVE}: Daedalus writes for you at the project's level.",
        (),
    ),
    (OPERATOR_FILE_NAME, "no_long_dashes"): KeyRow(
        "Whether Daedalus text for you avoids long dashes. Nothing acts on it yet",
        "boolean or null",
        "`true`, `false` or `null`; any other value is refused",
        "`null`: no personal choice is set",
        "`true`",
        f"{NOT_ACTIVE}: Daedalus text keeps whatever dashes it has.",
        (),
    ),
    (OPERATOR_FILE_NAME, "guidance_source"): KeyRow(
        "Where your working guidance is read from: Claude Code's own memory files, or a guidance "
        "folder Daedalus keeps beside this file. Nothing acts on it yet",
        "string",
        " or ".join(f'`"{source}"`' for source in GUIDANCE_SOURCES),
        f'`"{GUIDANCE_SOURCES[0]}"`',
        f'`"{GUIDANCE_SOURCES[-1]}"`',
        f"{NOT_ACTIVE}: guidance is read where Claude Code reads it.",
        (),
    ),
    (OPERATOR_FILE_NAME, "script_language"): KeyRow(
        "The language you want new scripts written in, told to every agent as guidance. "
        "Nothing acts on it yet",
        "string or null",
        "A lowercase language name such as `python`, or `null`",
        "`null`: no language is preferred",
        '`"python"`',
        f"{NOT_ACTIVE}: agents choose the language for each script.",
        (),
    ),
}


def _json(value: object) -> object:
    if isinstance(value, tuple | list):
        return [_json(v) for v in value]
    if isinstance(value, dict):
        return {str(k): _json(v) for k, v in value.items()}
    if value is None or isinstance(value, bool | int | str):
        return value
    raise TypeError(f"a reader default of type {type(value).__name__} has no JSON form")


# 0245: the starter value of every starter key; a test holds this to the starter rows.
_STARTER_MANIFEST: dict[str, object] = {
    "commands": {key: None for key in COMMAND_KEYS},
    "docs": {"folder": DOCS_DEFAULT_FOLDER, "decisions_filename": None, "reading_level": None},
    "checks": {
        "secret_scan": False,
        "online_advisory_lookup": True,
        "terraform_format": True,
        "terraform_validate": False,
    },
    "prohibited_writes": {"paths": [], "file_types": []},
    "code_review_exemptions": {"folders": [], "file_types": []},
    "packages": {"allowed_installers": []},
    "run_output_priority": None,
    "local_testing": None,
}
_STARTER_CONFIG: dict[str, object] = {
    "local_docs_folder": None,
    "git_excluded_folders": [],
    "coding_rules": [],
    "personal_overrides": {},
}


def starter_manifest() -> dict[str, object]:
    # 0076, 0245: the starter keys at their starter values; overrides stay out.
    return _json(_STARTER_MANIFEST)  # type: ignore[return-value]


def starter_config() -> dict[str, object]:
    # 0072, 0245: the starter keys at their defaults; null and empty mean none declared.
    return _json(_STARTER_CONFIG)  # type: ignore[return-value]


def starter_operator() -> dict[str, object]:
    # 0242, 0245: every personal choice unset; the guidance source at its default.
    return {
        "hard_stops": [],
        "reading_level": None,
        "no_long_dashes": None,
        "guidance_source": GUIDANCE_SOURCES[0],
        "script_language": None,
    }


@dataclass(frozen=True)
class SettingsFile:
    form: str
    name: str
    where: str
    whose: str
    shared: str
    holds: str


# 0242: the three files as the wizard and the README describe them, spec section 1.
SETTINGS_FILES: tuple[SettingsFile, ...] = (
    SettingsFile(
        "manifest",
        MANIFEST_FILE,
        "the project root",
        "the project",
        "yes, git tracks it",
        "what the project is and what it turns on",
    ),
    SettingsFile(
        "config",
        CONFIG_FILE,
        "the .claude/daedalus folder in the project",
        "this checkout on this machine",
        "no, git ignores it",
        "how Daedalus is wired up here",
    ),
    SettingsFile(
        "operator",
        OPERATOR_FILE_NAME,
        "the .claude/daedalus folder in your home folder",
        "you, across every project",
        "no, it sits outside every project",
        "your personal preferences",
    ),
)


@dataclass(frozen=True)
class Group:
    id: str
    title: str
    order: int
    file: str
    keys: tuple[str, ...]
    # 0242: asked on the first walk; every day-one key has a reader and is a starter key.
    day_one: tuple[str, ...] = ()


def _members(file_keys: tuple[str, ...], top: str) -> tuple[str, ...]:
    return tuple(k for k in file_keys if k == top or k.startswith((f"{top}.", f"{top}[")))


_M = manifest_keys()
_C = config_keys()
# 0242, 0245: every key of the three files in exactly one wizard group; tests hold it.
GROUPS: tuple[Group, ...] = (
    Group(
        "commands",
        "The commands that test, type-check and lint the project",
        1,
        MANIFEST_FILE,
        _members(_M, "commands"),
        _members(_M, "commands"),
    ),
    Group(
        "docs",
        "The docs folder, the decisions file and how plainly Daedalus writes",
        2,
        MANIFEST_FILE,
        _members(_M, "docs"),
        ("docs.reading_level", "docs.decisions_filename"),
    ),
    Group(
        "checks",
        "The checks a run makes on a push, on package advisories and on Terraform files",
        3,
        MANIFEST_FILE,
        _members(_M, "checks"),
        ("checks.secret_scan", "checks.terraform_format"),
    ),
    Group(
        "prohibited_writes",
        "Files no coding agent may write",
        4,
        MANIFEST_FILE,
        _members(_M, "prohibited_writes"),
    ),
    Group(
        "code_review_exemptions",
        "Asset files the code review and the secret scan skip",
        5,
        MANIFEST_FILE,
        _members(_M, "code_review_exemptions"),
    ),
    Group(
        "packages",
        "Package installs and how new a package may be",
        6,
        MANIFEST_FILE,
        _members(_M, "packages"),
    ),
    Group(
        "run_output_priority",
        "Which concern wins when two clash",
        7,
        MANIFEST_FILE,
        _members(_M, "run_output_priority"),
    ),
    Group(
        "local_testing",
        "The local site you open to check web changes",
        8,
        MANIFEST_FILE,
        _members(_M, "local_testing"),
    ),
    Group(
        "compliance_rules",
        "Which compliance rules the audit judges each change against",
        9,
        MANIFEST_FILE,
        _members(_M, "compliance_rules"),
    ),
    Group(
        "project_layout",
        "Your own run definitions and the project's named file areas",
        10,
        MANIFEST_FILE,
        ("run_definitions_folder", "entrypoints"),
    ),
    Group(
        "folders",
        "A docs folder kept elsewhere, folders git never takes and folders tests may read",
        11,
        CONFIG_FILE,
        ("local_docs_folder", "git_excluded_folders", "test_readable_folders"),
    ),
    Group(
        "coding_rules",
        "Your own coding rules",
        12,
        CONFIG_FILE,
        _members(_C, "coding_rules"),
    ),
    Group(
        "models",
        "Which model each agent runs on",
        13,
        CONFIG_FILE,
        _members(_C, "models"),
    ),
    Group(
        "limits",
        "How many coding agents run at once, how many tokens a task may spend and how long logs "
        "are kept",
        14,
        CONFIG_FILE,
        _members(_C, "limits"),
    ),
    Group(
        "personal_overrides",
        "This project's own copy of your personal preferences",
        15,
        CONFIG_FILE,
        ("personal_overrides",),
    ),
    Group(
        "policy",
        "A policy check tool and its rules folder",
        16,
        CONFIG_FILE,
        _members(_C, "policy"),
    ),
    Group(
        "personal",
        "Your personal preferences across every project",
        17,
        OPERATOR_FILE_NAME,
        operator_keys(),
    ),
)


@dataclass(frozen=True)
class Block:
    file: str
    key: str
    # 0242: member keys in asking order, and those the block's reader refuses to see missing.
    members: tuple[str, ...]
    required: tuple[str, ...]


def _block(file: str, key: str, members: tuple[str, ...], required: tuple[str, ...]) -> Block:
    return Block(
        file, key, tuple(f"{key}.{m}" for m in members), tuple(f"{key}.{m}" for m in required)
    )


# 0242: object groups whose reader refuses a lone member; setup's block form sets each whole.
# Readers: manifest.py _dev_server and config.py _policy.
BLOCKS: tuple[Block, ...] = (
    _block(MANIFEST_FILE, "local_testing", LOCAL_TESTING_KEYS, LOCAL_TESTING_KEYS),
    _block(CONFIG_FILE, "policy", ("engine", "path"), ("engine", "path")),
)


@dataclass(frozen=True)
class Overlap:
    id: str
    text: str
    # 0242: (path, line, words on that line) the answer rests on; a test rereads each line.
    sources: tuple[tuple[str, int, str], ...]
    # 0242: the file form whose value wins, or None where no code decides yet.
    wins: str | None


# 0242: which file wins where two files overlap; the describe output and the README share these.
OVERLAPS: tuple[Overlap, ...] = (
    Overlap(
        "docs",
        "When this checkout's config names a docs folder kept elsewhere on this machine, the "
        "decisions file lives there, not in the project's own docs folder.",
        (("scripts/lib/ledger.py", 61, "kept elsewhere on this machine wins"),),
        "config",
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
        None,
    ),
    Overlap(
        "operator",
        "A project's config can hold its own copy of any personal preference. A value set "
        "there replaces your personal value for that project only, and the rest still come "
        "from your personal file. Nothing acts on those values yet.",
        (("scripts/lib/operator_file.py", 155, "a key the override sets replaces the base value"),),
        "config",
    ),
)
REFERENCE_HEADER = (
    "Key",
    "File",
    "What it governs",
    "What changes for you",
    "Starter or override",
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
            "override" if row.override else "starter",
            row.kind,
            row.values,
            row.default,
            row.example,
        )
        lines.append("| " + " | ".join(cell.replace("|", "\\|") for cell in cells) + " |")
    return "\n".join(lines) + "\n"
