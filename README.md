<!-- Copyright (c) 2026 Brad Duhon. SPDX-License-Identifier: GPL-3.0-or-later -->
# Daedalus

## What Daedalus is

Daedalus is a Claude Code plugin that runs a team of AI agents through trains, which are fixed sequences of steps. Every coding agent works from the same locked contract, a written spec of the interfaces its code must follow, fixed before coding starts. Each agent also works inside a jail, a set of rules that blocks anything outside its job.

While a train runs in a repository, tool calls there land in a hash-chained audit log. Each record carries the hash of the one before it, so an edited or removed record breaks the chain.

## What you need

Daedalus is developed on Linux. macOS is untested.

| Tool | Version | How to get it |
|---|---|---|
| Python | 3.12 or newer | Your system's package manager |
| Claude Code | Developed against 2.1.280 | Claude Code's own install instructions |
| git | any | Your system's package manager |
| gitleaks, for the Push Train | any | https://github.com/gitleaks/gitleaks#installing |
| gh, the GitHub CLI, for the Push Train | any | Install it, then run `gh auth login` |

## Install

This one-command form needs Claude Code 2.1.275 or later. Start Claude Code in your project, then type:

    /plugin install daedalus --marketplace bradduhon/Daedalus

Claude Code asks you to confirm the marketplace, then to pick a scope. Choose "Install for you". To install from a shell instead, run these two commands, then start Claude Code:

    claude plugin marketplace add bradduhon/Daedalus

    claude plugin install daedalus@daedalus

Every Daedalus command acts on the repository you started Claude Code in.

## First run

If `/daedalus:doctor` is not offered yet after you install, run `/reload-plugins` or restart Claude Code. Then, inside the session, type:

    /daedalus:doctor

The doctor lists every file and tool Daedalus needs. Each `OK` line is a check that passed. Each `MISS` line names what is missing. Running the doctor changes nothing. Fix the `MISS` lines and run it again.

Every `MISS` line ends with a `Next:` instruction that says what to do. In a new repository, four lines read `OPT` until you add the files they name: `config.json`, `service-manifest.json`, `contracts/` and `.gitleaks.toml`. `/daedalus:setup` writes starter copies of the first two. `OPT` marks an optional scaffold your project declares about itself. Neither the Build Train nor the Push Train stops when they are absent, and their absence never fails the doctor. [docs/project-requirements.md](docs/project-requirements.md) lists every file Daedalus expects, says what each is for, and gives a small example of each.

## The three trains

### Build Train

The Build Train splits a task into units. It gives each unit to a coding agent in its own worktree, which is a separate checkout of your repository. The train creates each worktree itself and removes it when the train ends. A security audit runs before the units are merged into a local branch named `daedalus/<train-id>`. The Build Train never pushes.

Before you start, you need:

- a decision ledger, which is a file where your project records its design rulings; declare one or let the train find it or ask to create one
- a clean working tree
- optionally, `<repo>/.claude/daedalus/config.json` (see [docs/project-requirements.md](docs/project-requirements.md)); without it the defaults apply

Then type the command and your task:

    /daedalus:build-train Add a --verbose flag to the command-line tool

### Push Train

The Push Train commits, scans for secrets with gitleaks, pushes, and opens the pull request for a finished Build Train. Your repository needs a GitHub remote named `origin`, and `gh` must be signed in to it. The conductor, the agent named pr-train-conductor, does the pushing. You review and merge.

    /daedalus:push-train

### Execution Train

The Execution Train has no command. It is your own manual checks on live or staging systems. AI agents never take part in it, and a later release adds a readiness checklist for it.

### Audit report

To read what every agent did in a session, open its audit report:

    /daedalus:audit-report

## The agents

Each agent's file lists the only tools it may use, the reply lines it ends with, and the phases of a body of work it suits: context, clarification, plan, implementation, audit, and commit and release. Phases guide which agent the session picks; they never limit it. The table below is generated from the agent files by `python3 scripts/catalog.py table`, and `/daedalus:catalog` shows the session the same table. A test fails when it goes stale.

<!-- generated: catalog.py table -->
| Agent | Shape | Model | Tools | Job | Reply lines | Phases |
|---|---|---|---|---|---|---|
| charter-docs | producer | sonnet | Bash, Edit, Glob, Grep, Read, Write | Single-writer custodian of the Charter repository, the architectural decision ledger, and Build Train commits. | `[STATUS: LEDGER_PROBED] <probe line>`; `[STATUS: LEDGER_APPENDED] <id>`; `[STATUS: LEDGER_MISMATCH] expected=<n> ledger=<m>`; `[STATUS: COMMITTED] <sha> ids=<id>[,<id>]`; `[STATUS: BLOCKED] <detail>` | clarification, commit, release |
| cis-specialist | judge | sonnet | Bash, Grep, Read | Evaluates cloud infrastructure, IAM/RCP policies, and OS/container hardening against operator-supplied CIS Benchmarks. | `[STATUS: CACHE_INVALID] <detail>`; `[STATUS: COMPLIANCE] <PASS/FAIL list with control ids and file:line>` | clarification, audit |
| contract-spec | producer | sonnet | Edit, Glob, Grep, Read, Write | Reads and updates service handshake contracts, API schemas, and specifications. | `## Locked Contract Packet` | clarification, plan |
| nist-specialist | judge | sonnet | Bash, Grep, Read | Evaluates architecture, IAM, and cryptographic boundaries against the pinned NIST SP 800-53 OSCAL catalog and SP 800-57 key-management guidance. | `[STATUS: CACHE_INVALID] <detail>`; `[STATUS: COMPLIANCE] <PASS/FAIL list with control ids and file:line>` | clarification, audit |
| planner | shaper | opus | Glob, Grep, Read, Write | Cuts a design spec into work units that coders can build in parallel. | `[STATUS: PLAN] path=<path> units=<n> critical_path=<k> width=<w>`; `[STATUS: QUESTION] <what the task leaves open>` | plan |
| pr-train-conductor | mover | opus | Bash, Glob, Grep, Read | GitHub specialist for the Push Train. | `[STATUS: PUSHED] branch=<b> pr=<url>`; `[STATUS: CI] run=<id> conclusion=<text>`; `[STATUS: BLOCKED] <precondition that failed>` | commit, release |
| repo-coder | producer | opus | Bash, Edit, Glob, Grep, Read, Write | Scoped implementation worker. | `[STATUS: YIELD_WEB] <query>`; `[STATUS: YIELD_CONTRACT] <mismatch>`; `[STATUS: YIELD_COMPLIANCE] <question>`; `[STATUS: YIELD_STANDARDS] <question>`; `[STATUS: COMPLETE] branch=<b> packet_version=<n> files=<list> tests=<summary> ledger_notes=<text> contract=<12 hex> standards=<12 hex>` | implementation |
| security-auditor | judge | opus | Bash, Glob, Grep, Read | Adversarial pre-commit security and contract verifier. | `[VERDICT: APPROVED]`; `[VERDICT: REJECTED]` | audit |
| standards-rules-specialist | finder | sonnet | Glob, Grep, Read | Adopts the project's declared standards. | `## Standards Packet`; `[STANDARDS: CONTRADICTION] <spec ref> vs <source:line>`; `[STATUS: STANDARD] <answer>` | clarification, plan |
| web-researcher | finder | haiku | Read, WebFetch, WebSearch | Fast external documentation lookup on Haiku. | `[STATUS: RESEARCH] <payload under 300 words with URLs>` | context |
<!-- end generated -->

Each agent file also declares a shape and the hook scripts listed in its hooks block, with their flags. The table below is generated from the agent files by `python3 scripts/catalog.py matrix`; a test fails when it goes stale.

<!-- generated: catalog.py matrix -->
| Agent | Shape | Hooks |
|---|---|---|
| charter-docs | producer | credential_paths, workspace_integrity, tool_bound, shell_tripwires, network_tools, git_push, git_grammar --allow docs, root_writes --touch charter,docs --ledger-guard, command_allowlist --allow append_ledger,git,read, gh_classes |
| cis-specialist | judge | credential_paths, workspace_integrity, tool_bound, shell_tripwires, network_tools, read_only_bash --git specialist, gh_classes |
| contract-spec | producer | credential_paths, workspace_integrity, tool_bound, root_writes --touch contracts,charter-specs |
| nist-specialist | judge | credential_paths, workspace_integrity, tool_bound, shell_tripwires, network_tools, read_only_bash --git specialist, gh_classes |
| planner | shaper | credential_paths, workspace_integrity, tool_bound, root_writes --touch scratch --name plan.md |
| pr-train-conductor | mover | credential_paths, workspace_integrity, tool_bound, shell_tripwires, network_tools --gh, command_allowlist --allow git,gh,gitleaks, git_grammar --allow conductor, git_push --conductor, gh_classes --conductor |
| repo-coder | producer | credential_paths, workspace_integrity, tool_bound, shell_tripwires, network_tools, git_push, git_grammar --allow coder, unit_writes, gh_classes |
| security-auditor | judge | credential_paths, workspace_integrity, tool_bound, shell_tripwires, network_tools, read_only_bash --git read-only, gh_classes |
| standards-rules-specialist | finder | credential_paths, tool_bound |
| web-researcher | finder | credential_paths, tool_bound, network_tools --web |
<!-- end generated -->

## Files Daedalus creates

`<repo>` is the main working tree of the git repository you started Claude Code in.

| Path | When | Why |
|---|---|---|
| `<repo>/service-manifest.json` | You run `/daedalus:setup` and the file is missing | The starter manifest, with every feature off |
| `<repo>/.claude/daedalus/config.json` | You run `/daedalus:setup` and the file is missing | The starter config, with every setting at its default |
| `<repo>/.claude/daedalus/.gitignore` | A Build Train starts in the repository for the first time, or `/daedalus:setup` writes the config | Holds `*` so git ignores the whole directory |
| `<repo>/.claude/daedalus/audit/<session_id>.jsonl` | Every session, while a train runs in that repository | The hash-chained audit log for that session |
| `.claude/daedalus/ledger-locks/` in the repo that holds the ledger | A ledger entry is appended | Locks so two writers never change the ledger at once |
| `<repo>/docs/.tmp/daedalus/` | A Build Train starts | Scratch files and the train summary, ignored by git |
| `<repo>/.claude/daedalus/train.active` | A Build Train or Push Train starts | Marks a running train; removed when the train ends or stops |
| `<repo>/.claude/worktrees/<train-id>-<unit-slug>` | The Build Train starts a unit | The coding agent's worktree, on branch `daedalus-unit/<train-id>-<unit-slug>`; removed when the train ends or stops, and the branch is kept |
| `<repo>/.claude/worktrees/.gitignore` | The first unit worktree is created | Holds `*` so git ignores every worktree there |
| `<repo>/docs/decisions.md` | You answer "create" to the Build Train's ledger question | A new ledger holding only a table header |
| `contracts/<name>.md` | The contract is locked | The contract every coding agent works from, committed on the train's branch |
| Rows in your decision ledger | An approved Build Train ends | One entry per ruling, appended through `append_ledger.py` |
| `<cache>/frameworks/<family>/` | You run `refresh_frameworks.py` | The pinned framework files and their manifest |

`<repo>/.claude/daedalus/config.json` is optional. `/daedalus:setup` writes a starter copy when it is missing, and nothing else in Daedalus writes it (see Configuration below for the fields).

### The NIST and CIS cache

The commands below run from your own shell. `<plugin>` is the path the doctor prints on its `plugin root` line.

`<cache>` is a directory whose name depends on how you installed Daedalus. Print it with:

    python3 <plugin>/scripts/daedalus_doctor.py --print-cache-dir

Exit 1 means no cache exists yet; run `/daedalus:doctor` inside Claude Code once.

The nist-specialist needs the NIST catalog, in NIST's OSCAL JSON format. Without it, the specialist stops the train with `CACHE_INVALID`. Fetch every pinned framework with:

    python3 <plugin>/scripts/refresh_frameworks.py

CIS Benchmark files are licensed, so you place them by hand in `<cache>/frameworks/cis/`. Next to them you write a `manifest.json` with one entry per file, holding its name and its `sha256sum` hash. The exact format is in [docs/project-requirements.md](docs/project-requirements.md), under "CIS benchmarks".

## Configuration

Every file and setting Daedalus reads is described, with a small working example, in [docs/project-requirements.md](docs/project-requirements.md). The full operator guide is [docs/howto/README.md](docs/howto/README.md). It covers each train step by step, how to read a block message, and how to read an audit report.

To start both project files, type `/daedalus:setup`. It writes a starter `service-manifest.json` at the project root, with every feature off, and a starter `.claude/daedalus/config.json`, with every setting at its default. It writes only a file that is missing and never overwrites one. It prints one line per file: `written:` when it created the file, `kept:` when the file already existed (0076).

### Key reference

One row per key the two readers accept. The service manifest is committed and shared by everyone who works on the project; the config never leaves your machine (0070). A dotted key is a key inside an object, and `[]` marks a key inside each entry of a list.

<!-- key reference -->
| Key | File | What it does | Values | Default |
|---|---|---|---|---|
| `jail_narrowing.forbidden_paths` | `service-manifest.json` | Paths in your project no coding agent may write, on top of the paths the jail always protects (0054) | A list of project-relative paths with forward slashes and no leading slash, `..` or glob characters; a trailing slash covers the whole folder | `[]` |
| `jail_narrowing.forbidden_extensions` | `service-manifest.json` | File endings no coding agent may write (0054) | A list of endings that each start with a dot, such as `.pem` | `[]` |
| `features.scope` | `service-manifest.json` | Whether a train treats the project as a git repository or as a plain folder (0074) | `"repository"`, `"folder"` or `null` | `null`: a git work tree is a repository, anything else is a plain folder |
| `features.secrets_scan` | `service-manifest.json` | Reserved for a gitleaks scan of the commits a push sends; the reader checks the value, and no train step acts on it yet (0069) | `true` or `false` | `false` |
| `features.scrub_file` | `service-manifest.json` | Reserved for a file of terms that every commit and pull request body a train makes is checked against; the reader checks the path, and no train step reads the file yet (0069) | A project-relative path, or `null` | `null`: nothing is checked |
| `features.ledger` | `service-manifest.json` | Turns the decision ledger steps on or off (0069) | `true`: the ledger is used, and a train asks before creating one; `false`: no ledger step and no ledger question; `null` | `null`: a ledger the config declares or the probe finds is used, and none is created |
| `trains_dir` | `service-manifest.json` | Reserved for the project folder that holds its own train definitions; the reader checks the path, and no train reads the folder yet (0073) | A project-relative folder path, or `null` | `null` |
| `stack.unit_test_cmd` | `service-manifest.json` | The command that runs the project's unit tests; a coding agent may run it exactly as written, as one command (0073, 0098) | A non-empty command string, or `null` | `null`: no declared command |
| `stack.typecheck_cmd` | `service-manifest.json` | The command that type-checks the project; a coding agent may run it exactly as written, as one command (0098) | A non-empty command string, or `null` | `null`: no declared command |
| `stack.lint_cmd` | `service-manifest.json` | The command that lints the project; a coding agent may run it exactly as written, as one command (0098) | A non-empty command string, or `null` | `null`: no declared command |
| `ledger.path` | `service-manifest.json` | Where rulings are appended, declared for everyone who works on the project; it wins over the config's ledger block (0004) | A path; `<repo_root>` and `<charter_root>` are filled in, and a relative path is read from the project root | No block: the config's ledger block or the ledger probe is used |
| `ledger.format` | `service-manifest.json` | How each ruling is written to the manifest's ledger (0004) | `"markdown-table-row"` or `"heading-entry"` | Required once the block exists |
| `ledger.id_scheme` | `service-manifest.json` | The pattern each new ruling id follows (0004) | A pattern such as `{seq:04d}-{repo}-{type}` | Required once the block exists |
| `ledger.sequence_source` | `service-manifest.json` | Where the next ruling number comes from (0004) | `"last-row-id"` or `"frontmatter:<key>"` | Required once the block exists |
| `charter_root` | `.claude/daedalus/config.json` | The repository where your decisions and specs live; the contract and ledger agents may write there | An absolute path | None declared: those agents write only inside the project |
| `ledger.path` | `.claude/daedalus/config.json` | Where rulings are appended on this machine, used when the manifest declares no ledger (0004) | A path; `<repo_root>` and `<charter_root>` are filled in, and a relative path is read from the project root | None declared: the ledger probe looks for one |
| `ledger.format` | `.claude/daedalus/config.json` | How each ruling is written to the config's ledger (0004) | `"markdown-table-row"` or `"heading-entry"` | Required once the block exists |
| `ledger.id_scheme` | `.claude/daedalus/config.json` | The pattern each new ruling id follows (0004) | A pattern such as `{seq:04d}-{repo}-{type}` | Required once the block exists |
| `ledger.sequence_source` | `.claude/daedalus/config.json` | Where the next ruling number comes from (0004) | `"last-row-id"` or `"frontmatter:<key>"` | Required once the block exists |
| `policy.engine` | `.claude/daedalus/config.json` | The tool for a deterministic policy check on infrastructure changes; no train runs it yet | `"cfn-guard"` or `"conftest"` | None declared |
| `policy.path` | `.claude/daedalus/config.json` | The folder that holds your policy rules; no train reads it yet | A path | None declared |
| `standards_sources[].kind` | `.claude/daedalus/config.json` | What one source of your standards is; the standards specialist reads only these entries (0019) | `"rules-dir"`, `"file"` or `"pack"` | An empty list: the Standards Packet is empty |
| `standards_sources[].path` | `.claude/daedalus/config.json` | Where a rules folder or rules file lives | An absolute path; a pack has none | Required for a folder or file entry |
| `standards_sources[].name` | `.claude/daedalus/config.json` | Which pack shipped with Daedalus to use (0019) | `"baseline"`, the one pack Daedalus ships | Required for a pack entry |
| `operator_signing_keys` | `.claude/daedalus/config.json` | Reserved for the key fingerprints allowed to sign merges; no check reads it yet | A list of non-empty strings | `[]` |
| `max_concurrent_builders` | `.claude/daedalus/config.json` | How many coding agents a parallel stage runs at once (0072) | A whole number of at least 1 | `5` |
<!-- end key reference -->

## Safety model

Outside a train, Daedalus leaves your session and your repository alone, with one exception: it refuses reads and searches of credential files for every agent and the main session. Outside a train, Daedalus writes no files and keeps no audit log in any repository, including one where a train ran before; the one exception is `/daedalus:setup`, which writes its two starter files when you run it. Inside a train, the jail judges every tool call and the audit log records each step. A train works in three folders: the repository's `.claude/worktrees/` folder holds the unit worktrees, its `.claude/daedalus/` folder holds train state and the audit log, and the git-ignored `docs/.tmp/daedalus/` folder holds scratch files and summaries. To have the plugin's hooks in some repositories only, enable the plugin at project scope in each of those repositories' `.claude/settings.json` (Claude Code's `enabledPlugins`) instead of for your user.

Each agent gets a short list of allowed tools, and a tool not on the list is never offered to it. A PreToolUse hook is a check Claude Code runs before each tool call. Daedalus uses one, the jail, to compare every call against that agent's rules and block anything outside them. A coding agent may write only inside its own unit worktree, and there never to `contracts/`, `.github/`, `.claude/`, `service-manifest.json`, the decision ledger, or the paths and file extensions the repository lists under `jail_narrowing` in `service-manifest.json`. Every agent, and the main session, is refused reads and searches of `~/.ssh`, `~/.aws`, `~/.gnupg`, `~/.config/gh` and `~/.claude/.credentials.json` at all times. Daedalus's own agents always, and the main session while a train runs, are also refused writing those paths with a file tool or naming them in Bash. While a train runs, agents from Claude Code itself or from other plugins are refused every checked tool except reads and searches, in the train's repository and when they write into it from another one. The jail hooks are the enforced boundary and judge each tool call before it runs. Code an agent runs inside a tool call, such as its tests, is the same exposure any developer accepts when using a model in their environment, so Daedalus asks every agent never to circumvent its boundaries and does not try to control the environment. A blocked agent sees a line starting with `daedalus-jail[<agent>]:` that says what was refused and what to do next. Hooks, not agents, write each step to the hash-chained audit log. No agent pushes except the conductor inside the Push Train, and no agent merges. You merge.

With no declared standards, the Standards Packet is empty and the auditor judges each unit against its contract only. The NIST and CIS specialists review only units that touched IAM, KMS, mTLS, key custody or infrastructure configuration. To declare your standards, see [docs/project-requirements.md](docs/project-requirements.md). To start from a shipped set instead, declare the opt-in baseline pack, `{"kind": "pack", "name": "baseline"}`: five baseline checks plus the Daedalus cloud security standards, written in Daedalus's own words. The doctor offers it while `standards_sources` is empty.

## What is in this repo

```
Daedalus/
├── .claude-plugin/
│   ├── marketplace.json             # marketplace id: daedalus
│   └── plugin.json                  # plugin id: daedalus
├── .gitignore
├── LICENSE
├── README.md
├── pyproject.toml                   # dev tooling; the plugin itself is stdlib only
├── agents/
│   ├── charter-docs.md
│   ├── cis-specialist.md
│   ├── contract-spec.md
│   ├── nist-specialist.md
│   ├── planner.md
│   ├── pr-train-conductor.md
│   ├── repo-coder.md
│   ├── security-auditor.md
│   ├── standards-rules-specialist.md
│   └── web-researcher.md
├── docs/
│   ├── howto/README.md              # operator guide
│   └── project-requirements.md      # every file Daedalus reads, with examples
├── hooks/
│   └── hooks.json                   # enforcement and audit bindings
├── packs/
│   └── baseline/rules.md            # opt-in baseline and cloud security standards pack
├── scripts/                         # Python 3.12, stdlib only
│   ├── lib/__init__.py
│   ├── lib/audit.py                 # hash-chained append, redaction
│   ├── lib/config.py                # config.json loading and validation
│   ├── lib/fetch.py                 # GitHub-only download, size cap and cache lock for refreshes
│   ├── lib/jail.py                  # per-agent tool policy
│   ├── lib/ledger.py                # ledger resolution, sequence read, entry format
│   ├── lib/locks.py                 # bounded flock shared by audit and ledger writers
│   ├── lib/project_keys.py          # every manifest and config key, and the starter files
│   ├── lib/redact.py                # secret masking for audit records
│   ├── lib/workspace.py             # unit worktrees and the train marker
│   ├── append_ledger.py             # locked, sequence-checked ledger writer
│   ├── audit_log.py                 # all other hook events to the audit log
│   ├── audit_report.py              # digest of a verified session log
│   ├── daedalus_doctor.py           # first-run check behind /daedalus:doctor
│   ├── daedalus_setup.py            # writes the missing starter files behind /daedalus:setup
│   ├── daedalus_workspace.py        # create and remove unit worktrees; mark the running train
│   ├── enforce_agent_jail.py        # PreToolUse policy
│   ├── refresh_frameworks.py        # operator-run: compile the pinned framework caches
│   └── verify_audit_chain.py        # recompute and verify a session's hash chain
├── skills/
│   ├── audit-report/SKILL.md        # /daedalus:audit-report
│   ├── build-train/SKILL.md         # /daedalus:build-train
│   ├── catalog/SKILL.md             # /daedalus:catalog
│   ├── doctor/SKILL.md              # /daedalus:doctor
│   ├── push-train/SKILL.md          # /daedalus:push-train
│   └── setup/SKILL.md               # /daedalus:setup
└── tests/                           # the pytest suite
```

## License

Daedalus is licensed under the GNU General Public License v3.0 or later. See LICENSE.

## Developing Daedalus

    pip install -e '.[dev]'
    pytest
    ruff check scripts tests
