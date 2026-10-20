<!-- Copyright (c) 2026 Brad Duhon. SPDX-License-Identifier: GPL-3.0-or-later -->
# Daedalus

## What Daedalus is

Daedalus is a Claude Code plugin that gives your session a catalog of scoped AI agents. Each agent has a short list of tools and works inside a jail, a set of hook-checked rules that blocks anything outside its job. Daedalus is an open composition over those agents (0088): you compose each body of work yourself, and the Build Train (`/daedalus:build-train`) is one saved recipe over this catalog, not the required shape. The Push Train (`/daedalus:push-train`) is a second saved recipe, for the push and the pull request.

Every body of work passes through six phases: context, clarification, plan, implementation, audit, and commit and release (0089). Phases overlap freely. A phase's weight scales with the task: a one-file fix carries a one-unit plan and no contract packet, and a cross-module build carries the packet. A contract packet is a written spec of the interfaces each coding agent's code must follow, locked before coding starts.

Hooks check four exit conditions today: a plan record before a coder, a worktree binding for every coder, an approved verdict on the exact tip (or the operator's exception) before a push or pull request, and the conductor as the only agent that pushes. Capturing each ruling in your decision ledger and merging the pull request are your duty; no hook checks them.

While a train runs in a repository, tool calls there land in a hash-chained audit log. Each record carries the hash of the one before it, so an edited or removed record breaks the chain.

## What you need

Daedalus is developed on Linux. macOS is untested.

| Tool | Version | How to get it |
|---|---|---|
| Python | 3.12 or newer | Your system's package manager |
| Claude Code | Developed against 2.1.280 | Claude Code's own install instructions |
| git | any | Your system's package manager |
| gitleaks, for the Push Train's secret scan when the service manifest turns it on | any | https://github.com/gitleaks/gitleaks#installing |
| gh, the GitHub CLI, for the Push Train | any | Install it, then run `gh auth login` |

## Install

This one-command form needs Claude Code 2.1.275 or later. Start Claude Code in your project, then type:

    /plugin install daedalus --marketplace bradduhon/Daedalus

Claude Code asks you to confirm the marketplace, then to pick a scope. Choose "Install for you". To install from a shell instead, run these two commands, then start Claude Code:

    claude plugin marketplace add bradduhon/Daedalus

    claude plugin install daedalus@daedalus

Every Daedalus command acts on the repository you started Claude Code in.

### Install from a local clone

To run the code in your own clone of this repository instead of the published release (0095), add the clone as a path marketplace and install from it. The clone path is the one value to fill in:

    claude plugin marketplace add /path/to/Daedalus

    claude plugin install daedalus@daedalus

The clone and the published marketplace both carry the marketplace name `daedalus`. If you added the published one before, remove it first with `claude plugin marketplace remove daedalus`. After the clone changes, update the marketplace and the plugin, then restart Claude Code so the new code loads:

    claude plugin marketplace update daedalus

    claude plugin update daedalus@daedalus

## First run

If `/daedalus:doctor` is not offered yet after you install, run `/reload-plugins` or restart Claude Code. Then, inside the session, type:

    /daedalus:doctor

The doctor lists every file and tool Daedalus needs. Each `OK` line is a check that passed. Each `MISS` line names what is missing. Running the doctor changes nothing. Fix the `MISS` lines and run it again.

Every `MISS` line ends with a `Next:` instruction that says what to do. In a new repository, four lines read `OPT` until you add the files they name: `config.json`, `service-manifest.json`, `contracts/` and `.gitleaks.toml`. `/daedalus:setup` writes starter copies of the first two. `OPT` marks an optional scaffold your project declares about itself. Neither the Build Train nor the Push Train stops when they are absent, and their absence never fails the doctor. [docs/project-requirements.md](docs/project-requirements.md) lists every file Daedalus expects, says what each is for, and gives a small example of each.

### Your first body of work

1. Read the catalog. Type `/daedalus:catalog`. It prints every agent with its tools, its reply lines and the phases it suits, then the six phases with their exit conditions and the musts.
2. Write a spec, or point at one. A spec is a file in your repository that says what to build and how you will know it works. A one-line task needs no file; the Build Train saves the words you type as the spec.
3. Cut the spec into units. Type `/daedalus:plan` and the spec's path, for example `/daedalus:plan docs/specs/healthz.md`. The planner agent writes a plan file, and the plan validator checks it and prints `OK plan: graph: units=<n> critical_path=<k> width=<w> overlap_only=<pairs>`. The session then shows a unit table with the columns Unit, What it builds, Starts from, Waits on and Shares files with. Each row is one coding agent's work. Waits on names the units that must finish first, and Shares files with names the units that edit the same files, with the order they merge in. Outside a train the plan lands at `docs/.tmp/daedalus/plan-<YYYYMMDD>.md`.
4. Start the Build Train. Type `/daedalus:build-train` and your task, naming the plan file the plan step wrote, as its `Next:` line says. The session hands it to the orchestrator as the train's plan; the orchestrator checks it with the plan validator and records it instead of cutting a new one. With no plan named, the orchestrator cuts and records the plan itself before any coder starts. The session checks the preconditions and prints the first State Block lines. The hooks check then prints `OK hooks live: session <id>, chain intact (<n> records)`. That check also marks where this train's audit begins; the Push Train later reads the security verdict only from records after that mark (issue 57).
5. Watch it run. The main session starts one orchestrator agent and relays between it and you (0060). After each phase you see a progress note that names the phase, its weight and the state of each unit. Before each choice the train prints one line, `Chose <what> over <alternative>: <cost>`.
6. Answer its questions. When the train needs a ruling, the orchestrator writes a decision brief, and the session asks you through Claude Code's question prompt. Each question has a question line ending in a question mark, two or three context sentences and its options, with the recommended option first. The orchestrator ends each reply with one of four lines, and the session routes it:
   - `[STATUS: DECISION]`: the session asks you the brief's questions and sends your picks back.
   - `[STATUS: EXCEPTION]`: you chose to merge with each remaining audit finding as a tracked-risk issue, and the session binds that exception ruling to the integration tip.
   - `[STATUS: STOP]`: the session runs the stop command and shows its `Next:` line. Say continue to resume.
   - `[STATUS: TRAIN_COMPLETE]`: the session shows the summary path and the audit log path, then ends the train.
7. Read the audit result. The units merge onto the local branch `daedalus/<train-id>` first, and the security auditor judges that merged integration tip against the train's base. After two rejected rounds you pick what happens to the remaining findings: one more fix round, a merge with each finding as a tracked-risk issue, or a stop with the branches kept. A train merged on that exception stops at the Push Train's verdict check, so you push it by hand from the main session once the issues are filed (issue 62).
8. Push and merge. Review the integration branch, then read the session's audit log with `/daedalus:audit-report <session>`. Type `/daedalus:push-train` to push the branch and open its pull request. You merge the pull request.

## Saved recipes

The Build Train and the Push Train are saved recipes over the catalog, not the required shape (0088). A body of work can use any agents from the catalog in any order. Outside a train, catalog agents keep their own hooks; the main session and agents from Claude Code itself or other plugins meet only the credential check on reads and searches, which asks the main session and refuses an agent (see Safety model below).

### Build Train

The Build Train (`/daedalus:build-train`) takes a task from its plan to an audited local branch. The main session checks the preconditions, starts one orchestrator agent, and relays between it and you. The orchestrator follows its recipe over the catalog. It reads your standards, cuts and records the plan, and locks the contract when the task carries one. It gives each unit to a coding agent in its own worktree, which is a separate checkout of your repository. It merges every unit into a local branch named `daedalus/<train-id>` and has the security auditor judge that merged branch. The train creates each worktree itself and removes it when the train ends. The Build Train never pushes.

Before you start, you need:

- a decision ledger, which is a file where your project records its design rulings; declare one or let the train find it or ask to create one
- a clean working tree
- optionally, `<repo>/.claude/daedalus/config.json` (see [docs/project-requirements.md](docs/project-requirements.md)); without it the defaults apply

Then type the command and your task:

    /daedalus:build-train Add a --verbose flag to the command-line tool

### Push Train

The Push Train commits, pushes, and opens the pull request for a finished Build Train. It first checks that the Build Train's audit log holds an approved security verdict for that train. When `features.secrets_scan` is `true` in `service-manifest.json`, it scans the commits for secrets with gitleaks before the push. Your repository needs a GitHub remote named `origin`, and `gh` must be signed in to it. The conductor, the agent named pr-train-conductor, does the pushing and watches CI. When the Build Train used a Charter branch, the conductor also pushes that branch and opens its pull request after the code one. You review and merge.

    /daedalus:push-train

### Execution Train

The Execution Train is not a saved recipe and has no command. It is your own manual checks on live or staging systems. AI agents never take part in it, and a later release adds a readiness checklist for it.

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
| orchestrator | dispatcher | fable | Agent, Bash, Edit, Glob, Grep, Read, SendMessage, Write | Runs one Build Train from its plan to the audited integration tip. | `[STATUS: DECISION] brief=<path> questions=<n>`; `[STATUS: EXCEPTION] ledger_id=<id>`; `[STATUS: TRAIN_COMPLETE] summary=<path> audit_log=<path>`; `[STATUS: STOP] reason=<what happened> next=<next action>` | context, clarification, plan, implementation, audit |
| planner | shaper | opus | Glob, Grep, Read, Write | Cuts a design spec into work units that coders can build in parallel. | `[STATUS: PLAN] path=<path> units=<n> critical_path=<k> width=<w>`; `[STATUS: QUESTION] <what the task leaves open>` | plan |
| pr-train-conductor | mover | opus | Bash, Glob, Grep, Read | GitHub specialist for the Push Train. | `[STATUS: PUSHED] branch=<b> pr=<url>`; `[STATUS: CI] run=<id> conclusion=<text>`; `[STATUS: BLOCKED] <precondition that failed>` | commit, release |
| repo-coder | producer | opus | Bash, Edit, Glob, Grep, Read, Write | Scoped implementation worker. | `[STATUS: YIELD_WEB] <query>`; `[STATUS: YIELD_CONTRACT] <mismatch>`; `[STATUS: YIELD_COMPLIANCE] <question>`; `[STATUS: YIELD_STANDARDS] <question>`; `[STATUS: COMPLETE] branch=<b> packet_version=<n> files=<list> tests=<summary> ledger_notes=<text> contract=<12 hex> standards=<12 hex>` | implementation |
| security-auditor | judge | opus | Bash, Edit, Glob, Grep, Read, Write | Adversarial pre-commit security and contract verifier. | `[VERDICT: APPROVED] tip=<40 lowercase hex>`; `[VERDICT: REJECTED] tip=<40 lowercase hex>` | audit |
| standards-rules-specialist | finder | sonnet | Glob, Grep, Read | Adopts the project's declared standards. | `## Standards Packet`; `[STANDARDS: CONTRADICTION] <spec ref> vs <source:line>`; `[STATUS: STANDARD] <answer>` | clarification, plan |
| verifier | judge | opus | Bash, Glob, Grep, Read | Adversarial read-only verifier of a coder's completion report. | `[VERDICT: VERIFIED] claims=<n>`; `[VERDICT: REFUTED] <rows>` | implementation |
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
| orchestrator | dispatcher | credential_paths, workspace_integrity, tool_bound, shell_tripwires, network_tools, git_push, command_allowlist --allow train,inspect, root_writes --touch scratch --ledger-guard, gh_classes, dispatch_gate |
| planner | shaper | credential_paths, workspace_integrity, tool_bound, root_writes --touch scratch --name plan*.md |
| pr-train-conductor | mover | credential_paths, workspace_integrity, tool_bound, shell_tripwires, network_tools --gh, command_allowlist --allow git,gh,gitleaks, git_grammar --allow conductor, git_push --conductor, gh_classes --conductor |
| repo-coder | producer | credential_paths, workspace_integrity, tool_bound, shell_tripwires, network_tools, git_push, git_grammar --allow coder, unit_writes, gh_classes |
| security-auditor | judge | credential_paths, workspace_integrity, tool_bound, shell_tripwires, network_tools, read_only_bash --git read-only --test-runner audit, gh_classes, root_writes --touch audit |
| standards-rules-specialist | finder | credential_paths, tool_bound |
| verifier | judge | credential_paths, workspace_integrity, tool_bound, shell_tripwires, network_tools, read_only_bash --git read-only --test-runner unit, gh_classes |
| web-researcher | finder | credential_paths, tool_bound, network_tools --web |
<!-- end generated -->

## Files Daedalus creates

`<repo>` is the main working tree of the git repository you started Claude Code in.

| Path | When | Why |
|---|---|---|
| `<repo>/service-manifest.json` | You run `/daedalus:setup` and the file is missing | The starter manifest, with every feature off |
| `<repo>/.claude/daedalus/config.json` | You run `/daedalus:setup` and the file is missing | The starter config, with every setting at its default |
| `<repo>/.claude/daedalus/.gitignore` | A Build Train starts in the repository for the first time, or `/daedalus:setup` writes the config | Holds `*` so git ignores the whole directory |
| `<repo>/.claude/daedalus/audit/<session_id>.jsonl` | Every session, while a train runs in that repository | The hash-chained audit log for that session; kept until `audit_retention_days` says otherwise |
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

One row per key the two readers accept: what the key governs, then what goes there, as its type, its allowed values, its default and an example value. The table is generated from `scripts/lib/project_keys.py`, and a test fails when this copy goes stale. The service manifest is committed and shared by everyone who works on the project; the config never leaves your machine (0070). A dotted key is a key inside an object, and `[]` marks a key inside each entry of a list. The manifest keys no reader checks, `.gitleaks.toml`, `contracts/`, the standing-rules backfill file and a project train definition are spelled out key by key in [docs/project-requirements.md](docs/project-requirements.md).

<!-- key reference -->
| Key | File | What it governs | Type | Allowed values | Default | Example |
|---|---|---|---|---|---|---|
| `jail_narrowing.forbidden_paths` | `service-manifest.json` | Paths in your project no coding agent may write, on top of the paths the jail always protects (0054) | list of strings | Project-relative paths with forward slashes and no leading slash, `..` or glob characters; a trailing slash covers the whole folder, and matching ignores case | `[]` | `["infra/", "scripts/release.sh"]` |
| `jail_narrowing.forbidden_extensions` | `service-manifest.json` | File endings no coding agent may write (0054) | list of strings | Endings that each start with a dot and hold no slash or glob characters; matching ignores case | `[]` | `[".pem", ".tfstate"]` |
| `features.scope` | `service-manifest.json` | Whether a train treats the project as a git repository or as a plain folder (0074) | string or null | `"repository"`, `"folder"` or `null` | `null`: a git work tree is a repository, anything else is a plain folder | `"repository"` |
| `features.secrets_scan` | `service-manifest.json` | Turns on the Push Train's gitleaks scan of the commits a push sends; with the scan on, the Push Train stops when gitleaks is missing or finds a secret, and the doctor's gitleaks line is a `MISS` (0069) | boolean | `true` or `false` | `false`: no scan, and gitleaks need not be installed | `true` |
| `features.scrub_file` | `service-manifest.json` | A file of terms, one per line, that the release step checks the release notes against; a hit stops the release and names how many terms it found, never the terms (0069) | string or null | A project-relative path without a leading slash, `..` or glob characters, or `null` | `null`: nothing is checked | `"docs/scrub-terms.txt"` |
| `features.ledger` | `service-manifest.json` | Turns the decision ledger steps on or off (0069) | boolean or null | `true`: the ledger is used, and a train asks before creating one; `false`: no ledger step and no ledger question; `null`: the default | `null`: a ledger the config declares or the probe finds is used, and none is created | `true` |
| `trains_dir` | `service-manifest.json` | The project folder that holds its own train definitions; a train is looked up there first, as `<trains_dir>/<name>.json`, and then in the plugin's own trains folder (0073) | string or null | A project-relative folder path without a leading slash, `..` or glob characters, or `null` | `null`: only the plugin's trains are used | `"trains"` |
| `stack.unit_test_cmd` | `service-manifest.json` | The command that runs the project's unit tests; a coding agent may run it exactly as written, as one command (0073, 0098) | string or null | A non-empty command string, or `null` | `null`: no declared command | `"pytest -q"` |
| `stack.typecheck_cmd` | `service-manifest.json` | The command that type-checks the project; a coding agent may run it exactly as written, as one command (0098) | string or null | A non-empty command string, or `null` | `null`: no declared command | `"mypy src"` |
| `stack.lint_cmd` | `service-manifest.json` | The command that lints the project; a coding agent may run it exactly as written, as one command (0098) | string or null | A non-empty command string, or `null` | `null`: no declared command | `"ruff check ."` |
| `ledger.path` | `service-manifest.json` | Where rulings are appended, declared for everyone who works on the project; it wins over the config's ledger block (0004) | string | A path; `<repo_root>` and `<charter_root>` are filled in, and a relative path is read from the project root | No block, or `ledger: null`: the config's ledger block or the ledger probe is used | `"docs/decisions.md"` |
| `ledger.format` | `service-manifest.json` | How each ruling is written to the ledger (0004) | string | `"markdown-table-row"` (one table row per ruling) or `"heading-entry"` (one `## Entry N` section per ruling) | Required once the block exists | `"markdown-table-row"` |
| `ledger.id_scheme` | `service-manifest.json` | The pattern each new ruling id follows (0004) | string | A pattern such as `{seq:04d}-{repo}-{type}`; a heading ledger uses `{seq}` | Required once the block exists | `"{seq:04d}-{repo}-{type}"` |
| `ledger.sequence_source` | `service-manifest.json` | Where the next ruling number comes from (0004) | string | `"last-row-id"` or `"frontmatter:<key>"` | Required once the block exists | `"last-row-id"` |
| `charter_root` | `.claude/daedalus/config.json` | The repository where your decisions and specs live; the contract and ledger agents may write there, and a Build Train branches it as `daedalus/<train-id>` (0011) | string or null | A non-empty path to a git repository, written absolute | `null`: those agents write only inside the project, and the contract lives in `contracts/` | `"/work/decisions"` |
| `ledger.path` | `.claude/daedalus/config.json` | Where rulings are appended on this machine, used when the manifest declares no ledger (0004) | string | A path; `<repo_root>` and `<charter_root>` are filled in, and a relative path is read from the project root | `null`: the ledger probe looks for one | `"<charter_root>/decision-log.md"` |
| `ledger.format` | `.claude/daedalus/config.json` | How each ruling is written to the ledger (0004) | string | `"markdown-table-row"` (one table row per ruling) or `"heading-entry"` (one `## Entry N` section per ruling) | Required once the block exists | `"markdown-table-row"` |
| `ledger.id_scheme` | `.claude/daedalus/config.json` | The pattern each new ruling id follows (0004) | string | A pattern such as `{seq:04d}-{repo}-{type}`; a heading ledger uses `{seq}` | Required once the block exists | `"{seq:04d}-{repo}-{type}"` |
| `ledger.sequence_source` | `.claude/daedalus/config.json` | Where the next ruling number comes from (0004) | string | `"last-row-id"` or `"frontmatter:<key>"` | Required once the block exists | `"last-row-id"` |
| `policy.engine` | `.claude/daedalus/config.json` | The tool for a deterministic policy check on infrastructure changes; no train runs it yet | string | `"cfn-guard"` or `"conftest"` | `policy: null`: none declared | `"conftest"` |
| `policy.path` | `.claude/daedalus/config.json` | The folder that holds your policy rules; no train reads it yet | string | A non-empty path | Required once the block exists | `"/work/decisions/policy"` |
| `standards_sources[].kind` | `.claude/daedalus/config.json` | What one source of your standards is; the standards specialist reads only these entries (0019) | string | `"rules-dir"` (a folder of rule files), `"file"` (one file) or `"pack"` (a pack shipped inside the plugin) | `[]`: the Standards Packet is empty | `"rules-dir"` |
| `standards_sources[].path` | `.claude/daedalus/config.json` | Where a rules folder or rules file lives | string | A non-empty path, written absolute; a pack entry carries none | Required for a `rules-dir` or `file` entry | `"/work/rules"` |
| `standards_sources[].name` | `.claude/daedalus/config.json` | Which pack shipped with Daedalus to use (0019) | string | The name of a folder under the plugin's `packs/` that holds a `rules.md`; any other name is refused | Required for a `pack` entry | `"baseline"` |
| `operator_signing_keys` | `.claude/daedalus/config.json` | Reserved for the key fingerprints allowed to sign merges; no check reads it yet | list of strings | Non-empty strings | `[]` | `["ABCD1234EF567890"]` |
| `max_concurrent_builders` | `.claude/daedalus/config.json` | How many coding agents a parallel stage runs at once, and the cap on the plan width the plan validator prints (0072) | integer | A whole number of at least 1; `true` and `false` are refused | `5` | `3` |
| `audit_retention_days` | `.claude/daedalus/config.json` | How many days a session's audit log is kept after its last record. When a new session starts writing, older logs are deleted, each named with its final record in the new session's own log. A log named on a train summary's `Session` line, the log of a train not yet merged, and the current session's log are never deleted (issue 50) | integer or null | A whole number of at least 90, or `null` | `null`: every log is kept | `365` |
| `audit_round_budget` | `.claude/daedalus/config.json` | How many audit rounds a Build Train runs on its own. A rejected round continues while each round's findings shrink and no new high or critical finding appears; once the rounds used reach this number, the train stops and asks the operator (0109) | integer | A whole number from 1 to 10; `true` and `false` are refused | `5` | `3` |
| `agent_models` | `.claude/daedalus/config.json` | Which model each catalog agent runs on, in place of the `model:` line of its agent file; a model a skill is given for one run still comes first | object | Keys are agent names the catalog lists; values are `"sonnet"`, `"opus"`, `"haiku"` or `"fable"`; any other name or value is refused | `{}`: every agent runs on its agent file's model | `{"repo-coder": "sonnet"}` |
<!-- end key reference -->

## Safety model

Outside a train, Daedalus leaves your session and your repository alone, except that catalog agents keep their own hooks and a read or search of a credential file meets one check, which asks the main session and refuses an agent. Outside a train, Daedalus writes no files and keeps no audit log in any repository, including one where a train ran before; the one exception is `/daedalus:setup`, which writes its two starter files when you run it. Inside a train, the jail judges every tool call and the audit log records each step. A train works in three folders: the repository's `.claude/worktrees/` folder holds the unit worktrees, its `.claude/daedalus/` folder holds train state and the audit log, and the git-ignored `docs/.tmp/daedalus/` folder holds scratch files and summaries. To have the plugin's hooks in some repositories only, enable the plugin at project scope in each of those repositories' `.claude/settings.json` (Claude Code's `enabledPlugins`) instead of for your user.

Each agent gets a short list of allowed tools, and a tool not on the list is never offered to it. A PreToolUse hook is a check Claude Code runs before each tool call. Daedalus uses one, the jail, to compare every call against that agent's rules and block anything outside them. A coding agent may write only inside its own unit worktree, and there never to `contracts/`, `.github/`, `.claude/`, `service-manifest.json`, the decision ledger, or the paths and file extensions the repository lists under `jail_narrowing` in `service-manifest.json`. At all times, a read or search of `~/.ssh`, `~/.aws`, `~/.gnupg`, `~/.config/gh` or `~/.claude/.credentials.json` is refused for every agent and asked of the main session. Daedalus's own agents are always refused writing those paths with a file tool or naming them in Bash; while a train runs, the main session is asked before it does either. While a train runs, agents from Claude Code itself or from other plugins are refused every checked tool except reads and searches, in the train's repository and when they write into it from another one. The jail hooks are the enforced boundary and judge each tool call before it runs. Code an agent runs inside a tool call, such as its tests, is the same exposure any developer accepts when using a model in their environment, so Daedalus asks every agent never to circumvent its boundaries and does not try to control the environment. A blocked agent sees a line starting with `daedalus-jail[<agent>]:` that says what was refused and what to do next. Hooks, not agents, write each step to the hash-chained audit log. No agent pushes except the conductor inside the Push Train, and no agent merges. You merge.

With no declared standards, the Standards Packet is empty and the auditor judges each unit against its contract only. The NIST and CIS specialists review only units that touched IAM, KMS, mTLS, key custody or infrastructure configuration. To declare your standards, see [docs/project-requirements.md](docs/project-requirements.md). To start from a shipped set instead, declare the opt-in baseline pack, `{"kind": "pack", "name": "baseline"}`: five baseline checks plus the Daedalus cloud security standards, written in Daedalus's own words. The doctor offers it while `standards_sources` is empty.

## What is in this repo

```
Daedalus/
├── .claude-plugin/
│   ├── marketplace.json             # marketplace id: daedalus
│   └── plugin.json                  # plugin id: daedalus
├── .claude/settings.json            # this repository's own Claude Code settings
├── .gitignore
├── LICENSE
├── README.md
├── VERSION                          # the release version
├── pyproject.toml                   # dev tooling; the plugin itself is stdlib only
├── service-manifest.json            # this repository's own service manifest
├── agents/
│   ├── charter-docs.md
│   ├── cis-specialist.md
│   ├── contract-spec.md
│   ├── nist-specialist.md
│   ├── orchestrator.md
│   ├── planner.md
│   ├── pr-train-conductor.md
│   ├── repo-coder.md
│   ├── security-auditor.md
│   ├── standards-rules-specialist.md
│   ├── verifier.md
│   └── web-researcher.md
├── docs/
│   ├── howto/README.md              # operator guide
│   └── project-requirements.md      # every file Daedalus reads, with examples
├── hooks/
│   └── hooks.json                   # enforcement and audit bindings
├── packs/
│   └── baseline/rules.md            # opt-in baseline and cloud security standards pack
├── references/
│   ├── hardening-rubric.md          # the rubric the cis-specialist maps findings to
│   └── nist-800-53-distilled.md     # the rubric the nist-specialist maps findings to
├── scripts/                         # Python 3.12, stdlib only
│   ├── checks/command_allowlist.py  # every Bash segment runs a command the --allow list names
│   ├── checks/controls/             # the failure each control prevents and its premise test
│   ├── checks/credential_paths.py   # refuses a path or command that names a credential store
│   ├── checks/dispatch_gate.py      # the orchestrator's coder dispatch and plan gates
│   ├── checks/gh_classes.py         # the gh deny classes; the conductor's gh rules
│   ├── checks/git_grammar.py        # each git segment fits the grammar of its grant
│   ├── checks/git_push.py           # refuses remote git; the conductor pushes the train branch only
│   ├── checks/network_tools.py      # refuses web tools and network commands without a grant
│   ├── checks/read_only_bash.py     # every Bash segment is a read-only command or git read
│   ├── checks/root_writes.py        # writes land only under the named path classes
│   ├── checks/shapes.json           # the hooks each agent shape carries
│   ├── checks/shell_tripwires.py    # the worker shell model and its tripwires
│   ├── checks/tool_bound.py         # refuses a tool the agent file does not list
│   ├── checks/unit_writes.py        # the coder writes only in its own unit worktree
│   ├── checks/workspace_integrity.py # refuses writes into .git and the data folder
│   ├── lib/__init__.py
│   ├── lib/agent_files.py           # reads agent files and their hooks blocks
│   ├── lib/agent_models.py          # the model each agent runs on: override, config, agent file
│   ├── lib/audit.py                 # hash-chained append, redaction
│   ├── lib/audit_proof.py           # the hooks-live and approved-verdict proofs
│   ├── lib/config.py                # config.json loading and validation
│   ├── lib/controls.py              # loads the controls fragments
│   ├── lib/credential_paths.py      # the credential-path deny every agent meets
│   ├── lib/dispatch_binding.py      # coder dispatch, warm rebind and first-write claim
│   ├── lib/fetch.py                 # GitHub-only download, size cap and cache lock for refreshes
│   ├── lib/gh_policy.py             # the gh commands each agent may run
│   ├── lib/hook_io.py               # hook input and output for the check scripts
│   ├── lib/human_text.py            # counts the plain words in operator lines
│   ├── lib/jail.py                  # per-agent tool policy
│   ├── lib/ledger.py                # ledger resolution, sequence read, entry format
│   ├── lib/locks.py                 # bounded flock shared by audit and ledger writers
│   ├── lib/manifest.py              # the one reader of service-manifest.json
│   ├── lib/plan_record.py           # loads and validates plan records
│   ├── lib/project_keys.py          # every manifest and config key, its reference row, and the starter files
│   ├── lib/project_root.py          # finds the project root
│   ├── lib/redact.py                # secret masking for audit records
│   ├── lib/repo_root.py             # finds a train marker before other lib modules load
│   ├── lib/router.py                # runs each agent's calls through its hooks
│   ├── lib/scrub.py                 # reads the declared scrub file's terms
│   ├── lib/shell.py                 # the shell model the jail and checks share
│   ├── lib/train_definition.py      # loads and validates train definitions
│   ├── lib/train_runner.py          # the train state machine behind daedalus_train.py
│   ├── lib/train_scope.py           # the train scope the jail's entry script reads first
│   ├── lib/train_state.py           # one state file per train
│   ├── lib/unit_binding.py          # one coder per unit worktree
│   ├── lib/workspace.py             # unit worktrees and the train marker
│   ├── append_ledger.py             # locked, sequence-checked ledger writer
│   ├── audit_log.py                 # all other hook events to the audit log
│   ├── audit_report.py              # digest of a verified session log
│   ├── catalog.py                   # prints the agent table and hooks matrix
│   ├── daedalus_doctor.py           # first-run check behind /daedalus:doctor
│   ├── daedalus_setup.py            # writes the missing starter files behind /daedalus:setup
│   ├── daedalus_train.py            # the train runner: progress, choice, plan, verdict, exception
│   ├── daedalus_workspace.py        # begin, lock, create, remove, finish, stop, resume, mark, unmark, release
│   ├── enforce_agent_jail.py        # PreToolUse policy
│   ├── refresh_frameworks.py        # operator-run: compile the pinned framework caches
│   ├── standing_rules.py            # derives the standing-rules file from the ledger
│   ├── validate_plan.py             # checks a plan file and prints its graph line
│   ├── validate_train.py            # checks a train definition file
│   └── verify_audit_chain.py        # recompute and verify a session's hash chain
├── skills/
│   ├── audit-report/SKILL.md        # /daedalus:audit-report
│   ├── build-train/SKILL.md         # /daedalus:build-train
│   ├── catalog/SKILL.md             # /daedalus:catalog
│   ├── doctor/SKILL.md              # /daedalus:doctor
│   ├── plan/SKILL.md                # /daedalus:plan
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
