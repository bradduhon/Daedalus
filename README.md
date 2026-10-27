<!-- Copyright (c) 2026 Brad Duhon. SPDX-License-Identifier: GPL-3.0-or-later -->
# Daedalus

## What Daedalus is

Daedalus is a Claude Code plugin that gives your session a catalog of scoped AI agents. Each agent has a short list of tools and works inside a jail, a set of hook-checked rules that blocks anything outside its job. Daedalus is an open composition over those agents (0088): you compose each body of work yourself, and the Build Train (`/daedalus:build-train`) is one saved recipe over this catalog, not the required shape. The Push Train (`/daedalus:push-train`) is a second saved recipe, for the push and the pull request.

Every body of work passes through six phases: context, clarification, plan, implementation, audit, and commit and release (0089). Phases overlap freely. A phase's weight scales with the task: a one-file fix carries a one-unit plan and no contract packet, and a cross-module build carries the packet. A contract packet is a written spec of the interfaces each coding agent's code must follow, locked before coding starts.

Hooks check four exit conditions today: a plan record before a coder, a worktree binding for every coder, an approved verdict on the exact tip (or the operator's exemption for every finding of a rejected round) before a push or pull request, and the conductor as the only agent that pushes. Capturing each ruling in your decision ledger and merging the pull request are your duty; no hook checks them.

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
2. Write a spec, or point at one. A spec is a file in your repository that says what to build and how you will know it works. A one-line task needs no file; the Build Train saves the words you type as the spec. With only an idea and no spec, type `/daedalus:brainstorm` and the idea, or the path of a notes file. The planner answers in numbered rounds of contradictions, gaps and proposals, each tied to a sentence you wrote, and you answer in your own words. When the idea settles, the planner writes a spec draft under `docs/.tmp/daedalus/brainstorm-<YYYYMMDD>/`. Move it where your project keeps its specs and say the spec stands; the same planner then cuts the plan, as in step 3.
3. Cut the spec into units. Type `/daedalus:plan` and the spec's path, for example `/daedalus:plan docs/specs/healthz.md`. The planner agent writes a plan file, and the plan validator checks it and prints `OK plan: graph: units=<n> critical_path=<k> width=<w> overlap_only=<pairs>`. The session then shows a unit table with the columns Unit, What it builds, Starts from, Waits on and Shares files with. Each row is one coding agent's work. Waits on names the units that must finish first, and Shares files with names the units that edit the same files, with the order they merge in. Outside a train the plan lands at `docs/.tmp/daedalus/plan-<YYYYMMDD>.md`.
4. Start the Build Train. Type `/daedalus:build-train` and your task, naming the plan file the plan step wrote, as its `Next:` line says. The session hands it to the orchestrator as the train's plan; the orchestrator checks it with the plan validator and records it instead of cutting a new one. With no plan named, the orchestrator cuts and records the plan itself before any coder starts. The session checks the preconditions and prints the first State Block lines. The hooks check then prints `OK hooks live: session <id>, chain intact (<n> records)`. That check also marks where this train's audit begins; the Push Train later reads the security verdict only from records after that mark (issue 57).
5. Watch it run. The main session starts one orchestrator agent and relays between it and you (0060). After each phase you see a progress note that names the phase, its weight and the state of each unit. Before each choice the train prints one line, `Chose <what> over <alternative>: <cost>`.
6. Answer its questions. When the train needs a ruling, the orchestrator writes a decision brief, and the session asks you through Claude Code's question prompt. Each question has a question line ending in a question mark, two or three context sentences and its options, with the recommended option first. The orchestrator ends each reply with one of four lines, and the session routes it:
   - `[STATUS: DECISION]`: the session asks you the brief's questions and sends your picks back.
   - `[STATUS: EXCEPTION]`: you exempted every finding of the last audit round, and the session records one exemption per finding, each with its ruling and how you chose to track it.
   - `[STATUS: STOP]`: the session runs the stop command and shows its `Next:` line. Say continue to resume.
   - `[STATUS: TRAIN_COMPLETE]`: the session shows the summary path and the audit log path, then ends the train. If a commit lands on the integration branch after that, tell the session; it runs one recovery audit round on the new tip (`daedalus_train.py reaudit`) instead of a full rerun. A train that stopped before its ledger commit is finished by the session's ledger resume (`daedalus_train.py resume`).
7. Read the audit result. The units merge onto the local branch `daedalus/<train-id>` first, and the security auditor judges that merged integration tip against the train's base. After each rejected round the session asks you about every finding, one question per finding, with three choices: `Fix it now (Recommended)`, `Skip, track or exempt it` and `Stop the train` (0133). No fix round starts without your pick, and no number of rounds is set in advance. `Skip, track or exempt it` brings a second question, how the exemption is tracked: `Skip it` (dropped silently), `Track it` (a GitHub tracked-risk issue), `Exempt it` (the local ledger record alone), or your own answer. The Push Train's verdict check accepts a rejected round once every one of its findings carries an exemption.
8. Push and merge. Review the integration branch, then read the session's audit log with `/daedalus:audit-report <session>`. Type `/daedalus:push-train` to push the branch and open its pull request. You merge the pull request.

## Saved recipes

The Build Train and the Push Train are saved recipes over the catalog, not the required shape (0088). A body of work can use any agents from the catalog in any order. Outside a train, catalog agents keep their own hooks; the main session and agents from Claude Code itself or other plugins meet only the credential check on reads and searches, which warns the main session in its context and refuses an agent (see Safety model below).

### Build Train

The Build Train (`/daedalus:build-train`) takes a task from its plan to an audited local branch. The main session checks the preconditions, starts one orchestrator agent, and relays between it and you. The orchestrator follows its recipe over the catalog. It reads your standards, cuts and records the plan, and locks the contract when the task carries one. It gives each unit to a coding agent in its own worktree, which is a separate checkout of your repository. It merges every unit into a local branch named `daedalus/<train-id>` and has the security auditor judge that merged branch. The train creates each worktree itself and removes it when the train ends. The Build Train never pushes.

Before you start, you need:

- a decision ledger, which is a file where your project records its design rulings; declare one or let the train find it or ask to create one
- a clean working tree
- optionally, `<repo>/.claude/daedalus/config.json` (see [docs/project-requirements.md](docs/project-requirements.md)); without it the defaults apply

Then type the command and your task:

    /daedalus:build-train Add a --verbose flag to the command-line tool

### Push Train

The Push Train commits, pushes, and opens the pull request for a finished Build Train. It first checks that the Build Train's audit log holds an approved security verdict for that train. When `features.secrets_scan` is `true` in `service-manifest.json`, it scans the commits for secrets with gitleaks before the push. Your repository needs a GitHub remote named `origin`, and `gh` must be signed in to it. The conductor, the agent named pr-train-conductor, does the pushing and watches CI. When the Build Train used a Charter branch, the conductor also pushes that branch and opens its pull request after the code one. When a commit landed on the integration branch after the audit, the Push Train runs one recovery audit round on the new tip before it pushes. You review and merge, then delete the train branch from your own shell with `git branch -D daedalus/<train-id>` once `gh pr view <url> --json state` shows the merge.

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
| change-logger | producer | opus | Bash, Glob, Grep, Read, Write | Produces the change gate between a baseline and a derived document, or between two baselines when no deriver runs: one row per departure, with the baseline quote, the derived quote, the reason, and a status the operator rules on. | `[STATUS: COMPLETE] change_log=<path> rows=<n> open=<k>`; `[STATUS: BLOCKED] <what the manifest or brief leaves out>` | implementation |
| charter-docs | producer | sonnet | Bash, Edit, Glob, Grep, Read, Write | Single-writer custodian of the Charter repository, the architectural decision ledger, and Build Train commits. | `[STATUS: LEDGER_PROBED] <probe line>`; `[STATUS: LEDGER_APPENDED] <id>`; `[STATUS: LEDGER_MISMATCH] expected=<n> ledger=<m>`; `[STATUS: COMMITTED] <sha> ids=<id>[,<id>]`; `[STATUS: BLOCKED] <detail>` | clarification, commit, release |
| cis-specialist | judge | sonnet | Bash, Grep, Read | Evaluates cloud infrastructure, IAM/RCP policies, and OS/container hardening against operator-supplied CIS Benchmarks. | `[STATUS: CACHE_INVALID] <detail>`; `[STATUS: COMPLIANCE] <PASS/FAIL list with control ids and file:line>` | clarification, audit |
| contract-spec | producer | sonnet | Edit, Glob, Grep, Read, Write | Reads and updates service handshake contracts, API schemas, and specifications. | `## Locked Contract Packet` | clarification, plan |
| dependency-auditor | judge | sonnet | Bash, Glob, Grep, Read | Read-only judge of the dependency manifests and lockfiles a train changes. | `[STATUS: YIELD_WEB] <query>`; `[STATUS: COMPLIANCE] <PASS/FAIL list with rule ids and file:line>` | audit |
| doc-deriver | producer | opus | Bash, Edit, Glob, Grep, Read, Write | Derives one document from frozen, manifest-declared sources with a file:line receipt on every value. | `[STATUS: COMPLETE] outputs=<path>[,<path>] claims=<n> judgments=<k> assumed=<m>`; `[STATUS: BLOCKED] <what the manifest or brief leaves out>` | implementation |
| docs-writer | producer | opus | Bash, Edit, Glob, Grep, Read, Write | Writes the public docs to match what a train merged. | `[STATUS: DOCS_WRITTEN] branch=<b> commit=<40 hex> claims=<n>`; `[STATUS: DOCS_UNCHANGED] reason=<why no passage needed an edit>` | audit |
| nist-specialist | judge | sonnet | Bash, Grep, Read | Evaluates architecture, IAM, and cryptographic boundaries against the pinned NIST SP 800-53 OSCAL catalog and SP 800-57 key-management guidance. | `[STATUS: CACHE_INVALID] <detail>`; `[STATUS: COMPLIANCE] <PASS/FAIL list with control ids and file:line>` | clarification, audit |
| orchestrator | dispatcher | fable | Agent, Bash, Edit, Glob, Grep, Read, SendMessage, Write | Runs one Build Train from its plan to the audited integration tip. | `[STATUS: DECISION] brief=<path> questions=<n>`; `[STATUS: EXCEPTION] ledger_id=<id>`; `[STATUS: TRAIN_COMPLETE] summary=<path> audit_log=<path> tip=<40 hex>`; `[STATUS: STOP] reason=<what happened> next=<next action>` | context, clarification, plan, implementation, audit |
| planner | shaper | opus | Glob, Grep, Read, Write | Cuts a design spec into work units that coders can build in parallel. | `[STATUS: PLAN] path=<path> units=<n> critical_path=<k> width=<w>`; `[STATUS: QUESTION] <what the task leaves open>`; `[STATUS: ROUND] round=<k> items=<m>`; `[STATUS: SPEC] round=<k> path=<path> open=<m>`; `[STATUS: NOT_VIABLE] round=<k> <the blocking fact in one line>`; `[STATUS: YIELD_WEB] <query>` | clarification, plan |
| pr-train-conductor | mover | opus | Bash, Glob, Grep, Read | GitHub specialist for the Push Train. | `[STATUS: PUSHED] branch=<b> pr=<url>`; `[STATUS: CI] run=<id> conclusion=<text>`; `[STATUS: BLOCKED] <precondition that failed>` | commit, release |
| repo-coder | producer | opus | Bash, Edit, Glob, Grep, Read, Write | Scoped implementation worker. | `[STATUS: YIELD_WEB] <query>`; `[STATUS: YIELD_CONTRACT] <mismatch>`; `[STATUS: YIELD_COMPLIANCE] <question>`; `[STATUS: YIELD_STANDARDS] <question>`; `[STATUS: COMPLETE] branch=<b> packet_version=<n> files=<list> tests=<summary> ledger_notes=<text> contract=<12 hex> standards=<12 hex>` | implementation |
| security-auditor | judge | opus | Bash, Edit, Glob, Grep, Read, Write | Adversarial pre-commit security and contract verifier. | `[VERDICT: APPROVED] tip=<40 lowercase hex>`; `[VERDICT: REJECTED] tip=<40 lowercase hex>` | audit |
| standards-rules-specialist | finder | sonnet | Glob, Grep, Read | Adopts the project's declared standards. | `## Standards Packet`; `[STANDARDS: CONTRADICTION] <spec ref> vs <source:line>`; `[STATUS: STANDARD] <answer>` | clarification, plan |
| terraform-reviewer | judge | sonnet | Bash, Glob, Grep, Read | Read-only judge of the .tf and .tfvars changes a train makes. | `[STATUS: COMPLIANCE] <PASS/FAIL list with rule ids and file:line, warnings included>` | audit |
| verifier | judge | opus | Bash, Glob, Grep, Read | Adversarial read-only verifier of one unit's diff against its brief. | `[VERDICT: VERIFIED] claims=<n>`; `[VERDICT: REFUTED] <rows>` | implementation |
| web-researcher | finder | haiku | Read, WebFetch, WebSearch | Fast external documentation lookup on Haiku. | `[STATUS: RESEARCH] <payload under 300 words with URLs>` | context |
<!-- end generated -->

Each agent file also declares a shape and the hook scripts listed in its hooks block, with their flags. The table below is generated from the agent files by `python3 scripts/catalog.py matrix`; a test fails when it goes stale.

<!-- generated: catalog.py matrix -->
| Agent | Shape | Hooks |
|---|---|---|
| change-logger | producer | credential_paths, workspace_integrity, tool_bound, shell_tripwires, network_tools, git_push, git_grammar, read_only_bash, doc_outputs |
| charter-docs | producer | credential_paths, workspace_integrity, tool_bound, shell_tripwires, network_tools, git_push, git_grammar --allow docs, root_writes --touch charter,docs --ledger-guard, command_allowlist --allow append_ledger,git,read, gh_classes |
| cis-specialist | judge | credential_paths, workspace_integrity, tool_bound, shell_tripwires, network_tools, read_only_bash --git specialist, gh_classes |
| contract-spec | producer | credential_paths, workspace_integrity, tool_bound, root_writes --touch contracts,charter-specs |
| dependency-auditor | judge | credential_paths, workspace_integrity, tool_bound, shell_tripwires, network_tools, read_only_bash --git read-only, gh_classes |
| doc-deriver | producer | credential_paths, workspace_integrity, tool_bound, shell_tripwires, network_tools, git_push, git_grammar, read_only_bash, doc_outputs |
| docs-writer | producer | credential_paths, workspace_integrity, tool_bound, shell_tripwires, network_tools, git_push, git_grammar --allow coder, unit_writes --docs, gh_classes, confine |
| nist-specialist | judge | credential_paths, workspace_integrity, tool_bound, shell_tripwires, network_tools, read_only_bash --git specialist, gh_classes |
| orchestrator | dispatcher | credential_paths, workspace_integrity, tool_bound, shell_tripwires, network_tools, git_push, command_allowlist --allow train,inspect, root_writes --touch scratch --ledger-guard, gh_classes, dispatch_gate |
| planner | shaper | credential_paths, workspace_integrity, tool_bound, root_writes --touch scratch --name plan*.md --sub brainstorm-*/spec.md |
| pr-train-conductor | mover | credential_paths, workspace_integrity, tool_bound, shell_tripwires, network_tools --gh, command_allowlist --allow git,gh,gitleaks, git_grammar --allow conductor, git_push --conductor, gh_classes --conductor |
| repo-coder | producer | credential_paths, workspace_integrity, tool_bound, shell_tripwires, network_tools, git_push, git_grammar --allow coder, unit_writes, gh_classes, confine |
| security-auditor | judge | credential_paths, workspace_integrity, tool_bound, shell_tripwires, network_tools, read_only_bash --git read-only --test-runner audit, gh_classes, root_writes --touch audit |
| standards-rules-specialist | finder | credential_paths, tool_bound |
| terraform-reviewer | judge | credential_paths, workspace_integrity, tool_bound, shell_tripwires, network_tools, command_allowlist --allow terraform,inspect, gh_classes |
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
| `<repo>/.claude/daedalus/trains/<train-id>.json` | A Build Train starts | The train state file: plan record, units, verdicts, exemptions and ledger record (see How it works) |
| `<repo>/.claude/daedalus/trains/<train-id>.bindings.json` | The first coder of a train is dispatched | Which coding agent holds each unit worktree |
| `<repo>/.claude/daedalus/trains/<train-id>.sources.json` | A document train freezes its sources | Each frozen source with its sha256, and the excluded folders |
| `<repo>/.claude/daedalus/reply-hmac.key` | The first agent reply recorded during a train | The secret that keys each reply digest in the audit log; no agent may read it |
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

To start both project files, type `/daedalus:setup`. It writes a starter `service-manifest.json` at the project root, with every feature off, and a starter `.claude/daedalus/config.json`, with every setting at its default. It writes only a file that is missing and never overwrites one. It prints one line per file: `written:` when it created the file, `kept:` when the file already existed (0076). After writing a new manifest it prints one more line with example values for the docs writer's `docs.literacy` key, which the manifest holds as `null` (0134).

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
| `features.github` | `service-manifest.json` | Says the project pushes to GitHub and opens its pull requests there with the gh tool; with it on, the doctor's two gh lines are a `MISS` when gh is missing or not signed in, and with it off they are `OPT` (0069) | boolean or null | `true`, `false` or `null`; `null` reads as `false` | `false`: the doctor never fails on gh | `true` |
| `features.dependency_web_lookup` | `service-manifest.json` | Lets the dependency auditor ask for security advisories on the web; the train sends its questions to the web researcher. With it off, the auditor judges from the lockfile and any advisory export the project supplies (0132) | boolean or null | `true`, `false` or `null`; only `false` turns the lookup off | `null`: the lookup is on | `false` |
| `features.terraform_tools` | `service-manifest.json` | Lets the Terraform reviewer run `terraform fmt -check` and `terraform validate` on the Terraform files a train changes. With it off, the reviewer judges by reading the files (0132) | boolean or null | `true`, `false` or `null`; only `false` turns both commands off | `null`: both commands may run | `false` |
| `trains_dir` | `service-manifest.json` | The project folder that holds its own train definitions; a train is looked up there first, as `<trains_dir>/<name>.json`, and then in the plugin's own trains folder (0073) | string or null | A project-relative folder path without a leading slash, `..` or glob characters, or `null` | `null`: only the plugin's trains are used | `"trains"` |
| `stack.unit_test_cmd` | `service-manifest.json` | The command that runs the project's unit tests; a coding agent may run it exactly as written, as one command (0073, 0098) | string or null | A non-empty command string, or `null` | `null`: no declared command | `"pytest -q"` |
| `stack.typecheck_cmd` | `service-manifest.json` | The command that type-checks the project; a coding agent may run it exactly as written, as one command (0098) | string or null | A non-empty command string, or `null` | `null`: no declared command | `"mypy src"` |
| `stack.lint_cmd` | `service-manifest.json` | The command that lints the project; a coding agent may run it exactly as written, as one command (0098) | string or null | A non-empty command string, or `null` | `null`: no declared command | `"ruff check ."` |
| `docs.literacy` | `service-manifest.json` | How plainly the docs writer writes the public docs at the end of a Build Train, as a reader level or a voice profile the project declares; a brief may override it (0134) | string or null | `"plain"`, `"standard"`, `"expert"` or `"profile:docs/voice-profile.md"`, a project-relative path to the profile file without a leading slash, `..` or glob characters | `null`: the writer keeps the register the public docs already use | `"plain"` |
| `priorities.drivers` | `service-manifest.json` | Which concern wins when two conflict and no rule below matches, for every agent in every train, never the operator's own session (0129, 0137) | list of strings | Each of `security`, `trust`, `ops`, `cost` exactly once, highest first | No `priorities` key: none declared, and agents follow no project ranking | `["security", "trust", "ops", "cost"]` |
| `priorities.rules[].when.conflict` | `service-manifest.json` | The two concerns a rule settles; rules are tried in order and the first match decides (0129) | list of two strings | Two different names of `security`, `trust`, `ops`, `cost`; at most 32 rules | `rules` absent: no rule, so the ranking decides | `["security", "cost"]` |
| `priorities.rules[].when.reason` | `service-manifest.json` | Why the conflict arises; the rule matches only these reasons (0129) | list of strings | One or more of `certification`, `framework`, `best-practice`, `incident`, `shape`, `domain-separation`, `ownership`, `convenience`, `latency`, `margin`, `running-cost`, each once | Required in each rule | `["certification", "framework"]` |
| `priorities.rules[].then` | `service-manifest.json` | What a matching rule does: a concern named here wins and the agent decides alone; `surface` puts the decision to the operator (0129) | string | One of `security`, `trust`, `ops`, `cost`, or `surface` | Required in each rule | `"surface"` |
| `priorities.rules[].note` | `service-manifest.json` | The one line a choice record or a decision brief quotes when the rule applies (0129) | string | One printable line of 1 to 200 characters | Required in each rule | `"a control a certification asks for wins over its running cost"` |
| `priorities.principles[].id` | `service-manifest.json` | The name an agent cites when a decision rests on one of the project's principles (0129) | string | `P` followed by digits, unique in the block; at most 64 principles | `principles` absent: none declared | `"P1"` |
| `priorities.principles[].driver` | `service-manifest.json` | The concern a principle serves (0129) | string | One of `security`, `trust`, `ops`, `cost` | Required in each principle | `"security"` |
| `priorities.principles[].text` | `service-manifest.json` | The principle itself, as one sentence a decision brief quotes (0129) | string | One printable line of 1 to 300 characters | Required in each principle | `"Each tenant keeps its own key."` |
| `priorities.principles[].source` | `service-manifest.json` | Where the principle is written down, so a reader can follow it (0129) | string | A repo-relative path or a ruling id of the project's own ledger, without a leading slash, `..` or glob characters | Absent: no source named | `"docs/design.md"` |
| `priorities.agents.<name>.drivers` | `service-manifest.json` | A different ranking for one agent; rules and principles still apply to it (0129) | list of strings | Each of `security`, `trust`, `ops`, `cost` exactly once; `<name>` is a Daedalus agent file name other than `security-auditor`, which is refused | Absent: the agent follows `priorities.drivers` | `{"repo-coder": {"drivers": ["cost", "security", "ops", "trust"]}}` |
| `frameworks.pack_dir` | `service-manifest.json` | The project folder that holds its own control packs; each subfolder holding a `pack.json` is one pack (0157) | string or null | A project-relative folder path without a leading slash, `..` or glob characters, or `null` | No `frameworks` key: only the packs Daedalus ships are read | `"compliance/packs"` |
| `frameworks.default_packs` | `service-manifest.json` | Whether the packs Daedalus ships are read beside the project's own packs (0157) | boolean | `true` or `false`; `false` reads only the packs under `frameworks.pack_dir` | `true`: the shipped packs are read | `false` |
| `ledger.path` | `service-manifest.json` | Where rulings are appended, declared for everyone who works on the project; it wins over the config's ledger block (0004) | string | A path; `<repo_root>` and `<charter_root>` are filled in, and a relative path is read from the project root | No block, or `ledger: null`: the config's ledger block or the ledger probe is used | `"docs/decisions.md"` |
| `ledger.format` | `service-manifest.json` | How each ruling is written to the ledger (0004) | string | `"markdown-table-row"` (one table row per ruling) or `"heading-entry"` (one `## Entry N` section per ruling) | Required once the block exists | `"markdown-table-row"` |
| `ledger.id_scheme` | `service-manifest.json` | The pattern each new ruling id follows (0004) | string | A pattern such as `{seq:04d}-{repo}-{type}`; a heading ledger uses `{seq}` | Required once the block exists | `"{seq:04d}-{repo}-{type}"` |
| `ledger.sequence_source` | `service-manifest.json` | Where the next ruling number comes from (0004) | string | `"last-row-id"` or `"frontmatter:<key>"` | Required once the block exists | `"last-row-id"` |
| `charter_root` | `.claude/daedalus/config.json` | The repository where your decisions and specs live; the contract and ledger agents may write there, and a Build Train branches it as `daedalus/<train-id>` (0011) | string or null | A non-empty path to a git repository, written absolute | `null`: those agents write only inside the project, and the contract lives in `contracts/` | `"/work/decisions"` |
| `excluded_roots` | `.claude/daedalus/config.json` | Folders whose files must never reach git, GitHub or a redirect. A Daedalus agent is refused such a command in every session, and the main session is warned during a train. A document train records the resolved folders in its frozen sources file (0136) | list of objects | `{"kind": "path", "path": "<folder>"}`, a folder with `<repo_root>` and `<charter_root>` filled in and a relative path read from the project root; or `{"kind": "gitignore", "match": "directories"}` (every folder git ignores) or `"match": "all"` (every ignored path); a folder holding a linked worktree is skipped | `[]`: no folder is excluded | `[{"kind": "path", "path": "<repo_root>/private/"}]` |
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
| `agent_models` | `.claude/daedalus/config.json` | Which model each catalog agent runs on, in place of the `model:` line of its agent file; a model a skill is given for one run still comes first | object | Keys are agent names the catalog lists; values are `"sonnet"`, `"opus"`, `"haiku"` or `"fable"`; any other name or value is refused | `{}`: every agent runs on its agent file's model | `{"repo-coder": "sonnet"}` |
<!-- end key reference -->

## Safety model

Outside a train, Daedalus leaves your session and your repository alone, except that catalog agents keep their own hooks and a read or search of a credential file meets one check, which warns the main session in its context and refuses an agent. Outside a train, Daedalus writes no files and keeps no audit log in any repository, including one where a train ran before; the one exception is `/daedalus:setup`, which writes its two starter files when you run it. Inside a train, the jail judges every tool call and the audit log records each step. A train works in three folders: the repository's `.claude/worktrees/` folder holds the unit worktrees, its `.claude/daedalus/` folder holds train state and the audit log, and the git-ignored `docs/.tmp/daedalus/` folder holds scratch files and summaries. To have the plugin's hooks in some repositories only, enable the plugin at project scope in each of those repositories' `.claude/settings.json` (Claude Code's `enabledPlugins`) instead of for your user.

Each agent gets a short list of allowed tools, and a tool not on the list is never offered to it. A PreToolUse hook is a check Claude Code runs before each tool call. Daedalus uses one, the jail, to compare every call against that agent's rules and block anything outside them. A coding agent may write only inside its own unit worktree, and there never to `contracts/`, `.github/`, `.claude/`, `service-manifest.json`, the decision ledger, or the paths and file extensions the repository lists under `jail_narrowing` in `service-manifest.json`. At all times, a read or search of `~/.ssh`, `~/.aws`, `~/.gnupg`, `~/.config/gh` or `~/.claude/.credentials.json` is refused for every agent; the main session's call runs with a warning in its context and its transcript. Daedalus's own agents are always refused writing those paths with a file tool or naming them in Bash; while a train runs, the main session is warned in context when it does either. A train never stops the main session with a permission prompt: each call the jail flags in your own session runs, and the warning names what the call touches and what can go wrong (Main never prompted, amending 0105 and 0106). While a train runs, agents from Claude Code itself or from other plugins are refused every checked tool except reads and searches, in the train's repository and when they write into it from another one. The jail hooks are the enforced boundary and judge each tool call before it runs. Code an agent runs inside a tool call, such as its tests, is the same exposure any developer accepts when using a model in their environment, so Daedalus asks every agent never to circumvent its boundaries and does not try to control the environment. A blocked agent sees a line starting with `daedalus-jail[<agent>]:` that says what was refused and what to do next. Hooks, not agents, write each step to the hash-chained audit log. No agent pushes except the conductor inside the Push Train, and no agent merges. You merge.

[docs/guardrails.md](docs/guardrails.md) pairs each of these principles with the mechanism that enforces it and the test that shows the mechanism exists.

With no declared standards, the Standards Packet is empty and the auditor judges each unit against its contract only. The NIST and CIS specialists review only units that touched IAM, KMS, mTLS, key custody or infrastructure configuration. To declare your standards, see [docs/project-requirements.md](docs/project-requirements.md). To start from a shipped set instead, declare the opt-in baseline pack, `{"kind": "pack", "name": "baseline"}`: five baseline checks plus the Daedalus cloud security standards, written in Daedalus's own words. The doctor offers it while `standards_sources` is empty.

## How it works

This section follows one tool call from Claude Code to its audit record, then one Build Train from the first command to the pull request. Each passage says what a piece is, what reads it and what it feeds.

### One tool call, end to end

Claude Code runs the hooks that `hooks/hooks.json` binds. Before a Bash, file, search, web, agent, message or MCP call, it runs `scripts/enforce_agent_jail.py` with the call as JSON on its input. That entry has a 10-second timeout, and its failure mode is block, so a hook that crashes or hangs refuses the call. Input that is empty, unparsable or missing a tool name is refused.

The entry first decides the call's train scope. It walks up from the call's working folder to the project root. The root is the first folder holding `service-manifest.json` or `.claude/daedalus/`, or the main checkout when that folder is a linked worktree; with neither, it is the git root. The entry then looks for the train marker `.claude/daedalus/train.active` there. `scripts/lib/train_scope.py` names who meets the jail without a marker: every Daedalus agent, arriving as `daedalus:<name>`. The main session and agents from Claude Code itself or other plugins meet the full jail only during a train.

With no marker, a call from the main session or a foreign agent takes the fast path, unless a path it names lies in a repository with a marker. The fast path loads none of the jail's other libraries and runs one check: a read or search of a credential store refuses an agent and warns the main session. A Bash command the entry cannot split, or one with more than 256 words or naming more than 16 repositories, goes to the full jail instead.

Otherwise the entry loads the config and the jail libraries and judges the call:

- A Daedalus agent's call goes to the router, `scripts/lib/router.py`. The router reads the agent's file under `agents/`, runs each check its hooks block names, then runs the excluded-roots check that every routed agent meets.
- The main session's call goes to `scripts/lib/jail.py`. The jail never refuses the operator's own session: a call it flags runs, with a warning in the session's context (Main never prompted, amending 0105 and 0106).
- A foreign agent's call also goes to `scripts/lib/jail.py`. During a train it may read and search in the train's repository, and every other checked tool there is refused.

The entry then appends the decision to the session's audit log as a PreToolUse record, with the refusing check's name as the prefix of its reason. When the record cannot be written, an agent's call is refused unless it is an allowed read, and the main session's call runs with an alert. A refusal exits 2 and prints `daedalus-jail[<agent>]: <reason> Next: <what to do>` on stderr, which Claude Code shows the agent. An allowed call exits 0. After the tool runs, `scripts/audit_log.py` records the PostToolUse or PostToolUseFailure event in the background, with a hash and the start of the tool's output.

When the jail's own libraries fail to load, a call in a train is refused for an agent and runs with an alert for the main session. Outside a train such a call proceeds, with a note on stderr.

### How a rule set is built from a hooks block

Each agent file's frontmatter carries a hooks block: one `PreToolUse` event holding one `- hooks:` item, then one entry per check, written `{type: command, command: "python3 ${CLAUDE_PLUGIN_ROOT}/scripts/checks/<script>.py <flags>"}`. The agent file loader, `scripts/lib/agent_files.py`, refuses any other shape and any script that is not shipped under `scripts/checks/`. Claude Code itself ignores hooks blocks on plugin agents, so the router is what runs them, in the jail's own process (jail rules through a router, 0044).

- Order: the checks run in the order the block lists them, and the first refusal ends the call. The hooks matrix under "The agents" above prints each block in that order.
- Flags: the words after the script path are that check's flags. Each check declares the flags it takes, and a flag it does not know or a value of the wrong form refuses the call.
- Tools: a check that names the tools it judges allows every other tool without judging it.
- Combination: the call passes only when every check allows it. A check that fails to load, raises, or returns something other than a decision refuses the call with its full cause. An agent with no agent file or no hooks block is refused before any check runs.

`scripts/checks/shapes.json` lists the checks each agent shape must carry. A test fails when an agent file lacks a check its shape lists.

### The train marker

The train marker is the file `<repo>/.claude/daedalus/train.active`, whose first line names the running train's id. `daedalus_workspace.py begin` writes it when a Build Train starts, `daedalus_workspace.py mark` writes it for a Push Train and a document train, and the stop and unmark commands remove it. While the marker exists in a repository, it switches on all of these there:

- The full jail for the main session and for foreign agents; without it they meet only the credential check.
- The refusal of every foreign agent's checked tools except reads and searches.
- The main session's warnings in context: writes into `.git` or `.claude/daedalus/`, writes into the repository outside the train's scratch folder, naming a credential store, the shell tripwires, a skipped dispatch rule, and a git, gh or redirect command that names an excluded root.
- The audit log: without a marker no hook writes a record, and the first record in a new session log also runs log retention.
- The reply key, created with the first record that carries an agent's reply.
- The receipts check on a coding agent's hand-back.
- The checks that read the running train's id: the coding agent's unit worktree binding, the scratch and audit folders other writers may write, the document train's output folder, the unit worktree a test run is bound to, and the folder the dependency map may be written to.
- The push and pull request gate, which reads the train branch and its recorded verdict through the marker.

Daedalus's own agents keep their hooks with or without a marker.

### The audit log and the reply key

Each session gets one log, `<repo>/.claude/daedalus/audit/<session_id>.jsonl`, written only by the hooks. `scripts/lib/audit.py` writes every record under a lock. Each record holds its sequence number `seq`, the hash of the record before it (`prev_hash`) and its own `hash` over the rest of the record, so an edited, removed or reordered record breaks the chain. The chain verifier and the audit report recompute it before they read anything else. These are the record types and what each one holds:

| Event | What the record holds | Who reads it |
|---|---|---|
| `SessionStart`, `UserPromptSubmit`, `Stop`, `SessionEnd` | The event, the session and its working folder, and for a prompt the redacted prompt text | The audit report |
| `PreToolUse` | The tool and its redacted input (a Read records only its path), the jail's decision (`allow` or `block`), the refusal reason with its check name, and the jail's own time in milliseconds | The hooks check, the summary's Blocks section, the control cost report, the push proof's summary anchor, and the wave merge and summary, which find each verifier dispatch by its `Unit worktree:` line |
| `PostToolUse`, `PostToolUseFailure` | A sha256 of the tool's output and its first 4096 characters, redacted, or the error | The push proof, which reads the summary command's own output line; the audit report |
| `SubagentStart` | The agent's id and type | The stop record, which takes its agent type from here when Claude Code omits it |
| `SubagentStop` | The redacted head and tail of the agent's last reply, 2048 characters each, a keyed digest of the whole reply, and every `[VERDICT: ...]` line of the reply | The push proof, the wave merge's verifier check, the docs verdict record, the summary, the reply check of project train definitions |
| `SubagentHandback` tool call | An agent's report, in the tool input of its PostToolUse record | The same readers as a stop record, which read the report from the tool input |
| `AuditRotation`, `AuditRotationFailed` | Each old session log retention deleted, or each one it failed to delete | The audit report |

The reply key is `<repo>/.claude/daedalus/reply-hmac.key`: 32 random bytes in an owner-only file. The hooks create it with the first record that carries an agent's reply. Each such record gets `last_message_hmac`, an HMAC-SHA256 of the whole reply under that key. The key keeps the log alone from confirming a guessed reply, since the log holds only a redacted head and tail. Its reader is `daedalus_train.py check-reply`, which compares a reply a project train definition saved to a file with the agent's own stop record. No agent may read the key, and the credential check refuses one that tries. A key file that is not a 32-byte owner-only regular file stops the record. Its `Next:` line says to delete the key from your own shell, and the next reply creates a new one.

### Train state and the bindings file

Each train has one state file, `<repo>/.claude/daedalus/trains/<train-id>.json`. Only scripts write it, under the lock file `<train-id>.lock` beside it, and the jail refuses tool writes into `.claude/daedalus/`. Its fields:

- `train_id`, `repo`, `base_branch`, `base_sha`, `charter_root`, `charter_base`, `charter_branch_created`, `ledger_line` and `cache_dir`, written by `begin`.
- `lock_sha`, the contract lock commit every unit branch must descend from, written by `lock`.
- `merged`, set by finish once every unit merged.
- `units`, one entry per worktree with its `name`, `branch` and `path`, and `audit: true` on the audit worktree.
- `plan`, the recorded plan's `path` and `sha256`; the dispatch gate refuses a coder when the file no longer matches.
- `choices`, `phase` and `weight`, from the choice command; with project priorities a choice also records the deciding `driver` and `rule`.
- `start_seq`, `audit_session` and `audit_bounds`, from the hooks check: the log record after which the train's verdicts are read.
- `verdict`, holding `status`, `tip`, `round` and `seq`, from the verdict command; `seq` is the auditor reply's record number in the log.
- `audit_rounds`, one map of findings per round with each finding's severity and class.
- `exemptions`, per round and per finding: the exemption's `ledger_id`, the `tip` it covers and how it is `tracking`.
- `docs_verdict`, the docs stage record: `status`, `tip`, and for a refuted record its `findings` and `exemptions`.
- `ledger`, the ledger commit's `sha` and `ids`; `reaudit` and `resume` for the recovery paths; `consults_open`, the consulted agents whose reply the train still waits for.
- A train started from a project train definition adds the runner's own fields, such as `mode`, `definition`, `stage_index`, `dispatches`, `records` and `stage_log`.

The progress note, the summary command, the dispatch gate, the merge commands, the push proof and the push gate read it.

The bindings file, `<repo>/.claude/daedalus/trains/<train-id>.bindings.json`, holds one entry per unit worktree under `units`, written under its own lock. It keeps one coding agent per unit, in four steps:

1. Dispatch: when the orchestrator starts a repo-coder with one `Worktree:` line, the dispatch gate records the unit with no agent yet. A second dispatch to the same unit is refused.
2. Claim: the coding agent's first write, or first git write, in that worktree binds the unit to its agent id. Every later write by that agent must stay in that worktree, and no other agent may write there.
3. Rebind: when the orchestrator resumes a coder with a new `Worktree:` line, the gate moves the coder to the new unit and records the old unit as `retired_to` the new one.
4. Finish: finish and the wave merge mark each merged unit `finished`, and a later write into it is refused.

### The push proof

`python3 <plugin>/scripts/verify_audit_chain.py --approved <train-id> --repo <repo>` is the check the Push Train runs before it pushes. The push gate applies the same tip and exemption rules to an agent's `git push` and `gh pr create`. It reads the train summary's `Session <id>:` line to find the audit log, and the train state for the hooks-check bound of that session. It grades the approved path first:

1. The recorded verdict must be approved and name the auditor reply's record number, its `seq`.
2. The anchor is the first record after that number of the summary command, `daedalus_train.py summary --repo <repo>`, whose own output says the summary was written for this train. A summary written by any other tool never anchors the proof.
3. The graded turn is the last security auditor turn after the hooks-check bound and before the anchor. A reply in it that carries both an approved and a rejected verdict line is refused with `carries both verdicts`, and the round must be rerun.
4. The turn's verdict must be approved, its record number must equal the recorded `seq`, and its `tip=` must equal the recorded tip.
5. The integration branch must sit on that tip. Two moves past it are admitted. The first is one plain commit on the judged tip that changes only the ledger. The second, when a docs record exists, is a run of commits that change nothing but the four public docs, and one ledger-only commit may follow that run. In the run, each changed doc is a regular, non-executable file after the commit, and a regular file or a new one before it, so a commit that deletes a doc, makes it executable or turns it into a link is refused. A merge in the run is judged against its first parent.

When the approved path fails and the recorded verdict is rejected, the proof takes the exemption path instead. Every finding in that round's findings file and in its recorded round must carry an exemption for the judged tip, with a ledger id and a tracking answer, and the tip rule of step 5 still applies. On either path, a docs record must name the tip the docs-only commits end at, as verified or as refuted with every refuted claim exempted. That tip is the current tip, or the commit below the current tip when a ledger-only commit follows the docs commits.

Exit 0 prints `OK approved: approved verdict, ...` or `OK approved: every finding exempted, ...`, followed by the docs result when a docs record covers the tip. Exit 1 prints `NOT APPROVED: <reason>` with a `Next:` line. Run it from your own shell to see what a push would meet.

### The controls register

`scripts/checks/controls/` holds one JSON fragment per unit of work that added a control. Each key is `checks/<script>` for a hook script, or `<module>.<R_ constant>` for a refusal message. Each value holds exactly two fields: `failure`, the failure the control prevents, starting with its ruling or issue id, and `premise_test`, the test that goes red when that control's premise stops holding. `scripts/lib/controls.py` merges the fragments and refuses a key named twice.

`python3 <plugin>/scripts/audit_report.py --session <id> --controls` reads it for its Control cost section, which lists the blocks per check and one `failure:` line for each check that blocked. The orchestrator reads that report at the end of a train. Each check that blocked and whose line reads `failure: none` goes to you as a keep, redesign or remove question. `tests/test_controls.py` fails when a hook script or a refusal constant has no row, when a field is empty, when a failure does not start with an id, when a premise test does not exist, or when a row names a constant its module no longer has.

### One train, end to end

1. Start. The main session runs `daedalus_workspace.py begin`. That command refuses a dirty tree, writes the data folder and its `.gitignore`, the train state file and the train marker, and prints the first State Block lines. Then `verify_audit_chain.py --hooks-live` finds its own command as the newest Bash record of this session's log and records the bound the push proof reads. The main session starts one orchestrator agent and relays between it and you.
2. Standards and the map. The standards specialist writes the Standards Packet from your declared sources. Its fifth part is a `## Priorities` section, holding your `priorities` block or the line `priorities: none declared`. The orchestrator runs `daedalus_map.py --repo <repo> --out <repo>/docs/.tmp/daedalus/<train-id>/map` and records the sha256 of `map.json`; the jail refuses an `--out` outside that folder.
3. Plan. The planner cuts the work into units. Each unit has a line in the plan block and a requirement section below it. `validate_plan.py` checks the file, and `daedalus_train.py plan` records its path and sha256 in train state.
4. Contract lock. The contract agent writes the Locked Contract Packet. `daedalus_workspace.py lock` commits it on the integration branch `daedalus/<train-id>` and records `lock_sha`.
5. Units. For each wave, the orchestrator checks the units' `needs:` with `daedalus_doctor.py --check-tools`. For each unit it then runs `daedalus_workspace.py create`, writes the brief file, and starts a repo-coder with the brief path and one `Worktree:` line. The dispatch gate checks the recorded plan and records the dispatch, and the coder's first write claims the unit.
6. Hand-back and verification. The coder ends with a receipts block above its `[STATUS: COMPLETE]` line, which the receipts check reads. The orchestrator checks the reply's branch, packet hashes and lock ancestry. The verifier then judges the unit's diff against its brief, and the unit is ready to merge once its verdict is `[VERDICT: VERIFIED]`.
7. Merge. `daedalus_workspace.py finish` merges every unit into the integration branch with `--no-ff`. A train cut into waves merges each wave first with the wave merge command.
8. Audit. Judges join by what the diff touches. The NIST and CIS specialists come in for IAM, KMS, mTLS, key custody or infrastructure changes, the dependency auditor for a dependency manifest or lockfile, and the Terraform reviewer for a `.tf` or `.tfvars` file. The security auditor judges the merged tip in its own audit worktree, and `daedalus_train.py verdict` records its verdict. Each finding of a rejected round goes to you one question at a time.
9. Ledger and docs. On an approved verdict, or once you exempted every finding, charter-docs commits the ledger entries. After an approval, the approved verdict is recorded next. The docs writer then brings the four public docs up to date in the docs stage.
10. Summary. `daedalus_train.py summary` writes the summary from train state and the audit log, and the orchestrator ends with `[STATUS: TRAIN_COMPLETE]`.
11. Push. `/daedalus:push-train` marks the train again, runs the hooks check and the push proof, and has the conductor push the branch and open the pull request. The push gate checks the verdict again on the conductor's own push. You review and merge.

### Requirement sections and needs

Each unit of a plan has a requirement section outside the plan block. The section opens with a heading `### <unit id>: <title>`. Somewhere under it, a line reading exactly `Requirements:` is followed by lines `1. <requirement>`, numbered from 1. Each requirement is one sentence ending in a period, and it names a backticked token or a path holding a slash. `scripts/lib/plan_record.py` reads the sections, and `validate_plan.py` refuses a unit without one, a list that breaks its numbering, and a requirement in another shape. The dispatch gate runs the same check before any coder starts. The orchestrator copies each unit's section into its brief, and the verifier counts one claim per numbered line.

A unit line may also carry `needs: <tool or protected path>[, ...]`: the tools the unit's build needs, such as `mypy` or `.venv/bin/ruff`, and each protected file it needs changed. Before a wave starts, the orchestrator passes every tool need to `daedalus_doctor.py --check-tools <names> --repo <repo>`. That command prints `OK   tool <name>` or `MISS tool <name>` per name and exits 1 on any MISS. Missing tools and protected-file needs reach you as one question per wave.

### The receipts check

`scripts/handback_check.py` runs on every SubagentStop and on every `SubagentHandback` tool call, during a train only. It judges only a repo-coder's reply whose last line is `[STATUS: COMPLETE]`. Directly above that line it wants a `## Receipts` line followed only by lines of five shapes: `- commit <40 hex> <subject>`, `- test <command> => <last output line>`, `- typecheck <command> => <last output line>`, `- yield <kind> <question> => <who answered>` and `- deviation <file or behaviour> | <reason>`. At least one commit line and one test line must be there. A reply in another shape is sent back with one `Next:` line naming the shape, before the verifier sees it. A check that cannot run never blocks the coder, and the verifier still judges the unit. `scripts/cite.py` prints the `file:line` of each line holding a fixed string, so a coder can paste a citation instead of retyping it.

### The verifier

The verifier judges each unit's diff against its brief, never against the coder's report (verify against the brief, 0128). Its claims are the brief's numbered requirements, the unit's files list, the pins that name the unit and the Standards Packet rules a changed line falls under. The map adds two more kinds of claim. For each module the diff changes, `imports.<module>.fan_in` lists its importers, and each one must still get what it relied on. Each `duplicates` entry that overlaps the added lines must not repeat code the project already holds. Each refuted claim is a `code` row or a `scope` row. A `scope` row is a file outside the files list, or a behaviour change no requirement asks for, unless a `- deviation` receipt names it with a reason.

A receipt the branch contradicts, such as a wrong test count or commit subject, is corrected inside the verdict and counted on a `corrected=<k>` line above the closing verdict line. It never refutes the unit, and the coder is not resumed for it (report refutations never stop, 0127). Only `code` and `scope` rows send a coder a fix pass, and a second refutation of the same unit stops the train. The orchestrator runs finish only once every unit's verdict is `[VERDICT: VERIFIED] claims=<n>`. The wave merge command reads that last line itself, from the verifier's reply in the audit log. The summary's Verification section prints each unit's verdict line with its corrected count. A prompt whose first line is `CLAIMS MODE.` lists `Claim: <path>:<line> <claim>` lines instead of a brief, and the verifier checks only those lines. The docs stage and the document train use this form.

### Merges and fix units

`daedalus_workspace.py finish` merges every recorded unit except the audit worktree's, one `--no-ff` merge commit each, and skips a unit already on the integration branch. Each merge message reads `Merge <name> for train <train-id>`, where `<name>` is the worktree name without its `<train-id>-` prefix. The wave merge command, `python3 <plugin>/scripts/daedalus_workspace.py merge --repo <repo> --units <id>[,<id>]`, merges only the named units and leaves the train open for the next wave. It refuses a unit the recorded plan does not name, and a unit without a `[VERDICT: VERIFIED]` verifier reply for its worktree in the audit log. A fix unit from an audit round, the worktree `<train-id>-fix<n>-<unit>`, is outside the plan, so the wave merge refuses it and finish merges it on its next run. To merge such a unit by hand, run this from your own shell on the integration branch, with `<name>` the worktree name without its `<train-id>-` prefix, and finish then skips it:

    git merge --no-ff daedalus-unit/<train-id>-<name> -m "Merge <name> for train <train-id>"

### Exemptions, the docs stage and the personas

Each failing finding goes to you as one question. Its first line says what is at stake in one plain sentence, then asks, and two or three short sentences say what breaks and what happened in the test. The three choices are `Fix it now (Recommended)`, which runs a fix round, `Skip, track or exempt it`, which exempts the finding, and `Stop the train`, which ends the train. No round budget applies, and the train never opens a fix round or stops on its own authority (operator holds every gate, 0133). An exemption brings a second question, how it is tracked: `Skip it` (dropped silently), `Track it` (a GitHub tracked-risk issue), `Exempt it` (the local ledger record alone), or your own answer, stored as `dropped`, `issue`, `local` and `other`. The main session records each exemption with `daedalus_train.py exception --repo <repo> --ledger-id <id> --finding <id> --tracking <dropped, issue, local or other>`. The command writes it in train state, under the round for a security finding and in the docs record for a docs claim. The push proof reads it, and the summary's Audit section prints each exempted finding with its tracking answer.

The docs stage runs after the security verdict is recorded (docs writer ends the train, 0134). It creates the worktree `<train-id>-docstage`, which the dispatch gate binds to the docs writer alone. The docs writer may write only the four public docs: `README.md`, `docs/howto/README.md`, `docs/guardrails.md` and `docs/project-requirements.md`. Its claims go to the verifier in claims mode. A verified reply merges the docs branch, and `daedalus_train.py verdict --gate docs` records the docs verdict in train state. Each refuted claim goes to you as a finding. The summary's Audit section names the docs verdict, or `Docs: not run`.

Two read-only judges join by what the diff touches (personas by diff, 0132). The dependency auditor judges a changed dependency manifest or lockfile. It asks for security advisories only through a web question the train sends to the web researcher. When `features.dependency_web_lookup` is `false`, the train answers that question with "web lookup is off", and the auditor judges from the lockfile and any advisory export. The Terraform reviewer judges a changed `.tf` or `.tfvars` file. It may run only `terraform fmt -check` and `terraform validate`, and neither when `features.terraform_tools` is `false`. Each FAIL row from either judge goes to you as a finding.

### Project priorities

The `priorities` block of `service-manifest.json` ranks four concerns, `security`, `trust`, `ops` and `cost`, and may add rules, principles and per-agent rankings (see the key reference above). The doctor prints `priorities: <ranking>, <n> rules` or `priorities: none declared`. The standards specialist writes it into the Standards Packet's `## Priorities` section, and every agent of every train reads that section, never your own session (priorities bind agents in every train, 0137). When two concerns conflict, the orchestrator walks the rules in order, and the first match decides. A rule ending in a concern settles the choice alone, and its choice record names the driver and the rule. A rule ending in `surface` puts the choice to you. A coder surfaces a default with `[STATUS: YIELD_STANDARDS] priorities rule <n>: ...`. A global rule or your answer outranks the ranking, and no rule lowers an audit finding's severity. The summary's Priorities section lists each decision a rule settled or surfaced.

### The document train and excluded roots

`/daedalus:doc-train` derives a document from frozen sources (document train accepted, 0135). `freeze_sources.py --train <id> --output-dir <folder> --source <alias>=<role>:<path>` records each source with its sha256 in `<repo>/.claude/daedalus/trains/<id>.sources.json`. `freeze_sources.py --verify <that file>` exits 4 when a source changed. It exits 5 when an output carries an en or em dash, placeholder copy, or a sentence copied from a style source that carries a number. The doc-deriver and the change-logger write only inside the output folder, which `scripts/checks/doc_outputs.py` checks. The verifier checks the deriver's claims in claims mode. `/daedalus:round` keeps the record of one round of correspondence.

The `excluded_roots` key of `config.json` names folders whose files must never reach git, GitHub or a redirect. `scripts/checks/excluded_roots.py` runs for every Daedalus agent after its own checks. It refuses a git command that stages, commits or stashes a path inside such a folder, a gh command or a redirect that names one. The doc-deriver and the change-logger may redirect into such a folder, since their outputs live there. During a train the main session is warned instead. `freeze_sources.py` records the resolved folders in the sources file.

### The summary's path rule

The train summary becomes a public pull request body, so `scripts/lib/train_summary.py` lets no absolute path through. It first rewrites paths under the repository as relative paths, and paths under the Charter as starting with the Charter's folder name. Every other word holding a `/`, a `\` or a percent-encoded slash must then be a plain relative path inside the repository or the Charter. Each part of such a path is a plain ASCII name, with no `..`, `~`, `%`, `$`, `@`, scheme, drive, or leading or doubled slash. A path from the summary notes file that breaks this rule stops the summary, with a `Next:` line naming the path. A path from the audit log or train state, which nobody may edit, prints as `[path withheld]`, and the summary is still written.

### The kernel wrapper's grants

On a kernel with Landlock and seccomp, a coder's test command runs as `daedalus_confine.py --unit <worktree> -- <command>`, which the coder's confine check requires. The wrapper applies its rules to its own process, then runs the command, and every child inherits them. Nothing is installed, and the rules end with the process tree. It grants:

- Read and write: the unit worktree, a private temporary folder `daedalus-confine-<uid>/<hash>` under the system temp folder (mode 0700, owned by you), and `/dev/null`.
- Read only: every entry of the repository except `.claude/daedalus` and `.claude/worktrees`, never following a link; the running Python's prefixes and site-packages folders; and `/usr`, `/lib`, `/lib64`, `/lib32`, `/bin`, `/sbin`, `/etc`, `/proc`, `/sys` and `/dev`. A folder that holds or sits inside a credential store is left out.
- Network: a seccomp filter refuses a `socket()` call for every family except `AF_NETLINK`, `AF_UNIX` included, and refuses io_uring. A `socketpair()` call still works. On Landlock ABI 4 and later, TCP bind and connect are refused too.
- Environment: `TMPDIR` names the private folder, `GIT_CONFIG_GLOBAL` names an empty git config written fresh for each run, and `XDG_CONFIG_HOME` names an empty folder.

It prints one `daedalus_confine:` line naming the ABI, the architecture and every grant before the command starts.

On a kernel without Landlock, or when the kernel probe fails, the confine check refuses every coder test command and names the cause.

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
│   ├── change-logger.md
│   ├── charter-docs.md
│   ├── cis-specialist.md
│   ├── contract-spec.md
│   ├── dependency-auditor.md
│   ├── doc-deriver.md
│   ├── docs-writer.md
│   ├── nist-specialist.md
│   ├── orchestrator.md
│   ├── planner.md
│   ├── pr-train-conductor.md
│   ├── repo-coder.md
│   ├── security-auditor.md
│   ├── standards-rules-specialist.md
│   ├── terraform-reviewer.md
│   ├── verifier.md
│   └── web-researcher.md
├── docs/
│   ├── guardrails.md                # each principle with its mechanism and test
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
│   ├── checks/confine.py            # a coder's test command starts with the kernel wrapper
│   ├── checks/controls/             # the failure each control prevents and its premise test
│   ├── checks/credential_paths.py   # refuses a path or command that names a credential store
│   ├── checks/dispatch_gate.py      # the orchestrator's coder dispatch and plan gates
│   ├── checks/doc_outputs.py        # document agents write only in the train's output folder
│   ├── checks/excluded_roots.py     # git, gh and redirects never take a file from an excluded root
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
│   ├── lib/atomic.py                # the one atomic writer and create-once writer
│   ├── lib/audit.py                 # hash-chained append, redaction
│   ├── lib/audit_proof.py           # the hooks-live and approved-verdict proofs
│   ├── lib/audit_rounds.py          # the auditor's finding list and the round number
│   ├── lib/config.py                # config.json loading and validation
│   ├── lib/controls.py              # loads the controls fragments
│   ├── lib/credential_paths.py      # the credential-path deny every agent meets
│   ├── lib/dispatch_binding.py      # coder dispatch, warm rebind and first-write claim
│   ├── lib/fetch.py                 # GitHub-only download, size cap and cache lock for refreshes
│   ├── lib/gh_policy.py             # the gh commands each agent may run
│   ├── lib/git.py                   # the one git runner: timeout and redirect scrub
│   ├── lib/hook_io.py               # hook input and output for the check scripts
│   ├── lib/human_text.py            # counts the plain words in operator lines
│   ├── lib/jail.py                  # per-agent tool policy
│   ├── lib/ledger.py                # ledger resolution, sequence read, entry format
│   ├── lib/locks.py                 # the one FIFO-safe lock opener and bounded lock
│   ├── lib/manifest.py              # the one reader of service-manifest.json
│   ├── lib/narrow.py                # narrows parsed JSON values to typed values
│   ├── lib/packs.py                 # loads and checks framework control packs
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
│   ├── lib/train_summary.py         # the train summary, written from state and the audit log
│   ├── lib/unit_binding.py          # one coder per unit worktree
│   ├── lib/workspace.py             # unit worktrees and the train marker
│   ├── append_ledger.py             # locked, sequence-checked ledger writer
│   ├── audit_log.py                 # all other hook events to the audit log
│   ├── audit_report.py              # digest of a verified session log
│   ├── catalog.py                   # prints the agent table and hooks matrix
│   ├── cite.py                      # prints file:line for each line holding a fixed string
│   ├── daedalus_confine.py          # kernel wrapper: a coder's test command stays in its worktree, no network
│   ├── daedalus_doctor.py           # first-run check behind /daedalus:doctor
│   ├── daedalus_map.py              # the dependency map: imports, coverage, record readers, ownership, duplicates
│   ├── daedalus_setup.py            # writes the missing starter files behind /daedalus:setup
│   ├── daedalus_train.py            # the train runner: progress, choice, plan, verdict, exception
│   ├── daedalus_workspace.py        # begin, lock, create, remove, finish, stop, resume, mark, unmark, release
│   ├── enforce_agent_jail.py        # PreToolUse policy
│   ├── freeze_sources.py            # freezes and verifies a document train's sources
│   ├── handback_check.py            # SubagentStop check of a coder's receipts block
│   ├── import_pack.py               # operator-run: writes a control pack from an OSCAL catalog or a CIS id map
│   ├── refresh_frameworks.py        # operator-run: compile the pinned framework caches
│   ├── standing_rules.py            # derives the standing-rules file from the ledger
│   ├── validate_plan.py             # checks a plan file and prints its graph line
│   ├── validate_train.py            # checks a train definition file
│   └── verify_audit_chain.py        # recompute and verify a session's hash chain
├── skills/
│   ├── audit-report/SKILL.md        # /daedalus:audit-report
│   ├── brainstorm/SKILL.md          # /daedalus:brainstorm
│   ├── build-train/SKILL.md         # /daedalus:build-train
│   ├── catalog/SKILL.md             # /daedalus:catalog
│   ├── doc-train/SKILL.md           # /daedalus:doc-train
│   ├── doctor/SKILL.md              # /daedalus:doctor
│   ├── plan/SKILL.md                # /daedalus:plan
│   ├── push-train/SKILL.md          # /daedalus:push-train
│   ├── round/SKILL.md               # /daedalus:round
│   └── setup/SKILL.md               # /daedalus:setup
└── tests/                           # the pytest suite
```

## License

Daedalus is licensed under the GNU General Public License v3.0 or later. See LICENSE.

## Developing Daedalus

    pip install -e '.[dev]'
    pytest
    ruff check scripts tests
