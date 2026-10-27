<!-- Copyright (c) 2026 Brad Duhon. SPDX-License-Identifier: GPL-3.0-or-later -->
# Daedalus

## What Daedalus is

Daedalus is a Claude Code plugin. It gives your session a set of AI agents, each with one job. Each agent may use only the tools that job needs. Before every tool call, a check compares the call with the agent's rules and blocks anything outside its job. Daedalus calls this check the jail, and its refusal messages start with `daedalus-jail`.

You start any piece of work with one command: `/daedalus:run` followed by your task. Daedalus sizes the task, tells you which phases it picked, and runs them. When the work is built and audited, `/daedalus:run push` pushes the branch and opens a pull request. No fixed recipe is required. You can run a phase on its own, and you can use the agents in any order.

Daedalus calls a run that builds code a train. You will see that word in branch names, file names and messages. The old commands `/daedalus:build-train`, `/daedalus:push-train` and `/daedalus:doc-train` now only print the new command. The release after 5.1.0 removes them.

Work moves through seven phases: brainstorm, plan, build, verify, audit, document and release. Each phase is a skill, and phases can overlap. Agent files name their phases with older words: context, clarification, plan, implementation, audit, and commit and release. The catalog maps each of those words to a phase skill.

A small task gets a light run. A fix of at most 3 files, none of them a control file (a check, agent, skill, hook or jail file), gets a one-unit plan and no contract packet. A contract packet is a written spec of the interfaces each coding agent's code must follow, locked before coding starts. A build that spans several modules gets one.

Hooks enforce four rules today:

- No coding agent starts before a plan is recorded.
- Each coding agent is bound to its own worktree, a separate checkout of your repository.
- Nothing is pushed and no pull request opens until the security audit approved the exact commit being pushed, or until you exempted every finding of a rejected audit round.
- Only the push agent pushes.

Two jobs stay with you, and no hook checks them: recording each decision in your decision ledger, and merging the pull request.

While a train runs in a repository, every tool call there is written to an audit log. Each record carries the hash of the record before it. Editing or removing a record breaks that chain, so the change shows.

## What you need

Daedalus is developed on Linux. macOS is untested.

| Tool | Version | How to get it |
|---|---|---|
| Python | 3.12 or newer | Your system's package manager |
| Claude Code | Developed against 2.1.280 | Claude Code's own install instructions |
| git, for a project that is a git repository | any | Your system's package manager |
| gitleaks, for the push run's secret scan when the service manifest turns it on | any | https://github.com/gitleaks/gitleaks#installing |
| gh, the GitHub CLI, for the push run | any | Install it, then run `gh auth login` |

## Install

This one-command form needs Claude Code 2.1.275 or later. Start Claude Code in your project, then type:

    /plugin install daedalus --marketplace bradduhon/Daedalus

Claude Code asks you to confirm the marketplace, then to pick a scope. Choose "Install for you". To install from a shell instead, run these two commands, then start Claude Code:

    claude plugin marketplace add bradduhon/Daedalus

    claude plugin install daedalus@daedalus

Every Daedalus command acts on the repository you started Claude Code in.

### Install from a local clone

To run the code in your own clone of this repository instead of the published release, add the clone as a local marketplace and install from it. Replace `/path/to/Daedalus` with the path of your clone:

    claude plugin marketplace add /path/to/Daedalus

    claude plugin install daedalus@daedalus

The clone and the published marketplace both use the marketplace name `daedalus`. If you added the published one before, remove it first with `claude plugin marketplace remove daedalus`. After the clone changes, update the marketplace and the plugin, then restart Claude Code so the new code loads:

    claude plugin marketplace update daedalus

    claude plugin update daedalus@daedalus

## First run

If `/daedalus:doctor` is not offered after you install, run `/reload-plugins` or restart Claude Code. Then type:

    /daedalus:doctor

The doctor checks every file and tool Daedalus needs. It prints one line per check and changes nothing. Each line starts with one of three words:

- `OK`: the check passed. There is nothing to do.
- `MISS`: something Daedalus needs is missing. The line ends with `Next:` and says what to do. Do it, then run the doctor again.
- `OPT`: something optional is absent. Daedalus works without it, and an `OPT` line never fails the doctor.

In a new repository, four lines read `OPT`: `config.json`, `service-manifest.json`, `contracts/` and `.gitleaks.toml`. These are files your project writes about itself. Type `/daedalus:setup` to write starter copies of the first two. A build run and a push run both work without any of them.

If the features object of your `service-manifest.json` still has a `github` key, the doctor prints one `OPT` line saying the key does nothing.

If your project is a plain folder and not a git repository, Daedalus works in folder scope. Only a repository can be pushed, so the doctor marks the `git repository` line and the two gh lines `OPT`. When the secret scan is on, the gitleaks line reads `OPT` too.

[docs/project-requirements.md](docs/project-requirements.md) lists every file Daedalus expects, says what each is for, and gives a small example of each.

### Your first body of work

1. See what Daedalus has. Type `/daedalus:catalog` once. It prints a list of the agents and the seven phases.
2. Start a run. Type `/daedalus:run` and your task in your own words, for example `/daedalus:run Add a --verbose flag to the command-line tool`. A one-line task needs no file, because the run saves the words you type as the spec. With only an idea and no spec, type `/daedalus:brainstorm` and the idea, or the path of a notes file. The [operator guide](docs/howto/README.md) shows how to turn an idea into a spec and how to split a spec into units before you build.
3. Answer its questions. The run works on its own and stops only when it needs you. Each question arrives in Claude Code's question prompt, with the recommended answer first. When the security audit finds a problem, you get one question per problem with three choices: fix it now, skip, track or exempt it, or stop the train.
4. Merge the pull request. When the run ends, you can read what every agent did with `/daedalus:audit-report <session>`. Type `/daedalus:run push` to push the branch and open its pull request. Review the pull request and merge it yourself. Daedalus never merges.

## Runs and reports

The build run and the push run below are the usual way to use Daedalus, not the only way. A piece of work can use any agents from the catalog in any order.

Outside a train, Daedalus's own agents keep their own checks. Your session, and agents from Claude Code itself or from other plugins, meet only one check outside a train: a read or search of a credential file. That check warns your session in its context and refuses an agent (see Safety model below).

### Build run

`/daedalus:run <task>` takes a task from its plan to an audited local branch. `/daedalus:run build <task>` runs the full build order. Your session checks that the run can start, then starts one orchestrator agent, which runs the work. Your session passes messages between the orchestrator and you.

The orchestrator does this work in order:

1. It reads your standards.
2. It splits the task into units, each a piece of work one coding agent builds, and records the plan.
3. It locks the contract packet when the task needs one.
4. It gives each unit to a coding agent working in its own worktree.
5. It merges every unit into a local branch named `daedalus/<train-id>`.
6. It has the security auditor judge that merged branch.

The train creates each worktree itself and removes it when the train ends. The build run never pushes.

Before you start, you need:

- a decision ledger, a file where your project records its design decisions. Declare one, or let the train find one or offer to create one.
- a clean working tree.
- optionally, `<repo>/.claude/daedalus/config.json` (see [docs/project-requirements.md](docs/project-requirements.md)). Without it the defaults apply.

Then type the command and your task:

    /daedalus:run Add a --verbose flag to the command-line tool

After each phase you see a progress note. It names the phase, its weight and the state of each unit. Before each choice the train makes, it prints one line: `Chose <what> over <alternative>: <cost>`.

When the train ends, your session shows the summary path and the audit log path. If a commit lands on the train's branch after that, tell the session. It runs one recovery audit round on the new tip (`daedalus_train.py reaudit`) instead of a full rerun. A train that stopped before its ledger commit is finished by the session's ledger resume (`daedalus_train.py resume`).

### Push run

The push run commits, pushes and opens the pull request for a finished build run:

    /daedalus:run push

It first checks that the build run's audit log holds an approved security verdict for that train. When `features.secrets_scan` is `true` in `service-manifest.json`, it also scans the commits for secrets with gitleaks before the push. Your repository needs a GitHub remote named `origin`, and `gh` must be signed in to it.

The push agent, pr-train-conductor, pushes the branch and watches CI. If the build run used a branch in your Charter repository, the push agent also pushes that branch and opens its pull request after the code one. The Charter is a separate repository for your decisions and specs, named by the `charter_root` setting. If a commit landed on the train's branch after the audit, the push run adds one recovery audit round on the new tip before it pushes.

You review and merge. Once `gh pr view <url> --json state` shows the merge, delete the train branch from your own shell with `git branch -D daedalus/<train-id>`.

### Execution Train

The Execution Train is your own manual checks on live or staging systems. It has no command, and Daedalus does not run it. AI agents never take part in it. A later release adds a readiness checklist for it.

### Audit report

To read what every agent did in a session, open its audit report:

    /daedalus:audit-report

### Token report

To see what a run cost in tokens, type the command below. It counts the agents only, in the same columns for every kind of run:

    /daedalus:token-report <run id or session id>

`/daedalus:token-report history` prints the totals row of every saved run.

## The agents

Each agent's file lists the only tools it may use, the status lines it ends its replies with, and the phases it suits: context, clarification, plan, implementation, audit, and commit and release. The phases help your session pick an agent. They never limit the choice. The table below is generated from the agent files by `python3 scripts/catalog.py table`. `/daedalus:catalog` shows your session the same table, and a test fails when this copy goes stale.

<!-- generated: catalog.py table -->
| Agent | Shape | Model | Tools | Job | Reply lines | Phases |
|---|---|---|---|---|---|---|
| change-logger | producer | opus | Bash, Glob, Grep, Read, Write | Produces the change gate between a baseline and a derived document, or between two baselines when no deriver runs: one row per departure, with the baseline quote, the derived quote, the reason, and a status the operator rules on. | `[STATUS: COMPLETE] change_log=<path> rows=<n> open=<k>`; `[STATUS: BLOCKED] <what the manifest or brief leaves out>` | implementation |
| charter-docs | producer | sonnet | Bash, Edit, Glob, Grep, Read, Write | Single-writer custodian of the Charter repository, the architectural decision ledger, and Build Train commits. | `[STATUS: LEDGER_PROBED] <probe line>`; `[STATUS: LEDGER_APPENDED] <id>`; `[STATUS: LEDGER_MISMATCH] expected=<n> ledger=<m>`; `[STATUS: COMMITTED] <sha> ids=<id>[,<id>]`; `[STATUS: BLOCKED] <detail>` | clarification, commit, release |
| contract-spec | producer | sonnet | Edit, Glob, Grep, Read, Write | Reads and updates service handshake contracts, API schemas, and specifications. | `## Locked Contract Packet` | clarification, plan |
| dependency-auditor | judge | sonnet | Bash, Glob, Grep, Read | Read-only judge of the dependency manifests and lockfiles a train changes. | `[STATUS: YIELD_WEB] <query>`; `[STATUS: COMPLIANCE] <PASS/FAIL list with rule ids and file:line>` | audit |
| doc-deriver | producer | opus | Bash, Edit, Glob, Grep, Read, Write | Derives one document from frozen, manifest-declared sources with a file:line receipt on every value. | `[STATUS: COMPLETE] outputs=<path>[,<path>] claims=<n> judgments=<k> assumed=<m>`; `[STATUS: BLOCKED] <what the manifest or brief leaves out>` | implementation |
| docs-writer | producer | opus | Bash, Edit, Glob, Grep, Read, Write | Writes the public docs to match what a train merged. | `[STATUS: DOCS_WRITTEN] branch=<b> commit=<40 hex> claims=<n>`; `[STATUS: DOCS_UNCHANGED] reason=<why no passage needed an edit>` | audit |
| framework-specialist | judge | sonnet | Bash, Grep, Read | Evaluates a diff against the control packs named in its prompt, by default the shipped AWS hardening and NIST SP 800-53 packs, and cites each pack control id with its NIST, CIS and ASVS ids. | `[STATUS: PACK_INVALID] <pack id>: <problem>`; `[STATUS: COMPLIANCE] <PASS/FAIL list with pack control ids, refs ids and file:line>` | clarification, audit |
| orchestrator | dispatcher | fable | Agent, Bash, Edit, Glob, Grep, Read, SendMessage, Write | Runs one Build Train from its plan to the audited integration tip. | `[STATUS: ANNOUNCE] size=<size> phases=<list>`; `[STATUS: DECISION] brief=<path> questions=<n>`; `[STATUS: EXCEPTION] ledger_id=<id>`; `[STATUS: TRAIN_COMPLETE] summary=<path> audit_log=<path> tip=<40 hex>`; `[STATUS: STOP] reason=<what happened> next=<next action>` | context, clarification, plan, implementation, audit |
| planner | shaper | opus | Glob, Grep, Read, Write | Cuts a design spec into work units that coders can build in parallel. | `[STATUS: PLAN] path=<path> units=<n> critical_path=<k> width=<w>`; `[STATUS: QUESTION] <what the task leaves open>`; `[STATUS: ROUND] round=<k> items=<m>`; `[STATUS: SPEC] round=<k> path=<path> open=<m>`; `[STATUS: NOT_VIABLE] round=<k> <the blocking fact in one line>`; `[STATUS: YIELD_WEB] <query>` | clarification, plan |
| pr-train-conductor | mover | opus | Bash, Glob, Grep, Read | GitHub specialist for the Push Train. | `[STATUS: PUSHED] branch=<b> pr=<url>`; `[STATUS: CI] run=<id> conclusion=<text>`; `[STATUS: BLOCKED] <precondition that failed>` | commit, release |
| repo-coder | producer | opus | Bash, Edit, Glob, Grep, Read, Write | Scoped implementation worker. | `[STATUS: YIELD_WEB] <query>`; `[STATUS: YIELD_CONTRACT] <mismatch>`; `[STATUS: YIELD_COMPLIANCE] <question>`; `[STATUS: YIELD_STANDARDS] <question>`; `[STATUS: COMPLETE] branch=<b> packet_version=<n> files=<list> tests=<summary> ledger_notes=<text> contract=<12 hex> standards=<12 hex>` | implementation |
| security-auditor | judge | opus | Bash, Edit, Glob, Grep, Read, Write | Adversarial pre-commit security and contract verifier. | `[VERDICT: APPROVED] tip=<40 lowercase hex>`; `[VERDICT: REJECTED] tip=<40 lowercase hex>`; `[STATUS: YIELD_WEB] <tool> options and config files` | audit |
| standards-rules-specialist | finder | sonnet | Glob, Grep, Read | Adopts the project's declared standards. | `## Standards Packet`; `[STANDARDS: CONTRADICTION] <spec ref> vs <source:line>`; `[STATUS: STANDARD] <answer>` | clarification, plan |
| terraform-reviewer | judge | sonnet | Bash, Glob, Grep, Read | Read-only judge of the .tf and .tfvars changes a train makes. | `[STATUS: COMPLIANCE] <PASS/FAIL list with rule ids and file:line, warnings included>` | audit |
| verifier | judge | opus | Bash, Glob, Grep, Read | Adversarial read-only verifier of one unit's diff against its brief. | `[VERDICT: VERIFIED] claims=<n>`; `[VERDICT: REFUTED] <rows>` | implementation |
| web-researcher | finder | haiku | Read, WebFetch, WebSearch | Fast external documentation lookup on Haiku. | `[STATUS: RESEARCH] <payload under 300 words with URLs>` | context |
<!-- end generated -->

Each agent file also declares a shape, the kind of job it does, and the checks that run before each of its tool calls, with their flags. The table below is generated from the agent files by `python3 scripts/catalog.py matrix`, and a test fails when it goes stale.

<!-- generated: catalog.py matrix -->
| Agent | Shape | Hooks |
|---|---|---|
| change-logger | producer | credential_paths, workspace_integrity, tool_bound, shell_tripwires, network_tools, git_push, git_grammar, read_only_bash, doc_outputs |
| charter-docs | producer | credential_paths, workspace_integrity, tool_bound, shell_tripwires, network_tools, git_push, git_grammar --allow docs, root_writes --touch charter,docs --ledger-guard, command_allowlist --allow append_ledger,git,read, gh_classes |
| contract-spec | producer | credential_paths, workspace_integrity, tool_bound, root_writes --touch contracts,charter-specs |
| dependency-auditor | judge | credential_paths, workspace_integrity, tool_bound, shell_tripwires, network_tools, read_only_bash --git read-only, gh_classes |
| doc-deriver | producer | credential_paths, workspace_integrity, tool_bound, shell_tripwires, network_tools, git_push, git_grammar, read_only_bash, doc_outputs |
| docs-writer | producer | credential_paths, workspace_integrity, tool_bound, shell_tripwires, network_tools, git_push, git_grammar --allow coder, unit_writes --docs, gh_classes, confine |
| framework-specialist | judge | credential_paths, workspace_integrity, tool_bound, shell_tripwires, network_tools, read_only_bash --git specialist, gh_classes |
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

To list every path Daedalus can write, run this from your own shell. `<plugin>` is the path the doctor prints on its `plugin root` line:

    python3 <plugin>/scripts/daedalus_doctor.py --print-files

Each line reads `<path pattern> | <writer> | <when>`. The writer is the script function that writes the path. `<repo>` is the main working tree of the git repository you started Claude Code in. The list is never empty, so empty output means the plugin files are damaged; reinstall Daedalus. A `No such file` error means `<plugin>` is wrong; copy it again from the doctor's `plugin root` line.

Part of the output on 2026-10-26:

    <repo>/service-manifest.json | scripts/daedalus_setup.py:_write_new | you run /daedalus:setup and the file is missing
    <repo>/.claude/daedalus/train.active | scripts/lib/workspace.py:mark_train | a Build Train begins or resumes; removed when the train ends or stops
    <repo>/.claude/worktrees/<train-id>-<unit-slug> | scripts/lib/workspace.py:create | the Build Train starts a unit; removed when the train ends or stops
    refs/heads/daedalus/<train-id> | scripts/lib/workspace.py:_merge | a wave merges; one merge commit per unit branch

`<repo>/.claude/daedalus/config.json` is optional. `/daedalus:setup` writes a starter copy when it is missing, and nothing else in Daedalus writes it. Configuration below lists its fields.

### Control packs

A control pack is a list of security controls a change is judged against. When a train touches IAM, keys, network rules or other infrastructure, the framework specialist judges the merged change against the control packs. Daedalus ships two packs under `<plugin>/packs/frameworks/`:

- `aws-default` holds AWS hardening controls, written in Daedalus's own words.
- `nist-distilled` holds a NIST SP 800-53 checklist.

A project with no `frameworks` block in `service-manifest.json` is judged against those two packs and needs no setup. To add your own packs, name a project folder in `frameworks.pack_dir`. Each subfolder holding a `pack.json` and a `controls.json` is one pack. Set `frameworks.default_packs` to `false` to read only your own packs. A pack that fails its hash or format check stops the train.

The commands below run from your own shell, in your project. `<plugin>` is the path the doctor prints on its `plugin root` line. `<cache>` is a directory whose name depends on how you installed Daedalus. Print it with:

    python3 <plugin>/scripts/daedalus_doctor.py --print-cache-dir

To build a pack from the NIST catalog, fetch the catalog first, then import the controls you want:

    python3 <plugin>/scripts/refresh_frameworks.py --only nist-800-53 --cache-root <cache>

    python3 <plugin>/scripts/import_pack.py oscal --catalog <cache>/frameworks/nist/catalog.json --ids AC-2,SC-12 --out compliance/packs/nist-picked

CIS Benchmark text is licensed, so a CIS pack carries ids only. Write a CSV with exactly the columns `cis_id,control_id`. Each row maps a CIS id to a control in another pack. Then import it:

    python3 <plugin>/scripts/import_pack.py cis-map --map cis-map.csv --benchmark "CIS AWS Foundations" --version 3.0.0 --out compliance/packs/cis-aws

## Configuration

[docs/project-requirements.md](docs/project-requirements.md) describes every file and setting Daedalus reads, each with a small working example. The [operator guide](docs/howto/README.md) covers each run step by step, how to read a block message, and how to read an audit report.

To start both project files, type `/daedalus:setup`. It writes a starter `service-manifest.json` at the project root, with every feature off. It writes a starter `.claude/daedalus/config.json`, with every setting at its default. It writes only a file that is missing and never overwrites one. It prints one line per file: `written:` when it created the file, `kept:` when the file already existed. After writing a new manifest, it prints one more line with example values for the `docs.literacy` key. That key sets how plainly the docs writer writes, and the new manifest holds it as `null`.

### Key reference

The table has one row per key Daedalus reads. Each row says what the key controls, then its type, its allowed values, its default and an example value. The table is generated from `scripts/lib/project_keys.py`, and a test fails when this copy goes stale. Commit `service-manifest.json`, because everyone who works on the project shares it. `config.json` never leaves your machine. A dotted key is a key inside an object, and `[]` marks a key inside each entry of a list.

Some keys and files have no row here, because no reader checks them: the unchecked manifest keys, `.gitleaks.toml`, `contracts/`, the standing-rules backfill file and a project train definition. [docs/project-requirements.md](docs/project-requirements.md) spells those out key by key.

<!-- key reference -->
| Key | File | What it governs | Type | Allowed values | Default | Example |
|---|---|---|---|---|---|---|
| `jail_narrowing.forbidden_paths` | `service-manifest.json` | Paths in your project no coding agent may write, on top of the paths the jail always protects; see the requirements page, the section on the coder write boundary | list of strings | Project-relative paths with forward slashes and no leading slash, `..` or glob characters; a trailing slash covers the whole folder, and matching ignores case | `[]` | `["infra/", "scripts/release.sh"]` |
| `jail_narrowing.forbidden_extensions` | `service-manifest.json` | File endings no coding agent may write | list of strings | Endings that each start with a dot and hold no slash or glob characters; matching ignores case | `[]` | `[".pem", ".tfstate"]` |
| `features.scope` | `service-manifest.json` | Whether a train treats the project as a git repository or as a plain folder | string or null | `"repository"`, `"folder"` or `null` | `null`: a git work tree is a repository, anything else is a plain folder | `"repository"` |
| `features.secrets_scan` | `service-manifest.json` | Turns on the Push Train's gitleaks scan of the commits a push sends; with the scan on, the Push Train stops when gitleaks is missing or finds a secret, and the doctor's gitleaks line is a `MISS` | boolean | `true` or `false` | `false`: no scan, and gitleaks need not be installed | `true` |
| `features.scrub_file` | `service-manifest.json` | A file of terms, one per line, that the release step checks the release notes against; a hit stops the release and names how many terms it found, never the terms | string or null | A project-relative path without a leading slash, `..` or glob characters, or `null` | `null`: nothing is checked | `"docs/scrub-terms.txt"` |
| `features.ledger` | `service-manifest.json` | Turns the decision ledger steps on or off | boolean or null | `true`: the ledger is used, and a train asks before creating one; `false`: no ledger step and no ledger question; `null`: the default | `null`: a ledger the config declares or the probe finds is used, and none is created | `true` |
| `features.dependency_web_lookup` | `service-manifest.json` | Lets the dependency auditor ask for security advisories on the web; the train sends its questions to the web researcher. With it off, the auditor judges from the lockfile and any advisory export the project supplies | boolean or null | `true`, `false` or `null`; only `false` turns the lookup off | `null`: the lookup is on | `false` |
| `features.terraform_tools` | `service-manifest.json` | Lets the Terraform reviewer run `terraform fmt -check` and `terraform validate` on the Terraform files a train changes; validate also needs `features.terraform_validate`. With it off, the reviewer judges by reading the files | boolean or null | `true`, `false` or `null`; only `false` turns both commands off; validate also needs `features.terraform_validate` | `null`: `fmt -check` may run | `false` |
| `features.terraform_validate` | `service-manifest.json` | Lets the Terraform reviewer run `terraform validate`, which starts the provider programs in a module's `.terraform` folder. Setup never writes it, and `features.terraform_tools` set to `false` still turns it off | boolean | `true` or `false` | `false`: the reviewer runs no validate and marks that check N/A | `true` |
| `trains_dir` | `service-manifest.json` | The project folder that holds its own train definitions; a train is looked up there first, as `<trains_dir>/<name>.json`, and then in the plugin's own trains folder; see the requirements page, the section on project train definitions | string or null | A project-relative folder path without a leading slash, `..` or glob characters, or `null` | `null`: only the plugin's trains are used | `"trains"` |
| `stack.unit_test_cmd` | `service-manifest.json` | The command that runs the project's unit tests; a coding agent may run it exactly as written, as one command | string or null | A non-empty command string, or `null` | `null`: no declared command | `"pytest -q"` |
| `stack.typecheck_cmd` | `service-manifest.json` | The command that type-checks the project; a coding agent may run it exactly as written, as one command | string or null | A non-empty command string, or `null` | `null`: no declared command | `"mypy src"` |
| `stack.lint_cmd` | `service-manifest.json` | The command that lints the project; a coding agent may run it exactly as written, as one command | string or null | A non-empty command string, or `null` | `null`: no declared command | `"ruff check ."` |
| `docs.literacy` | `service-manifest.json` | How plainly the docs writer writes the public docs at the end of a Build Train, as a reader level or a voice profile the project declares; a brief may override it | string or null | `"plain"`, `"standard"`, `"expert"` or `"profile:docs/voice-profile.md"`, a project-relative path to the profile file without a leading slash, `..` or glob characters | `null`: the writer keeps the register the public docs already use | `"plain"` |
| `priorities.drivers` | `service-manifest.json` | Which concern wins when two conflict and no rule below matches, for every agent in every train, never the operator's own session; see the guardrails page, the row on project priorities | list of strings | Each of `security`, `trust`, `ops`, `cost` exactly once, highest first | No `priorities` key: none declared, and agents follow no project ranking | `["security", "trust", "ops", "cost"]` |
| `priorities.rules[].when.conflict` | `service-manifest.json` | The two concerns a rule settles; rules are tried in order and the first match decides | list of two strings | Two different names of `security`, `trust`, `ops`, `cost`; at most 32 rules | `rules` absent: no rule, so the ranking decides | `["security", "cost"]` |
| `priorities.rules[].when.reason` | `service-manifest.json` | Why the conflict arises; the rule matches only these reasons | list of strings | One or more of `certification`, `framework`, `best-practice`, `incident`, `shape`, `domain-separation`, `ownership`, `convenience`, `latency`, `margin`, `running-cost`, each once | Required in each rule | `["certification", "framework"]` |
| `priorities.rules[].then` | `service-manifest.json` | What a matching rule does: a concern named here wins and the agent decides alone; `surface` puts the decision to the operator | string | One of `security`, `trust`, `ops`, `cost`, or `surface` | Required in each rule | `"surface"` |
| `priorities.rules[].note` | `service-manifest.json` | The one line a choice record or a decision brief quotes when the rule applies | string | One printable line of 1 to 200 characters | Required in each rule | `"a control a certification asks for wins over its running cost"` |
| `priorities.principles[].id` | `service-manifest.json` | The name an agent cites when a decision rests on one of the project's principles | string | `P` followed by digits, unique in the block; at most 64 principles | `principles` absent: none declared | `"P1"` |
| `priorities.principles[].driver` | `service-manifest.json` | The concern a principle serves | string | One of `security`, `trust`, `ops`, `cost` | Required in each principle | `"security"` |
| `priorities.principles[].text` | `service-manifest.json` | The principle itself, as one sentence a decision brief quotes | string | One printable line of 1 to 300 characters | Required in each principle | `"Each tenant keeps its own key."` |
| `priorities.principles[].source` | `service-manifest.json` | Where the principle is written down, so a reader can follow it | string | A repo-relative path or a ruling id of the project's own ledger, without a leading slash, `..` or glob characters | Absent: no source named | `"docs/design.md"` |
| `priorities.agents.<name>.drivers` | `service-manifest.json` | A different ranking for one agent; rules and principles still apply to it | list of strings | Each of `security`, `trust`, `ops`, `cost` exactly once; `<name>` is a Daedalus agent file name other than `security-auditor`, which is refused | Absent: the agent follows `priorities.drivers` | `{"repo-coder": {"drivers": ["cost", "security", "ops", "trust"]}}` |
| `frameworks.pack_dir` | `service-manifest.json` | The project folder that holds its own control packs; each subfolder holding a `pack.json` is one pack; see the requirements page, the section on framework control packs | string or null | A project-relative folder path without a leading slash, `..` or glob characters, or `null` | No `frameworks` key: only the packs Daedalus ships are read | `"compliance/packs"` |
| `frameworks.default_packs` | `service-manifest.json` | Whether the packs Daedalus ships are read beside the project's own packs | boolean | `true` or `false`; `false` reads only the packs under `frameworks.pack_dir` | `true`: the shipped packs are read | `false` |
| `ledger.path` | `service-manifest.json` | Where rulings are appended, declared for everyone who works on the project; it wins over the config's ledger block | string | A path; `<repo_root>` and `<charter_root>` are filled in, and a relative path is read from the project root | No block, or `ledger: null`: the config's ledger block or the ledger probe is used | `"docs/decisions.md"` |
| `ledger.format` | `service-manifest.json` | How each ruling is written to the ledger; see the requirements page, the section on ledger formats | string | `"markdown-table-row"` (one table row per ruling) or `"heading-entry"` (one `## Entry N` section per ruling) | Required once the block exists | `"markdown-table-row"` |
| `ledger.id_scheme` | `service-manifest.json` | The pattern each new ruling id follows | string | A pattern such as `{seq:04d}-{repo}-{type}`; a heading ledger uses `{seq}` | Required once the block exists | `"{seq:04d}-{repo}-{type}"` |
| `ledger.sequence_source` | `service-manifest.json` | Where the next ruling number comes from | string | `"last-row-id"` or `"frontmatter:<key>"` | Required once the block exists | `"last-row-id"` |
| `charter_root` | `.claude/daedalus/config.json` | The repository where your decisions and specs live; the contract and ledger agents may write there, and a Build Train branches it as `daedalus/<train-id>` | string or null | A non-empty path to a git repository, written absolute | `null`: those agents write only inside the project, and the contract lives in `contracts/` | `"/work/decisions"` |
| `standing_rules` | `.claude/daedalus/config.json` | The standing-rules file the planner reads as the rules every plan must satisfy, derived from the ledger by `scripts/standing_rules.py`; see the requirements page, the section on the standing-rules backfill file | string or null | A non-empty path; a relative path is read from `charter_root` when one is declared, else from the project root | `null`: the repository has no standing-rules file | `"standing-rules.md"` |
| `excluded_roots` | `.claude/daedalus/config.json` | Folders whose files must never reach git, GitHub or a redirect. A Daedalus agent is refused such a command in every session, and the main session is warned during a train. A document train records the resolved folders in its frozen sources file. See the guardrails page, the row on excluded roots | list of objects | `{"kind": "path", "path": "<folder>"}`, a folder with `<repo_root>` and `<charter_root>` filled in and a relative path read from the project root; or `{"kind": "gitignore", "match": "directories"}` (every folder git ignores) or `"match": "all"` (every ignored path); a folder holding a linked worktree is skipped | `[]`: no folder is excluded | `[{"kind": "path", "path": "<repo_root>/private/"}]` |
| `ledger.path` | `.claude/daedalus/config.json` | Where rulings are appended on this machine, used when the manifest declares no ledger | string | A path; `<repo_root>` and `<charter_root>` are filled in, and a relative path is read from the project root | `null`: the ledger probe looks for one | `"<charter_root>/decision-log.md"` |
| `ledger.format` | `.claude/daedalus/config.json` | How each ruling is written to the ledger; see the requirements page, the section on ledger formats | string | `"markdown-table-row"` (one table row per ruling) or `"heading-entry"` (one `## Entry N` section per ruling) | Required once the block exists | `"markdown-table-row"` |
| `ledger.id_scheme` | `.claude/daedalus/config.json` | The pattern each new ruling id follows | string | A pattern such as `{seq:04d}-{repo}-{type}`; a heading ledger uses `{seq}` | Required once the block exists | `"{seq:04d}-{repo}-{type}"` |
| `ledger.sequence_source` | `.claude/daedalus/config.json` | Where the next ruling number comes from | string | `"last-row-id"` or `"frontmatter:<key>"` | Required once the block exists | `"last-row-id"` |
| `policy.engine` | `.claude/daedalus/config.json` | The tool for a deterministic policy check on infrastructure changes; no train runs it yet | string | `"cfn-guard"` or `"conftest"` | `policy: null`: none declared | `"conftest"` |
| `policy.path` | `.claude/daedalus/config.json` | The folder that holds your policy rules; no train reads it yet | string | A non-empty path | Required once the block exists | `"/work/decisions/policy"` |
| `standards_sources[].kind` | `.claude/daedalus/config.json` | What one source of your standards is; the standards specialist reads only these entries; see the requirements page, the section on standards_sources kinds | string | `"rules-dir"` (a folder of rule files), `"file"` (one file) or `"pack"` (a pack shipped inside the plugin) | `[]`: the Standards Packet is empty | `"rules-dir"` |
| `standards_sources[].path` | `.claude/daedalus/config.json` | Where a rules folder or rules file lives | string | A non-empty path, written absolute; a pack entry carries none | Required for a `rules-dir` or `file` entry | `"/work/rules"` |
| `standards_sources[].name` | `.claude/daedalus/config.json` | Which pack shipped with Daedalus to use | string | The name of a folder under the plugin's `packs/` that holds a `rules.md`; any other name is refused | Required for a `pack` entry | `"baseline"` |
| `operator_signing_keys` | `.claude/daedalus/config.json` | Reserved for the key fingerprints allowed to sign merges; no check reads it yet | list of strings | Non-empty strings | `[]` | `["ABCD1234EF567890"]` |
| `max_concurrent_builders` | `.claude/daedalus/config.json` | How many coding agents a parallel stage runs at once, and the cap on the plan width the plan validator prints | integer | A whole number of at least 1; `true` and `false` are refused | `5` | `3` |
| `audit_retention_days` | `.claude/daedalus/config.json` | How many days a session's audit log is kept after its last record. When a new session starts writing, older logs are deleted, each named with its final record in the new session's own log. A log named on a train summary's `Session` line, the log of a train not yet merged, and the current session's log are never deleted | integer or null | A whole number of at least 90, or `null` | `null`: every log is kept | `365` |
| `agent_models` | `.claude/daedalus/config.json` | Which model each catalog agent runs on, in place of the `model:` line of its agent file; a model a skill is given for one run still comes first | object | Keys are agent names the catalog lists; values are `"sonnet"`, `"opus"`, `"haiku"` or `"fable"`; any other name or value is refused | `{}`: every agent runs on its agent file's model | `{"repo-coder": "sonnet"}` |
<!-- end key reference -->

## Safety model

Outside a train, Daedalus leaves your session and your repository alone, with two exceptions. Daedalus's own agents keep their own checks. A read or search of a credential file meets one check, which warns your session in its context and refuses an agent.

Outside a train, Daedalus writes no files and keeps no audit log in any repository, even one where a train ran before. The one exception is `/daedalus:setup`, which writes its two starter files when you run it.

Inside a train, the jail judges every tool call and the audit log records each step. A train works in three folders of your repository:

- `.claude/worktrees/` holds the unit worktrees.
- `.claude/daedalus/` holds the train's state and the audit log.
- `docs/.tmp/daedalus/`, which git ignores, holds the train's working files and summaries.

To have the plugin's hooks in some repositories only, enable the plugin at project scope in each of those repositories' `.claude/settings.json` (Claude Code's `enabledPlugins`), instead of for your user.

Each agent gets a short list of allowed tools. A tool not on its list is never offered to it. A PreToolUse hook is a check Claude Code runs before each tool call. Daedalus's hook, the jail, compares every call with that agent's rules and blocks anything outside them.

A coding agent may write only inside its own unit worktree. Even there it may never write to `contracts/`, `.github/`, `.claude/`, `service-manifest.json`, the decision ledger, or the paths and file endings your repository lists under `jail_narrowing` in `service-manifest.json`.

At all times, every agent is refused a read or search of `~/.ssh`, `~/.aws`, `~/.gnupg`, `~/.config/gh` or `~/.claude/.credentials.json`. When your own session does it, the call runs with a warning in its context and its transcript. The check follows links before it judges a path, so a link into one of those folders is refused the same way. Daedalus's own agents are always refused writing those paths with a file tool or naming them in Bash. While a train runs, your session is warned in its context when it does either.

A train never stops your session with a permission prompt. A call the jail flags in your own session runs, and the warning names what the call touches and what can go wrong.

While a train runs, agents from Claude Code itself or from other plugins may only read and search. Every other checked tool is refused, both in the train's repository and when they write into it from another one.

The jail hooks are the enforced boundary, and they judge each tool call before it runs. Code an agent runs inside a tool call, such as its tests, is the same exposure any developer accepts when using a model on their own machine. Daedalus asks every agent never to get around its boundaries. It does not try to control your environment.

A blocked agent sees a line starting with `daedalus-jail[<agent>]:`. The line says what was refused and what to do next. The hooks, not the agents, write each step to the audit log. No agent merges. Only the push agent pushes, and only inside a push run. You merge.

[docs/guardrails.md](docs/guardrails.md) pairs each of these promises with the mechanism that enforces it and the test that shows the mechanism exists.

With no declared standards, the Standards Packet, the list of your rules that apply to a task, is empty. The auditor then judges each unit against its contract only. The framework specialist reviews only trains that touched IAM, KMS, mTLS, key custody or infrastructure configuration, against the packs described under Control packs. To declare your standards, see [docs/project-requirements.md](docs/project-requirements.md). To start from a shipped set instead, declare the opt-in baseline pack, `{"kind": "pack", "name": "baseline"}`. It holds five baseline checks plus the Daedalus cloud security standards, written in Daedalus's own words. The doctor offers it while `standards_sources` is empty.

## How it works

This section is for readers who want the internals. It follows one tool call from Claude Code to its audit record, then one build run from the first command to the pull request. Each passage says what a piece is, what reads it and what it feeds.

### One tool call, end to end

Claude Code runs the hooks that `hooks/hooks.json` binds. Before a Bash, file, search, web, agent, message or MCP call, it runs `scripts/enforce_agent_jail.py` and passes it the call as JSON. That hook has a 10-second timeout. If it crashes or hangs, the call is refused. Input that is empty, unreadable or missing a tool name is refused too.

The script first decides whether the call belongs to a train. It walks up from the call's working folder to the project root. The root is the first folder holding `service-manifest.json` or `.claude/daedalus/`, or the main checkout when that folder is a linked worktree. With neither, the root is the git root. The script then looks for the train marker, `.claude/daedalus/train.active`, in that root. `scripts/lib/train_scope.py` names who meets the jail without a marker: every Daedalus agent, which arrives as `daedalus:<name>`. Your session, and agents from Claude Code itself or other plugins, meet the full jail only during a train.

With no marker, a call from your session or an outside agent takes a fast path, unless a path it names lies in a repository that has a marker. The fast path loads none of the jail's other code and runs one check: a read or search of a credential store refuses an agent and warns your session. Some Bash commands go to the full jail instead: one the script cannot split, one with more than 256 words, and one naming more than 16 repositories.

Otherwise the script loads the config and the jail code and judges the call:

- A Daedalus agent's call goes to the router, `scripts/lib/router.py`. The router reads the agent's file under `agents/` and runs each check its hooks block names. Then it runs the excluded-folders check that every routed agent meets.
- Your session's call goes to `scripts/lib/jail.py`. The jail never refuses your own session. A call it flags runs, with a warning in the session's context.
- An outside agent's call also goes to `scripts/lib/jail.py`. During a train it may read and search in the train's repository, and every other checked tool there is refused. Some commands carry another command inside a string: an `env -S` value, or the body of `bash -c`, `sh -c` or `flock -c`. The jail does not walk that string. It judges the command by the repositories the string writes into, and refuses it when it reaches the train's repository.

The script then appends its decision to the session's audit log as a PreToolUse record. A refusal's reason starts with the name of the check that refused. If the record cannot be written, an agent's call is refused unless it is an allowed read, and your session's call runs with an alert. A refusal exits 2 and prints `daedalus-jail[<agent>]: <reason> Next: <what to do>` on stderr, which Claude Code shows the agent. An allowed call exits 0. After the tool runs, `scripts/audit_log.py` records the PostToolUse or PostToolUseFailure event in the background, with a hash and the start of the tool's output.

If the jail's own code fails to load during a train, an agent's call is refused and your session's call runs with an alert. Outside a train such a call goes ahead, with a note on stderr.

### How a rule set is built from a hooks block

Each agent file's frontmatter carries a hooks block. The block holds one `PreToolUse` event with one `- hooks:` item, then one entry per check, written `{type: command, command: "python3 ${CLAUDE_PLUGIN_ROOT}/scripts/checks/<script>.py <flags>"}`. The agent file loader, `scripts/lib/agent_files.py`, refuses any other shape and any script that is not shipped under `scripts/checks/`. Claude Code itself ignores hooks blocks on plugin agents, so the router runs them, inside the jail's own process.

- Order: the checks run in the order the block lists them, and the first refusal ends the call. The hooks table under "The agents" above prints each block in that order.
- Flags: the words after the script path are that check's flags. Each check declares the flags it takes. A flag it does not know, or a value of the wrong form, refuses the call.
- Tools: a check that names the tools it judges lets every other tool through without judging it.
- Combination: a call passes only when every check allows it. A check that fails to load, raises an error, or returns something other than a decision refuses the call and shows the full cause. An agent with no agent file or no hooks block is refused before any check runs.

`scripts/checks/shapes.json` lists the checks each agent shape must carry. A test fails when an agent file lacks a check its shape lists.

### The train marker

The train marker is the file `<repo>/.claude/daedalus/train.active`. Its first line names the running train's id. `daedalus_workspace.py begin` writes it when a build run starts. `daedalus_workspace.py mark` writes it for a push run and a document run. The stop and unmark commands remove it. While the marker exists in a repository, it switches on all of these there:

- The full jail for your session and for outside agents. Without a marker they meet only the credential check.
- The refusal of every checked tool except reads and searches, for outside agents.
- Warnings in your session's context when it writes into `.git` or `.claude/daedalus/`, writes into the repository outside the train's working folder, names a credential store, trips a shell tripwire, skips a dispatch rule, or runs a git, gh or redirect command that names an excluded folder.
- The audit log. Without a marker no hook writes a record. The first record in a new session log also runs log retention.
- The reply key, created with the first record that carries an agent's reply.
- The receipts check on a coding agent's report.
- The checks that read the running train's id: the coding agent's claim on its unit worktree, the working and audit folders other writers may write, the document train's output folder, the unit worktree a test run is bound to, and the folder the dependency map may be written to.
- The push and pull request gate, which reads the train branch and its recorded verdict through the marker.

Daedalus's own agents keep their checks with or without a marker.

### The audit log and the reply key

Each session gets one log, `<repo>/.claude/daedalus/audit/<session_id>.jsonl`, and only the hooks write it. `scripts/lib/audit.py` writes every record under a lock. Each record holds its sequence number `seq`, the hash of the record before it (`prev_hash`), and its own `hash` over the rest of the record. An edited, removed or reordered record breaks the chain. The chain verifier and the audit report recompute the chain before they read anything else. These are the record types:

| Event | What the record holds | Who reads it |
|---|---|---|
| `SessionStart`, `UserPromptSubmit`, `Stop`, `SessionEnd` | The event, the session and its working folder, and for a prompt the redacted prompt text | The audit report |
| `PreToolUse` | The tool and its redacted input (a Read records only its path), the jail's decision (`allow` or `block`), the refusal reason with its check name, and the jail's own time in milliseconds | The hooks check, the summary's Blocks section, the control cost report, the push proof's summary anchor, and the wave merge and summary, which find each verifier dispatch by its `Unit worktree:` line |
| `PostToolUse`, `PostToolUseFailure` | A sha256 of the tool's output and its first 4096 characters, redacted, or the error | The push proof, which reads the summary command's own output line; the audit report |
| `SubagentStart` | The agent's id and type | The stop record, which takes its agent type from here when Claude Code omits it |
| `SubagentStop` | The redacted head and tail of the agent's last reply, 2048 characters each, a keyed digest of the whole reply, and every `[VERDICT: ...]` line of the reply | The push proof, the wave merge's verifier check, the docs verdict record, the summary, the reply check of project train definitions |
| `SubagentHandback` tool call | An agent's report, in the tool input of its PostToolUse record | The same readers as a stop record, which read the report from the tool input |
| `AuditRotation`, `AuditRotationFailed` | Each old session log retention deleted, or each one it failed to delete | The audit report |

The reply key is `<repo>/.claude/daedalus/reply-hmac.key`: 32 random bytes in a file only your user can read. The hooks create it with the first record that carries an agent's reply. Each such record gets `last_message_hmac`, an HMAC-SHA256 of the whole reply under that key. The log holds only a redacted head and tail of each reply, and the key stops the log alone from confirming a guessed reply. Its reader is `daedalus_train.py check-reply`. That command compares a reply a project train definition saved to a file with the agent's own stop record.

No agent may read the key, and the credential check refuses one that tries. A search pattern that can reach the key from the search's folder is refused too: an `rg` `-g`, `--glob` or `--iglob` pattern, or a Grep tool glob. A pattern holding a glob character the check does not model counts as reaching it. A key file that is not a 32-byte regular file only your user can read stops the record. Its `Next:` line says to delete the key from your own shell, and the next reply creates a new one.

### Train state and the bindings file

Each train has one state file, `<repo>/.claude/daedalus/trains/<train-id>.json`. Only scripts write it, under the lock file `<train-id>.lock` beside it, and the jail refuses tool writes into `.claude/daedalus/`. Its fields:

- `train_id`, `repo`, `base_branch`, `base_sha`, `charter_root`, `charter_base`, `charter_branch_created`, `ledger_line` and `cache_dir`, written by `begin`.
- `lock_sha`, the contract lock commit every unit branch must descend from, written by `lock`.
- `contract_skip`, `true` once `daedalus_train.py contract` printed `contract: skip` for the recorded plan. `lock --no-contract` refuses without it, and a new plan clears it.
- `merged`, set by finish once every unit merged.
- `units`, one entry per worktree with its `name`, `branch` and `path`, and `audit: true` on the audit worktree.
- `plan`, the recorded plan's `path` and `sha256`. The dispatch gate refuses a coder when the file no longer matches.
- `choices`, `phase` and `weight`, from the choice command. With project priorities, a choice also records the deciding `driver` and `rule`.
- `start_seq`, `audit_session` and `audit_bounds`, from the hooks check: the log record after which the train's verdicts are read.
- `verdict`, holding `status`, `tip`, `round` and `seq`, from the verdict command. `seq` is the auditor reply's record number in the log.
- `audit_rounds`, one map of findings per round, with each finding's severity and class.
- `exemptions`, per round and per finding: the exemption's `ledger_id`, the `tip` it covers and how it is `tracking`.
- `docs_verdict`, the docs stage record: `status` and `tip`, the `judged` docs branch head for a verified record, and the `findings` and `exemptions` for a refuted one.
- `ledger`, the ledger commit's `sha` and `ids`; `reaudit` and `resume` for the recovery paths; and `consults_open`, the consulted agents whose reply the train still waits for.
- A train started from a project train definition adds the runner's own fields, such as `mode`, `definition`, `stage_index`, `dispatches`, `records` and `stage_log`.

The progress note, the summary command, the dispatch gate, the merge commands, the push proof and the push gate read it.

The bindings file, `<repo>/.claude/daedalus/trains/<train-id>.bindings.json`, keeps one coding agent per unit worktree. It holds one entry per unit worktree under `units`, written under its own lock. Each entry moves through four steps:

1. Dispatch: when the orchestrator starts a repo-coder with one `Worktree:` line, the dispatch gate records the unit with no agent yet. A second dispatch to the same unit is refused.
2. Claim: the coding agent's first write, or first git write, in that worktree binds the unit to its agent id. Every later write by that agent must stay in that worktree, and no other agent may write there.
3. Rebind: when the orchestrator resumes a coder with a new `Worktree:` line, the gate moves the coder to the new unit and records the old unit as `retired_to` the new one.
4. Finish: finish and the wave merge mark each merged unit `finished`, and a later write into it is refused.

### The push proof

`python3 <plugin>/scripts/verify_audit_chain.py --approved <train-id> --repo <repo>` is the check a push run makes before it pushes. The push gate applies the same rules on the tip and the exemptions to an agent's `git push` and `gh pr create`. The proof reads the train summary's `Session <id>:` line to find the audit log. It reads the train state for the point in that log where the hooks check started the train. It tries the approved path first:

1. The recorded verdict must be approved and name the auditor reply's record number, its `seq`.
2. The anchor is the first record after that number of the summary command, `daedalus_train.py summary --repo <repo>`, whose own output says the summary was written for this train. A summary written by any other tool never anchors the proof.
3. The graded turn is the last security auditor turn after the hooks-check point and before the anchor. A reply in it that carries both an approved and a rejected verdict line is refused with `carries both verdicts`, and the round must be rerun.
4. The turn's verdict must be approved. Its record number must equal the recorded `seq`, and its `tip=` must equal the recorded tip.
5. The integration branch must sit on that tip, with two allowed moves past it. The first is one plain commit on the judged tip that changes only the ledger. The second, when a docs record exists, is a run of commits that change nothing but the four public docs, and one ledger-only commit may follow that run. In the run, each changed doc must be a regular, non-executable file after the commit, and a regular file or a new one before it. So a commit that deletes a doc, makes it executable or turns it into a link is refused. A merge in the run is judged against its first parent.

When the approved path fails and the recorded verdict is rejected, the proof tries the exemption path. Every finding in that round's findings file and in its recorded round must carry an exemption for the judged tip, with a ledger id and a tracking answer. The tip rule of step 5 still applies. On either path, a docs record must name the tip the docs-only commits end at, as verified, or as refuted with every refuted claim exempted. That tip is the current tip, or the commit below it when a ledger-only commit follows the docs commits.

Exit 0 prints `OK approved: approved verdict, ...` or `OK approved: every finding exempted, ...`, followed by the docs result when a docs record covers the tip. Exit 1 prints `NOT APPROVED: <reason>` with a `Next:` line. Run it from your own shell to see what a push would meet.

### The controls register

`scripts/checks/controls/` holds one JSON fragment per unit of work that added a control. Each key is `checks/<script>` for a hook script, or `<module>.<R_ constant>` for a refusal message. Each value holds exactly two fields. `failure` is the failure the control prevents, starting with its ruling or issue id. `premise_test` is the test that goes red when the control's premise stops holding. `scripts/lib/controls.py` merges the fragments and refuses a key named twice.

`python3 <plugin>/scripts/audit_report.py --session <id> --controls` reads the register for its Control cost section. That section lists the blocks per check, and one `failure:` line for each check that blocked. The orchestrator reads that report at the end of a train. Each check that blocked and whose line reads `failure: none` comes to you as a question: keep it, redesign it or remove it. `tests/test_controls.py` fails when a hook script or a refusal constant has no row, a field is empty, a failure does not start with an id, a premise test does not exist, or a row names a constant its module no longer has.

### One train, end to end

1. Start. Your session runs `daedalus_workspace.py begin`. That command refuses a working tree with uncommitted changes. It writes the data folder and its `.gitignore`, the train state file and the train marker, then prints the first status lines. Next, `verify_audit_chain.py --hooks-live` finds its own command as the newest Bash record of this session's log and records the point the push proof reads. Your session starts one orchestrator agent and passes messages between it and you.
2. Standards and the map. The standards specialist writes the Standards Packet from your declared sources. Its fifth part is a `## Priorities` section, holding your `priorities` block or the line `priorities: none declared`. The orchestrator runs `daedalus_map.py --repo <repo> --out <repo>/docs/.tmp/daedalus/<train-id>/map` to build a dependency map of your code, and records the sha256 of `map.json`. The jail refuses an `--out` outside that folder. The map skips every folder the `excluded_roots` key of `config.json` names, and exits 2 when those folders cannot be resolved.
3. Plan. The planner cuts the work into units. Each unit has a line in the plan block and a requirement section below it. `validate_plan.py` checks the file, and `daedalus_train.py plan` records its path and sha256 in train state.
4. Contract lock. The orchestrator first runs `daedalus_train.py contract --repo <repo>`. It prints `contract: skip` when the recorded plan has one unit and that unit meets every condition below. Otherwise it prints `contract: required (<reason>)`.
   - It changes at most 3 files.
   - No file is under `scripts/checks/`, `agents/`, `skills/` or `hooks/`.
   - No file is `scripts/lib/jail.py`, `scripts/lib/shell.py`, `scripts/enforce_agent_jail.py` or a protected path.
   - The plan has no pin line and has a `wire: none` line.

   The finish step then merges only a unit whose changes stay inside the plan's files. On a skip, no contract agent starts. `daedalus_workspace.py lock --no-contract` puts the integration branch `daedalus/<train-id>` at the base commit, commits nothing, and records the base as `lock_sha`. Each brief then carries `Contract: none`, and `daedalus_train.py plan` refuses a new plan for that train. Without a skip, the contract agent writes the Locked Contract Packet, and `daedalus_workspace.py lock` commits it on the integration branch and records `lock_sha`. A later contract revision leaves `lock_sha` at the first lock.
5. Units. A wave is a group of units built at the same time. For each wave, the orchestrator checks the tools the units list under `needs:` with `daedalus_doctor.py --check-tools`. For each unit it then runs `daedalus_workspace.py create`, writes the brief file, and starts a repo-coder with the brief path and one `Worktree:` line. The dispatch gate checks the recorded plan and records the dispatch. The coder's first write claims the unit.
6. Report and verification. The coder ends its reply with a receipts block above its `[STATUS: COMPLETE]` line, and the receipts check reads that block. The orchestrator checks the reply's branch, its packet hashes and that the branch descends from the contract lock. The verifier then judges the unit's diff against its brief. The unit is ready to merge once its verdict is `[VERDICT: VERIFIED]`.
7. Merge. `daedalus_workspace.py finish` merges every unit into the integration branch with `--no-ff`. A train cut into waves merges each wave first with the wave merge command. A merge that fails is aborted, and the repository stays on `daedalus/<train-id>` with the merges that completed. The `Next:` line names the conflicting files. Merge that unit there by hand, then run the merge step again, which skips units already merged.
8. Audit. Extra judges join depending on what the diff touches. The framework specialist joins for IAM, KMS, mTLS, key custody or infrastructure changes, with the shipped AWS and NIST packs or your own. The dependency auditor joins for a dependency manifest or lockfile. The Terraform reviewer joins for a `.tf` or `.tfvars` file. The security auditor judges the merged tip in its own audit worktree, and `daedalus_train.py verdict` records its verdict. Each finding of a rejected round comes to you as its own question.
9. Ledger and docs. On an approved verdict, or once you exempted every finding, charter-docs commits the ledger entries. After an approval, the approved verdict is recorded next. The docs writer then brings the four public docs up to date in the docs stage.
10. Summary. `daedalus_train.py summary` writes the summary from train state and the audit log, and the orchestrator ends with `[STATUS: TRAIN_COMPLETE]`.
11. Push. `/daedalus:run push` marks the train again and runs the hooks check and the push proof. The push agent pushes the branch and opens the pull request. The push gate checks the verdict again on the push agent's own push. You review and merge.

### Requirement sections and needs

Each unit of a plan has a requirement section outside the plan block. The section opens with a heading `### <unit id>: <title>`. Somewhere under it, a line reading exactly `Requirements:` is followed by lines `1. <requirement>`, numbered from 1. Each requirement is one sentence ending in a period, and it names a backticked token or a path holding a slash. `scripts/lib/plan_record.py` reads the sections. `validate_plan.py` refuses a unit without a section, a list that breaks its numbering, and a requirement in another shape. The dispatch gate runs the same check before any coder starts. The orchestrator copies each unit's section into its brief, and the verifier counts one claim per numbered line.

A unit line may also carry `needs: <tool or protected path>[, ...]`. It lists the tools the unit's build needs, such as `mypy` or `.venv/bin/ruff`, and each protected file the unit needs changed. Before a wave starts, the orchestrator passes every tool need to `daedalus_doctor.py --check-tools <names> --repo <repo>`. That command prints `OK   tool <name>` or `MISS tool <name>` per name, and exits 1 on any MISS. Missing tools and protected-file needs reach you as one question per wave.

### The receipts check

`scripts/handback_check.py` runs on every SubagentStop and on every `SubagentHandback` tool call, during a train only. It judges only a repo-coder's reply whose last line is `[STATUS: COMPLETE]`. Directly above that line it expects a `## Receipts` line, followed only by lines of five shapes:

- `- commit <40 hex> <subject>`
- `- test <command> => <last output line>`
- `- typecheck <command> => <last output line>`
- `- yield <kind> <question> => <who answered>`
- `- deviation <file or behaviour> | <reason>`

At least one commit line and one test line must be there. A reply in another shape goes back to the coder with one `Next:` line naming the shape, before the verifier sees it. A check that cannot run never blocks the coder, and the verifier still judges the unit. `scripts/cite.py` prints the `file:line` of each line holding a fixed string, so a coder can paste a citation instead of retyping it.

### The verifier

The verifier judges each unit's diff against its brief, never against the coder's report. Its claims are the brief's numbered requirements, the unit's files list, the pins that name the unit, and the Standards Packet rules a changed line falls under. The dependency map adds two more kinds of claim. For each module the diff changes, `imports.<module>.fan_in` lists the modules that import it, and each must still get what it relied on. Each `duplicates` entry that overlaps the added lines must not repeat code the project already holds. Each refuted claim is a `code` row or a `scope` row. A `scope` row is a file outside the files list, or a behaviour change no requirement asks for, unless a `- deviation` receipt names it with a reason.

A receipt the branch contradicts, such as a wrong test count or commit subject, is corrected inside the verdict. It is counted on a `corrected=<k>` line above the closing verdict line. It never refutes the unit, and the coder is not resumed for it. Only `code` and `scope` rows send a coder back for a fix, and a second refutation of the same unit stops the train. The orchestrator runs finish only once every unit's verdict is `[VERDICT: VERIFIED] claims=<n>`. The wave merge command reads that last line itself, from the verifier's reply in the audit log. The summary's Verification section prints each unit's verdict line with its corrected count.

The orchestrator gives the verifier a `Read: <file>:<first>-<last>[, ...]` line, built from the diff's changed hunks and the map's importer lines. The verifier reads those ranges, and lists each other file it opens as an `extra read` row. It judges typecheck and lint receipts from the coder's receipts block and reruns only pytest. A brief whose contract line reads `Contract: none` has no contract pin to judge. A prompt whose first line is `CLAIMS MODE.` lists `Claim: <path>:<line> <claim>` lines instead of a brief, and the verifier checks only those lines. The docs stage and the document train use this form.

### Merges and fix units

`daedalus_workspace.py finish` merges every recorded unit except the audit worktree's, one `--no-ff` merge commit each. It skips a unit already on the integration branch. Each merge message reads `Merge <name> for train <train-id>`, where `<name>` is the worktree name without its `<train-id>-` prefix. The wave merge command, `python3 <plugin>/scripts/daedalus_workspace.py merge --repo <repo> --units <id>[,<id>]`, merges only the named units and leaves the train open for the next wave. It refuses a unit the recorded plan does not name. It also refuses a unit without a `[VERDICT: VERIFIED]` verifier reply for its worktree in the audit log.

A fix unit from an audit round, the worktree `<train-id>-fix<n>-<unit>`, is outside the plan. So the wave merge refuses it, and finish merges it on its next run. To merge such a unit by hand, run this from your own shell on the integration branch, with `<name>` the worktree name without its `<train-id>-` prefix. Finish then skips it:

    git merge --no-ff daedalus-unit/<train-id>-<name> -m "Merge <name> for train <train-id>"

### Exemptions, the docs stage and the extra judges

Each failing finding comes to you as one question. Its first line says what is at stake in one plain sentence, then asks. Two or three short sentences follow on what breaks and what happened in the test. The three choices are:

- `Fix it now (Recommended)` runs a fix round.
- `Skip, track or exempt it` exempts the finding.
- `Stop the train` ends the train.

No limit on rounds applies. The train never opens a fix round or stops on its own; you hold every one of those choices. An exemption brings a second question, how it is tracked: `Skip it` (dropped silently), `Track it` (a GitHub tracked-risk issue), `Exempt it` (the local ledger record alone), or your own answer. These are stored as `dropped`, `issue`, `local` and `other`. Your session records each exemption with `daedalus_train.py exception --repo <repo> --ledger-id <id> --finding <id> --tracking <dropped, issue, local or other>`. The command writes it in train state: under the round for a security finding, and in the docs record for a docs claim. The push proof reads it. The summary's Audit section prints each exempted finding with its tracking answer.

The docs stage runs after the security verdict is recorded, and the docs writer ends the train. The stage creates the worktree `<train-id>-docstage`, which the dispatch gate binds to the docs writer alone. The docs writer may write only the four public docs: `README.md`, `docs/howto/README.md`, `docs/guardrails.md` and `docs/project-requirements.md`. Its claims go to the verifier in claims mode. A claim that a check, gate or refusal exists needs its definition and a caller on the path it governs. The docs writer's receipt includes that caller search, and the verifier runs its own. A definition with no caller is an overstated claim. The verifier's dispatch names the docs branch head on a `Docs tip:` line. A verified reply merges the docs branch. Then `daedalus_train.py verdict --gate docs --status verified --judged <sha>` records the docs verdict in train state, with `<sha>` that docs tip. The command refuses a verified record without `--judged`, and refuses when the merged docs commits end at another commit. Each refuted claim comes to you as a finding. The summary's Audit section names the docs verdict, or `Docs: not run`.

Two read-only judges join depending on what the diff touches. The dependency auditor judges a changed dependency manifest or lockfile. It asks for security advisories only through a web question, which the train sends to the web researcher. When `features.dependency_web_lookup` is `false`, the train answers that question with "web lookup is off", and the auditor judges from the lockfile and any advisory export. The Terraform reviewer judges a changed `.tf` or `.tfvars` file. It may run only `terraform fmt -check` and `terraform validate`, and neither when `features.terraform_tools` is `false`. The jail refuses `terraform validate` unless `features.terraform_validate` is `true`, because validate starts the provider programs under `.terraform/providers`. Without it the reviewer marks that check N/A. Each FAIL row from either judge comes to you as a finding.

### Project priorities

The `priorities` block of `service-manifest.json` ranks four concerns: `security`, `trust`, `ops` and `cost`. It may add rules, principles and a ranking per agent (see the key reference above). The doctor prints `priorities: <ranking>, <n> rules` or `priorities: none declared`. The standards specialist writes the block into the Standards Packet's `## Priorities` section. Every agent of every train reads that section; your own session does not.

When two concerns conflict, the orchestrator tries the rules in order, and the first match decides. A rule ending in a concern settles the choice alone, and its choice record names the driver and the rule. A rule ending in `surface` puts the choice to you. A coder raises a default with `[STATUS: YIELD_STANDARDS] priorities rule <n>: ...`. A global rule or your answer outranks the ranking, and no rule lowers an audit finding's severity. The summary's Priorities section lists each decision a rule settled or put to you.

### The document train and excluded roots

`/daedalus:run doc <what, sources, folder>` derives a document from frozen sources, files whose contents are recorded so a change shows. `freeze_sources.py --train <id> --output-dir <folder> --source <alias>=<role>:<path>` records each source with its sha256 in `<repo>/.claude/daedalus/trains/<id>.sources.json`. `freeze_sources.py --verify <that file>` checks them:

- It exits 4 when a source changed.
- It exits 1 when the recorded output folder fails the output folder check, before it reads any output.
- It exits 5 when an output carries an en or em dash, placeholder copy, or a sentence copied from a style source that carries a number.

The doc-deriver and the change-logger write only inside the output folder, which `scripts/checks/doc_outputs.py` checks. The verifier checks the deriver's claims in claims mode. `/daedalus:round` keeps the record of one round of correspondence.

The `excluded_roots` key of `config.json` names folders whose files must never reach git, GitHub or a redirect. `scripts/checks/excluded_roots.py` runs for every Daedalus agent after its own checks. It refuses a git command that stages, commits or stashes a path inside such a folder, and a gh command or a redirect that names one. While any such folder is declared, it also refuses a git command that matches paths in any letter case: an `:(icase)` or short `:i:` pathspec, `--icase-pathspecs` or `GIT_ICASE_PATHSPECS`. The doc-deriver and the change-logger may redirect into such a folder, since their outputs live there. During a train your session is warned instead. `freeze_sources.py` records the resolved folders in the sources file.

### A run in a plain folder

Outside a git repository, `/daedalus:run` runs only the brainstorm, plan, document and verify phases, in your session, and no security audit runs. It asks where the run's outputs go: the project's `docs` folder, a new folder under `/tmp`, or a folder you name. Then it opens the run with `daedalus_workspace.py begin --repo <folder> --scope folder --out <outputs>`, which runs no git command. Begin refuses an output folder that is the project folder, one of its parents, your home folder or a folder under `.claude`. The planner writes its plan file and brainstorm spec straight into that output folder. The doc-deriver and the change-logger write each derived document and change log there too. The write checks admit that folder only while the run that recorded it is active. Building, auditing and pushing need a git repository.

### The summary's path rule

The train summary becomes a public pull request body, so `scripts/lib/train_summary.py` lets no absolute path through. It first rewrites paths under the repository as relative paths, and paths under the Charter as starting with the Charter's folder name. Every other word holding a `/`, a `\` or a percent-encoded slash must then be a plain relative path inside the repository or the Charter. Each part of such a path is a plain ASCII name, with no `..`, `~`, `%`, `$`, `@`, scheme, drive, or leading or doubled slash. A path from the summary notes file that breaks this rule stops the summary, with a `Next:` line naming the path. A path from the audit log or train state, which nobody may edit, prints as `[path withheld]`, and the summary is still written.

### The kernel wrapper's grants

On a kernel with Landlock and seccomp, a coder's test command runs as `daedalus_confine.py --unit <worktree> -- <command>`, and the coder's confine check requires it. A test command is one the runner table names: `pytest`, `make`, `tox`, `nox`, `just`, `npx`, `uv run`, `go test` and `cargo test`. The wrapper applies its rules to its own process, then runs the command, and every child process inherits them. Nothing is installed, and the rules end with the process tree. It grants:

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
│   ├── contract-spec.md
│   ├── dependency-auditor.md
│   ├── doc-deriver.md
│   ├── docs-writer.md
│   ├── framework-specialist.md
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
│   ├── baseline/rules.md            # opt-in baseline and cloud security standards pack
│   ├── frameworks/aws-default/      # AWS hardening control pack the framework specialist reads by default
│   └── frameworks/nist-distilled/   # NIST SP 800-53 control pack the framework specialist reads by default
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
│   ├── lib/briefs.py                # decision briefs checked at the manifest literacy level
│   ├── lib/config.py                # config.json loading and validation
│   ├── lib/controls.py              # loads the controls fragments
│   ├── lib/credential_paths.py      # the credential-path deny every agent meets
│   ├── lib/dispatch_binding.py      # coder dispatch, warm rebind and first-write claim
│   ├── lib/fetch.py                 # GitHub-only download, size cap and cache lock for refreshes
│   ├── lib/gh_policy.py             # the gh commands each agent may run
│   ├── lib/git.py                   # the one git runner: timeout and redirect scrub
│   ├── lib/hook_io.py               # hook input and output for the check scripts
│   ├── lib/human_text.py            # counts the plain words in operator lines
│   ├── lib/inventory.py             # FILES: every path the plugin can write, for --print-files
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
│   ├── token_economy.py             # the token table of one run, and the saved-run history
│   ├── validate_plan.py             # checks a plan file and prints its graph line
│   ├── validate_train.py            # checks a train definition file
│   └── verify_audit_chain.py        # recompute and verify a session's hash chain
├── skills/
│   ├── audit/SKILL.md               # the audit phase, run by the orchestrator
│   ├── audit-report/SKILL.md        # /daedalus:audit-report
│   ├── brainstorm/SKILL.md          # /daedalus:brainstorm, the brainstorm phase
│   ├── build/SKILL.md               # /daedalus:build, the build phase
│   ├── build-train/SKILL.md         # moved to /daedalus:run; prints the new command
│   ├── catalog/SKILL.md             # /daedalus:catalog
│   ├── doc-train/SKILL.md           # moved to /daedalus:run doc; prints the new command
│   ├── document/SKILL.md            # the document phase, in two modes
│   ├── doctor/SKILL.md              # /daedalus:doctor
│   ├── plan/SKILL.md                # /daedalus:plan, the plan phase
│   ├── push-train/SKILL.md          # moved to /daedalus:run push; prints the new command
│   ├── release/SKILL.md             # the release phase, started by /daedalus:run push
│   ├── round/SKILL.md               # /daedalus:round
│   ├── run/SKILL.md                 # /daedalus:run, the one command that starts any run
│   ├── setup/SKILL.md               # /daedalus:setup
│   ├── token-report/SKILL.md        # /daedalus:token-report
│   └── verify/SKILL.md              # /daedalus:verify, the verify phase
└── tests/                           # the pytest suite
```

## License

Daedalus is licensed under the GNU General Public License v3.0 or later. See LICENSE.

## Developing Daedalus

    pip install -e '.[dev]'
    pytest
    ruff check scripts tests
