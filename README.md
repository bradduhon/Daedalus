<!-- Copyright (c) 2026 Brad Duhon. SPDX-License-Identifier: GPL-3.0-or-later -->
# Daedalus

## What Daedalus is

Daedalus is a Claude Code plugin. It gives your session a set of AI agents, each with one job. Each agent may use only the tools that job needs. Before every tool call, a check compares the call with the agent's rules and blocks anything outside its job. Daedalus calls this check the jail, and its refusal messages start with `daedalus-jail`.

You start any piece of work with one command: `/daedalus:run` followed by your task. Daedalus sizes the task, tells you which phases it picked, and runs them. When the work is built and audited, `/daedalus:run push` pushes the branch and opens a pull request. No fixed recipe is required. You can run a phase on its own, and you can use the agents in any order.

Daedalus calls a run that builds code a train. You will see that word in branch names, file names and messages.

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

In a new repository, the `config.json`, `service-manifest.json`, `contracts/` and `.gitleaks.toml` lines read `OPT`. These are files your project writes about itself. Type `/daedalus:setup` to write starter copies of the first two. A build run and a push run both work without any of them.

The `fable` line reads `OPT` until `models.fable_available` is `true` in `config.json` or a running train's audit log shows the session started on Fable. Until then the planner and the auditor run on their own model.

If your project is a plain folder and not a git repository, Daedalus works in folder scope. Only a repository can be pushed, so the doctor marks the `git repository` line and the two gh lines `OPT`. When the secret scan is on, the gitleaks line reads `OPT` too.

[docs/project-requirements.md](docs/project-requirements.md) lists every file Daedalus expects, says what each is for, and gives a small example of each.

### Your first body of work

1. See what Daedalus has. Type `/daedalus:catalog` once. It prints a list of the agents and the seven phases.
2. Start a run. Type `/daedalus:run` and your task in your own words, for example `/daedalus:run Add a --verbose flag to the command-line tool`. A one-line task needs no file, because the run saves the words you type as the spec. With only an idea and no spec, type `/daedalus:brainstorm` and the idea, or the path of a notes file. First it talks the idea through with you and offers other ways to see it. When you pick a direction, it shows you a short brief of what you chose. Then it asks you one question at a time. Each question comes with a proposal you can accept, or you type your own answer. It writes the design when you say it stands. The [operator guide](docs/howto/README.md) shows how to turn an idea into a spec and how to split a spec into units before you build.
3. Answer its questions. The run works on its own and stops only when it needs you. Each question arrives in Claude Code's question prompt, with the recommended answer first. When the security audit finds a problem, you get one question per problem with three choices: `Fix it now (Recommended)`, `Skip, track or exempt it` or `Stop the run`.
4. Merge the pull request. When the run ends, you can read what every agent did with `/daedalus:audit-report <session>`. Type `/daedalus:run push` to push the branch and open its pull request. Review the pull request and merge it yourself with a merge commit. Daedalus never merges.

## Runs and reports

The build run and the push run below are the usual way to use Daedalus, not the only way. A piece of work can use any agents from the catalog in any order.

Outside a train, Daedalus's own agents keep their own checks. Your session, and agents from Claude Code itself or from other plugins, meet only one check outside a train: a read or search of a credential file. That check gives your session a note in its context and refuses an agent (see Safety model below).

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

- optionally, a decisions file, where your project records its design decisions. Name it in `docs.decisions_filename` of `service-manifest.json`. With no file named, a run records no decision and asks nothing about one. A named file that does not exist yet is created as a table with the first decision.
- a clean working tree. The one exception is your settings files, `service-manifest.json` and `.claude/daedalus/config.json`. Each may be changed or new, as long as it is not staged. The pull request does not carry them unless you commit them.
- optionally, `<repo>/.claude/daedalus/config.json` (see [docs/project-requirements.md](docs/project-requirements.md)). Without it the defaults apply.

Then type the command and your task:

    /daedalus:run Add a --verbose flag to the command-line tool

After each phase you see a progress note. It names the phase, its weight and the state of each unit. Before each choice the train makes, it prints one line: `Chose <what> over <alternative>: <cost>`.

When the train ends, your session shows the summary path and the audit log path. If a commit lands on the train's branch after that, tell the session. It runs one recovery audit round on the new tip (`daedalus_train.py reaudit`) instead of a full rerun. A train that stopped before its ledger commit is finished by the session's ledger resume (`daedalus_train.py resume`).

### Push run

The push run commits, pushes and opens the pull request for a finished build run:

    /daedalus:run push

It first checks that the build run's audit log holds an approved security verdict for that train. When `checks.secret_scan` is `true` in `service-manifest.json`, it also scans the commits for secrets with gitleaks before the push. Your repository needs a GitHub remote named `origin`, and `gh` must be signed in to it.

The push agent, the releaser, pushes the branch and watches CI. The pull request body is the build run's summary, with one line per issue the summary names. An issue named with a GitHub closing word, such as `Closes #<n>` or `Fixes #<n>`, gets a `Closes #<n>` line, so merging the pull request closes it. Every other mention, partial work included, gets a `Refs #<n>` line and stays open. If the build run used a branch in your Charter repository, the push agent also pushes that branch and opens its pull request after the code one. The Charter is a separate repository for your decisions and specs, named by the `local_docs_folder` setting. If a commit landed on the train's branch after the audit, the push run adds one recovery audit round on the new tip before it pushes.

You review and merge. Merge with a merge commit, never a squash or a rebase merge. A merge commit lands every commit of the run on your default branch as written, and the release step checks that the run's commits are there. Once `gh pr view <url> --json state` shows the merge, delete the train branch from your own shell with `git branch -D daedalus/<train-id>`.

### Execution Train

The Execution Train is your own manual checks on live or staging systems. It has no command, and Daedalus does not run it. AI agents never take part in it. A later release adds a readiness checklist for it.

### Audit report

To read what every agent did in a session, open its audit report:

    /daedalus:audit-report

### Token report

To see what a run cost in tokens, type the command below. It counts the agents only, in the same columns for every kind of run:

    /daedalus:token-report <run id or session id>

When your settings name a docs folder (`local_docs_folder`), the skill saves a run's table there under `reports/` without asking and prints the path; with none named it saves the table in the `reports` folder of the plugin data folder and prints that path; `history` reads whichever folder applies. `/daedalus:audit-report` follows the same rule and saves under `audit/`. `/daedalus:token-report history` prints the totals row of every saved run.

## The agents

Each agent's file lists the only tools it may use, the status lines it ends its replies with, and the phases it suits: context, clarification, plan, implementation, audit, and commit and release. The phases help your session pick an agent. They never limit the choice. The table below is generated from the agent files by `python3 scripts/catalog.py table`. `/daedalus:catalog` shows your session the same table, and a test fails when this copy goes stale.

<!-- generated: catalog.py table -->
| Agent | Shape | Model | Tools | Job | Reply lines | Phases |
|---|---|---|---|---|---|---|
| auditor | judge | opus, prefers fable | Bash, Edit, Glob, Grep, Read, Write | Adversarial pre-commit security and contract verifier. | `[VERDICT: APPROVED] tip=<40 lowercase hex>`; `[VERDICT: REJECTED] tip=<40 lowercase hex>`; `[STATUS: YIELD_WEB] <query>`; `[STATUS: HANDOFF] path=<path>`; `[STATUS: COMPLIANCE] <control ids with pack ids and refs ids>` | implementation, audit |
| charter-docs | producer | sonnet | Bash, Edit, Glob, Grep, Read, Write | Single-writer custodian of the Charter repository, the architectural decision ledger, and Build Train commits. | `[STATUS: LEDGER_PROBED] <probe line>`; `[STATUS: LEDGER_APPENDED] <id>`; `[STATUS: LEDGER_MISMATCH] expected=<n> ledger=<m>`; `[STATUS: COMMITTED] <sha> ids=<id>[,<id>]`; `[STATUS: BLOCKED] <detail>`; `[STATUS: HANDOFF] path=<path>` | clarification, commit, release |
| coder | producer | opus | Bash, Edit, Glob, Grep, Read, Write | Scoped implementation worker. | `[STATUS: YIELD_WEB] <query>`; `[STATUS: YIELD_CONTRACT] <mismatch>`; `[STATUS: YIELD_COMPLIANCE] <question>`; `[STATUS: YIELD_STANDARDS] <question>`; `[STATUS: YIELD_GRANT] <exact command> \| <why>`; `[STATUS: HANDOFF] path=<path>`; `[STATUS: COMPLETE] branch=<b> packet_version=<n> files=<list> tests=<summary> ledger_notes=<text> contract=<12 hex> standards=<12 hex>` | implementation |
| comparer | producer | opus | Bash, Glob, Grep, Read, Write | Produces the change gate between a baseline and a derived document, or between two baselines when no deriver runs: one row per departure, with the baseline quote, the derived quote, the reason, and a status the operator rules on. | `[STATUS: COMPLETE] change_log=<path> rows=<n> open=<k>`; `[STATUS: BLOCKED] <what the manifest or brief leaves out>`; `[STATUS: HANDOFF] path=<path>` | implementation |
| contract-spec | producer | sonnet | Edit, Glob, Grep, Read, Write | Reads and updates service handshake contracts, API schemas, and specifications. | `## Locked Contract Packet`; `[STATUS: HANDOFF] path=<path>` | clarification, plan |
| orchestrator | dispatcher | opus | Agent, Bash, Edit, Glob, Grep, Read, SendMessage, Write | Runs one Build Train from its plan to the audited integration tip. | `[STATUS: ANNOUNCE] size=<size> phases=<list>`; `[STATUS: DECISION] brief=<path> questions=<n>`; `[STATUS: EXCEPTION] ledger_id=<id>`; `[STATUS: TRAIN_COMPLETE] summary=<path> audit_log=<path> tip=<40 hex>`; `[STATUS: STOP] reason=<what happened> next=<next action>`; `[STATUS: CHECKPOINT] state=<path> next=<unit ids>`; `[STATUS: HANDOFF] path=<path>` | context, clarification, plan, implementation, audit |
| planner | shaper | opus, prefers fable | Glob, Grep, Read, Write | Cuts a design spec into work units that coders can build in parallel. | `[STATUS: PLAN] path=<path> units=<n> critical_path=<k> width=<w>`; `[STATUS: QUESTION] <what the task leaves open>`; `[STATUS: ASK] n=<n>`; `[STATUS: SPEC] n=<n> path=<path> open=<m>`; `[STATUS: NOT_VIABLE] n=<n> <the blocking fact in one line>`; `[STATUS: YIELD_WEB] <query>`; `[STATUS: HANDOFF] path=<path>` | clarification, plan |
| releaser | mover | opus | Bash, Glob, Grep, Read | GitHub specialist for the Push Train. | `[STATUS: PUSHED] branch=<b> pr=<url>`; `[STATUS: CI] run=<id> conclusion=<text>`; `[STATUS: BLOCKED] <precondition that failed>`; `[STATUS: HANDOFF] inline` | commit, release |
| verifier | judge | opus | Bash, Glob, Grep, Read | Adversarial read-only verifier of one unit's diff against its brief. | `[VERDICT: VERIFIED] claims=<n>`; `[VERDICT: REFUTED] <rows>`; `[ROWS] n=<count>`; `[STATUS: HANDOFF] inline` | implementation |
| web-researcher | finder | haiku | Read, WebFetch, WebSearch | Fast external documentation lookup on Haiku. | `[STATUS: RESEARCH] <payload under 300 words with URLs>`; `[STATUS: HANDOFF] inline` | context |
| writer | producer | opus | Bash, Edit, Glob, Grep, Read, Write | Writes documents with a rerunnable receipt on every claim, in the one kind its brief names: the four public docs after a run merged, or one document derived from frozen sources. | `[STATUS: DOCS_WRITTEN] branch=<b> commit=<40 hex> claims=<n>`; `[STATUS: DOCS_UNCHANGED] reason=<why no passage needed an edit>`; `[STATUS: COMPLETE] outputs=<path>[,<path>] claims=<n> judgments=<k> assumed=<m>`; `[STATUS: BLOCKED] <what the manifest or brief leaves out>`; `[STATUS: HANDOFF] path=<path>` | implementation, audit |
<!-- end generated -->

Each agent file also declares a shape, the kind of job it does, and the checks that run before each of its tool calls, with their flags. The table below is generated from the agent files by `python3 scripts/catalog.py matrix`, and a test fails when it goes stale. The writer has one row per document kind. Each row lists the writer's own checks, then the checks of that kind, and a writer runs only the row of the kind its dispatch recorded.

<!-- generated: catalog.py matrix -->
| Agent | Shape | Hooks |
|---|---|---|
| auditor | judge | credential_paths, workspace_integrity, tool_bound, shell_tripwires, network_tools, read_only_bash --git read-only --test-runner audit --terraform, gh_classes, root_writes --touch audit |
| charter-docs | producer | credential_paths, workspace_integrity, tool_bound, shell_tripwires, network_tools, git_push, git_grammar --allow docs, root_writes --touch charter,docs --ledger-guard, command_allowlist --allow append_ledger,git,read, gh_classes |
| coder | producer | credential_paths, workspace_integrity, tool_bound, shell_tripwires, network_tools, git_push, git_grammar --allow coder, unit_writes, gh_classes, confine |
| comparer | producer | credential_paths, workspace_integrity, tool_bound, shell_tripwires, network_tools, git_push, git_grammar, read_only_bash, doc_outputs |
| contract-spec | producer | credential_paths, workspace_integrity, tool_bound, root_writes --touch contracts,charter-specs |
| orchestrator | dispatcher | credential_paths, workspace_integrity, tool_bound, shell_tripwires, network_tools, git_push, command_allowlist --allow train,inspect, root_writes --touch scratch --ledger-guard, gh_classes, dispatch_gate |
| planner | shaper | credential_paths, workspace_integrity, tool_bound, root_writes --touch scratch --name plan*.md --sub brainstorm-*/spec.md |
| releaser | mover | credential_paths, workspace_integrity, tool_bound, shell_tripwires, network_tools --gh, command_allowlist --allow git,gh,gitleaks, git_grammar --allow conductor, git_push --conductor, gh_classes --conductor |
| verifier | judge | credential_paths, workspace_integrity, tool_bound, shell_tripwires, network_tools, read_only_bash --git read-only --test-runner unit, gh_classes |
| web-researcher | finder | credential_paths, tool_bound, network_tools --web |
| writer (public-docs) | producer | credential_paths, workspace_integrity, tool_bound, shell_tripwires, network_tools, git_push, git_grammar --allow coder, unit_writes --docs, gh_classes, confine |
| writer (derived) | producer | credential_paths, workspace_integrity, tool_bound, shell_tripwires, network_tools, git_push, git_grammar, read_only_bash, doc_outputs |
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

`<repo>/.claude/daedalus/config.json` is optional. `/daedalus:setup` writes a starter copy when it is missing, and changes one setting at a time when you answer its questions. Nothing else in Daedalus writes it. Configuration below lists its fields.

### Control packs

A control pack is a list of security controls a change is judged against. The auditor judges every merged change against the control packs. Daedalus ships four packs under `<plugin>/packs/frameworks/`:

- `aws-default` holds AWS hardening controls, written in Daedalus's own words. It is read by default.
- `nist-distilled` holds a NIST SP 800-53 checklist. It is read by default.
- `stripe-default` holds Stripe rules: no secret key in the code or in a committed file, webhook signatures checked, and prices set by the server. It is read by default, but only when a change touches a file with `stripe` in its name, a `.env` file, `package.json` or an npm lockfile. Only such a change is judged against it.
- `cost-tier` holds cost rules for Terraform on AWS, such as service-default keys, on-demand tables, no idle NAT gateway and log retention. It is off by default. To read it, add `"packs": ["cost-tier"]` to the `frameworks` block of `service-manifest.json`.

When a change touches `package.json` or an npm lockfile, the auditor also judges four npm rules from `<plugin>/packs/dependencies/npm.md`.
When a change touches `pyproject.toml`, a `requirements*.txt` file, `setup.py`, `setup.cfg` or a Python lockfile, it also judges six Python rules from `<plugin>/packs/dependencies/python.md`.

The auditor also checks how new each added or updated package version is. A version published fewer days ago than `packages.minimum_age_days`, seven by default, fails. The publish date comes from the web lookup or from an advisory export you supply. With neither, the audit cannot check advisories or ages, and it stops on a finding that asks you to turn the lookup on or supply an export.

A project with no `compliance_rules` group in `service-manifest.json` is judged against the three packs that are on by default and needs no setup. To add your own packs, name a project folder in `compliance_rules.folder`. Each subfolder holding a `pack.json` and a `controls.json` is one pack. Set `compliance_rules.use_builtin` to `false` to stop reading the shipped packs that are on by default. Your own packs and any shipped pack named in `compliance_rules.extra_builtin` are still read. The `default` and `triggers` keys of `pack.json` work only in the packs Daedalus ships; a pack of your own that holds either one fails its check. A pack that fails its hash or format check stops the train.

The commands below run from your own shell, in your project. `<plugin>` is the path the doctor prints on its `plugin root` line. `<cache>` is a directory whose name depends on how you installed Daedalus. Print it with:

    python3 <plugin>/scripts/daedalus_doctor.py --print-cache-dir

To build a pack from the NIST catalog, fetch the catalog first, then import the controls you want:

    python3 <plugin>/scripts/refresh_frameworks.py --only nist-800-53 --cache-root <cache>

    python3 <plugin>/scripts/import_pack.py oscal --catalog <cache>/frameworks/nist/catalog.json --ids AC-2,SC-12 --out compliance/packs/nist-picked

CIS Benchmark text is licensed, so a CIS pack carries ids only. Write a CSV with exactly the columns `cis_id,control_id`. Each row maps a CIS id to a control in another pack. Then import it:

    python3 <plugin>/scripts/import_pack.py cis-map --map cis-map.csv --benchmark "CIS AWS Foundations" --version 3.0.0 --out compliance/packs/cis-aws

## Configuration

[docs/project-requirements.md](docs/project-requirements.md) describes every file and setting Daedalus reads, each with a small working example. The [operator guide](docs/howto/README.md) covers each run step by step, how to read a block message, and how to read an audit report.

To start or change your settings, type `/daedalus:setup`. It is a short conversation in your session. It first tells you what the three settings files below are. It writes a starter `service-manifest.json` at the project root when that file is missing. It writes a starter `.claude/daedalus/config.json` when that file is missing. Each starter file holds only the starter settings, at their starting values. It asks you once before it creates your personal file in your home folder. It prints one line per file: `written:` when it created the file, `kept:` when the file already existed. After writing a new manifest, it prints one more line with example values for the `docs.reading_level` key. That key sets how plainly the docs writer writes, and the new manifest holds it as `null`.

Next it asks about the settings that change what Daedalus does on your first day, one question at a time: the test, type-check and lint commands, the reading level, whether to record decisions and in which file, the secret scan before a push, and the Terraform format check. Each question says what the setting changes, shows its value now and offers a proposal. It skips a question your project already answers, such as the Terraform questions in a project with no Terraform files. Then it lists the other groups of settings and asks which one to walk, until you choose Done. An override, a setting with a good default that most projects keep, is offered only in those groups. A setting that nothing in Daedalus acts on yet is named as not active and is never asked.

### The three settings files

Daedalus reads three settings files. Each one has a different owner.

| File | Where it lives | Whose it is | Shared by git | What it holds |
|---|---|---|---|---|
| `service-manifest.json` | the project root | the project | yes, git tracks it | what the project is and what it turns on |
| `.claude/daedalus/config.json` | the .claude/daedalus folder in the project | this checkout on this machine | no, git ignores it | how Daedalus is wired up here |
| `~/.claude/daedalus/operator.json` | the .claude/daedalus folder in your home folder | you, across every project | no, it sits outside every project | your personal preferences |

Where two files overlap, this is which one wins:

- When this checkout's config names a docs folder kept elsewhere on this machine, the decisions file lives there, not in the project's own docs folder.
- Today only the project's reading level changes how Daedalus writes. Your personal reading level is checked but nothing reads it yet. Once it is read, it will apply only to a project that sets no reading level of its own.
- A project's config can hold its own copy of any personal preference. A value set there replaces your personal value for that project only, and the rest still come from your personal file. Today Daedalus reads the project's copy of the Self-Assessment and Developer Profile switches, the work classes, the class mapping and the context limit; nothing acts yet on the project's copy of any other value.

A key that starts with an underscore is your own, such as `"_copyright": "Copyright (c) 2026 Example Co."`. JSON has no comments, so a project whose rules require a copyright line in every JSON file can put it there. Daedalus accepts such a key at any level of a settings file. It never reads the key, and the setup wizard keeps it when it changes or replaces the file. Every other key Daedalus does not know is still refused, so a misspelled setting is still caught.

To change a setting later, type `/daedalus:setup` again. It starts from the values your files hold now. It asks only the first-day settings still at their default, and offers every other group. Each answer changes one setting and leaves the rest of the file as it was, byte for byte. Before it writes, it checks the whole file with the same check Daedalus runs when it reads that file. A value that check refuses is not written, and you see the check's own message. Each change prints one line: `changed:`, then the file, the setting, its old value and its new value. You can also edit a file by hand. The [examples folder](docs/examples/) holds the three files a new project gets, filled in, and one manifest and config pair with every override set. A test loads each one, so the examples always match what Daedalus accepts.

Every setting a file accepts can be set from the wizard. A setting inside a list, such as one coding rules entry, is set as the whole list that holds it.

A settings file written for an older version of Daedalus may hold names this version no longer reads. This version then refuses the whole file. The wizard shows a plan for that file and writes nothing yet. The plan has one `carry:` line for each value a new file would keep. A value is kept only when this version still has a setting of that name at the same place, and its check accepts the value. Old names are never renamed or guessed at. The plan has one `drop:` line for each old entry the new file would leave out, with its old value and the reason. A value that looks like a secret shows as `<value withheld>`, since a settings file should hold no secrets. The plan names the backup path too. The wizard asks you once whether to replace the file. When you say yes, it copies the old file byte for byte to that backup path under `/tmp/.daedalus/`. Then it builds the new file from the starter file and the kept values, checks it, and writes it. It prints a `replaced:` line. A file that is not valid JSON, or that is a link, is never replaced. Move such a file out of the project, and the wizard writes a new starter file. Your personal file is changed only when the wizard is on that file and you say yes.

Each settings file holds a `schema` number, which says which layout the file was written in. A file with no number is read as it always was. A release that changes a layout also ships a map from every earlier layout. When the wizard finds a file in an older layout, it shows the plan first. The plan lists each move, drop, new setting and conversion, step by step. It writes the file only after you say yes, and it copies the old file to a backup first. A file with a higher number was written by a newer plugin, and this version refuses it. Update the plugin in that case. The wizard never sets the number by hand.

The wizard never commits a settings file. A run can still start when `service-manifest.json` and `.claude/daedalus/config.json` are the only uncommitted changes. The run reads them from your working tree. Its pull request does not carry them unless you commit them yourself.

### Key reference

The table has one row per key Daedalus reads. Each row says what the key controls and what changes for you, whether it is a starter setting or an override, then its type, its allowed values, its default and an example value. A starter setting sits in the files `/daedalus:setup` writes. An override has a good default, stays out of those files, and is offered only when you walk its group. The table is generated from `scripts/lib/project_keys.py`, and a test fails when this copy goes stale. Commit `service-manifest.json`, because everyone who works on the project shares it. `config.json` never leaves your machine. A dotted key is a key inside an object, and `[]` marks a key inside each entry of a list.

Some keys and files have no row here, because no reader checks them: the unchecked manifest keys, `.gitleaks.toml`, `contracts/`, the standing-rules backfill file and a project train definition. [docs/project-requirements.md](docs/project-requirements.md) spells those out key by key.

The operator file is a third file in the table. It lives at `~/.claude/daedalus/operator.json` and holds your own settings for every project. A project can override single values with a `personal_overrides` object in its `config.json`. `/daedalus:setup` creates the operator file when you agree, and changes one value at a time when you answer. Nothing else in Daedalus writes it. Nothing acts on its values yet.

<!-- key reference -->
| Key | File | What it governs | What changes for you | Starter or override | Type | Allowed values | Default | Example |
|---|---|---|---|---|---|---|---|---|
| `schema` | `service-manifest.json` | The layout number of the project file; it tells Daedalus which version of the file layout the file was written in | Daedalus can upgrade an older file to the current layout, after it shows you the plan, and refuses a file written for a newer plugin. | starter | whole number | A whole number from 1 to the current layout number, which is 1 | no number: read as today | `1` |
| `commands.unit_test` | `service-manifest.json` | The commands that run the project's unit tests; a coding agent may run each exactly as written, as one command | A coding agent may run these test commands as written, inside the test wrapper. | starter | string, list of strings or null | A non-empty command string, a non-empty list of non-empty command strings run one after another, or `null`; a command holding a line break or other control character is refused | `null`: no declared command | `["python3 -m pytest -q"]` |
| `commands.typecheck` | `service-manifest.json` | The commands that type-check the project; a coding agent may run each exactly as written, as one command | A coding agent may run these type-check commands as written. | starter | string, list of strings or null | A non-empty command string, a non-empty list of non-empty command strings run one after another, or `null`; a command holding a line break or other control character is refused | `null`: no declared command | `["python3 -m mypy ."]` |
| `commands.lint` | `service-manifest.json` | The commands that lint the project; a coding agent may run each exactly as written, as one command | A coding agent may run these lint commands as written. | starter | string, list of strings or null | A non-empty command string, a non-empty list of non-empty command strings run one after another, or `null`; a command holding a line break or other control character is refused | `null`: no declared command | `["python3 -m ruff check ."]` |
| `docs.folder` | `service-manifest.json` | The project's docs folder; the decisions file and the decisions-in-force summary live in it unless `local_docs_folder` names a folder kept elsewhere | Decisions are written to the named file in this folder. | starter | string | A project-relative folder path without a leading slash, `..` or glob characters | `"docs"` | `"docs"` |
| `docs.decisions_filename` | `service-manifest.json` | The file in the docs folder where decisions are recorded; naming it turns recording on. Its layout, id pattern and numbering are read from the file itself, and a file that does not exist yet is created as a table when the first decision is recorded | A run records each decision in this file, or records none and asks nothing about it. | starter | string or null | A plain file name without a slash or glob characters, or `null` | `null`: no decisions are recorded, and a run has no decision step at all | `"decisions.md"` |
| `docs.reading_level` | `service-manifest.json` | How plainly Daedalus writes for people, as a reading level or a voice profile the project declares. The docs writer writes the public docs at the end of a run at this level, and a brief may override it. Every question Daedalus puts to you is written at this level. At `standard`, simple sentences a high schooler with no background in the project can follow. At `expert`, text that assumes you know the project. A voice profile, the old word `plain` and an unset key all read as `standard` for questions | The public docs, the decision briefs and the questions a run asks you are written at this reading level. | starter | string or null | `"standard"`, `"expert"` or `"profile:docs/voice-profile.md"`, a project-relative path to the profile file without a leading slash, `..` or glob characters | `null`: the writer keeps the register the public docs already use; every question is written at `standard` | `"standard"` |
| `docs.git_branch` | `service-manifest.json` | The branch the decisions file's checkout must be on; a decision written or a probe run on any other branch, or on a detached HEAD, is refused, and Daedalus never switches the branch itself | A decision written while the file's checkout is on any other branch is refused. | override | string or null | A branch name with no spaces; refused while `local_docs_folder` is set, because a run branches that folder as `daedalus/<run id>` | `null`: decisions are written on whatever branch the file's checkout is on | `"main"` |
| `checks.secret_scan` | `service-manifest.json` | Turns on the push step's gitleaks scan of the commits a push sends; with the scan on, the push stops when gitleaks is missing or finds a secret, and the doctor's gitleaks line is a `MISS` | The push step scans the commits it sends for secrets and stops on a hit. | starter | boolean | `true` or `false` | `false`: no scan, and gitleaks need not be installed | `true` |
| `checks.online_advisory_lookup` | `service-manifest.json` | Lets the auditor ask for security advisories on the web; the run sends its questions to the web researcher. With it off, the auditor judges from the lockfile and any advisory export the project supplies | The audit looks up security advisories on the web, or judges from the lockfile alone. | starter | boolean or null | `true`, `false` or `null`; only `false` turns the lookup off | `true`: the lookup is on | `false` |
| `checks.terraform_format` | `service-manifest.json` | Lets the auditor run `terraform fmt -check` on the Terraform files a change touches. With it off, the auditor judges by reading the files, and validate and its init are off too | The audit may run the Terraform format check on changed Terraform files, or only reads them. | starter | boolean or null | `true`, `false` or `null`; only `false` turns it off | `true`: `fmt -check` may run | `false` |
| `checks.terraform_validate` | `service-manifest.json` | Turns on the run's Terraform validate. The build phase downloads the providers once, outside the kernel wrapper, into a private folder the wrapper lets coders read, so that a coder's `terraform -chdir=<folder> init -backend=false -input=false -lockfile=readonly` needs no network. The run then validates each unit after its coder hands it in, and the merged result before the auditor starts, outside the wrapper, on a copy of the Terraform files; the auditor reads that result and runs no validate itself; `checks.terraform_format` set to `false` still turns all of it off | The run downloads the providers, validates each unit's Terraform before its verifier starts, and gives the auditor the merged result. | starter | boolean | `true` or `false` | `false`: nothing validates and the auditor marks that check N/A | `true` |
| `checks.release_banned_terms` | `service-manifest.json` | A file of terms, one per line, that the release step checks the release notes against; a hit stops the release and names how many terms it found, never the terms | The release step checks the release notes against your list of terms. | override | string or null | A project-relative path without a leading slash, `..` or glob characters, or `null` | `null`: nothing is checked | `"docs/banned-terms.txt"` |
| `prohibited_writes.paths` | `service-manifest.json` | Paths in your project no coding agent may write, on top of the paths Daedalus always protects | A coding agent is refused every write to these paths, and the health check counts them. | starter | list of strings | Project-relative paths with forward slashes and no leading slash, `..` or glob characters; a trailing slash covers the whole folder, and matching ignores case | `[]` | `["infra/", "scripts/release.sh"]` |
| `prohibited_writes.file_types` | `service-manifest.json` | File endings no coding agent may write | A coding agent is refused every write to a file with one of these endings. | starter | list of strings | Endings that each start with a dot and hold no slash or glob characters; matching ignores case | `[]` | `[".pem", ".tfstate"]` |
| `code_review_exemptions.folders` | `service-manifest.json` | Folders of asset files, such as models, textures, sounds and shaders, kept out of the diffs the verifier and the auditor read and out of the secret scan. A source file inside one, such as a `.py` or `.ts` file, is never kept out, and the doctor and the auditor report it | The checks and the secret scan skip asset files in these folders. | starter | list of strings | Project-relative folder paths of letters, digits, dots, dashes, underscores and slashes, without a leading slash, `..` or glob characters | `[]`: no folder is kept out | `["assets/", "public/models/"]` |
| `code_review_exemptions.file_types` | `service-manifest.json` | File endings kept out of those diffs and the secret scan wherever the file sits; matching keeps case | The checks and the secret scan skip files with these endings. | starter | list of strings | Endings that each start with a dot and hold only letters, digits, dots, dashes and underscores; a source ending such as `.py`, `.ts`, `.json` or `.env` is refused | `[]`: no ending is kept out | `[".glb", ".png", ".wav"]` |
| `code_review_exemptions.report_over_bytes` | `service-manifest.json` | The size above which a kept-out asset file is listed by name and size, so the judges know it changed; it never keeps out a file that is not an asset | The checks list each skipped asset file above this size by name and size. | override | integer or null | A whole number of at least 1, or `null` | `null`: no asset file is listed by size | `1048576` |
| `packages.allowed_installers` | `service-manifest.json` | The ecosystems whose frozen, scripts-off install a coding agent may run, such as `npm ci --ignore-scripts` or `uv sync --frozen --no-build`; every other install, update, add or resolve command stays refused for every agent | A coding agent may run a locked, scripts-off install for these ecosystems. | starter | list of strings | Each of `npm`, `python`, `cargo`, `go` at most once; `npm` covers npm, pnpm, yarn and bun, `python` covers pip and uv | `[]`: no agent runs any install | `["npm", "python"]` |
| `packages.minimum_age_days` | `service-manifest.json` | The youngest a package version a change adds or updates may be, in days since it was published; the auditor fails a younger version. A security fix this holds back is tracked as a risk, never exempted silently | The audit fails a package version published fewer than this many days ago. | override | integer | A whole number of 0 or more; below 7 it needs `packages.minimum_age_reason`, else the manifest is refused | `7` | `14` |
| `packages.minimum_age_reason` | `service-manifest.json` | Why the project sets the package age below 7 days; the doctor prints it | The health check prints this reason beside a lowered package age. | override | string or null | One printable line of at least 20 characters, or `null` | `null`: no reason, so the age may not go below the default | `"internal registry mirrors with its own quarantine"` |
| `run_output_priority.order` | `service-manifest.json` | Which concern wins when two conflict and no rule below matches, for every agent in a run, never the operator's own session | Every agent in a run settles a clash between two concerns by this ranking. | starter | list of strings | Each of `security`, `trust`, `operations`, `cost` exactly once, highest first | `run_output_priority: null`: none declared, and agents follow no project ranking | `["security", "trust", "operations", "cost"]` |
| `run_output_priority.rules[].between` | `service-manifest.json` | The two concerns a rule settles; rules are tried in order and the first match decides | A rule applies only to a clash between these two concerns. | starter | list of two strings | Two different names of `security`, `trust`, `operations`, `cost`; at most 32 rules | `rules` empty: no rule, so the order decides | `["security", "cost"]` |
| `run_output_priority.rules[].reasons` | `service-manifest.json` | Why the conflict arises; the rule matches only these reasons | A rule applies only when the clash arises for one of these reasons. | starter | list of strings | One or more of `certification`, `framework`, `best-practice`, `incident`, `shape`, `domain-separation`, `ownership`, `convenience`, `latency`, `margin`, `running-cost`, each once | Required in each rule | `["certification", "framework"]` |
| `run_output_priority.rules[].outcome` | `service-manifest.json` | What a matching rule does: a concern named here wins and the agent decides alone; `ask_me` puts the decision to you | A matching rule lets the agent decide alone, or puts the choice to you. | starter | string | One of `security`, `trust`, `operations`, `cost`, or `ask_me` | Required in each rule | `"ask_me"` |
| `run_output_priority.rules[].note` | `service-manifest.json` | The one line a choice record or a decision brief quotes when the rule applies | Choice records and decision briefs quote this line when the rule applies. | starter | string | One printable line of 1 to 200 characters | Required in each rule | `"a control a certification asks for wins over its running cost"` |
| `run_output_priority.principles[].name` | `service-manifest.json` | The name an agent cites when a decision rests on one of the project's principles | Agents cite the principle by this name when a decision rests on it. | starter | string | `P` followed by digits, unique in the list; at most 64 principles | `principles` empty: none declared | `"P1"` |
| `run_output_priority.principles[].category` | `service-manifest.json` | The concern a principle serves | The run's standards list the principle under this concern. | starter | string | One of `security`, `trust`, `operations`, `cost` | Required in each principle | `"security"` |
| `run_output_priority.principles[].text` | `service-manifest.json` | The principle itself, as one sentence a decision brief quotes | Decision briefs quote this sentence when a decision rests on the principle. | starter | string | One printable line of 1 to 300 characters | Required in each principle | `"Each tenant keeps its own key."` |
| `run_output_priority.agent_order.<name>` | `service-manifest.json` | A different order for one agent; rules and principles still apply to it | That one agent ranks the concerns in this order instead. | override | list of strings | Each of `security`, `trust`, `operations`, `cost` exactly once; `<name>` is a Daedalus agent file name other than `auditor`, which is refused | Absent: the agent follows `run_output_priority.order` | `{"coder": ["cost", "security", "operations", "trust"]}` |
| `local_testing.url` | `service-manifest.json` | The address of the site you host on your own machine for testing; the verify step asks you to open it, and Daedalus never starts, polls or fetches it | The verify step asks you to open this address after a change to web code. | starter | string | An `http` or `https` address on `localhost` or the IPv4 loopback address, with any port; any other host is refused | `local_testing: null`: no site is named | `"http://localhost:5173"` |
| `local_testing.instructions` | `service-manifest.json` | What you check on that site after a change to web code; your answer of pass, fail or skip goes into the change's evidence | The verify step asks you to check this on your site and records your answer. | starter | string | One printable line of plain words | Required once the group exists | `"The level loads and the player can move."` |
| `compliance_rules.folder` | `service-manifest.json` | The project folder that holds its own compliance rule sets; each subfolder holding a `pack.json` is one rule set | The audit also judges each change against the rule sets in this folder. | override | string or null | A project-relative folder path without a leading slash, `..` or glob characters, or `null` | `null`: only the rule sets Daedalus ships are read | `"compliance/rules"` |
| `compliance_rules.use_builtin` | `service-manifest.json` | Whether the rule sets Daedalus ships are read beside the project's own | The audit reads the rule sets Daedalus ships, or only your own and the named ones. | override | boolean | `true` or `false`; `false` reads only the rule sets under `compliance_rules.folder` and those named in `compliance_rules.extra_builtin` | `true`: the shipped rule sets that are on by default are read | `false` |
| `compliance_rules.extra_builtin` | `service-manifest.json` | Shipped rule sets that are off until a project names them, such as the cost-tier set; a named set is read even when `compliance_rules.use_builtin` is `false` | The audit also reads these shipped rule sets that are off by default. | override | list of strings | Rule set ids of lowercase letters, digits and hyphens, each named once | `[]`: only the shipped rule sets that are on by default are read | `["cost-tier"]` |
| `custom_workflows_folder` | `service-manifest.json` | The project folder that holds its own run definitions; a run definition is looked up there first, as `<folder>/<name>.json`, and then in the plugin's own folder | A run looks for its run definitions in this folder before the plugin's own. | override | string or null | A project-relative folder path without a leading slash, `..` or glob characters, or `null` | `null`: only the plugin's run definitions are used | `"runs"` |
| `code_areas` | `service-manifest.json` | The project's file areas by name; the plan phase pastes this object into the planner's prompt, and the planner cuts work along these areas | The planner cuts the work along these named areas of the project. | override | object of strings | Each key names an area, and each value is a project-relative path | Absent: the planner is told `none declared` | `{"handlers": "src/handlers/", "infra": "infra/"}` |
| `schema` | `.claude/daedalus/config.json` | The layout number of the checkout file; it tells Daedalus which version of the file layout the file was written in | Daedalus can upgrade an older file to the current layout, after it shows you the plan, and refuses a file written for a newer plugin. | starter | whole number | A whole number from 1 to the current layout number, which is 1 | no number: read as today | `1` |
| `local_docs_folder` | `.claude/daedalus/config.json` | A docs folder kept elsewhere on this machine, which may be its own git repository; when set, the decisions file and its summary live there in place of `docs.folder`, the contract and decision agents may write there, and a run branches it as `daedalus/<run id>` | Decisions are written in this folder kept elsewhere on this machine. | starter | string or null | An absolute folder path outside the project; a relative path, a symlink or a folder inside the project is refused | `null`: the project's own `docs.folder` is used | `"/work/decisions"` |
| `git_excluded_folders` | `.claude/daedalus/config.json` | Folders whose files must never reach git, GitHub or a redirect. A Daedalus agent is refused such a command in every session, and the main session is warned during a run. A document run records the resolved folders in its frozen sources file | Agents are refused any command that sends these folders to git, GitHub or a file. | starter | list of objects | `{"kind": "path", "path": "<folder>"}`, a folder with `<repo_root>` and `<charter_root>` (the local docs folder) filled in and a relative path read from the project root; or `{"kind": "gitignore", "match": "directories"}` (every folder git ignores) or `"match": "all"` (every ignored path); a folder holding a linked worktree is skipped | `[]`: no folder is excluded | `[{"kind": "path", "path": "<repo_root>/private/"}]` |
| `coding_rules[].folder` | `.claude/daedalus/config.json` | A folder of rule files every run reads as your coding rules | A run reads your coding rules from the rule files in this folder. | starter | string | A non-empty path, written absolute; an entry holds exactly one of `folder`, `file` or `builtin` | `[]`: no coding rules are read | `"/work/rules"` |
| `coding_rules[].file` | `.claude/daedalus/config.json` | One file every run reads as your coding rules | A run reads your coding rules from this one file. | starter | string | A non-empty path, written absolute | `[]`: no coding rules are read | `"/work/rules/python.md"` |
| `coding_rules[].builtin` | `.claude/daedalus/config.json` | A set of coding rules shipped with Daedalus | A run reads this set of coding rules that ships with Daedalus. | starter | string | The name of a folder under the plugin's `packs/` that holds a `rules.md`; any other name is refused | `[]`: no coding rules are read | `"baseline"` |
| `personal_overrides` | `.claude/daedalus/config.json` | This project's own values for keys of your personal file; a key set here replaces the personal file's value for this project, and a key left out inherits it | Daedalus reads this project's copy of the Self-Assessment and Developer Profile switches, the work classes, the class mapping and the context limit, and checks and keeps the rest for later. | starter | object | The keys of the personal file, checked the same way; any other key is refused | `{}`: the personal file's values stand | `{"reading_level": "expert"}` |
| `models.agents` | `.claude/daedalus/config.json` | Which model each catalog agent runs on, in place of the `model:` line of its agent file; a model a skill is given for one run still comes first. Inside a run the coding agent and the verifier of a unit take their model from the unit's class instead | Each agent you name runs on the model you give it instead of its own. | override | object | Keys are agent names the catalog lists; values are `"sonnet"`, `"opus"`, `"haiku"` or `"fable"`; any other name or value is refused | `{}`: every agent runs on its agent file's model | `{"planner": "sonnet"}` |
| `models.coder` | `.claude/daedalus/config.json` | The model a coding agent runs on for most units | Nothing acts on it yet: the class of each unit's work picks its coding agent's model. | override | string or null | `"sonnet"`, `"opus"`, `"haiku"` or `"fable"`, or `null`; any other value is refused | `null`: `"sonnet"` | `"opus"` |
| `models.plugin_file_coder` | `.claude/daedalus/config.json` | The model a coding agent runs on for a unit that changes a file under `agents/`, `skills/`, `hooks/` or `scripts/checks/`, or one of the three jail files | Nothing acts on it yet: the class of each unit's work picks its coding agent's model. | override | string or null | `"sonnet"`, `"opus"`, `"haiku"` or `"fable"`, or `null`; any other value is refused | `null`: `"opus"` | `"opus"` |
| `models.coder_after_rejection` | `.claude/daedalus/config.json` | The model a coding agent runs on for the fresh coding agent that takes over a unit after its second failed check | Nothing acts on it yet: the class of each unit's work picks its coding agent's model. | override | string or null | `"sonnet"`, `"opus"`, `"haiku"` or `"fable"`, or `null`; any other value is refused | `null`: `"opus"` | `"opus"` |
| `models.fable_available` | `.claude/daedalus/config.json` | Whether your plan offers the Fable model. When it does, the planner and the auditor run on Fable unless `models.agents` names them; every other agent keeps its own model | The planner and the auditor run on the Fable model when your plan offers it. | override | boolean or null | `true`, `false` or `null`; any other value is refused | `null`: Fable is used only when a running train's audit log shows this session started on it | `true` |
| `limits.parallel_coders` | `.claude/daedalus/config.json` | How many coding agents a parallel stage runs at once, and the cap on the plan width the plan validator prints | A run starts at most this many coding agents at once. | override | integer | A whole number of at least 1; `true` and `false` are refused | `5` | `3` |
| `limits.task_tokens` | `.claude/daedalus/config.json` | The most tokens one task may spend, its coding and checking agents together. The token report lists every task over it, and its gate form fails the audit phase's budget check | The token report flags each task over this budget, and the audit's budget check fails. | override | integer or null | A whole number of at least 1, or `null`; `true` and `false` are refused | `null`: no budget, and the gate never fails | `4000000` |
| `limits.log_retention_days` | `.claude/daedalus/config.json` | How many days a session's audit log is kept after its last record. When a new session starts writing, older logs are deleted, each named with its final record in the new session's own log. A log named on a run summary's `Session` line, the log of a run not yet merged, and the current session's log are never deleted | Session audit logs older than this are deleted when a new session starts writing. | override | integer or null | A whole number of at least 90, or `null` | `null`: every log is kept | `365` |
| `test_readable_folders` | `.claude/daedalus/config.json` | Folders outside the project that a test run under the kernel wrapper may read and run programs from, such as the pnpm package store or a Node.js install; the wrapper never lets it write there | Tests run inside the test wrapper may read and run programs from these folders. | override | list of strings | Absolute paths or paths starting with `~/`; a path that holds or sits inside a credential store, such as `~/.ssh`, is refused | `[]`: the wrapper reads only the project, the system folders and Python | `["~/.local/share/pnpm/store", "~/.nvm"]` |
| `policy.engine` | `.claude/daedalus/config.json` | The tool for a deterministic policy check on infrastructure changes; no run runs it yet | A run's opening lines name this tool; no check runs it yet. | override | string | `"cfn-guard"` or `"conftest"` | `policy: null`: none declared | `"conftest"` |
| `policy.path` | `.claude/daedalus/config.json` | The folder that holds your policy rules; no run reads it yet | A run's opening lines name this folder; no check reads the rules in it yet. | override | string | A non-empty path | Required once the group exists | `"/work/decisions/policy"` |
| `schema` | `~/.claude/daedalus/operator.json` | The layout number of the personal file; it tells Daedalus which version of the file layout the file was written in | Daedalus can upgrade an older file to the current layout, after it shows you the plan, and refuses a file written for a newer plugin. | starter | whole number | A whole number from 1 to the current layout number, which is 1 | no number: read as today | `1` |
| `hard_stops` | `~/.claude/daedalus/operator.json` | The warning classes your own session turns into refusals for itself. The file only lists them; nothing acts on the list yet | Nothing acts on it yet: your own session is still only warned. | starter | list of strings | Each of `commit_on_main`, `push_merged_branch`, `redirect_to_file`, `download_to_shell`, `credential_export`, `credential_read` at most once; any other name is refused | `[]`: your session is warned and never refused | `["commit_on_main", "credential_read"]` |
| `reading_level` | `~/.claude/daedalus/operator.json` | How plainly Daedalus writes for you, for every project that does not set `docs.reading_level` itself. Nothing acts on it yet | Nothing acts on it yet: Daedalus writes for you at the project's level. | starter | string or null | `"standard"`, `"expert"` or `"profile:docs/voice-profile.md"`, a project-relative path to the profile file without a leading slash, `..` or glob characters, or `null` | `null`: no personal level is set | `"standard"` |
| `no_long_dashes` | `~/.claude/daedalus/operator.json` | Whether Daedalus text for you avoids long dashes. Nothing acts on it yet | Nothing acts on it yet: Daedalus text keeps whatever dashes it has. | starter | boolean or null | `true`, `false` or `null`; any other value is refused | `null`: no personal choice is set | `true` |
| `guidance_source` | `~/.claude/daedalus/operator.json` | Where your working guidance is read from: Claude Code's own memory files, or a guidance folder Daedalus keeps beside this file. Nothing acts on it yet | Nothing acts on it yet: guidance is read where Claude Code reads it. | starter | string | `"claude"` or `"daedalus"` | `"claude"` | `"daedalus"` |
| `script_language` | `~/.claude/daedalus/operator.json` | The language you want new scripts written in, told to every agent as guidance. Nothing acts on it yet | Nothing acts on it yet: agents choose the language for each script. | starter | string or null | A lowercase language name such as `python`, or `null` | `null`: no language is preferred | `"python"` |
| `self_assessment` | `~/.claude/daedalus/operator.json` | Whether Self-Assessment mode is on. When it is on, Daedalus records its findings about its own skills, each a bug or a feature, and shows them at the close | Daedalus saves each finding outside your project. | starter | boolean | `true` or `false`; any other value is refused | `false`: Self-Assessment mode is off | `true` |
| `developer_profile` | `~/.claude/daedalus/operator.json` | Whether Daedalus keeps a Developer Profile of your past answers and choices, to propose better answers later | Daedalus saves your stated rules and answer tallies on your machine only. | starter | boolean | `true` or `false`; any other value is refused | `false`: no Developer Profile is kept | `true` |
| `work_classes` | `~/.claude/daedalus/operator.json` | The classes of work a run tells apart, each a name and a one-sentence definition. A project's config may set its own list under `personal_overrides`; that list wins for that project and may add, remove or change classes | Each unit of a run's plan names one of these classes, and the plan is refused when it names another. | starter | list of objects | `{"name": "<class>", "definition": "<one sentence>"}` entries, at most 64; a name is one line of 1 to 40 characters, unique ignoring case and not starting with an underscore; a definition is one line of 1 to 300 characters | Absent or `null`: the shipped classes, eighteen kinds of security work plus `Plumbing` and `Mechanical`; `[]` means no classes, so all work runs on `"sonnet"` | `[{"name": "Plumbing", "definition": "The work builds or changes none of the things another class names, including work that only uses one of them."}]` |
| `class_models` | `~/.claude/daedalus/operator.json` | Which model each class of work runs on; a class with no model here runs on `"sonnet"`. A project's config may set its own mapping under `personal_overrides`; that mapping wins for that project and may raise or lower any class | In a run, the coding agent and the verifier of each unit run on the model its class maps to. | starter | object | Keys are names the classes list holds; values are `"sonnet"`, `"opus"`, `"haiku"` or `"fable"`; any other name or value is refused | Absent or `null`: the eighteen security classes on `"opus"`, `Plumbing` on `"sonnet"` and `Mechanical` on `"haiku"` | `{"Plumbing": "sonnet", "Tokens": "opus"}` |
| `context_limit` | `~/.claude/daedalus/operator.json` | How many tokens a Daedalus agent's context may hold during a run. Past it the agent may only write its hand-off and hand back. A project's config may set its own value under `personal_overrides` | During a run, an agent whose context grows past the limit stops and hands its work on. | starter | integer or null | A whole number of tokens, 0 or more, or `null`; `0` and `null` turn the check off; a negative number, a fraction, `true`, `false` or a string is refused | `250000`: an agent past 250,000 tokens stops and hands off | `400000` |
<!-- end key reference -->

Uninstalling the plugin deletes its data folder by default. The findings that `self_assessment` saves live in that folder and go with it. The Developer Profile that `developer_profile` keeps lives in that folder too. It goes with the folder on an uninstall unless you use `--keep-data`. An uninstall run with the `--keep-data` option keeps the data folder.

## Safety model

Outside a train, Daedalus leaves your session and your repository alone, with three exceptions. Daedalus's own agents keep their own checks. A read or search of a credential file meets one check, which gives your session a note in its context and refuses an agent. Four of the plugin's own calls are approved by its hook, as the next paragraph says.

Daedalus's hook approves four of the plugin's own calls by itself, inside a train and outside one, so Claude Code does not ask you about them. Three are the calls to the findings script that start, save and show Self-Assessment findings. The fourth is the write of one hand-over file under `/tmp/.daedalus/`. That write is approved only while Self-Assessment mode is on. Nothing is approved when any Daedalus check refuses or warns about the call. A call that is not exactly one of those four shapes is handled as before. Your own ask and deny rules in Claude Code still win over this approval.

Outside a train, Daedalus writes no files and keeps no audit log in any repository, even one where a train ran before. The one exception is `/daedalus:setup`. It writes the settings files you agree to and changes the settings you answer. It also saves each question under `docs/.tmp/daedalus/` and checks it before you see it. The check refuses an id, and a web address that is not a site on your own machine.

Inside a train, the jail judges every tool call and the audit log records each step. A train works in three folders of your repository:

- `.claude/worktrees/` holds the unit worktrees.
- `.claude/daedalus/` holds the train's state and the audit log.
- `docs/.tmp/daedalus/`, which git ignores, holds the train's working files and summaries.

To have the plugin's hooks in some repositories only, enable the plugin at project scope in each of those repositories' `.claude/settings.json` (Claude Code's `enabledPlugins`), instead of for your user.

Each agent gets a short list of allowed tools. A tool not on its list is never offered to it. A PreToolUse hook is a check Claude Code runs before each tool call. Daedalus's hook, the jail, compares every call with that agent's rules and blocks anything outside them.

A coding agent may write only inside its own unit worktree. Even there it may never write to `contracts/`, `.github/`, `.claude/`, `service-manifest.json`, the decisions file, or the paths and file endings your repository lists under `prohibited_writes` in `service-manifest.json`.

At all times, every agent is refused a read or search of `~/.ssh`, `~/.aws`, `~/.gnupg`, `~/.config/gh` or `~/.claude/.credentials.json`. When your own session does it, the call runs with a note in its context and its transcript. The check follows links before it judges a path, so a link into one of those folders is refused the same way. Daedalus's own agents are always refused writing those paths with a file tool or naming them in Bash. While a train runs, your session is warned in its context when it does either.

An agent is also refused a read or write of a `.env` file, because such a file holds live keys such as a Stripe secret key. That covers `.env` and every `.env.<name>` in any letter case, such as `.env.local`. `.env.example` stays open, because it holds the variable names only. Listing files by name stays open. The check also refuses a folder-wide read when it finds a `.env` file anywhere under the folder, up to 24 folder levels down, skipping `.git` and `node_modules`. That covers a recursive grep, `rg --hidden`, an rg glob that names `.env`, `tar` and `cp -r`. It also covers the Grep tool when its glob names a `.env` file, or when it has no glob and git does not report the `.env` file as ignored. A folder with more than 100000 entries or more than 24 levels is refused too, because the check cannot rule out a `.env` file inside it.

A train never stops your session with a permission prompt. Every call of your own session runs. Your session is not held to the command tables that fence the agents. It gets a note only for these thirteen kinds of call:

- reading or searching a credential file, a `.env` file or the run's reply key;
- writing into the run's protected folder, `.claude/daedalus/` or the plugin's data folder;
- a push or a merge while a run is active, outside its release phase, by git or by gh;
- writing a credential file or a `.env` file;
- writing inside `.git`;
- writing into the main checkout while a run works in unit worktrees;
- starting an agent in a way that skips a rule the run checks;
- resuming an agent in a way that skips the run's unit check;
- sending a file from a folder the project excludes to git, GitHub or a file write;
- a command that could not be checked against the excluded folders, because their setting could not be read;
- signing a commit or a tag with your key;
- a git option that can run another program;
- a recursive delete from the root folder, your home folder or a folder above home.

The release phase records that it has started. A push or a merge after that runs with no note. Any other call runs with no note too. That includes a nested Claude session, a change on GitHub that is neither a push nor a merge, and a change to a variable such as `PATH`. It also includes a call that reaches the hook with no working folder; only the credential checks judge that call. A note starts with `Warning:`, says what the call does and why it matters, and ends with a `Next:` step. It never says the call was refused, because it was not.

While a train runs, agents from Claude Code itself or from other plugins may only read and search. Every other checked tool is refused, both in the train's repository and when they write into it from another one.

During a run, the jail first reads how full each Daedalus agent's context is, from the agent's own transcript. The limit is the `context_limit` setting. Past it, an agent that has the Write tool may make one call: a Write of its own hand-off file, `/tmp/.daedalus/<uid>/handoffs/<project key>/<agent id>.md`. An agent without the Write tool may make no call at all. Every other call is refused. The refusal names the hand-off path, or asks an agent without Write to put the hand-off in its reply. The agent then hands back with the last line `[STATUS: HANDOFF] path=<path>` or `[STATUS: HANDOFF] inline`. That one Write carries the plugin's approval, so it never waits on a permission prompt. When the size cannot be read, the call is refused and the reason is named. Three cases run instead, with a warning in the audit log: an agent's first call, before its transcript records any usage, an agent with no transcript of its own, such as a fork, and a call whose hook input carries no transcript path at all. When your personal settings file cannot be read, every call of an agent in a run is refused until you repair the file with `/daedalus:setup`. Your own session is never measured, and neither is an agent outside a run. A tool the plugin's hook does not watch never meets this check.

Run binding is best effort. A dispatch can be recorded only when all of these hold: the main session or an orchestrator starts a Daedalus agent; the jail lets the call run, with or without a warning; and the repository holding the dispatch's single `Worktree:` line, or else the folder the call is judged in, has an active run. A main-session dispatch whose `Worktree:` line names a folder in a repository with an active run is recorded from any session folder. A dispatch with no such line, from a folder with no run, is not recorded. A recorded agent is bound to that run and judged against it wherever the session moves; any other agent is judged by its own folder, as before run binding existed. A bound agent outside its run's repository must name every path absolutely. When waiting dispatches from two runs leave its run unclear, the agent is judged by its own folder instead. A coder started from a folder with no run is still bound to its run. Its writes in its unit are then refused, because the unit's own dispatch record is written only when the session folder is inside the run. To avoid this, start the work from inside the repository.

The jail hooks are the enforced boundary, and they judge each tool call before it runs. Code an agent runs inside a tool call, such as its tests, is the same exposure any developer accepts when using a model on their own machine. Daedalus asks every agent never to get around its boundaries. It does not try to control your environment.

A blocked agent sees a line starting with `daedalus-jail[<agent>]:`. The line says what was refused and what to do next. The hooks, not the agents, write each step to the audit log. No agent merges. Only the push agent pushes, and only inside a push run. You merge.

[docs/guardrails.md](docs/guardrails.md) pairs each of these promises with the mechanism that enforces it and the test that shows the mechanism exists.

With no declared standards, the Standards Packet, the list of your rules that apply to a task, is empty. The auditor then judges each unit against its contract only. The auditor still judges every train against the packs described under Control packs. To declare your standards, see [docs/project-requirements.md](docs/project-requirements.md). To start from a shipped set instead, declare the opt-in baseline rules, `{"builtin": "baseline"}` in `coding_rules`. They hold five baseline checks plus the Daedalus cloud security standards, written in Daedalus's own words. The doctor offers them while `coding_rules` is empty.

## How it works

This section is for readers who want the internals. It follows one tool call from Claude Code to its audit record, then one build run from the first command to the pull request. Each passage says what a piece is, what reads it and what it feeds.

### One tool call, end to end

Claude Code runs the hooks that `hooks/hooks.json` binds. Before a Bash, file, search, web, agent, message or MCP call, it runs `scripts/enforce_agent_jail.py` and passes it the call as JSON. That hook has a 10-second timeout. If it crashes or hangs, the call is refused. Input that is empty, unreadable or missing a tool name is refused too.

The script first decides whether the call belongs to a train. It walks up from the call's working folder to the project root. The root is the first folder holding `service-manifest.json` or `.claude/daedalus/`, or the main checkout when that folder is a linked worktree. With neither, the root is the git root. The script then looks for the train marker, `.claude/daedalus/train.active`, in that root. `scripts/lib/train_scope.py` names who meets the jail without a marker: every Daedalus agent, which arrives as `daedalus:<name>`. Your session, and agents from Claude Code itself or other plugins, meet the full jail only during a train.

With no marker, a call from your session or an outside agent takes a fast path, unless a path it names lies in a repository that has a marker. The fast path loads none of the jail's other code and runs one check: a read or search of a credential store refuses an agent and gives your session a note. Some Bash commands go to the full jail instead: one the script cannot split, one with more than 256 words, and one naming more than 16 repositories.

Otherwise the script loads the config and the jail code and judges the call:

- A Daedalus agent's call goes to the router, `scripts/lib/router.py`. The router reads the agent's file under `agents/` and runs each check its hooks block names. Then it runs the excluded-folders check that every routed agent meets.
- Your session's call goes to `scripts/lib/jail.py`. The jail never refuses your own session. It checks the call against the note table in `scripts/lib/session_notes.py`. A call that a row names runs with that note in the session's context. A command the jail's tables cannot read is read word by word for those rows alone, shell bodies and `find -exec` included.
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
- Notes in your session's context for the calls the note table names, as the Safety model section lists them.
- The audit log. Without a marker no hook writes a record. The first record in a new session log also runs log retention.
- The reply key, created with the first record that carries an agent's reply.
- The receipts check on a coding agent's report.
- The checks that read the running train's id: the coding agent's claim on its unit worktree, the working and audit folders other writers may write, the document train's output folder, the unit worktree a test run is bound to, the folder the dependency map may be written to, and the run binding of each Daedalus agent started during the run.
- The push and pull request gate, which reads the train branch and its recorded verdict through the marker.

Daedalus's own agents keep their checks with or without a marker.

### The audit log and the reply key

Each session gets one log, `<repo>/.claude/daedalus/audit/<session_id>.jsonl`, and only the hooks write it. `scripts/lib/audit.py` writes every record under a lock. Each record holds its sequence number `seq`, the hash of the record before it (`prev_hash`), and its own `hash` over the rest of the record. An edited, removed or reordered record breaks the chain. The chain verifier and the audit report recompute the chain before they read anything else. A bare command of your own session that starts with `cd <absolute folder> &&` or `cd <absolute folder> ;` is recorded in that folder's log when a train runs there. Any other target leaves the record in the session's own folder. Every record also holds `payload_cwd` and `binding`. When a run binding judged an agent in its run folder, `cwd` is that folder, `payload_cwd` is the folder Claude Code reported, and `binding` names the train, the repository, the worktree and how the agent was bound. The call that first binds an agent inside its own repository carries `binding` too. Otherwise both are null. These are the record types:

| Event | What the record holds | Who reads it |
|---|---|---|
| `SessionStart`, `UserPromptSubmit`, `Stop`, `SessionEnd` | The event, the session and its working folder, and for a prompt the redacted prompt text | The audit report |
| `PreToolUse` | The tool and its redacted input (a Read records only its path), the jail's decision (`allow`, `block`, or `warn` for a main-session call that ran with a note), the refusal, or for a note its check name, its class name, the note and the check's own finding, and the jail's own time in milliseconds | The hooks check, the summary's Blocks section, the control cost report, the push proof's summary anchor, and the wave merge and summary, which find each verifier dispatch by its `Unit worktree:` line |
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
- `units`, one entry per worktree with its `name`, `branch` and `path`, and `audit: true` on the audit worktree. `daedalus_train.py refuted` adds `refutations` to a unit: one audit record number per refuted verifier reply, and one text key per operator check you failed.
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

The bindings file, `<repo>/.claude/daedalus/trains/<train-id>.bindings.json`, keeps one coding agent per unit worktree. It holds one entry per unit worktree under `units`, and the train-wide `retired` list of coder ids, written under its own lock. Each entry moves through these steps:

1. Dispatch: when the orchestrator starts a coder with one `Worktree:` line, the dispatch gate records the unit with no agent yet. A second dispatch to the same unit is refused.
2. Claim: the coding agent's first write, or first git write, in that worktree binds the unit to its agent id. Every later write by that agent must stay in that worktree, and no other agent may write there.
3. Rebind: when the orchestrator resumes a coder with a new `Worktree:` line, the gate moves the coder to the new unit and records the old unit as `retired_to` the new one.
4. Finish: finish and the wave merge mark each merged unit `finished`, and a later write into it is refused.

The run binding store, `<cache>/run-bindings/<session-id>.json` under the plugin's data folder, ties a Daedalus agent your session or the orchestrator starts to a run. Run binding is best effort. A dispatch can be recorded only when all of these hold: the main session or an orchestrator starts a Daedalus agent; the jail lets the call run, with or without a warning; and the repository holding the dispatch's single `Worktree:` line, or else the folder the call is judged in, has an active run. A main-session dispatch whose `Worktree:` line names a folder in a repository with an active run is recorded from any session folder. A dispatch with no such line, from a folder with no run, is not recorded. A recorded agent is bound to that run and judged against it wherever the session moves; any other agent is judged by its own folder, as before run binding existed. Each recorded dispatch adds one waiting entry, holding that run's repository, its train id and the named worktree. The agent's first call takes the sole waiting entry of its type. When several waiting entries of its type belong to one run, each binds at the run's root, and the bindings file above still decides the worktree. When they belong to two runs, none binds, and the agent is judged by the folder Claude Code reports. A bound agent whose session sits outside its run's repository is judged in its run folder. It must then name every path absolutely, or start its command with `cd <its worktree> &&`. Its credential check runs at both folders. A coder started from a folder with no run is still bound to its run. Its writes in its unit are then refused, because the unit's own dispatch record is written only when the session folder is inside the run. To avoid this, start the work from inside the repository. An entry whose repository's marker no longer names its train never binds, and the next write of the store drops it. A malformed store binds nothing and is never rewritten; delete it from your own shell. Agents Daedalus did not start get no binding.

The writer record, `<repo>/.claude/daedalus/trains/<train-id>.writers.json`, holds the document kind of each writer, under its own lock. The writer is the one agent that writes documents, in one of two kinds. Each writer dispatch joins a queue with its kind: one `Worktree:` line naming the docs worktree is the public docs kind, and no `Worktree:` line is the derived kind, which needs the run's frozen sources file. A dispatch whose kind cannot be read joins with no kind. The orchestrator's dispatch joins only an empty queue and is refused otherwise. The main session's dispatch always joins, with a warning when a second dispatch now waits. A writer's first call takes the kind when exactly one dispatch waits, and binds it to the writer's agent id. From then on each of its calls meets the writer's own checks and the checks of its kind, never the other kind's. When two or more dispatches wait, every writer that has no kind yet is refused, because nothing tells which dispatch started it. To clear the queue, run `python3 <plugin>/scripts/daedalus_train.py writer-clear --repo <repo>` from your own shell or the main session; a stop and an unmark clear it too. A writer with no recorded kind is refused every call.

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

`python3 <plugin>/scripts/audit_report.py --session <id> --controls` reads the register for its Control cost section. That section lists the blocks and the warned main-session calls per check, and one `failure:` line for each check that blocked. The orchestrator reads that report at the end of a train. Each check that blocked and whose line reads `failure: none` comes to you as a question: keep it, redesign it or remove it. `tests/test_controls.py` fails when a hook script or a refusal constant has no row, a field is empty, a failure does not start with an id, a premise test does not exist, or a row names a constant its module no longer has.

### One train, end to end

1. Start. Your session runs `daedalus_workspace.py begin`. That command refuses a working tree with uncommitted changes. Only the two settings files may be changed or new, and not staged. Their contents are recorded, and each later merge step refuses them once they change. It writes the data folder and its `.gitignore`, the train state file and the train marker, then prints the first status lines. Next, `verify_audit_chain.py --hooks-live` finds its own command as the newest Bash record of this session's log and records the point the push proof reads. Your session starts one orchestrator agent and passes messages between it and you.
2. Standards and the map. The orchestrator writes the Standards Packet from your declared sources. Its fifth part is a `## Priorities` section, holding your `run_output_priority` group or the line `priorities: none declared`. The orchestrator runs `daedalus_map.py --repo <repo> --out <repo>/docs/.tmp/daedalus/<train-id>/map` to build a dependency map of your code, and records the sha256 of `map.json`. The jail refuses an `--out` outside that folder. The map skips every folder the `git_excluded_folders` key of `config.json` names, and exits 2 when those folders cannot be resolved.
3. Plan. The planner cuts the work into units. Each unit has a line in the plan block and a requirement section below it. `validate_plan.py` checks the file, and `daedalus_train.py plan` records its path and sha256 in train state.
4. Contract lock. The orchestrator first runs `daedalus_train.py contract --repo <repo>`. It prints `contract: skip` when the recorded plan has one unit and that unit meets every condition below. Otherwise it prints `contract: required (<reason>)`.
   - It changes at most 3 files.
   - No file is under `scripts/checks/`, `agents/`, `skills/` or `hooks/`.
   - No file is `scripts/lib/jail.py`, `scripts/lib/shell.py`, `scripts/enforce_agent_jail.py` or a protected path.
   - The plan has no pin line and has a `wire: none` line.

   The finish step then merges only a unit whose changes stay inside the plan's files. On a skip, no contract agent starts. `daedalus_workspace.py lock --no-contract` puts the integration branch `daedalus/<train-id>` at the base commit, commits nothing, and records the base as `lock_sha`. Each brief then carries `Contract: none`, and `daedalus_train.py plan` refuses a new plan for that train. Without a skip, the contract agent writes the Locked Contract Packet, and `daedalus_workspace.py lock` commits it on the integration branch and records `lock_sha`. A later contract revision leaves `lock_sha` at the first lock.
5. Units. A wave is a group of units built at the same time. For each wave, the orchestrator checks the tools the units list under `needs:` with `daedalus_doctor.py --check-tools`. For each unit it then runs `daedalus_workspace.py create`, writes the brief file, and starts a coder with the brief path and one `Worktree:` line. The dispatch gate checks the recorded plan and records the dispatch. The coder's first write claims the unit.
6. Report and verification. The coder ends its reply with a receipts block above its `[STATUS: COMPLETE]` line, and the receipts check reads that block. The orchestrator checks the reply's branch, its packet hashes and that the branch descends from the contract lock. The verifier then judges the unit's diff against its brief. The unit is ready to merge once its verdict is `[VERDICT: VERIFIED]`.
7. Merge. `daedalus_workspace.py finish` merges every unit into the integration branch with `--no-ff`. A train cut into waves merges each wave first with the wave merge command. A merge that fails is aborted, and the repository stays on `daedalus/<train-id>` with the merges that completed. The `Next:` line names the conflicting files. Merge that unit there by hand, then run the merge step again, which skips units already merged.
8. Audit. The security auditor also reads rulebooks picked by what the diff touches. It always reads the control packs, the shipped AWS and NIST packs or your own. It reads the dependency rules for a dependency manifest or lockfile, and the Terraform rules for a `.tf` or `.tfvars` file. The security auditor judges the merged tip in its own audit worktree, and `daedalus_train.py verdict` records its verdict. Each finding of a rejected round comes to you as its own question.
9. Ledger and docs. On an approved verdict, or once you exempted every finding, charter-docs commits the ledger entries to the decisions file the manifest names. With no decisions file named, this step records nothing and asks nothing. After an approval, the approved verdict is recorded next. The docs writer then brings the four public docs up to date in the docs stage.
10. Summary. `daedalus_train.py summary` writes the summary from train state and the audit log, and the orchestrator ends with `[STATUS: TRAIN_COMPLETE]`.
11. Push. `/daedalus:run push` marks the train again and runs the hooks check and the push proof. The push agent pushes the branch and opens the pull request. The push gate checks the verdict again on the push agent's own push. You review and merge.

### Requirement sections and needs

Each unit of a plan has a requirement section outside the plan block. The section opens with a heading `### <unit id>: <title>`. Somewhere under it, a line reading exactly `Requirements:` is followed by lines `1. <requirement>`, numbered from 1. Each requirement is one sentence ending in a period, and it names a backticked token or a path holding a slash. `scripts/lib/plan_record.py` reads the sections. `validate_plan.py` refuses a unit without a section, a list that breaks its numbering, and a requirement in another shape. The dispatch gate runs the same check before any coder starts. The orchestrator copies each unit's section into its brief, and the verifier counts one claim per numbered line.

A unit line may also carry `needs: <tool or protected path>[, ...]`. It lists the tools the unit's build needs, such as `mypy` or `.venv/bin/ruff`, and each protected file the unit needs changed. Before a wave starts, the orchestrator passes every tool need to `daedalus_doctor.py --check-tools <names> --repo <repo>`. That command prints `OK   tool <name>` or `MISS tool <name>` per name, and exits 1 on any MISS. Missing tools and protected-file needs reach you as one question per wave.

A unit line may also carry `class: <class name>`, `place: <file>:<named part>` and `class_reason: <one line>`. The class says what kind of work the unit is, from the work classes in your settings. A unit with no `class:` field is `Plumbing`. The place is a file from the unit's own `files:` list and the named part of it where the work happens, such as a function in code or a section in a document. The reason says in one line why the work has that class. `validate_plan.py --classes --repo <repo>` prints the classes your settings hold, with the project's override, and the planner gets that list. `validate_plan.py` checks the three fields against the classes of the repository `--repo` names, else of the repository that holds the plan file. It refuses a class the list does not hold, and a place whose file is not in the unit's list. It also refuses a class whose model ranks above the middle model when the unit names no place, and any class but `Plumbing` with no reason. `daedalus_train.py plan` runs the same class checks against the run's repository before it records a plan, and refuses with the same lines. A plan with none of the three fields never reads the settings. The plan table shows each unit's class and, for every class but `Plumbing`, its reason.

### The receipts check

`scripts/handback_check.py` runs on every SubagentStop and on every `SubagentHandback` tool call, during a train only. It judges three kinds of reply: a coder's reply whose last line is `[STATUS: COMPLETE]`, a judge's failing verdict, and any agent's hand-off. In a coder's COMPLETE reply, directly above that line it expects a `## Receipts` line, followed only by lines of six shapes:

- `- commit <40 hex> <subject>`
- `- test <command> => <last output line>`
- `- typecheck <command> => <last output line>`
- `- yield <kind> <question> => <who answered>`
- `- deviation <file or behaviour> | <reason>`
- `- hunt <form> => refused` or `- hunt <form> => admitted, fixed in <7 to 40 hex>`

At least one commit line and one test line must be there. A COMPLETE line that carries ` hunt=<n>` must place it directly before ` turns=<n>`, and n must equal the number of hunt lines in the block (227). A reply in another shape goes back to the coder with one `Next:` line naming the shape, before the verifier sees it. A verifier's `[VERDICT: REFUTED]` reply and an auditor's `[VERDICT: REJECTED]` reply must end every finding with ` | rule: <the rule broken> | places: <file>:<line or named part>[, ...] | search: <the command that found every place>`. A finding without them goes back to the judge with one `Next:` line. A passing judge hand-back leaves a pass marker under `/tmp/.daedalus/<uid>/handback-pass/`, so the judge's later stop that repeats the same last line is not judged twice. An auditor reply that lists fewer findings than the round's findings file goes back the same way, a count compared only when a finding line in the reply names the same round as that file. A check that cannot run never blocks the coder, and the verifier still judges the unit. `scripts/cite.py` prints the `file:line` of each line holding a fixed string, so a coder can paste a citation instead of retyping it.

A reply from any Daedalus agent whose last line starts with `[STATUS: HANDOFF]` is judged as a hand-off, before any other check. An agent with the Write tool must end with `[STATUS: HANDOFF] path=<path>`. The path must be its own hand-off file, and that file must be a regular file that is not empty. An agent without the Write tool must end with `[STATUS: HANDOFF] inline`, with a `## Hand-off` heading and at least one line under it above that line. A hand-off in another shape goes back with one `Next:` line. A hand-off leaves no pass marker.

### The verifier

The verifier judges each unit's diff against its brief, never against the coder's report. Its claims are the brief's numbered requirements, the unit's files list, the pins that name the unit, and the Standards Packet rules a changed line falls under. The dependency map adds two more kinds of claim. For each module the diff changes, `imports.<module>.fan_in` lists the modules that import it, and each must still get what it relied on. Each `duplicates` entry that overlaps the added lines must not repeat code the project already holds. Each refuted claim is a `code` row or a `scope` row. A `scope` row is a file outside the files list, or a behaviour change no requirement asks for, unless a `- deviation` receipt names it with a reason.

A receipt the branch contradicts, such as a wrong test count or commit subject, is corrected inside the verdict. It is counted on a `corrected=<k>` line above the closing verdict line. It never refutes the unit, and the coder is not resumed for it. Only `code` and `scope` rows send a coder back for a fix. On every refuted verdict, and on every operator check you fail, the run records one refutation on the unit with `daedalus_train.py refuted --repo <repo> --unit <unit id>`, which prints `refuted <unit id>: <count>`. The first and the second refutation go back to the unit's coder, on the unit's own model. The third comes to you as a question.

Inside a run, the unit's class picks the model for its coder and its verifier alike. `daedalus_train.py model --repo <repo> --agent coder --unit <unit id>`, or `--agent verifier`, prints the model the `class_models` setting maps the class of the unit's plan line to. A unit with no class is `Plumbing`. The second line reads `<agent> <unit id>: <model> | class: <class>`, with ` | class_reason: <reason>` when the plan line has one. The number of refutations never changes the model. The command refuses a unit the recorded plan does not name, a run with no recorded plan, a settings file it cannot read, and a class your settings no longer hold. An agent with no unit, such as the auditor or the planner, keeps the model `models.agents` and its agent file give it. The orchestrator runs finish only once every unit's verdict is `[VERDICT: VERIFIED] claims=<n>`. The wave merge command reads that last line itself, from the verifier's reply in the audit log. The summary's Verification section prints each unit's verdict line with its corrected count.

The orchestrator gives the verifier a `Read: <file>:<first>-<last>[, ...]` line, built from the diff's changed hunks and the map's importer lines. The verifier reads those ranges, and lists each other file it opens as an `extra read` row. It judges typecheck and lint receipts from the coder's receipts block and reruns only pytest. A brief whose contract line reads `Contract: none` has no contract pin to judge. A prompt whose first line is `CLAIMS MODE.` lists `Claim: <path>:<line> <claim>` lines instead of a brief, and the verifier checks only those lines. The docs stage and the document train use this form.

### Merges and fix units

`daedalus_workspace.py finish` merges every recorded unit except the audit worktree's, one `--no-ff` merge commit each. It skips a unit already on the integration branch. Each merge message reads `Merge <name> for train <train-id>`, where `<name>` is the worktree name without its `<train-id>-` prefix. The wave merge command, `python3 <plugin>/scripts/daedalus_workspace.py merge --repo <repo> --units <id>[,<id>]`, merges only the named units and leaves the train open for the next wave. It refuses a unit the recorded plan does not name. It also refuses a unit without a `[VERDICT: VERIFIED]` verifier reply for its worktree in the audit log.

A fix unit from an audit round, the worktree `<train-id>-fix<n>-<unit>`, joins the recorded plan first. The main session runs `daedalus_train.py fix-unit --repo <repo> --unit fix<n>-<unit> --title <title> --files <files> --fixes <unit id> --finding <finding key> --requirements <file>`, with one `--finding` per finding the unit answers, or one `--row <n>` per row of the fixed unit's newest refuted verifier verdict. The file holds one requirement line per finding or row. The command adds the unit line, a serial edge from each unit it fixes, the requirement section and a recomputed graph line. It validates the whole plan as the plan step does, records the new sha256, and prints `fix-unit <unit id>: fixes <unit ids> plan sha256=<hex>`. It refuses when the run records no plan, the id is already in the plan, a fixed unit is not, or a finding or row is not one the run recorded. It also refuses a plan that would not validate. A refusal leaves the plan file and its recorded hash as they were. Every unit command then takes the fix unit as a planned unit, the wave merge included. The summary and `daedalus_train.py state` name each fix unit and what it fixes.

A fix worktree made without `fix-unit` stays outside the plan, so the wave merge refuses it, and finish merges it on its next run. To merge such a unit by hand, run this from your own shell on the integration branch, with `<name>` the worktree name without its `<train-id>-` prefix. Finish then skips it:

    git merge --no-ff daedalus-unit/<train-id>-<name> -m "Merge <name> for train <train-id>"

### Exemptions, the docs stage and the extra judges

Each failing finding comes to you as one question. Its first line says what is at stake in one sentence, then asks. Two or three short sentences follow on what breaks and what happened in the test. The three choices are:

- `Fix it now (Recommended)` runs a fix round.
- `Skip, track or exempt it` exempts the finding.
- `Stop the run` ends the run.

No limit on rounds applies. The train never opens a fix round or stops on its own; you hold every one of those choices. An exemption brings a second question, how it is tracked: `Skip it` (dropped silently), `Track it` (a GitHub tracked-risk issue), `Exempt it` (the local ledger record alone), or your own answer. These are stored as `dropped`, `issue`, `local` and `other`. Your session records each exemption with `daedalus_train.py exception --repo <repo> --ledger-id <id> --finding <id> --tracking <dropped, issue, local or other>`. The command writes it in train state: under the round for a security finding, and in the docs record for a docs claim. The push proof reads it. The summary's Audit section prints each exempted finding with its tracking answer.

The docs stage runs after the security verdict is recorded, and the docs writer ends the train. The stage creates the worktree `<train-id>-docstage`, which the dispatch gate binds to the docs writer alone. The docs writer may write only the four public docs: `README.md`, `docs/howto/README.md`, `docs/guardrails.md` and `docs/project-requirements.md`. Its claims go to the verifier in claims mode. A claim that a check, gate or refusal exists needs its definition and a caller on the path it governs. The docs writer's receipt includes that caller search, and the verifier runs its own. A definition with no caller is an overstated claim. The verifier's dispatch names the docs branch head on a `Docs tip:` line. A verified reply merges the docs branch. Then `daedalus_train.py verdict --gate docs --status verified --judged <sha>` records the docs verdict in train state, with `<sha>` that docs tip. The command refuses a verified record without `--judged`, and refuses when the merged docs commits end at another commit. Each refuted claim comes to you as a finding. The summary's Audit section names the docs verdict, or `Docs: not run`.

The auditor reads two more rulebooks depending on what the diff touches. The dependency rules judge a changed dependency manifest or lockfile. The auditor asks for security advisories only through a web question, which the train sends to the web researcher. When `checks.online_advisory_lookup` is `false`, the train answers that question with "web lookup is off", and the auditor judges from the lockfile and any advisory export. The Terraform rules judge a changed `.tf` or `.tfvars` file. The audit phase looks `terraform` up on the session PATH with `daedalus_doctor.py --check-tools terraform` and passes `Terraform binary: present` or `Terraform binary: missing` to the auditor. With the tools on and the binary missing, the auditor writes TF-0 as FAIL and files it as a blocking finding. The auditor may run only `terraform fmt -check`, and not when `checks.terraform_format` is `false`. The jail refuses it `terraform validate` and `terraform init` in every form, bare or under the kernel wrapper. Either one can start a program from a `.terraform` folder of the tree it judges, and that program would run as you. When `checks.terraform_validate` is `true`, the audit phase runs `daedalus_train.py validate --merged` before the auditor starts. That command validates the merged branch outside the wrapper, on a copy, as the build phase does for each unit. Its printed lines go into the auditor's instructions as a script's result. The auditor judges the validate check from those lines. With the setting off, the auditor marks the validate check N/A. A finding test on a Terraform file reads it with the built-in Terraform reader, `scripts/lib/hcl_reader.py`, and never with a regex. Each FAIL row comes to you as a finding.

### Project priorities

The `priorities` block of `service-manifest.json` ranks four concerns: `security`, `trust`, `ops` and `cost`. It may add rules, principles and a ranking per agent (see the key reference above). The doctor prints `priorities: <ranking>, <n> rules` or `priorities: none declared`. The orchestrator writes the block into the Standards Packet's `## Priorities` section. Every agent of every train reads that section; your own session does not.

When two concerns conflict, the orchestrator tries the rules in order, and the first match decides. A rule ending in a concern settles the choice alone, and its choice record names the driver and the rule. A rule ending in `surface` puts the choice to you. A coder raises a default with `[STATUS: YIELD_STANDARDS] priorities rule <n>: ...`. A global rule or your answer outranks the ranking, and no rule lowers an audit finding's severity. The summary's Priorities section lists each decision a rule settled or put to you.

### The document train and excluded roots

`/daedalus:run doc <what, sources, folder>` derives a document from frozen sources, files whose contents are recorded so a change shows. `freeze_sources.py --train <id> --output-dir <folder> --source <alias>=<role>:<path>` records each source with its sha256 in `<repo>/.claude/daedalus/trains/<id>.sources.json`. `freeze_sources.py --verify <that file>` checks them:

- It exits 4 when a source changed.
- It exits 1 when the recorded output folder fails the output folder check, before it reads any output.
- It exits 5 when an output carries an en or em dash, placeholder copy, or a sentence copied from a style source that carries a number.

The writer and the comparer write only inside the output folder, which `scripts/checks/doc_outputs.py` checks. The verifier checks the writer's claims in claims mode. `/daedalus:round` keeps the record of one round of correspondence.

The `git_excluded_folders` key of `config.json` names folders whose files must never reach git, GitHub or a redirect. `scripts/checks/excluded_roots.py` runs for every Daedalus agent after its own checks. It refuses a git command that stages, commits or stashes a path inside such a folder, and a gh command or a redirect that names one. While any such folder is declared, it also refuses a command that sets `GIT_ICASE_PATHSPECS`. That variable makes git match paths in any letter case. An `:(icase)` or short `:i:` pathspec is refused before this check, because no command table admits it. So is `--icase-pathspecs` on any git command that is not a read. The writer and the comparer may redirect into such a folder, since their outputs live there. During a train your session is warned instead. `freeze_sources.py` records the resolved folders in the sources file.

### A run in a plain folder

Outside a git repository, `/daedalus:run` runs only the brainstorm, plan, document and verify phases, in your session, and no security audit runs. It asks where the run's outputs go: the project's `docs` folder, a new folder under `/tmp`, or a folder you name. Then it opens the run with `daedalus_workspace.py begin --repo <folder> --scope folder --out <outputs>`, which runs no git command. Begin refuses an output folder that is the project folder, one of its parents, your home folder or a folder under `.claude`. The planner writes its plan file and brainstorm spec straight into that output folder. The writer and the comparer write each derived document and change log there too. The write checks admit that folder only while the run that recorded it is active. Building, auditing and pushing need a git repository.

### The summary's path rule

The train summary becomes a public pull request body, so `scripts/lib/train_summary.py` lets no absolute path through. It first rewrites paths under the repository as relative paths, and paths under the Charter as starting with the Charter's folder name. Every other word holding a `/`, a `\` or a percent-encoded slash must then be a plain relative path inside the repository or the Charter. Each part of such a path is a plain ASCII name, with no `..`, `~`, `%`, `$`, `@`, scheme, drive, or leading or doubled slash. A path from the summary notes file that breaks this rule stops the summary, with a `Next:` line naming the path. A path from the audit log or train state, which nobody may edit, prints as `[path withheld]`, and the summary is still written.

### The kernel wrapper's grants

On a kernel with Landlock and seccomp, a coder's test command runs as `daedalus_confine.py --unit <worktree> -- <command>`, and the coder's confine check requires it. A test command is one the runner table names: `pytest`, `make`, `tox`, `nox`, `just`, `npx --no-install`, `uv run`, `go test` and `cargo test`. The wrapper applies its rules to its own process, then runs the command, and every child process inherits them. Nothing is installed, and the rules end with the process tree. It grants:

- Read and write: the unit worktree, a private temporary folder `daedalus-confine-<uid>/<hash>` under the system temp folder (mode 0700, owned by you), and `/dev/null`.
- Read only: every entry of the repository except `.claude/daedalus` and `.claude/worktrees`, never following a link; the running Python's prefixes and site-packages folders; and `/usr`, `/lib`, `/lib64`, `/lib32`, `/bin`, `/sbin`, `/etc`, `/proc`, `/sys` and `/dev`. A folder that holds or sits inside a credential store is left out.
- Network: a seccomp filter refuses a `socket()` call for every family except `AF_NETLINK`, `AF_UNIX` included, and refuses io_uring. A `socketpair()` call still works. On Landlock ABI 4 and later, TCP bind and connect are refused too.
- Environment: `TMPDIR` names the private folder, `GIT_CONFIG_GLOBAL` names an empty git config written fresh for each run, and `XDG_CONFIG_HOME` names an empty folder.
- Terraform: the wrapper runs the `terraform` the session PATH names. When that file lies outside every grant above, the wrapper grants read and run on that one resolved file, never its folder. A script shim outside the grants is refused with one line. `TF_DATA_DIR` names `tf-data/<16 hex>` in the private folder, one folder per `-chdir` folder, whatever the caller set. The init form empties that folder before it runs.
- Terraform providers: when `checks.terraform_validate` is true, the build phase runs `daedalus_train.py providers` once before the first coder starts. That command runs as you, outside the wrapper, and downloads providers into `/tmp/.daedalus/<uid>/provider-mirror/<project key>/<run id>/mirror`. It reads Terraform files only as they are at the commit the run started from. Changes an agent makes during the run never decide what it downloads. A Terraform folder is one holding a `.tf` file with a `provider` block or a `required_providers` block at that commit. The command skips `.git`, `.terraform`, `.claude`, links and your excluded folders. For each folder it writes a small copy holding only those provider entries and the folder's lock file, then downloads from that copy. A failed download prints a warning and the run goes on. When a coder needs a provider that commit does not name, the run asks you first. It names the provider and the host it comes from. Only after your yes does the main session run the command with `--allow` and that provider's address. The hook refuses `--allow` from every agent. During that run the wrapper grants read only on that one mirror folder, never the folders above it. It writes a Terraform CLI config `terraformrc` in the private folder and points `TF_CLI_CONFIG_FILE` at it. That config installs providers from the mirror alone and never from the network. The wrapper also drops `TF_PLUGIN_CACHE_DIR`. A mirror that is a link, is owned by someone else, can be written by group or others, or resolves outside the run's folder is not granted, and the wrapper's first line says why.
- Terraform validate: a coder and the auditor never run `terraform validate`, and the auditor never runs `terraform init`. Under the wrapper it cannot work, because Terraform talks to each provider program over a local socket the wrapper refuses. After a coder hands a unit in, the build phase runs `daedalus_train.py validate` on that unit. That command runs as you, outside the wrapper. It reads the unit's `.tf` files and lock file from the unit branch's last commit through git, never from the worktree on disk. It copies them into a new folder under `/tmp/.daedalus/<uid>/terraform-validate/<project key>/<run id>`, one folder per Terraform folder the unit changed. It copies no `.terraform` folder, no `.tfvars` file, no `.terraformrc`, no script and no link. The copied lock file keeps each provider's version and drops its checksums, so a lock written on another machine does not fail. Terraform gets a config that installs providers from the run's mirror alone, with the network path turned off. Its data folder, its home folder and its config sit in the copy folder, and it gets no `PATH`, no proxy, no token and no `TF_CLI_ARGS` value. Each Terraform process, and each provider it starts, gets at most 8 GiB of memory and five minutes. Init never downloads a module. A module in a local folder of the repository is copied too, and the command writes Terraform's module list itself. A module from a registry, git, a web address or a path outside the repository leaves its folder not validated, and the line names the source. A provider the mirror lacks leaves its folder not validated, and the run asks you, as for the fetch. A failed validate goes back to the unit's coder once, with Terraform's error summaries and file lines only. Before the auditor starts, the audit phase runs the same command with `--merged` on the merged branch, and the auditor reads its lines. When a branch holds any file inside a `.terraform` or `terraform.d/plugins` folder, the command prints one warning line naming it, because Terraform starts programs from those folders. It never copies or runs such a file, and the run goes on. The command removes the copy folder when it ends.

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
│   ├── auditor.md
│   ├── charter-docs.md
│   ├── coder.md
│   ├── comparer.md
│   ├── contract-spec.md
│   ├── orchestrator.md
│   ├── planner.md
│   ├── releaser.md
│   ├── verifier.md
│   ├── web-researcher.md
│   └── writer.md
├── docs/
│   ├── examples/                    # one filled-in copy of each settings file
│   ├── guardrails.md                # each principle with its mechanism and test
│   ├── howto/README.md              # operator guide
│   └── project-requirements.md      # every file Daedalus reads, with examples
├── hooks/
│   └── hooks.json                   # enforcement and audit bindings
├── packs/
│   ├── baseline/rules.md            # opt-in baseline and cloud security standards pack
│   ├── dependencies/                # npm and Python dependency rules the auditor reads by diff content
│   ├── frameworks/aws-default/      # AWS hardening control pack the auditor reads by default
│   ├── frameworks/nist-distilled/   # NIST SP 800-53 control pack the auditor reads by default
│   └── judges/                      # frameworks, Terraform and dependency rulebooks the auditor loads
├── scripts/                         # Python 3.12, stdlib only
│   ├── checks/command_allowlist.py  # every Bash segment runs a command the --allow list names
│   ├── checks/confine.py            # a coder's test command starts with the kernel wrapper
│   ├── checks/controls/             # the failure each control prevents and its premise test
│   ├── checks/credential_paths.py   # refuses a path or command that names a credential store
│   ├── checks/dispatch_gate.py      # the orchestrator's coder dispatch and plan gates
│   ├── checks/doc_outputs.py        # document agents write only in the train's output folder
│   ├── checks/excluded_roots.py     # git, gh and redirects never take a file from an excluded root
│   ├── checks/gh_classes.py         # the gh deny classes; the releaser's gh rules
│   ├── checks/git_grammar.py        # each git segment fits the grammar of its grant
│   ├── checks/git_push.py           # refuses remote git; the releaser pushes the train branch only
│   ├── checks/network_tools.py      # refuses web tools and network commands without a grant
│   ├── checks/read_only_bash.py     # every Bash segment is a read-only command or git read
│   ├── checks/root_writes.py        # writes land only under the named path classes
│   ├── checks/shapes.json           # the hooks each agent shape carries
│   ├── checks/shell_tripwires.py    # the worker shell model and its tripwires
│   ├── checks/tool_bound.py         # refuses a tool the agent file does not list
│   ├── checks/unit_writes.py        # the coder writes only in its own unit worktree
│   ├── checks/workspace_integrity.py # refuses writes into .git and the data folder
│   ├── lib/__init__.py
│   ├── lib/admit.py                 # admits a parsed command only in a shape its agent's tables list
│   ├── lib/agent_files.py           # reads agent files and their hooks blocks
│   ├── lib/agent_models.py          # the model each agent runs on: override, config, agent file
│   ├── lib/assets.py                # the asset exclusion the judges' diffs and the secret scan copy
│   ├── lib/atomic.py                # the one atomic writer and create-once writer
│   ├── lib/audit.py                 # hash-chained append, redaction
│   ├── lib/audit_proof.py           # the hooks-live and approved-verdict proofs
│   ├── lib/audit_rounds.py          # the auditor's finding list and the round number
│   ├── lib/briefs.py                # decision briefs checked at the manifest literacy level
│   ├── lib/config.py                # config.json loading and validation
│   ├── lib/context_size.py          # reads a subagent's context size from its own transcript
│   ├── lib/controls.py              # loads the controls fragments
│   ├── lib/credential_paths.py      # the credential-path deny every agent meets
│   ├── lib/developer_profile.py     # keeps the Developer Profile rules and tallies
│   ├── lib/dispatch_binding.py      # coder dispatch, warm rebind and first-write claim
│   ├── lib/fable.py                 # whether Fable is available: config first, then the session record
│   ├── lib/fetch.py                 # GitHub-only download, size cap and cache lock for refreshes
│   ├── lib/findings.py              # the finding store: start, save and show for Self-Assessment
│   ├── lib/gh_policy.py             # the gh commands each agent may run
│   ├── lib/handoff.py               # the context limit: the hand-off path and the one call past it
│   ├── lib/hcl_reader.py            # the built-in Terraform reader finding tests import
│   ├── lib/git.py                   # the one git runner: timeout and redirect scrub
│   ├── lib/hook_io.py               # hook input and output for the check scripts
│   ├── lib/human_text.py            # counts the plain words in operator lines
│   ├── lib/inventory.py             # FILES: every path the plugin can write, for --print-files
│   ├── lib/jail.py                  # per-agent tool policy
│   ├── lib/ledger.py                # ledger resolution, sequence read, entry format
│   ├── lib/locks.py                 # the one FIFO-safe lock opener and bounded lock
│   ├── lib/manifest.py              # the one reader of service-manifest.json
│   ├── lib/narrow.py                # narrows parsed JSON values to typed values
│   ├── lib/operator_file.py         # reads the user-level operator file and its project override
│   ├── lib/packs.py                 # loads and checks framework control packs
│   ├── lib/passes.py                # writes and checks the operator's one-time pass for a refused command
│   ├── lib/plan_record.py           # loads and validates plan records
│   ├── lib/plugin_approvals.py      # the plugin's own approval list the jail hook reads
│   ├── lib/project_keys.py          # every manifest and config key, its reference row, and the starter files
│   ├── lib/project_root.py          # finds the project root
│   ├── lib/provider_mirror.py       # fetches Terraform providers into the run's mirror, which the wrapper grants
│   ├── lib/question_path.py         # stores and checks a conversation's path of questions
│   ├── lib/redact.py                # secret masking for audit records
│   ├── lib/reply_digest.py          # saves a hand-back as a report file and builds its digest
│   ├── lib/repo_root.py             # finds a train marker before other lib modules load
│   ├── lib/router.py                # runs each agent's calls through its hooks
│   ├── lib/scrub.py                 # reads the declared scrub file's terms
│   ├── lib/self_assessment.py       # the Self-Assessment flag and its two folders
│   ├── lib/session_notes.py         # the note table: what earns your session a note
│   ├── lib/session_reading.py       # reads an untyped command's words for the note table
│   ├── lib/settings_edit.py         # changes one key of a settings file in place
│   ├── lib/settings_replace.py      # carries an older settings file's still-valid values forward
│   ├── lib/settings_maps.py         # the schema number's upgrade maps and the chain
│   ├── lib/shell.py                 # the shell model the jail and checks share
│   ├── lib/shparse.py               # parses one Bash command into nodes with spans
│   ├── lib/storage.py               # the temporary and persistent folders every feature uses
│   ├── lib/tf_validate.py           # validates a unit's Terraform outside the wrapper, on a copy of its last commit
│   ├── lib/train_definition.py      # loads and validates train definitions
│   ├── lib/train_runner.py          # the train state machine behind daedalus_train.py
│   ├── lib/train_scope.py           # the train scope the jail's entry script reads first
│   ├── lib/train_state.py           # one state file per train
│   ├── lib/train_summary.py         # the train summary, written from state and the audit log
│   ├── lib/unit_binding.py          # one coder per unit worktree
│   ├── lib/user_keys.py             # the rule that a key starting with an underscore is the user's own
│   ├── lib/work_classes.py          # the shipped classes of work, their models and the class lookup
│   ├── lib/workspace.py             # unit worktrees and the train marker
│   ├── lib/writer_mode.py           # the kind each writer's dispatch recorded
│   ├── append_ledger.py             # locked, sequence-checked ledger writer
│   ├── audit_log.py                 # all other hook events to the audit log
│   ├── audit_report.py              # digest of a verified session log
│   ├── brainstorm_check.py          # checks the brainstorm's board, brief, turn log and open risks
│   ├── catalog.py                   # prints the agent table and hooks matrix
│   ├── cite.py                      # prints file:line for each line holding a fixed string
│   ├── daedalus_claims.py           # prints the verifier's claim ranges from a branch in one call (0230)
│   ├── daedalus_confine.py          # kernel wrapper: a coder's test command stays in its worktree, no network
│   ├── daedalus_doctor.py           # first-run check behind /daedalus:doctor
│   ├── daedalus_findings.py         # start, save and show for Self-Assessment findings
│   ├── daedalus_map.py              # the dependency map: imports, coverage, record readers, ownership, duplicates
│   ├── daedalus_path.py             # the question path store's open, check, ask and regenerate commands
│   ├── daedalus_profile.py          # the Developer Profile store's status, rule, tally, list and forget commands
│   ├── daedalus_setup.py            # the settings wizard's describe, create, set and replace forms
│   ├── daedalus_train.py            # the train runner: progress, choice, plan, verdict, exception
│   ├── daedalus_workspace.py        # begin, lock, create, remove, finish, stop, resume, mark, unmark, release, pr-body
│   ├── enforce_agent_jail.py        # PreToolUse policy
│   ├── freeze_sources.py            # freezes and verifies a document train's sources
│   ├── handback_check.py            # hand-back check of a coder's receipts and a judge's findings
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
│   ├── catalog/SKILL.md             # /daedalus:catalog
│   ├── document/SKILL.md            # the document phase, in two modes
│   ├── document/kinds/              # the writer's kind skills: public docs and derived
│   ├── doctor/SKILL.md              # /daedalus:doctor
│   ├── plan/SKILL.md                # /daedalus:plan, the plan phase
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
