<!-- Copyright (c) 2026 Brad Duhon. SPDX-License-Identifier: GPL-3.0-or-later -->
# Daedalus

## What Daedalus is

Daedalus is a Claude Code plugin that runs a team of AI agents through trains, which are fixed sequences of steps. Every coding agent works from the same locked contract, a written spec of the interfaces its code must follow, fixed before coding starts. Each agent also works inside a jail, a set of rules that blocks anything outside its job.

Tool calls land in a hash-chained audit log. Each record carries the hash of the one before it, so an edited or removed record breaks the chain.

## What you need

Daedalus is developed on Linux. macOS is untested.

| Tool | Version | How to get it |
|---|---|---|
| Python | 3.12 or newer | Your system's package manager |
| Claude Code | Developed against 2.1.280 | Claude Code's own install instructions |
| git | any | Your system's package manager |
| bubblewrap (binary `bwrap`), for the sandbox, optional; the Push Train needs it | any | Package `bubblewrap` |
| socat, for the sandbox, optional; the Push Train needs it | any | Package `socat` |
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

Every `MISS` line ends with a `Next:` instruction that says what to do. In a new repository, three lines read `OPT` until you add the files they name: `service-manifest.json`, `contracts/` and `.gitleaks.toml`. `OPT` marks an optional scaffold your project declares about itself. Neither the Build Train nor the Push Train stops when they are absent, and they never fail the doctor. [docs/project-requirements.md](docs/project-requirements.md) lists every file Daedalus expects, says what each is for, and gives a small example of each.

### Turning on the sandbox

The doctor's `sandbox` line reads `on`, `off` or `configured-unavailable`. The last means your settings turn the sandbox on but `bwrap` or `socat` is missing. When a settings file it reads is not valid JSON, the line reads `MISS sandbox: <path> is not valid JSON (...). Next: fix <path>` instead. While the sandbox is not on, each new session starts with that same line.

Daedalus runs without the sandbox. The Build Train records the sandbox state in its summary. It stops before its security audit when the sandbox is not on and a unit touched IAM, KMS, mTLS, key custody or infrastructure config. The Push Train refuses to run until the sandbox is on.

To turn it on, install bubblewrap and socat, then type:

    /daedalus:setup

Setup refuses while either tool is missing, writes nothing, and prints what to install: the apt line on Debian and Ubuntu, the package names elsewhere. Otherwise it adds the sandbox settings, the credential deny rules and two prompt cache settings to this repository's `.claude/settings.local.json`, and to no other file; run it once in each repository you use Daedalus in. It first checks that git ignores that file, and writes nothing until it does. It adds keys you lack and deny entries you lack, and never changes a value you already set. It prints the change, then `Restart Claude Code to apply`. It rewrites the file as JSON with a 2-space indent. Setup runs only when you type the command; Claude never starts it on its own.

## The three trains

### Build Train

The Build Train splits a task into units. It gives each unit to a coding agent in its own worktree, which is a separate checkout of your repository. The train creates each worktree itself and removes it when the train ends. A security audit runs before the units are merged into a local branch named `daedalus/<train-id>`. The Build Train never pushes.

Before you start, you need:

- a decision ledger, which is a file where your project records its design rulings; declare one or let the train find it or ask to create one
- a clean working tree
- the sandbox on, when the task touches IAM, KMS, mTLS, key custody or infrastructure config
- optionally, `<repo>/.claude/daedalus/config.json` (see [docs/project-requirements.md](docs/project-requirements.md)); without it the defaults apply

Then type the command and your task:

    /daedalus:build-train Add a --verbose flag to the command-line tool

### Push Train

The Push Train commits, scans for secrets with gitleaks, pushes, and opens the pull request for a finished Build Train. Your repository needs a GitHub remote named `origin`, and `gh` must be signed in to it. The sandbox must be on. The conductor, the agent named pr-train-conductor, does the pushing. You review and merge.

    /daedalus:push-train

### Execution Train

The Execution Train has no command. It is your own manual checks on live or staging systems. AI agents never take part in it, and a later release adds a readiness checklist for it.

### Audit report

To read what every agent did in a session, open its audit report:

    /daedalus:audit-report

## The agents

Each agent's file lists the only tools it may use.

| Agent | Model | Tools | Job |
|---|---|---|---|
| contract-spec | sonnet | Read, Grep, Glob, Write, Edit | Writes and updates the service contracts before coding starts. |
| charter-docs | sonnet | Read, Grep, Glob, Write, Edit, Bash | The only writer of the decision ledger; commits Build Train results. |
| repo-coder | opus | Read, Write, Edit, Bash, Glob, Grep | Writes code and unit tests for one work unit in its own worktree. |
| web-researcher | haiku | WebSearch, WebFetch, Read | Looks up external documentation and returns short facts. |
| nist-specialist | sonnet | Read, Grep, Bash | Checks designs and diffs against a pinned NIST SP 800-53 catalog. |
| cis-specialist | sonnet | Read, Grep, Bash | Checks cloud setup and server settings against the CIS Benchmark files you add. |
| standards-rules-specialist | sonnet | Read, Grep, Glob | Reads your declared standards and answers questions about them. |
| security-auditor | opus | Read, Grep, Glob, Bash | Reviews each unit's code for security flaws before the local commits are final. |
| pr-train-conductor | opus | Bash, Read, Glob, Grep | Commits, pushes, opens pull requests, and watches CI. Never merges. |

## Files Daedalus creates

`<repo>` is the main working tree of the git repository you started Claude Code in.

| Path | When | Why |
|---|---|---|
| `<repo>/.claude/daedalus/.gitignore` | The first hook runs | Holds `*` so git ignores the whole directory |
| `<repo>/.claude/daedalus/audit/<session_id>.jsonl` | Every session | The hash-chained audit log for that session |
| `.claude/daedalus/ledger-locks/` in the repo that holds the ledger | A ledger entry is appended | Locks so two writers never change the ledger at once |
| `<repo>/docs/.tmp/daedalus/` | A Build Train starts | Scratch files and the train summary, ignored by git |
| `<repo>/.claude/daedalus/train.active` | A Build Train or Push Train starts | Marks a running train; removed when the train ends or stops |
| `<repo>/.claude/worktrees/<train-id>-<unit-slug>` | The Build Train starts a unit | The coding agent's worktree, on branch `daedalus-unit/<train-id>-<unit-slug>`; removed when the train ends or stops, and the branch is kept |
| `<repo>/.claude/worktrees/.gitignore` | The first unit worktree is created | Holds `*` so git ignores every worktree there |
| `<repo>/docs/decisions.md` | You answer "create" to the Build Train's ledger question | A new ledger holding only a table header |
| `contracts/<name>.md` | The contract is locked | The contract every coding agent works from, committed on the train's branch |
| Rows in your decision ledger | An approved Build Train ends | One entry per ruling, appended through `append_ledger.py` |
| `<cache>/frameworks/<family>/` | You run `refresh_frameworks.py` | The pinned framework files and their manifest |
| `<repo>/.claude/settings.local.json` | You type `/daedalus:setup` | The sandbox, credential deny and cache settings, merged into the repo's own; Daedalus never writes user-level settings |

You write `<repo>/.claude/daedalus/config.json` yourself when you need it. It is optional and Daedalus never writes it (see Configuration below for the fields).

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

## Safety model

Each agent gets a short list of allowed tools, and a tool not on the list is never offered to it. The OS sandbox, once `/daedalus:setup` turns it on, limits what Bash can write and which hosts it can reach. A PreToolUse hook is a check Claude Code runs before each tool call. Daedalus uses one, the jail, to compare every call against that agent's rules and block anything outside them. A coding agent may write only inside the `src/` and `tests/` directories of its own unit worktree. Every agent, and the main session, is refused `~/.ssh`, `~/.aws`, `~/.gnupg`, `~/.config/gh` and `~/.claude/.credentials.json`, whether it reads, searches or writes them with a file tool or names them in Bash. While a train runs, agents from Claude Code itself or from other plugins are refused every checked tool except reads and searches, in the train's repository and when they write into it from another one. While a train runs, the main session's Bash commands must be plain: no command substitution, backticks, ANSI-C quoting, shell functions, eval, builtin, variables the jail cannot resolve, or archive and copy tools the jail does not model. The jail is a policy over each tool call's arguments and judges a Bash command by its text, so the OS sandbox is the only boundary against shell forms the jail does not model and against code a coding agent writes and then runs, such as its tests. A blocked agent sees a line starting with `daedalus-jail[<agent>]:` that says what was refused and what to do next. Hooks, not agents, write each step to the hash-chained audit log. No agent pushes except the conductor inside the Push Train, and no agent merges. You merge.

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
├── settings.recommended.json        # sandbox, credential deny and cache settings that /daedalus:setup merges
├── agents/
│   ├── charter-docs.md
│   ├── cis-specialist.md
│   ├── contract-spec.md
│   ├── nist-specialist.md
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
│   ├── lib/redact.py                # secret masking for audit records
│   ├── lib/sandbox_state.py         # sandbox state: on, off or configured-unavailable
│   ├── lib/settings_merge.py        # additive settings merge behind /daedalus:setup
│   ├── lib/workspace.py             # unit worktrees and the train marker
│   ├── append_ledger.py             # locked, sequence-checked ledger writer
│   ├── audit_log.py                 # all other hook events to the audit log
│   ├── audit_report.py              # digest of a verified session log
│   ├── daedalus_doctor.py           # first-run check behind /daedalus:doctor
│   ├── daedalus_setup.py            # sandbox settings merge behind /daedalus:setup
│   ├── daedalus_workspace.py        # create and remove unit worktrees; mark the running train
│   ├── enforce_agent_jail.py        # PreToolUse policy
│   ├── refresh_frameworks.py        # operator-run: compile the pinned framework caches
│   ├── sandbox_notice.py            # SessionStart sandbox line
│   └── verify_audit_chain.py        # recompute and verify a session's hash chain
├── skills/
│   ├── audit-report/SKILL.md        # /daedalus:audit-report
│   ├── build-train/SKILL.md         # /daedalus:build-train
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
