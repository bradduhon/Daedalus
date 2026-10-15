<!-- Copyright (c) 2026 Brad Duhon. SPDX-License-Identifier: GPL-3.0-or-later -->
# Daedalus

## What Daedalus is

Daedalus is a Claude Code plugin that runs a team of AI agents through trains, which are fixed sequences of steps. Every coding agent works from the same locked contract, a written spec of the interfaces its code must follow, fixed before coding starts. Each agent also works inside a jail, a set of rules that blocks anything outside its job.

Tool calls land in a hash-chained audit log. Each record carries the hash of the one before it, so an edited or removed record breaks the chain.

## What you need

Daedalus is developed on Linux. macOS is untested; there the doctor reports `bwrap` missing.

| Tool | Version | How to get it |
|---|---|---|
| Python | 3.12 or newer | Your system's package manager |
| Claude Code | Developed against 2.1.280 | Claude Code's own install instructions |
| git | any | Your system's package manager |
| bubblewrap (binary `bwrap`), for the sandbox | any | Package `bubblewrap` |
| socat, for the sandbox | any | Package `socat` |
| gitleaks, for the Push Train | any | https://github.com/gitleaks/gitleaks#installing |
| gh, the GitHub CLI, for the Push Train | any | Install it, then run `gh auth login` |

## Install

Clone Daedalus anywhere:

    git clone https://github.com/bradduhon/Daedalus.git

Install bubblewrap and socat first. The settings file below sets `sandbox.failIfUnavailable` to `true`. Without both tools, Bash stops working in every Claude Code session on this machine.

Then open `settings.recommended.json` in the clone. Copy each top-level key you do not already have into `~/.claude/settings.json`. This file turns on the OS sandbox. It sets the subagent spawn depth to 1, so an agent cannot start agents of its own. It also sets `worktree.baseRef` to `head`, which the Build Train needs. Restart Claude Code after merging.

Now start Claude Code inside your own project, with the path to the clone:

    claude --plugin-dir /path/to/Daedalus

Every Daedalus command acts on the repository you started Claude Code in.

## First run

Inside the session, type:

    /daedalus:doctor

The doctor lists every file and tool Daedalus needs. Each `OK` line is a check that passed. Each `MISS` line names what is missing. Running the doctor changes nothing. Fix the `MISS` lines and run it again.

Every `MISS` line ends with a `Next:` instruction that says what to do. [docs/project-requirements.md](docs/project-requirements.md) lists every file Daedalus expects, with a small example of each.

## The three trains

### Build Train

The Build Train splits a task into units. It gives each unit to a coding agent in its own worktree, which is a separate checkout of your repository. A security audit runs before the units are merged into a local branch named `daedalus/<train-id>`. The Build Train never pushes.

Before you start, you need:

- `<repo>/.claude/daedalus/config.json` (see [docs/project-requirements.md](docs/project-requirements.md))
- a decision ledger, which is a file where your project records its design rulings; declare one or let the train find or create it
- a clean working tree
- `worktree.baseRef` set to `head`, from `settings.recommended.json`

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
| `<repo>/.claude/worktrees/` | A Build Train starts | One worktree per coding agent, removed when the train ends |
| `contracts/<name>.md` | The contract is locked | The contract every coding agent works from, committed on the train's branch |
| Rows in your decision ledger | An approved Build Train ends | One entry per ruling, appended through `append_ledger.py` |
| `<cache>/frameworks/nist/` | You run `refresh_nist_oscal.py` | The pinned NIST catalog and its manifest |

You write `<repo>/.claude/daedalus/config.json` yourself; Daedalus never writes it (see Configuration below for the fields).

### The NIST and CIS cache

`<cache>` is a directory whose name depends on how you installed Daedalus. Print it with:

    python3 /path/to/Daedalus/scripts/daedalus_doctor.py --print-cache-dir

Exit 1 means no cache exists yet; run `/daedalus:doctor` inside Claude Code once.

The nist-specialist needs the NIST catalog, in NIST's OSCAL JSON format. Without it, the specialist stops the train with `CACHE_INVALID`. Fetch it from your own shell:

    python3 /path/to/Daedalus/scripts/refresh_nist_oscal.py

CIS Benchmark files are licensed, so you place them by hand in `<cache>/frameworks/cis/`. Next to them you write a `manifest.json` with one entry per file, holding its name and its `sha256sum` hash. The exact format is in [docs/project-requirements.md](docs/project-requirements.md), under "CIS benchmarks".

## Configuration

Every file and setting Daedalus reads is described, with a small working example, in [docs/project-requirements.md](docs/project-requirements.md). The full operator guide is [docs/howto/README.md](docs/howto/README.md). It covers each train step by step, how to read a block message, and how to read an audit report.

## Safety model

Each agent gets a short list of allowed tools, and a tool not on the list is never offered to it. The OS sandbox limits what Bash can write and which hosts it can reach. A PreToolUse hook is a check Claude Code runs before each tool call. Daedalus uses one to compare every call against that agent's rules and block anything outside them. A blocked agent sees a line starting with `daedalus-jail[<agent>]:` that says what was refused and what to do next. Hooks, not agents, write each step to the hash-chained audit log. No agent pushes except the conductor inside the Push Train, and no agent merges. You merge.

With no declared standards, the Standards Packet is empty and the auditor judges each unit against its contract only. The NIST and CIS specialists review only units that touched IAM, KMS, mTLS, key custody or infrastructure configuration. To declare your standards, see [docs/project-requirements.md](docs/project-requirements.md).

## What is in this repo

```
Daedalus/
├── .claude-plugin/
│   └── plugin.json                  # plugin id: daedalus
├── .gitignore
├── LICENSE
├── README.md
├── pyproject.toml                   # dev tooling; the plugin itself is stdlib only
├── settings.recommended.json        # sandbox, cache TTL, spawn depth, worktree baseRef
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
├── scripts/                         # Python 3.12, stdlib only
│   ├── lib/__init__.py
│   ├── lib/audit.py                 # hash-chained append, redaction
│   ├── lib/config.py                # config.json loading and validation
│   ├── lib/jail.py                  # per-agent tool policy
│   ├── lib/ledger.py                # ledger resolution, sequence read, entry format
│   ├── lib/locks.py                 # bounded flock shared by audit and ledger writers
│   ├── lib/redact.py                # secret masking for audit records
│   ├── append_ledger.py             # locked, sequence-checked ledger writer
│   ├── audit_log.py                 # all other hook events to the audit log
│   ├── audit_report.py              # digest of a verified session log
│   ├── daedalus_doctor.py           # first-run check behind /daedalus:doctor
│   ├── enforce_agent_jail.py        # PreToolUse policy
│   ├── refresh_nist_oscal.py        # operator-run: pull and pin the NIST OSCAL catalog
│   └── verify_audit_chain.py        # recompute and verify a session's hash chain
├── skills/
│   ├── audit-report/SKILL.md        # /daedalus:audit-report
│   ├── build-train/SKILL.md         # /daedalus:build-train
│   ├── doctor/SKILL.md              # /daedalus:doctor
│   └── push-train/SKILL.md          # /daedalus:push-train
└── tests/                           # the pytest suite
```

## License

Daedalus is licensed under the GNU General Public License v3.0 or later. See LICENSE.

## Developing Daedalus

    pip install -e '.[dev]'
    pytest
    ruff check scripts tests
