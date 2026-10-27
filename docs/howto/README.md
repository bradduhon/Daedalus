<!-- Copyright (c) 2026 Brad Duhon. SPDX-License-Identifier: GPL-3.0-or-later -->
# Daedalus: operator guide

This guide is for someone who has never used Daedalus. Each section says what to type, what you will see, and what to do if you do not see it.

## What Daedalus does

Daedalus is a Claude Code plugin. It gives your session a set of agents, each with one job, and seven phase skills that a run combines. A run that builds code is called a train in branch names, file names and messages. Here is what Daedalus does for you:

- It keeps each agent inside a jail. Before every tool call, a PreToolUse hook checks the call against that agent's rules and blocks anything outside them.
- It refuses every agent's reads of your credential stores, through file tools and the Bash commands it understands. When your own session reaches for one, the call runs with a warning in the session's context and in your transcript. You are never prompted.
- While a train runs, it writes an audit log of every tool call the hook sees: Bash, file reads, searches and edits, web fetches, agent starts, messages and MCP tools. Each record carries the hash of the one before it. Editing a record, or removing one from the middle, breaks the chain.
- `/daedalus:doctor` checks your setup.
- `/daedalus:audit-report` shows a readable digest of one session's log.
- `/daedalus:catalog` lists the agents and the seven phases.
- `/daedalus:plan` splits a design spec into units, each a piece of work for one coding agent.
- `/daedalus:run` starts a run. Your session starts one orchestrator agent, which gives each unit to a coding agent in its own git worktree. Agents put their questions to specialist agents. The units merge onto a local branch, and an adversarial security audit judges the merged result.
- `/daedalus:run push` commits, pushes and opens the pull request for a finished build run. You review and merge.

## Install

Inside any Claude Code session, type:

    /plugin install daedalus --marketplace bradduhon/Daedalus

Where it runs: any Claude Code session, version 2.1.275 or later. Check yours with `claude --version`. Daedalus is verified on Claude Code 2.1.280.

What you will see: Claude Code asks you to confirm the marketplace, then to pick a scope. Pick "Install for you".

If it fails: when your Claude Code does not accept `--marketplace`, run these two commands from a shell instead, then start Claude Code:

    claude plugin marketplace add bradduhon/Daedalus

    claude plugin install daedalus@daedalus

Every Daedalus command acts on the repository you started Claude Code in. The audit log records only while a train runs in a repository.

## First run

Inside the session, type:

    /daedalus:doctor

The doctor lists every file and tool Daedalus needs, and whether each is present. It changes nothing. `docs/project-requirements.md` describes every file it checks, each with a small example.

Here is the output of a real run in a new repository with one empty commit, no `service-manifest.json` and no `config.json`. The machine had gitleaks installed, gh signed in, a framework cache, and a kernel that can hold the kernel wrapper's rules. `CLAUDE_PLUGIN_DATA` was set, as it is inside a Claude Code session. Your paths differ. `<repo>` stands for your repository, `<cache>` for the plugin's data folder, and `<plugin>` for the plugin root:

    OK   python >= 3.12
    OK   project data dir: <repo>/.claude/daedalus (not created yet; a train's start creates it)
    OK   audit log: off until a train runs here
    OPT  config.json: not present, defaults in use. Next: run the Daedalus setup skill (/daedalus:setup) to write a starter config.json
    OK   ledger: none found (the Build Train asks before creating docs/decisions.md)
    OPT  standing_rules: not declared. Next: set standing_rules in .claude/daedalus/config.json to the standing-rules file, so the planner reads it
    OPT  standards_sources: no standards file or pack is declared. Next: to adopt the shipped baseline pack, add {"kind": "pack", "name": "baseline"} to standards_sources in .claude/daedalus/config.json
    OK   policy: not declared (optional)
    OK   train marker: none
    OK   cache dir: CLAUDE_PLUGIN_DATA=<cache>
    OK   plugin root: <plugin>
    OK   frameworks nist: pinned 2026-10-19
    OK   framework pack aws-default: 1.0.0, 34 controls
    OK   framework pack nist-distilled: 1.0.0, 27 controls
    OK   gitleaks on PATH
    OK   gh on PATH
    OK   gh authenticated
    OK   kernel rules: Landlock ABI 3 and the seccomp socket filter on x86_64; coder test commands run under the kernel wrapper
    OK   git repository
    OK   clean working tree
    OPT  service-manifest.json: not found at repo root. Next: run the Daedalus setup skill (/daedalus:setup) to write a starter service-manifest.json
    OK   priorities: none declared
    OPT  contracts/: directory missing. Next: mkdir contracts and add openapi.yaml or events/*.schema.json
    OPT  .gitleaks.toml: not found at repo root. Next: copy the baseline from docs/project-requirements.md
    daedalus doctor: all checks passed

Each line starts with one word:

- `OK` is a check that passed.
- `MISS` names what is missing, and after `Next:` says what to do about it. Fix each `MISS` line and run the doctor again.
- `OPT` marks an optional file your project declares about itself. A build run and a push run both work without it, and it never fails the doctor.
- `OLD` marks a framework cache or a control pack more than 90 days old. It never fails the doctor.

The doctor exits 0 when every check passes and 1 otherwise. Its last line reads `daedalus doctor: all checks passed`, or `daedalus doctor: fix each MISS line, then rerun` when a check failed. After the output, the doctor skill asks you once which `Next:` actions to take: all, the numbers you pick, or none.

Some lines need a word of explanation:

- In a new repository, the `config.json`, `service-manifest.json`, `contracts/` and `.gitleaks.toml` lines read `OPT` until you add those files. The `Next:` lines for the first two say to run `/daedalus:setup`, which writes a starter copy of each. `docs/project-requirements.md` has an example of every file.
- The `standing_rules` line reads `OPT` until `config.json` names a standing-rules file, the rules every plan must satisfy, which the planner reads.
- The `standards_sources` line reads `OPT` until you declare a standards source. Its `Next:` offers the baseline pack that ships with Daedalus. Taking it is your choice.
- `train marker: none` means no train is running in this repository.
- `priorities: none declared` means the manifest has no `priorities` block. With one, the line prints the ranking and the number of rules.
- The `kernel rules` line says whether this kernel can hold the kernel wrapper's rules, which keep a coder's test command inside its worktree and off the network. On a kernel that cannot, the line reads `OPT  kernel rules: not available on this kernel`, and coder test commands are refused.
- The gitleaks line is a `MISS` when gitleaks is missing and the secret scan is on. With the scan off, a missing gitleaks reads `OPT`.
- When gh is not signed in, the `gh authenticated` line is a `MISS`, and its `Next:` says to run `gh auth login`.
- When the working tree is not clean, the `clean working tree` line names up to ten changed paths, then `+N more`. When the only change is the `.claude/settings.json` that `/plugin install` wrote, its `Next:` says to commit that file.
- Once the `.claude/daedalus/` directory exists, the doctor also checks that `.claude/daedalus/.gitignore` holds a `*` line and that git ignores the directory.
- The `cache dir` and `plugin root` lines are for your information and never a `MISS`. When more than one `~/.claude/plugins/data/daedalus*` directory exists, the cache dir line names each one. The plugin root is the directory the commands in this guide call `<plugin>`.
- Once a framework cache holds a `manifest.json`, one line per family follows the plugin root line, as `OK   frameworks nist: pinned 2026-10-19` does in the example. When the oldest file in that family was pinned more than 90 days ago, the line reads `OLD  frameworks nist: pinned 2026-06-01 (137 days). Next: refresh the framework caches with python3 <plugin>/scripts/refresh_frameworks.py`. For CIS, the `Next:` says instead to build a CIS id-map pack with `import_pack.py cis-map` per docs/project-requirements.md.
- After those lines comes one line per control pack the next train reads. A control pack is a list of security controls a change is judged against. A pack that loads prints `OK   framework pack <id>: <version>, <n> controls`, like the two shipped packs in the example. Each problem prints `MISS framework pack <id>: <problem>. Next: <action>`. A missing or linked `frameworks.pack_dir` folder prints `MISS framework packs: <problem>`. A pack more than 90 days old prints `OLD  framework pack <id>: pinned <date> (<days> days). Next: <action>`. A `MISS` pack line fails the doctor.
- A `github` key left in the features object of `service-manifest.json` has no effect. The doctor prints one `OPT` line saying so.

Outside a git repository, the project is in folder scope. Only a repository can be pushed, so the `git repository` line and the two gh lines read `OPT`. With the secret scan on, the gitleaks line reads `OPT` too.

## Where things live

| Thing | Path | Who writes it |
|---|---|---|
| Audit logs, one per session | `<repo>/.claude/daedalus/audit/<session_id>.jsonl` | hooks only, and the jail refuses tool writes there |
| Plugin config, optional | `<repo>/.claude/daedalus/config.json` | you, from your own shell, when you need it |
| Machine caches (NIST, OWASP) | `${CLAUDE_PLUGIN_DATA}`, under `~/.claude/plugins/data/` | the plugin's refresh scripts |
| Your own control packs, optional | each subfolder of the `frameworks.pack_dir` folder in `service-manifest.json` | you, with `scripts/import_pack.py` from your own shell |
| Build run working files and summary | `<repo>/docs/.tmp/daedalus/` | the build run; a `*` marker inside keeps it out of git |
| Running-train marker | `<repo>/.claude/daedalus/train.active` | each train, removed when it ends or stops |
| Train state and unit bindings | `<repo>/.claude/daedalus/trains/<train-id>.json` and `<train-id>.bindings.json` | the train's scripts only, under a lock |
| Coder worktrees | `<repo>/.claude/worktrees/<train-id>-<unit-slug>` | the build run, removed when it ends or stops |

`<repo>` is the main working tree of the git repository you started Claude Code in. Every worktree of that repository shares the one `.claude/daedalus/` directory. Outside a git repository, `<repo>` is the starting directory itself.

The build run's start writes `.claude/daedalus/.gitignore` with a single `*` line. So git ignores the directory, and your own `.gitignore` is untouched. Outside a train, no hook writes anything into the repository. While a train runs, the jail also refuses any `git add` or `git commit` that names `.claude/daedalus`.

Each audit record holds a `result_head` field with the start of the tool's output. It is capped at 4096 characters, not bytes.

Uninstalling the plugin leaves the audit logs and config in the repository. A copy of each log's final hash should live outside this machine, so a deleted or altered log can be detected. Daedalus does not make that copy yet.

## Reading a block message

When Daedalus refuses an action, you see a line like this:

    daedalus-jail[repo-coder]: write outside your unit worktree: /work/repo/infra/x.tf. Next: ask the orchestrating session to route this to contract-spec or charter-docs.

The name in brackets is the agent that was blocked. The part before `Next:` says what was refused and why. The part after it says what to do instead. The orchestrating session is the Claude Code session you are talking to, not the plugin.

## Reading an audit report

Inside the session, type:

    /daedalus:audit-report

With no argument, it reports the newest session log for this repository, which is usually the session you are in. To report an older one, pass its id: `/daedalus:audit-report <session>`. The ids are the file names in `<repo>/.claude/daedalus/audit/`, without `.jsonl`.

The report checks the log's hash chain first. Only an intact chain gets a digest. The digest has eight parts:

- Header: the session id, the number of records, the hash of the last record (`head=`), and the repository the session ran in.
- Subagent timeline: one row per agent, with the record number where it started and stopped. `open` in the stop column means the log holds no stop record for that agent.
- Write, Edit and Bash calls: per agent type and tool, how many calls the jail allowed and how many it blocked.
- Blocks: every refused action, one line each.
- Control cost: blocks per check and agent type, the failure each blocking check prevents, the seconds each block cost the agent, the seconds each agent took to its first write, and the mean time the jail took to judge a call.
- Status lines: every `[STATUS: ...]`, `[VERDICT: ...]` and `[STANDARDS: ...]` line an agent reported.
- Totals by event: how many records of each hook event the log holds.
- Token economy: for each run the session holds, its token totals row and its mean per unit, the same rows `/daedalus:token-report` prints. The last group, run type `session`, holds the agents the main session started outside any run. A session whose agent transcripts are gone shows one line saying so.

A block line reads like this:

    - seq 3 repo-coder Bash: no remote git operations in the Build Train. Next: commit locally; the Push Train pushes.

`seq 3` is the record number in the log. `repo-coder` is the agent that was refused, and `Bash` is the tool it tried. The rest is the refusal the log stores. The agent saw the same text with a `daedalus-jail[<agent>]:` prefix. Every refusal ends with the `Next:` the agent was given. Characters such as brackets are shown with a backslash before them, so they do not act as Markdown. Text an agent wrote is shown escaped, so a link or tag in it appears as plain text and does nothing.

### When the chain is BROKEN

Instead of a digest, you see one line like this:

    audit_report: BROKEN line 7: hash mismatch

The log changed after it was written: a record was edited, removed or reordered. Line 7 is the first line of the file that fails the check. A broken chain is itself the finding, so no digest is shown. Do three things: keep the file, report it, and do not edit it. Editing the file destroys the evidence. To rerun the check by hand, where `<plugin>` is the plugin directory:

    python3 <plugin>/scripts/verify_audit_chain.py <repo>/.claude/daedalus/audit/<session>.jsonl

For an intact log it prints `OK: <n> records, chain intact, head=<hash>`. Otherwise it prints the same line as the report, without the `audit_report:` prefix, for example `BROKEN line 7: hash mismatch`.

### Saving the report

When the optional `<repo>/.claude/daedalus/config.json` sets `charter_root`, the skill asks whether to render the report again and save it to `<charter_root>/audit/<session>.md`. A live session gains a few records between the two renders, so the saved file can hold more than the screen showed. If `<charter_root>/audit` does not exist yet, the skill offers to create it. Say yes, and the file is written there for the charter-docs agent to commit in a later build run. Say no, or leave `charter_root` unset, and the digest stays on screen only.

You can also write the report yourself, from the repository directory. Create the folder first:

    mkdir -p docs/.tmp

Then:

    python3 <plugin>/scripts/audit_report.py --session <session> --out docs/.tmp/<session>.md

The file is written with mode 0600, so only your user can read it. Run `chmod` on it if others need to read it. The script refuses two kinds of path, and each refusal ends with a `Next:` line:

- Any path inside a `.claude/daedalus/` directory, in this repository or another one. The audit logs live there, and a report must never overwrite one.
- A path that is a symlink. The script never writes through a link. Pass the real file path instead.

It also refuses a path that names a directory, a path whose parent directory does not exist, and `--out -`. To print to the screen, leave out `--out`.

### Reading a token report

To see what a run cost in tokens, type `/daedalus:token-report <run id>` with a train id, or `/daedalus:token-report <session>` for every run in one session. It reads the transcripts Claude Code keeps for each agent. It prints one table in fixed columns: run type, run id, phase, agent, unit or round, turns, input, output, cache write, cache read and wall time.

Each run ends with a totals row, a mean per unit and a mean per audit round. The mean per unit counts the coding agents only, as the earlier hand counts did. The checking agents stay in the totals row. A session report ends with a `session` group: the agents the main session started outside any run, one row each with its own totals. The main session's own tokens are left out, so the totals cover the agents only. No column is in dollars. A value a run type does not have prints `none`. Every run type uses the same columns, so a build run, a push run and a plan run compare side by side.

After a run's table, the skill offers to save it: to `<charter_root>/reports/<date>-tokens-<run id>.md` when `charter_root` is set, and to `docs/.tmp/daedalus/<run id>/tokens.md` otherwise. `/daedalus:token-report history` prints the totals row of every saved run. The audit report prints the same totals rows after its own totals.

## Running a build

Start from a clean working tree, on the branch you want to build from. Type the command and the task in your own words:

    /daedalus:run Add a /healthz endpoint that returns the build version

Where it runs: a Claude Code session started inside the target repository. `<repo>/.claude/daedalus/config.json` is optional (see `docs/project-requirements.md`). Run `/daedalus:doctor` first if you have not.

Read the catalog once first with `/daedalus:catalog`. A one-line task needs no file, because the run saves the words you type as the spec. A spec is a file in your repository that says what to build and how you will know it works. For bigger work, the next two sections show how to start from an idea and how to split a spec into units before you build.

### Starting from an idea

With only an idea and no spec, type `/daedalus:brainstorm` and the idea, or the path of a notes file. The planner agent answers in numbered rounds. Each round lists contradictions, gaps and proposals, each tied to a sentence you wrote. You answer in your own words. When the idea settles, the planner writes a spec draft under `docs/.tmp/daedalus/brainstorm-<YYYYMMDD>/`. Move it to where your project keeps its specs, and say the spec stands. The same planner then cuts the plan, as in the next section.

### Splitting the work first

When the work spans more than one unit, split its spec into units first. Type `/daedalus:plan` and the spec's path:

    /daedalus:plan docs/specs/healthz.md

The planner agent writes a plan file. The plan validator checks it and prints `OK plan: graph: units=<n> critical_path=<k> width=<w> overlap_only=<pairs>`. Your session then shows a unit table with the columns Unit, What it builds, Starts from, Waits on and Shares files with. Each row is one coding agent's work. Waits on names the units that must finish first. Shares files with names the units that edit the same files, and the order they merge in. Outside a train the plan lands at `docs/.tmp/daedalus/plan-<YYYYMMDD>.md`.

Then start the run with that plan file, as the plan step's `Next:` line says:

    /daedalus:run <plan path>

Your session hands the file to the orchestrator as the train's plan. The orchestrator checks it with the plan validator and records it instead of cutting a new one. With no plan named, the orchestrator cuts and records the plan itself before any coder starts.

### While the run works

Your session checks the conditions in the next section, then starts one orchestrator agent and passes messages between it and you. The orchestrator never asks you anything itself. After each phase you see a progress note that names the phase, its weight and the state of each unit. Before each choice the train makes, you see one line: `Chose <what> over <alternative>: <cost>`.

When the train needs a decision from you, the orchestrator writes a decision brief. Your session asks you each question through Claude Code's question prompt. Each question has a question line ending in a question mark, two or three sentences of context, and its options, with the recommended option first. Each question is written at the reading level the `docs.literacy` key of `service-manifest.json` names, `plain` when the key is absent. At `plain` a sentence holds at most 15 words, and at `standard` at most 22. The orchestrator checks each brief with `daedalus_train.py brief-check` before you see it.

The orchestrator ends each reply with one of four status lines, and your session acts on it:

- `[STATUS: DECISION]`: your session asks you the brief's questions and sends your answers back.
- `[STATUS: EXCEPTION]`: you exempted every finding of the last audit round. Your session records one exemption per finding, each with its ruling and how you chose to track it.
- `[STATUS: STOP]`: your session runs the stop command and shows its `Next:` line. Say continue to resume.
- `[STATUS: TRAIN_COMPLETE]`: your session shows the summary path and the audit log path, then ends the train. "Recovering a train" below covers a commit that lands after that.

### Before anything is built

The train runs these checks and stops with a `Next:` line when one fails:

- The working tree must be clean. Commit or stash first.
- `config.json` is optional. When it exists, it must be valid JSON.
- A decision ledger must exist. The train runs `append_ledger.py --probe` to look for one. If no ledger is declared and none is found, it asks: "This repo has no decision ledger. Options: name an existing file, or let Daedalus create docs/decisions.md as a table. Which?" To name a file, add a `ledger` block for it to config.json from your own shell. Choosing create writes `docs/decisions.md` holding only the table header and separator, which the probe reads as `seq=0`. You review and commit it, then start the train again.
- The hooks must be writing this session's audit log. The train's start creates `<repo>/.claude/daedalus/`. The next check reads the newest log in `<repo>/.claude/daedalus/audit/` and looks for its own probe command as the last Bash record. If it is not there, the jail is not enforcing, and the train stops; run `/daedalus:doctor`. When it is there, the check prints `OK hooks live: session <id>, chain intact (<n> records)`. It also marks where this train's audit begins. The push run reads the security verdict only from records after that mark.
- Before the first compliance question, the orchestrator finds the control packs: your `frameworks.pack_dir` packs, then the shipped packs unless `frameworks.default_packs` is `false`. A pack that fails its check stops the train. Run `/daedalus:doctor` and fix the pack it names.

The train creates `docs/.tmp/daedalus/` with a `*` marker, so git ignores its working files and summary. It writes `<repo>/.claude/daedalus/train.active` while it runs and removes it when it ends or stops. While that file exists, agents from Claude Code itself or from other plugins are refused every checked tool except reads and searches.

### The status record

After the checks, your session prints the first six lines of the State Block, the train's status record. The orchestrator keeps the full block and prints it only at a stop, at a resume and in the summary. After each phase you see the progress note instead. The first lines, with example values:

    train: 20261014-153000  base: main @ 3f329dc  audit session: <session>
    ledger: /work/my-service/docs/decisions.md (probe, markdown-table-row, seq=12)
    charter_root: none  charter base: none
    policy: none declared  standards: 0 sources
    cache: unresolved
    standards packs: none declared

The start command prints the `cache:` line. In the block it keeps, the orchestrator replaces that line with `packs: <absolute pack folder>[, ...]`, the control pack folders it finds before the first compliance question. Until then the line reads `packs: unresolved`. The full block adds the standards specialist, the ledger codes, the packet version with the contract path and lock commit, both packet hashes, the plan, the merged integration tip, the verdict, one line per unit and the open questions.

The train id is the UTC start time. The audit session id is the name of the newest log in `<repo>/.claude/daedalus/audit/`, without `.jsonl`. Keep it for the audit report. `seq` is the last ledger entry number. The codes on the full block's `codes:` line are the `--repo` and `--type` parts of the next ledger id. The train takes them from the first ledger id the Standards Packet cites. If it cites none, or its ids disagree, the train asks you once. A heading-entry ledger ignores the codes.

The build run saves the Locked Contract Packet to a file, and the lock command commits it. Without `charter_root`, the file is `contracts/<name>.md`, committed on the integration branch `daedalus/<train-id>` before any coder starts. With `charter_root`, the file is `<charter_root>/specs/<name>.md`, committed on the Charter branch `daedalus/<train-id>` that the train creates in its checks. The Charter is a separate repository for your decisions and specs. Every contract revision is saved and committed again. Without `charter_root`, nothing is written to a Charter repository, and the ledger entry goes to this repository's own ledger.

### Standards and contract first

The standards specialist reads the sources you declared in `standards_sources`, and your ledger. It writes a Standards Packet: the rules that apply to this task. If your task contradicts one of your own standards, the train asks you about it as a decision. The question quotes both sides: your words, and the rule with its file and line. When the rule comes from your global Claude environment, you get three options:

- Follow Global: the plan or the plugin changes to comply.
- Follow Plugin: the plugin's way stands, recorded as a deviation.
- Follow Plugin + amend global: the plugin's way stands, and the main session edits that one global rule line by hand and shows you the diff.

Your pick becomes a ruling in your ledger before any coder starts. The train never picks a side.

The planner cuts the task into units alongside the standards step, and the train records the plan before any coder starts. The contract agent then writes a Locked Contract Packet with a `packet_version`. A small plan skips that step. It must have one unit that changes at most 3 files, with none of them under `scripts/checks/`, `agents/`, `skills/` or `hooks/`. None of them may be `scripts/lib/jail.py`, `scripts/lib/shell.py`, `scripts/enforce_agent_jail.py` or a protected path. Below its plan block it must have no pin line and a `wire: none` line. On a skip, the train prints `contract: skip` and puts the integration branch at the base commit without a contract commit. Each brief then carries `Contract: none`.

Every coding agent's brief names both packet files with their sha256 hashes. The agent refuses to start when a hash does not match. The train creates each coding agent's worktree at `<repo>/.claude/worktrees/<train-id>-<unit-slug>`, on the branch `daedalus-unit/<train-id>-<unit-slug>` cut from the integration branch. It writes a `.gitignore` holding `*` in `.claude/worktrees/`. No setting is needed for this. A coding agent may write anywhere inside its own worktree, except the protected paths [docs/project-requirements.md](../project-requirements.md) lists under "Coder write boundary".

Once coding has begun, the train removes every worktree after the merge and before any stop, so worktrees never outlive the train. Changes a coding agent left uncommitted were never audited. The train lists them, then discards them.

### What each yield means

A coding agent that is stuck commits its work in progress and asks a question. Daedalus calls that question a yield. The orchestrator sends it to the agent named below, then resumes the same coding agent:

| Yield | Meaning | Who answers |
|---|---|---|
| `YIELD_WEB` | It needs external documentation. | web-researcher, from official docs, with URLs |
| `YIELD_CONTRACT` | The contract does not cover what it found. Other affected agents are put on hold. | contract-spec, with a new packet_version sent to every affected agent; a train that skipped the contract stops instead, with `Next: rerun the train with a plan that declares the contract` |
| `YIELD_COMPLIANCE` | It has a security control question. | framework-specialist, with pack control ids from the shipped packs or your own |
| `YIELD_STANDARDS` | It has a question about one of your standards. | standards-rules-specialist, with the source and line |

The scope of each unit comes from the recorded plan and the contract.

### The security gate

Once every unit is complete, the train merges each unit into the local integration branch `daedalus/<train-id>` with `--no-ff`, so each unit stays visible in the history. A merge conflict stops the train. The merge is aborted, and the repository stays on `daedalus/<train-id>` with the merges that completed. The stop names the conflicting files. Merge that unit there by hand and run the merge step again, which skips units already merged. Or rerun the train with units that do not share files.

The summary records the policy gate as `[POLICY: none declared]` or `[POLICY: declared, gate not yet shipped]`. A later Daedalus release adds the gate itself. If a unit touched IAM, KMS, mTLS, key custody or infrastructure config, the framework specialist checks the merged diff against the control packs. Those are your `frameworks.pack_dir` packs, and the shipped AWS and NIST packs unless `frameworks.default_packs` is `false`.

Then the security auditor judges the merged integration tip against the train's base, so its verdict names the commit the push run pushes. It judges against the contract, your standards and the compliance reports. It treats anything a coder can commit or a project ships as attacker input, so a finding that needs a planted file still counts. Besides its pattern searches, it lists every option, config file and environment setting of each tool a jail rule allows. It feeds each new parser or loader wrong types, nested lists, and unreadable or linked folders. It reads every change to an agent or skill file in full, removed lines included.

Before the first round, the orchestrator lists the older rules and gates each new feature reaches, on `Reachable:` lines. For each unit that touches a jail, a gate, a parser or an agent instruction, it also writes one or two attacker questions, on `Hunt:` lines. The auditor answers each with a test or a reproduction. Every round judges the full diff from the base, never only the fixes.

The auditor works in its own audit worktree, a checkout of the integration branch. Before each later round, the train refreshes it with a fast-forward to the new integration tip. If that worktree holds a commit or a change the integration branch lacks, the refresh stops with a `Next:` line naming `git -C <path> status` instead of throwing the work away.

A `[VERDICT: REJECTED]` names the tip it judged and writes each blocking finding as a failing test. Your session then asks you about each finding, one question per finding. The question's first line says what is at stake in one plain sentence, then asks. Two or three short sentences follow on what breaks and what happened in the test. The three choices are:

- Fix it now (Recommended): the train sends the finding to the coding agent that wrote the code, in a fix unit cut from the integration branch, with the test it must make pass. Then it merges the fixes and audits again. How the fix is built is in the finding file, not in the choice.
- Skip, track or exempt it: the finding stays in the merged work, and the exemption becomes a ruling in the ledger. A second question asks how the exemption is tracked: Skip it (dropped silently), Track it (a GitHub tracked-risk issue the session files before the pull request opens), Exempt it (the local ledger record alone), or your own answer. Every choice is offered in every project. A Skip it or Exempt it answer puts a `Deviation:` line in the pull request body naming the finding and its exemption row.
- Stop the run: the run stops, and every unit branch stays for fixes by hand or a narrower rerun.

The same questions follow every later rejected round. No fix round starts without your pick, and there is no limit on the number of rounds. The train never runs a fix round or stops on its own. The push run's verdict check accepts a rejected round once every finding in its findings file carries an exemption.

On `[VERDICT: APPROVED]`, or once you exempted every finding, the charter-docs agent appends the ledger entries through `append_ledger.py` and commits them. When the ledger lives in your Charter repository, the Charter working tree must be clean first. The train creates the Charter's `daedalus/<train-id>` branch in its checks, for the contract and ledger commits, then switches the Charter back to the branch it was on. Nothing is pushed.

Each agent ends its reply with one of its set status lines or sections. A reply that does not stops the train and shows you the reply's last 10 lines. The auditor brief from standards-rules-specialist is the one exception: it ends with its rule list and has no status line. The security auditor writes its verdict line as both the first line and the last line of every reply.

Once the train has created a Charter branch, it switches the Charter back to the branch it was on before any stop. Before any stop ahead of the merge, it also switches this repository back to your base branch. There are two exceptions. A stop while the Charter tree is dirty leaves the Charter on its `daedalus/<train-id>` branch. A stop while the contract file is uncommitted leaves both repositories on `daedalus/<train-id>`. Either way, the stop names the uncommitted files and the branch they sit on.

### The summary

The train writes `docs/.tmp/daedalus/<train-id>-summary.md`. The push run uses this file as the pull request body, so it holds no absolute path. It holds:

- the task, the base commit and the integration branch
- the Charter repository by directory name, with its `daedalus/<train-id>` branch and the branch it forked from when `charter_root` is declared, or `charter: none (repo-local ledger)`
- the packet version, the ledger path relative to its repository, and the contract file with its version on a `Contract:` line. A train that skipped the contract reads `Contract: none. This plan changes at most 3 files and declares no contract, so no contract was written.` A train that stopped before its lock reads `Contract: none. No contract was locked before the run stopped.`
- the ledger entries added, on a `Ledger ids:` line. The train writes the summary before the ledger step with `Ledger ids: pending`, so a stop there still leaves a summary. The push run refuses a pending summary and names the ledger resume that finishes it. After the ledger commit and the approved verdict are recorded, the train rewrites the summary as its last step
- the policy line
- every ruling you made during the train, with its ledger id, and a `Deviation:` line for each pick that keeps the plugin's way
- each decision a project priorities rule settled alone or put to you, with its rule and driver, or `none`
- one row per unit: branch, packet, files, tests
- each verified unit's last verifier verdict line, followed by `corrected=<k>`, the number of the coder's receipts the verifier corrected, when the reply carries that count
- every yield and who answered it
- the compliance results, the dependency auditor's and the Terraform reviewer's included
- the audit verdict on the merged integration tip and its round count, or each exempted finding with its ledger id and how it is tracked
- the docs verdict on the tip the docs stage merged, with each exempted docs claim, or `Docs: not run`
- the blocks the hooks made, sorted into friction (work the agent's job needed) and habit (a reach outside the job)
- the audit log path, relative to the repository (`.claude/daedalus/audit/<session>.jsonl`)

The train ends by naming the audit session. To read what every agent did:

    /daedalus:audit-report <session>

## Running a push

After a build run ends, stay on its `daedalus/<train-id>` branch and type:

    /daedalus:run push

With no argument, it pushes the newest build run in `docs/.tmp/daedalus/`. To push an older one, pass its train id: `/daedalus:run push 20261014-120000`. A train id is the UTC time the build run started, `YYYYMMDD-HHMMSS`. Anything else stops the train. Start the session in the repository's top directory, not a subdirectory or a linked worktree. No summary there means no build run has happened yet; run `/daedalus:run` first.

### Before anything is pushed

The train stops, with a `Next:` line, when any of these fails:

- You are not on the `daedalus/<train-id>` branch the summary names.
- The service manifest turns the secret scan on (`features.secrets_scan` is `true`) and `gitleaks` is not installed. Install it (https://github.com/gitleaks/gitleaks#installing) and rerun. With the scan on, the train never pushes without it. With the scan off, the train neither runs nor needs gitleaks.
- `gh auth status` fails. Run `gh auth login` and rerun. The push agent opens the pull request with gh.
- The working tree has unstaged or untracked changes. Staged changes are fine, because the push agent commits them.
- This session's hooks are not writing the audit log. The train marks itself running before this check, since the log records only during a train. Run `/daedalus:doctor`.
- An audit log fails its hash chain check. Keep the file, report it, and do not edit it, as in "When the chain is BROKEN" above.
- The security auditor's last reply is not `[VERDICT: APPROVED]`, or the ledger commit is not on the branch. The reply checked is the last one before this train's summary, in the build run's audit log, after the mark its hooks check made. A rejected round passes when every one of its findings carries an exemption. The plugin README's "The push proof" lists each rule this check applies. When the only problem is a commit that landed on the branch after the audit, the push run adds one recovery round on the new tip instead of stopping (see "Recovering a train" below).

### What the conductor does

The conductor is the push agent, pr-train-conductor. It commits any staged result. With the secret scan on, it then scans the commits since the base with `gitleaks detect --redact`. It pushes the branch with `git push -u origin daedalus/<train-id>` and opens the pull request with the build run's summary as its body. When a pull request for the branch is already open, it updates that body instead. The jail lets it push only a named branch to `origin`. It can never push `main` or `master`, never force a push, and never merge.

Then it watches the GitHub Actions runs for the pushed commit and reports each conclusion. Only `success`, `skipped` and `neutral` let the train go on. Every `skipped` or `neutral` result is named in your checklist, even when a later run succeeded. Any other conclusion, including `startup_failure` or one Daedalus does not know, stops the train. Its log lines are added to the summary under `## CI` and shown to you. Fix the failure through `/daedalus:run`; the push run never fixes CI.

The conductor cannot wait, so it does not see a run that has not started yet. In that case the summary and the pull request body get the line `Deviation: CI not observed at push time`. Your checklist then starts with `CI not observed; check the PR's checks before merging`.

### When the Charter has a branch

The build run may have put its contract on a `daedalus/<train-id>` branch in your Charter repository, with its ledger entry when the ledger lives there. Then the push run opens a second pull request for that branch, once the code pull request exists. The train writes a two-line pull request body to `docs/.tmp/daedalus/<train-id>-charter-pr.md` naming the code pull request. The conductor pushes the Charter branch and opens its pull request against the branch the Charter forked from.

### Your checklist

The train ends with the pull request URLs and a numbered list:

1. Review the pull request.
2. Check CI on the pull request.
3. Merge the pull request. You merge; the train never does.
4. Check that the pull request is merged with `gh pr view <url> --json state`. Then, from your own shell, switch back to your base branch and delete the branch with `git branch -D daedalus/<train-id>`. A squash merge leaves the branch looking unmerged to git, so `git branch -d` would refuse it.
5. Run `/daedalus:audit-report <session>` to read this session's audit log.

With a Charter branch, item 6 covers the Charter pull request. You review and merge it after the code pull request and check it is merged the same way. The item's last step switches the Charter back and deletes its branch with `git branch -D`. The list ends with a note that a later Daedalus release adds the Execution Train readiness checklist: the manual drills and boundary checks before production.

### What BLOCKED means

`[STATUS: BLOCKED] <detail>` from the conductor means one of two things. A check it runs failed before anything changed on GitHub, or a command it needed was refused. The most common detail is `gitleaks findings`: the scan found something that looks like a secret in the branch's commits. The findings are shown with the secret redacted. Rotate the credential, remove it from the branch history from your own shell, and run `/daedalus:run push` again. For any other detail, do what the detail names and rerun.

## Recovering a train

Two kinds of trouble after the merge no longer need a full rerun. Both are handled in the session that ran the build.

- A commit landed on `daedalus/<train-id>` after the audit approved it, so the approval no longer names the tip. If the build run's train has completed, tell its session about the commit. In the push run, the verdict check finds the moved tip itself. Either way, the session runs `daedalus_train.py reaudit`, which prints `reaudit round=<n> tip=<sha>`, and one audit round judges the new tip. An approved round rewrites the summary, and the train goes on. A rejected round shows you the findings with the same three choices as any rejected round, and no second recovery round runs on the same tip.
- The train stopped after its merge and before its ledger commit, so the summary still reads `Ledger ids: pending`. Ask the build run's session for the ledger resume. It runs `daedalus_train.py resume`, which prints `resume ledger train=<train-id> summary=<path>`, and starts a fresh orchestrator for that one step. That orchestrator commits the ledger entries, records the verdict, rewrites the summary and ends the train. Then run `/daedalus:run push`.

The build run also stops at its start when an agent file changed after the session loaded it. The stop line reads `stale agents: <names>`. The session would run the old agent text, so start a new Claude Code session and run `/daedalus:run` again.

## Developing Daedalus

To try a local checkout of Daedalus for one session instead of the installed plugin, start Claude Code inside your own project with the path to the checkout:

    claude --plugin-dir /path/to/Daedalus

Where it runs: any shell with the claude CLI on PATH. A `--plugin-dir` session uses the cache directory `daedalus-inline`. The marketplace install uses `daedalus-daedalus`.
If it fails: `unknown option --plugin-dir` means the CLI is too old. Run `claude --version`.

To keep a local checkout installed across sessions, with no published release involved, add the checkout as a local marketplace and install from it. Replace `/path/to/Daedalus` with the path of your checkout. Both marketplaces use the name `daedalus`, so if you added the published one, remove it first with `claude plugin marketplace remove daedalus`.

    claude plugin marketplace add /path/to/Daedalus

    claude plugin install daedalus@daedalus

After the checkout changes, update the marketplace and the plugin, then restart Claude Code so the new code loads:

    claude plugin marketplace update daedalus

    claude plugin update daedalus@daedalus

Where it runs: any shell with the claude CLI on PATH. The install uses the cache directory `daedalus-daedalus`, the same name as the published install, because the marketplace name is the same.
If it fails: after the restart, run `/daedalus:doctor`. Its `plugin root` line names the folder the running copy loads from.

## Sections added by later plans

Later features add their own section here, in the pull request that ships them. Service manifests and the new-service scaffold are two of them.

### Running in a plain folder

When the session is not in a git repository, `/daedalus:run` can brainstorm, plan, write documents and check their claims. It cannot build, audit or push. It asks where the outputs go: the project's `docs` folder, a new folder under `/tmp`, or a folder you name. It then opens the run with `daedalus_workspace.py begin --repo <folder> --scope folder --out <outputs>`. The last line it prints is `scope: folder  out: <outputs>`. The plan file, the brainstorm spec, the derived documents and the change log are written straight into that output folder. When the run ends, the session runs the stop command, which clears the run marker and touches no branch.
