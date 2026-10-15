<!-- Copyright (c) 2026 Brad Duhon. SPDX-License-Identifier: GPL-3.0-or-later -->
# Daedalus: operator guide

This guide assumes you have never seen this plugin. Each section says what to type, what you will see, and what to do if you do not see it.

## What Daedalus does

Daedalus is a Claude Code plugin. Today it does seven things. It writes a hash-chained audit log of every tool call the hook matcher routes (Bash, file reads, searches and edits, web fetches, agent spawns, messages, MCP tools). Each record carries the hash of the one before it, so an edited record, or one removed from the middle, breaks the chain. It confines each agent to a jail: a PreToolUse hook checks every tool call against the rules for that agent and blocks anything outside them. It turns on the OS sandbox with `/daedalus:setup` when you ask it to, and refuses every read of your credential stores. It has a first-run doctor that checks your setup. It renders an audit report, a readable digest of one session's log, with `/daedalus:audit-report`. It runs a Build Train with `/daedalus:build-train`. The train splits a task into units and gives each unit to a coding agent in its own git worktree. Agents raise questions to specialists, and an adversarial security audit runs before the units are merged locally. It runs a Push Train with `/daedalus:push-train`, which commits, pushes, and opens the pull request for a finished Build Train. You review and merge.

## Install

Inside any Claude Code session, type:

    /plugin install daedalus --marketplace bradduhon/Daedalus

Every Daedalus command acts on the repository you started Claude Code in.

Where it runs: any Claude Code session, version 2.1.275 or later (`claude --version`). Daedalus is verified on Claude Code 2.1.280.
What you will see: Claude Code asks you to confirm the marketplace, then to pick a scope. Pick "Install for you". The audit log starts recording once the plugin is active.
If it fails: when your Claude Code does not accept `--marketplace`, run these two commands from a shell instead, then start Claude Code:

    claude plugin marketplace add bradduhon/Daedalus

    claude plugin install daedalus@daedalus

## First run

Inside the session type:

    /daedalus:doctor

It lists every file and tool daedalus needs and whether each is present, with a `Next:` line for each missing one. Nothing is changed by running it. Every file it checks is described, with a minimal example, in `docs/project-requirements.md`.

Example output from a real run in a new repository with one empty commit, on a machine with no Daedalus settings, gitleaks missing and gh not signed in. Your paths differ, and the doctor prints your home directory in full where this shows `~`:

    OK   python >= 3.12
    OK   project data dir: /work/my-service/.claude/daedalus (will be created by the first hook)
    OK   config.json: not present, defaults in use
    OK   ledger: none found (the Build Train asks before creating docs/decisions.md)
    OK   standards_sources: not declared (optional)
    OK   policy: not declared (optional)
    OK   cache dir: none yet (create it with scripts/refresh_nist_oscal.py or by hand per docs/project-requirements.md)
    OK   plugin root: ~/.claude/plugins/cache/daedalus/daedalus/2.0.0
    MISS sandbox: off. Next: run /daedalus:setup
    MISS gitleaks on PATH: not found. Next: the Push Train scans commits with gitleaks; install it so the scan can run
    OK   gh on PATH
    MISS gh authenticated: gh auth status exited 1. Next: run gh auth login
    OK   bwrap on PATH
    OK   socat on PATH
    OK   git repository
    OK   clean working tree
    MISS service-manifest.json: not found at repo root. Next: create it from the example in docs/project-requirements.md
    MISS contracts/: directory missing. Next: mkdir contracts and add openapi.yaml or events/*.schema.json
    MISS .gitleaks.toml: not found at repo root. Next: copy the baseline from docs/project-requirements.md
    daedalus doctor: fix each MISS line, then rerun

In a new repository the last three lines stay `MISS` until you add those files; `docs/project-requirements.md` has an example of each. Once the directory exists the doctor also checks that `.claude/daedalus/.gitignore` holds a `*` line and that git ignores the directory. The cache dir and plugin root lines are informational and never a MISS. When more than one `~/.claude/plugins/data/daedalus*` directory exists, the cache dir line names each one. The plugin root is the directory the commands in this guide call `<plugin>`. On macOS the `bwrap` and `socat` lines do not appear.

The `sandbox` line reads `~/.claude/settings.json`, then `.claude/settings.json` and `.claude/settings.local.json` in the repo; the last one that sets `sandbox.enabled` wins. It reads `on` when that value is true and `bwrap` and `socat` are on PATH, `configured-unavailable` when the value is true and a tool is missing, and `off` otherwise. When one of those files is not valid JSON, the line reads `MISS sandbox: <path> is not valid JSON (...). Next: fix <path>` instead. While it is not `on`, each new session starts with the same line. To turn the sandbox on, type:

    /daedalus:setup

Setup checks for `bwrap` and `socat` first. When one is missing it writes nothing and prints what to install: the apt line on Debian and Ubuntu, the package names elsewhere. On Ubuntu it reads `daedalus setup: bwrap, socat not on PATH; nothing written. Next: run sudo apt-get install -y bubblewrap socat, then rerun /daedalus:setup`. Otherwise it merges the sandbox, the credential deny rules and the two prompt cache settings into `~/.claude/settings.json`. It adds keys you lack and deny entries you lack, never overwrites a value you set, prints the change, and ends with `Restart Claude Code to apply`. It rewrites the file as JSON with a 2-space indent. Restart Claude Code after it writes. Without the sandbox the Build Train still runs and says `Sandbox: off` in its summary; the Push Train refuses.

Each `OK` line is a check that passed. Each `MISS` line names what is missing and, after `Next:`, what to do about it. The doctor exits 0 when every check passes and 1 otherwise. Fix the `MISS` lines and run it again.

## Where things live

| Thing | Path | Who writes it |
|---|---|---|
| Audit logs, one per session | `<repo>/.claude/daedalus/audit/<session_id>.jsonl` | hooks only, and the jail refuses tool writes there |
| Plugin config, optional | `<repo>/.claude/daedalus/config.json` | you, from your own shell, when you need it |
| Machine caches (NIST, CIS) | `${CLAUDE_PLUGIN_DATA}`, under `~/.claude/plugins/data/` | the plugin's refresh scripts |
| Build Train scratch files and summary | `<repo>/docs/.tmp/daedalus/` | the Build Train; a `*` marker inside keeps it out of git |
| Recommended settings | `settings.recommended.json` in the plugin | `/daedalus:setup` merges it into `~/.claude/settings.json` |
| Running-train marker | `<repo>/.claude/daedalus/train.active` | each train, removed when it ends or stops |
| Coder worktrees | `<repo>/.claude/worktrees/<train-id>-<unit-slug>` | the Build Train, removed when it ends or stops |

`<repo>` is the main working tree of the git repository you started Claude Code in. Every worktree of that repository shares the one `.claude/daedalus/` directory. Outside a git repository, `<repo>` is the starting directory itself. The first hook writes `.claude/daedalus/.gitignore` with a single `*` line, so git ignores the directory and your own `.gitignore` is untouched. The jail also refuses any `git add` or `git commit` that names `.claude/daedalus`.

Each audit record holds a `result_head` field with the start of the tool's output. It is capped at 4096 characters, not bytes.

Uninstalling the plugin leaves the audit logs and config in the repo. A copy of each log's final hash should live outside this machine so a deleted or altered log can be detected; Daedalus does not make that copy yet.

## Reading a block message

When daedalus refuses an action you see a line like:

    daedalus-jail[repo-coder]: write outside src/ or tests/ of your unit worktree: /work/repo/infra/x.tf. Next: ask Fable to route this to contract-spec or charter-docs.

The name in brackets is the agent that was blocked. The part before `Next:` is what was refused and why. The part after is what to do instead. Fable is the orchestrating session you are talking to, not the plugin.

## Reading an audit report

Inside the session type:

    /daedalus:audit-report

With no argument it reports the newest session log for this repo, which is usually the session you are in. To report an older one, pass its id: `/daedalus:audit-report <session>`. The ids are the file names in `<repo>/.claude/daedalus/audit/`, without `.jsonl`.

The report checks the log's hash chain first. Only an intact chain gets a digest. The digest has six parts:

- Header: the session id, the number of records, the hash of the last record (`head=`), and the repo the session ran in.
- Subagent timeline: one row per agent, with the record number where it started and stopped. `open` in the stop column means the log holds no stop record for that agent.
- Write, Edit and Bash calls: per agent type and tool, how many calls the jail allowed and how many it blocked.
- Blocks: every refused action, one line each.
- Status lines: every `[STATUS: ...]`, `[VERDICT: ...]` and `[STANDARDS: ...]` line an agent reported.
- Totals by event: how many records of each hook event the log holds.

A block line reads like this:

    - seq 3 repo-coder Bash: the operator merges; never push to the default branch \(0001\). Next: push the unit branch instead.

`seq 3` is the record number in the log. `repo-coder` is the agent that was refused, and `Bash` is the tool it tried. The rest is the refusal the log stores. The agent saw the same text with a `daedalus-jail[<agent>]:` prefix. Every refusal ends with the `Next:` the agent was given. The backslashes keep characters such as brackets from acting as Markdown. Text an agent wrote is shown escaped, so a link or tag in it appears as plain text and does nothing.

### When the chain is BROKEN

Instead of a digest you see one line like:

    audit_report: BROKEN line 7: hash mismatch

The log changed after it was written: a record was edited, removed, or reordered. Line 7 is the first line of the file that fails the check. A broken chain is itself the finding, so no digest is shown. Do three things: keep the file, report it, and do not edit it. Editing the file destroys the evidence. To rerun the check by hand, where `<plugin>` is the plugin directory:

    python3 <plugin>/scripts/verify_audit_chain.py <repo>/.claude/daedalus/audit/<session>.jsonl

It prints `OK: <n> records, chain intact, head=<hash>` for an intact log, or the same line without the `audit_report:` prefix, for example `BROKEN line 7: hash mismatch`.

### Saving the report

When the optional `<repo>/.claude/daedalus/config.json` sets `charter_root`, the skill asks whether to render the report again and save it to `<charter_root>/audit/<session>.md`. A live session gains a few records between the two runs, so the saved file can hold more than the screen showed. If `<charter_root>/audit` does not exist yet, the skill offers to create it. Say yes and the file is written there for the charter-docs agent to commit in a later Build Train. Say no, or leave `charter_root` unset, and the digest stays on screen only.

You can also write it yourself, from the repo directory. Create the folder first:

    mkdir -p docs/.tmp

Then:

    python3 <plugin>/scripts/audit_report.py --session <session> --out docs/.tmp/<session>.md

The file is written with mode 0600, so only your user can read it. Run `chmod` on it if others need to read it. The script refuses two kinds of path, and each refusal ends with a `Next:` line:

- Any path inside a `.claude/daedalus/` directory, in this repo or another one. The audit logs live there and a report must never overwrite one.
- A path that is a symlink. The script never writes through a link. Pass the real file path instead.

It also refuses a path that names a directory, a path whose parent directory does not exist, and `--out -`. To print to the screen, leave out `--out`.

## Running a Build Train

Start from a clean working tree on the branch you want to build from. Inside the session type the command and the task in your own words:

    /daedalus:build-train Add a /healthz endpoint that returns the build version

Where it runs: a Claude Code session started inside the target repository. `<repo>/.claude/daedalus/config.json` is optional (see `docs/project-requirements.md`). Run `/daedalus:doctor` first if you have not.

### Before anything is built

The train runs these checks and stops with a `Next:` line when one fails:

- The working tree must be clean. Commit or stash first.
- `config.json` is optional. When it exists it must be valid JSON.
- A decision ledger must exist. The train runs `append_ledger.py --probe`. If no ledger is declared and none is found, it asks: "This repo has no decision ledger. Options: name an existing file, or let Daedalus create docs/decisions.md as a table. Which?" Naming a file means you add a `ledger` block for it to config.json from your own shell. Choosing create writes `docs/decisions.md` holding only the table header and separator, which the probe reads as `seq=0`; you review and commit it, then start the train again.
- The hooks must be writing this session's audit log. The train reads the newest log in `<repo>/.claude/daedalus/audit/` and looks for its own probe command as the last Bash record. If it is not there, the jail is not enforcing and the train stops. Run `/daedalus:doctor`.
- Before the first NIST or CIS question, the plugin cache must exist. If `daedalus_doctor.py --print-cache-dir` finds none, run `/daedalus:doctor` once and start again.

The train also records the sandbox state. With the sandbox not `on` it still runs and puts `Sandbox: off` (or `Sandbox: configured-unavailable`) in its summary. It stops before the security audit and the merge when a unit touched IAM, KMS, mTLS, key custody or infrastructure config. Run `/daedalus:setup`, restart Claude Code, and run the train again.

The train creates `docs/.tmp/daedalus/` with a `*` marker so git ignores its scratch files and summary. It writes `<repo>/.claude/daedalus/train.active` while it runs and removes it when it ends or stops. While that file exists, agents from Claude Code itself or from other plugins are refused every checked tool except reads and searches.

### The State Block

After the checks and after each phase, the train prints a State Block. Its shape, with illustrative values:

    train: 20261014-153000  base: main @ 3f329dc  audit session: <session>
    ledger: /work/my-service/docs/decisions.md (probe, markdown-table-row, seq=12)  codes: --repo SVC --type PLT
    charter_root: none  policy: none declared  cache: unresolved
    packet_version: 1
    units: u1 | <branch> | COMPLETE | built against packet 1
    open yields: none

The train id is the UTC start time. The audit session id is the name of the newest log in `<repo>/.claude/daedalus/audit/`, without `.jsonl`; keep it for the audit report. `seq` is the last ledger entry number. `codes` are the `--repo` and `--type` parts of the next ledger id. The train takes them from the first ledger id the Standards Packet cites. If it cites none, or its ids disagree, the train asks you once. A heading-entry ledger ignores the codes.

The Build Train saves the Locked Contract Packet to a file, and the train's main session commits it. Without `charter_root`, the file is `contracts/<name>.md`, committed on the integration branch `daedalus/<train-id>` before any coder starts. With `charter_root`, the file is `<charter_root>/specs/<name>.md`, committed on the Charter branch `daedalus/<train-id>` that the train creates in its checks. Every contract revision is saved and committed again. Without `charter_root`, nothing is written to a Charter repo, and the ledger entry goes to this repo's own ledger.

### Standards and contract first

The standards specialist reads the sources you declared in `standards_sources` and your ledger. It writes a Standards Packet: the rules that apply to this task. If your task contradicts one of your own standards, the train stops and shows both sides: your words, and the rule with its file and line. Reword the task or change the standard, then start again. The train never picks a side.

The contract agent then writes a Locked Contract Packet with a `packet_version`. Every coding agent gets both packets at the top of its prompt. The train creates each coding agent's worktree at `<repo>/.claude/worktrees/<train-id>-<unit-slug>`, on the branch `daedalus-unit/<train-id>-<unit-slug>` cut from the integration branch, and writes a `.gitignore` holding `*` in `.claude/worktrees/`. No setting is needed for this. A coding agent may write only inside the `src/` and `tests/` directories of its own worktree. The train removes every worktree after the merge and before any stop once coding has begun, so worktrees never outlive the train. Changes a coding agent left uncommitted were never audited: the train lists them, then discards them.

### What each yield means

A coding agent that is stuck commits its work in progress and returns a yield. The train answers it and resumes the same agent:

| Yield | Meaning | Who answers |
|---|---|---|
| `YIELD_WEB` | It needs external documentation. | web-researcher, from official docs, with URLs |
| `YIELD_CONTRACT` | The contract does not cover what it found. Other affected agents are put on hold. | contract-spec, with a new packet_version sent to every affected agent |
| `YIELD_COMPLIANCE` | It has a security control question. | nist-specialist or cis-specialist, with control ids |
| `YIELD_STANDARDS` | It has a question about one of your standards. | standards-rules-specialist, with the source and line |

A later Daedalus release adds service manifests. Until then, the scope of each unit comes from your words and the contract.

### The security gate

The summary records the policy gate as `[POLICY: none declared]` or `[POLICY: declared, gate not yet shipped]`; a later Daedalus release adds the gate itself. If a unit touched IAM, KMS, mTLS, key custody or infrastructure config, the NIST and CIS specialists check those diffs. Then the security auditor reads every unit's diff, taken from the integration branch so the contract commits stay out of it, against the contract, your standards, and the compliance reports.

A `[VERDICT: REJECTED]` lists findings by branch, file and line. The train sends each finding to the agent that wrote the code and audits again. After three rejected rounds it stops and shows the last findings. The unit branches stay as they are; fix them by hand or start again with a narrower task.

A `[VERDICT: APPROVED]` merges each unit into the local integration branch `daedalus/<train-id>` with `--no-ff`, so each unit stays visible in the history. A merge conflict stops the train: the merge is aborted and you are back on your base branch. The stop names the conflicting files and the leftover `daedalus/<train-id>` branch, which you inspect or delete.

The charter-docs agent then appends the ledger entries through `append_ledger.py` and commits them. When the ledger lives in your Charter repo, the Charter working tree must be clean first. The train creates the Charter's `daedalus/<train-id>` branch in its checks, for the contract and ledger commits, then switches the Charter back to the branch it was on. Nothing is pushed.

Any agent reply that does not end in one of its contract lines or contract sections stops the train and shows you the reply's last 10 lines. The auditor brief from standards-rules-specialist is the one exception: it ends with its rule list and has no status line. Once the train has created a Charter branch, it switches the Charter back to the branch it was on before any stop. Before any stop ahead of the merge, it also switches this repo back to your base branch. The exceptions: a stop while the Charter tree is dirty leaves the Charter on its `daedalus/<train-id>` branch, and a stop while the contract file is uncommitted leaves both repos on `daedalus/<train-id>`. Either way the stop names the uncommitted files and the branch they sit on. The security auditor is read from the first line of its reply, where it writes its verdict.

### The summary

The train writes `docs/.tmp/daedalus/<train-id>-summary.md`. It holds:

- the task, the base commit, and the integration branch
- the Charter repo by directory name, with its `daedalus/<train-id>` branch and the branch it forked from when `charter_root` is declared, or `charter: none (repo-local ledger)`
- the packet version, the ledger path relative to its repo, and the contract file with its version on a `Contract:` line. The summary becomes the pull request body, so it holds no absolute path
- the ledger entries added, on a `Ledger ids:` line. The train writes the summary before the ledger step with `Ledger ids: pending`, so a stop there still leaves a summary. The Push Train refuses a pending summary and names the steps to finish it
- the policy line
- one row per unit: branch, packet, files, tests
- every yield and who answered it
- the compliance results
- the audit verdict and its round count
- the audit log path, relative to the repo (`.claude/daedalus/audit/<session>.jsonl`)

The Push Train uses this file as the pull request body.

The train ends by naming the audit session. To read what every agent did:

    /daedalus:audit-report <session>

## Running a Push Train

After a Build Train ends, stay on its `daedalus/<train-id>` branch and type:

    /daedalus:push-train

With no argument it pushes the newest Build Train in `docs/.tmp/daedalus/`. To push an older one, pass its train id: `/daedalus:push-train 20261014-120000`. A train id is the UTC time the Build Train started, `YYYYMMDD-HHMMSS`; anything else stops the train. Start the session in the repo's top directory, not a subdirectory or a linked worktree. No summary there means no Build Train has run yet; run `/daedalus:build-train` first.

### Before anything is pushed

The train stops, with a `Next:` line, when any of these fails:

- The sandbox is not `on`. The Push Train needs it. Run `/daedalus:setup`, restart Claude Code, and run the train again.
- You are not on the `daedalus/<train-id>` branch the summary names.
- `gitleaks` is not installed. Install it (https://github.com/gitleaks/gitleaks#installing) and rerun; the train never pushes without the secret scan.
- `gh auth status` fails. Run `gh auth login` and rerun; the conductor opens the pull request with gh.
- The working tree has unstaged or untracked changes. Staged changes are fine; the conductor commits them.
- This session's hooks are not writing the audit log. Run `/daedalus:doctor`.
- An audit log fails its hash chain check. Keep the file, report it, and do not edit it, as in "When the chain is BROKEN" above.
- The security auditor's last reply before this train's summary, in the Build Train's audit log, is not `[VERDICT: APPROVED]`, or the ledger commit is not on the branch.

### What the conductor does

The pr-train-conductor agent commits any staged result, then scans the commits since the base with `gitleaks detect --redact`. It pushes the branch with `git push -u origin daedalus/<train-id>` and opens the pull request with the Build Train summary as its body. When a pull request for the branch is already open, it updates that body instead. The jail lets it push only a named branch to `origin`, never `main` or `master`, never a force push, and it cannot merge.

Then it watches the GitHub Actions runs for the pushed commit and reports each conclusion. Only `success`, `skipped` and `neutral` let the train go on; every `skipped` or `neutral` result is named in your checklist, even when a later run succeeded. Any other conclusion, including `startup_failure` or one Daedalus does not know, stops the train: its log lines are added to the summary under `## CI` and shown to you. Fix the failure through `/daedalus:build-train`; the Push Train never fixes CI. The conductor cannot wait, so a run that has not started yet is not seen. Then the summary and the pull request body get the line `Deviation: CI not observed at push time`, and your checklist starts with `CI not observed; check the PR's checks before merging`.

### When the Charter has a branch

When the Build Train put its contract, and its ledger entry when the ledger lives there, on a `daedalus/<train-id>` branch in your Charter repo, the conductor cannot push it: the jail keeps it in this repo. The train writes a two-line pull request body to `docs/.tmp/daedalus/<train-id>-charter-pr.md` naming the code pull request. Your checklist then carries two commands to run from your own shell: one pushes the Charter branch, one opens its pull request against the branch the Charter forked from.

### Your checklist

The train ends with the pull request URLs and a numbered list:

1. Review the pull request.
2. Check CI on the pull request.
3. Merge the pull request. You merge; the train never does.
4. Delete the branch `daedalus/<train-id>`.
5. Run `/daedalus:audit-report <session>` to read this session's audit log.

With a Charter branch, items 6 to 8 push it, open its pull request, and merge it after the code pull request. The list ends with a note that a later Daedalus release adds the Execution Train readiness checklist: the manual drills and boundary checks before production.

### What BLOCKED means

`[STATUS: BLOCKED] <detail>` from the conductor means a check it runs failed before anything changed on GitHub, or a command it needed was refused. The most common detail is `gitleaks findings`: the scan found something that looks like a secret in the branch's commits. The findings are shown with the secret redacted. Rotate the credential, remove it from the branch history from your own shell, and run `/daedalus:push-train` again. For any other detail, do what the detail names and rerun.

## Developing Daedalus

To try a local checkout of Daedalus for one session instead of the installed plugin, start Claude Code inside your own project with the path to the checkout:

    claude --plugin-dir /path/to/Daedalus

Where it runs: any shell with the claude CLI on PATH. A `--plugin-dir` session uses the cache directory `daedalus-inline`; the marketplace install uses `daedalus-daedalus`.
If it fails: `unknown option --plugin-dir` means the CLI is too old. Run `claude --version`.

## Sections added by later plans

Service manifests, train recovery, and the new-service scaffold each add a section here in the pull request that ships them.
