---
name: build-train
description: Runs a Build Train on this repository. Checks the preconditions, then starts the orchestrator agent, which locks the contract and the project standards, gives each work unit to a repo-coder in its own worktree, merges the units locally and runs compliance and an adversarial security audit on the merged result. The session relays each operator decision. Never pushes.
argument-hint: Describe the feature, bugfix, or change to build in this repository.
---
<!-- Copyright (c) 2026 Brad Duhon. SPDX-License-Identifier: GPL-3.0-or-later -->

# daedalus Build Train

You are the main session of this train. You run the Preconditions, start one orchestrator agent, and relay between it and the operator (0060). The orchestrator runs every phase from the plan to the audited integration tip; its recipe is `agents/orchestrator.md`. You do not write application code, and you do not run the phases yourself.

Rules for the whole train:
- Read `/daedalus:catalog` first. It names every agent, the six phases with their exit conditions, the musts and the audit escalation prompt; the orchestrator's recipe is one saved recipe over it (0088, 0089).
- Your own writes go under `docs/.tmp/daedalus/`. While this train runs, the jail warns and asks before any Write or Edit of yours outside that folder in the repository that holds the train, and the operator approves or denies that one call; it never blocks the main session's Write or Edit (0105). Daedalus writes code only in unit worktrees.
- Start the orchestrator with the Agent tool, written below as `Agent(<name>)`; Claude Code loads it as `daedalus:<name>`. Resume it with SendMessage. Never start `claude` from Bash.
- Progress (0085): after Preconditions, run `python3 ${CLAUDE_PLUGIN_ROOT}/scripts/daedalus_train.py progress --repo <repo>` and show its note unchanged; the orchestrator shows it after each phase. Print the State Block only at a stop, at a resume, and in the summary.
- The train never pushes and never merges into `main` or `master` (0001). The operator merges. The Push Train (`/daedalus:push-train`), a separate step after this one, pushes.
- Every stop shows the operator what happened and names the next action as a `Next:` line.
- Human-facing text (0031): Text a human reads names each item in words: a short label or one line on what it is and what it does. Ids (ruling ids, issue numbers, task codes, agent names, snake_case keys) may trail in parentheses, never replace the description. Logs, status lines and messages to other agents may use ids alone. Documents carry both.
- Every stop: run `python3 ${CLAUDE_PLUGIN_ROOT}/scripts/daedalus_workspace.py stop --repo <repo> --reason "<what happened>" --next "<next action>"` and show its output unchanged; its `Next:` line is the next action. It shows and discards the unit worktrees, switches this repo and the Charter back to their base branches unless a dirty tree or an uncommitted contract keeps them on `daedalus/<train-id>`, and clears the train marker (0023, 0024). When the operator says continue after a stop, run `python3 ${CLAUDE_PLUGIN_ROOT}/scripts/daedalus_workspace.py resume --repo <repo>` first; it marks the train active again and switches back to `daedalus/<train-id>`. Then resume the orchestrator as the Relay section says.
- The stop and resume commands stay in this session, because begin and the hooks check run here and bind the train to this session's audit log.

## Preconditions

1. Set `<repo>` to the parent of the directory `git rev-parse --path-format=absolute --git-common-dir` prints (the main working tree; every worktree shares it). Not a repo: stop. Next: start the session inside the target repository, then run `/daedalus:build-train` again.
2. Run `python3 ${CLAUDE_PLUGIN_ROOT}/scripts/daedalus_workspace.py begin --repo <repo>` (0024). It refuses a dirty tree, reads `<repo>/.claude/daedalus/config.json` (0010; an absent config.json means the defaults: no `charter_root`, no `standards_sources`, no `policy`), probes the decision ledger (0004), creates `<repo>/.claude/daedalus/`, the folder for train state and the audit log (0035), sets `<train-id>` to the UTC time as `YYYYMMDD-HHMMSS`, creates `<repo>/docs/.tmp/daedalus/` with its `docs/.tmp/daedalus/.gitignore` so git ignores the train's scratch files and summary, branches a declared Charter to `daedalus/<train-id>` and marks the train active (0023).
   - Exit 0: it prints the first six State Block lines; copy them unchanged. The first line ends in `audit session: pending`; step 3 fills it in.
   - Exit 3: begin found no decision ledger and wrote nothing; ask the operator the question it prints, exactly.
     - An existing file: Next: add a `ledger` block naming it to `<repo>/.claude/daedalus/config.json` from your own shell (docs/project-requirements.md), then run `/daedalus:build-train` again.
     - Create: write `<repo>/docs/decisions.md` holding only the two table lines it prints, the header and its separator. Run `python3 ${CLAUDE_PLUGIN_ROOT}/scripts/append_ledger.py --probe` and show its line; it reads `seq=0`. Next: review and commit docs/decisions.md from your own shell, then run `/daedalus:build-train` again.
   - Exit 1: show its output unchanged and stop; begin left no train behind, so the stop command does not run. Its `Next:` line is the next action.
3. Run `python3 ${CLAUDE_PLUGIN_ROOT}/scripts/verify_audit_chain.py --hooks-live --repo <repo>`. It checks that this session's hooks are writing the audit log. Exit 0 prints `OK hooks live: session <id>, ...`; record `<id>` in the State Block as `audit session: <id>`. Exit 1: stop and show its output; its `Next:` line is the next action.

The first six lines of the **State Block** are begin's output, with the audit session id from step 3. The orchestrator keeps the full block and prints it at a stop, at a resume and in the summary:

    train: <train-id>  base: <branch> @ <sha>  audit session: <id>
    ledger: <path> (<origin>, <format>, seq=<n>)
    charter_root: <path or none>  charter base: <recorded branch or none>
    policy: <engine and path, or none declared>  standards: <n> sources
    cache: <path>/frameworks (or: cache: unresolved)
    standards packs: <name> at <path>, or none declared

## Relay

1. Record the agent choice: run `python3 ${CLAUDE_PLUGIN_ROOT}/scripts/daedalus_train.py choice --repo <repo> --chose "one orchestrator agent runs the train" --over "the main session runs every phase" --cost "one agent context; the session keeps only the relay"` and show its line. Then Agent(`orchestrator`) with a prompt holding, each on its own line: `Repo: <repo>`, `Plugin root: <the plugin root written out in full>`, `Task: $ARGUMENTS` (or `Spec: <path>` when the operator named a spec file), `Plan: <path>` when the operator named a plan file `/daedalus:plan` wrote, and the six State Block lines. Record the agent id the call returns; every resume addresses it.
2. Read the orchestrator's last line and route it:
   - `[STATUS: DECISION] brief=<path> questions=<n>`: read the brief file. Ask each question with AskUserQuestion exactly as the brief writes it: its header, its question, its context sentences and its options in the order given, the recommended option first. At most four questions go in one call. When the operator picks `Follow Plugin + amend global`, edit the one global rule line by hand from your own shell now and show the diff (0066); a plugin agent never makes this edit. Then SendMessage(orchestrator, "DECIDED.\n<one line per question: <header>: <the option picked>; reason: <the operator's words, or none>>") and read its next reply from this step.
   - `[STATUS: EXCEPTION] ledger_id=<id>`: the operator picked the merge with tracked-risk issues after the second rejected audit round, and charter-docs committed that exception ruling. Check that `<id>` is the ruling the orchestrator's last decision brief led to, then run `python3 ${CLAUDE_PLUGIN_ROOT}/scripts/daedalus_train.py exception --repo <repo> --ledger-id <id>` yourself; it binds the ruling to the integration tip. The orchestrator never runs it. Show its line, then SendMessage(orchestrator, "EXCEPTION BOUND. <its printed line>") and read its next reply from this step. Exit 1: stop with its output as the reason.
   - `[STATUS: STOP] reason=<what happened> next=<next action>`: run the stop command with that reason and that next action, and show its output. When the operator says continue, run the resume command, then SendMessage(orchestrator, "RESUMED. Go on at the step your stop named.") and read its next reply from this step.
   - `[STATUS: TRAIN_COMPLETE] summary=<path> audit_log=<path>`: show the summary path and the audit log path. Then end the train: run `python3 ${CLAUDE_PLUGIN_ROOT}/scripts/daedalus_workspace.py stop --repo <repo> --reason "train complete" --next "review the integration branch, run /daedalus:audit-report <id> to read this session's audit log, then run /daedalus:push-train to push the branch and open the pull request"` and show its output.
   - Any other last line: stop with the reason "the orchestrator's reply ended off its contract" and show its last 10 lines. Next: rerun the train or report the orchestrator.
3. If SendMessage to the orchestrator fails, never start a second orchestrator; it would start without the first one's State Block and the train's half-done state. Stop with "The orchestrator cannot be resumed. Next: rerun the train; the integration branch daedalus/<train-id> and every unit branch are kept for reference."
4. While the orchestrator runs, a refused call of one of its agents comes back to it, not to you. A hook that asks you instead (0106) asks about a call of your own session; the operator approves or denies it.
