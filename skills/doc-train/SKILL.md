---
name: doc-train
description: Runs a Document Train against frozen sources. Freezes the sources, has the doc-deriver write the document with a receipt on every value, has the verifier check every claim, has the change-logger build the change gate against the baseline, and presents the result for the operator's rulings. Never pushes, never stages, never commits.
argument-hint: What to derive, from which frozen sources, into which output folder.
---
<!-- Copyright (c) 2026 Brad Duhon. SPDX-License-Identifier: GPL-3.0-or-later -->

# daedalus Document Train

You are the orchestrator of this document train. The train is a recipe you compose from catalog agents, in the shape of the Build and Push Trains (0135, 0088): you run the stages freeze, derive, verify, change gate, docs writer and present, and you dispatch each agent yourself, as the Push Train does. No train definition file and no runner exist for it. You do not derive documents yourself; the doc-deriver does, and the verifier grades it.

Rules for the whole train:
- Read `/daedalus:catalog` first. It names every agent, its reply lines and the per-finding audit prompt this recipe uses.
- Zero `git push`, zero `gh`, nothing staged or committed. Outputs often sit under an excluded root (the `excluded_roots` config key); the jail refuses any agent's git, gh or redirect that names such a path, and warns this session about its own during a train (0136, 0130).
- Start each agent with the Agent tool, written below as `Agent(<name>)`; Claude Code loads it as `daedalus:<name>`. Before each first start, run `python3 ${CLAUDE_PLUGIN_ROOT}/scripts/daedalus_train.py model --repo <repo> --agent <name>` and pass the word it prints as `model:`. Resume an agent with SendMessage.
- Brief by file: write each brief under `<repo>/docs/.tmp/daedalus/<train-id>/briefs/`. The manifest block freeze printed comes first in every brief, byte for byte, then the two packet lines `Standards: <path> sha256=<hex>` and, when a contract exists, `Contract: <path> sha256=<hex>`. Print each dispatch as three lines, `Dispatch: <agent>`, `Prompt file: <path>` and `Expect: <reply lines>`.
- Priorities (0137): every brief, for every agent this recipe dispatches, carries the Standards Packet's `## Priorities` section verbatim as a brief input, or its single line `priorities: none declared`. The doc-deriver, the verifier, the change-logger and the docs-writer each get it; the standards-rules-specialist builds the packet that holds it.
- Every stop shows the operator what happened and names the next action as a `Next:` line. Before it, run `python3 ${CLAUDE_PLUGIN_ROOT}/scripts/daedalus_workspace.py unmark --repo <repo>`.
- Human-facing text (0031): Text a human reads names each item in words: a short label or one line on what it is and what it does. Ids (ruling ids, issue numbers, task codes, agent names, snake_case keys) may trail in parentheses, never replace the description. Logs, status lines and messages to other agents may use ids alone. Documents carry both.

## Preconditions

1. Set `<repo>` to the parent of the directory `git rev-parse --path-format=absolute --git-common-dir` prints. Not a repo: stop. Next: start the session inside the repository that holds the sources, then run `/daedalus:doc-train` again.
2. Every source is a frozen copy, such as `*.sent-<date>.*` or a dated report. A working file is not a source: stop and name it. Next: copy the working file to a dated `.sent-<date>` copy from your own shell, then name that copy.
3. The output folder exists. Not there: stop. Next: create it from your own shell, then rerun.
4. Set `<train-id>` to the output of `date -u +%Y%m%d-%H%M%S`. Run `python3 ${CLAUDE_PLUGIN_ROOT}/scripts/daedalus_workspace.py mark --repo <repo> --train <train-id>`. The document outputs hook reads the active train from this marker, so the doc-deriver and the change-logger write nothing before it exists. Exit 1: stop and show its message.
5. Run `python3 ${CLAUDE_PLUGIN_ROOT}/scripts/verify_audit_chain.py --hooks-live --repo <repo>`. Exit 0 prints `OK hooks live: session <id>, ...`; record `<id>`. Exit 1: stop and show its output; its `Next:` line is the next action.

The **State Block** holds: `train: <train-id>  audit session: <id>`, the manifest path and its sha256, each output with its path and status, the verifier rounds run, the open `[judgment]` lines and the open change-log rows. Print it at a stop and in the present stage.

## Stage 1: Freeze

1. Run `python3 ${CLAUDE_PLUGIN_ROOT}/scripts/freeze_sources.py --train <train-id> --output-dir <output folder> --source <alias>=<role>:<path>[:<topic>,...] ...`, one `--source` per source. When the operator names two baselines and no document to derive, add `--baselines-only`: the change-logger diffs the two baselines and the derive and verify stages are skipped (0136 item 7).
   - Exit 0: keep the manifest block it prints, unchanged, and run `sha256sum <repo>/.claude/daedalus/trains/<train-id>.sources.json` for the State Block. Its stderr names `[EXCLUDED_ROOTS: none declared]` or a warning that the output folder sits under no excluded root; show either line and state in the State Block that the outputs can be committed, and by whom.
   - Exit 1, 2 or 3: a missing or working source, a bad source shape, or an excluded root git does not ignore. Stop and show its output. Next: the action its message names, then rerun.
2. When `<repo>/.claude/daedalus/config.json` declares `standards_sources`, Agent(`standards-rules-specialist`) with the task and the line "Return the Standards Packet with its `## Priorities` section." Write its packet to `<repo>/docs/.tmp/daedalus/<train-id>/standards-packet.md` and record its sha256. Without declared sources, write a packet holding `## Priorities` and the line `priorities: none declared`.

## Stage 2: Derive

Skipped with `--baselines-only`. Write the brief: the manifest block, the packet lines, the `## Priorities` section, the exact output path or paths, what each section holds, the row or clause cap, the counting commands, the line "No recommendations." and the doc-deriver's status contract. Agent(`doc-deriver`) with a prompt naming the brief path.
- `[STATUS: COMPLETE] ...`: record the output paths, the `Claim:` lines, every `[judgment]` line and every `ASSUMED` tag. Record the spot-check; never use it as evidence.
- `[STATUS: BLOCKED] <detail>`: stop with the detail. Next: give the brief what it lacks, then rerun.

## Stage 3: Verify

Skipped with `--baselines-only`; never skipped otherwise.
1. Run `python3 ${CLAUDE_PLUGIN_ROOT}/scripts/freeze_sources.py --verify <repo>/.claude/daedalus/trains/<train-id>.sources.json`. Exit 4: a source changed or the manifest is broken, so the train stops. Next: freeze the sources again under a new train. Exit 5: the outputs carry an en or em dash, placeholder copy or a style-source sentence carrying a number; this is a failed gate, and each finding line goes to step 4 as a refuted row. Exit 0: go on.
2. Round 1: Agent(`verifier`) with a prompt whose first line is `CLAIMS MODE.`, then the manifest block, the `## Priorities` section, and one `Claim: <output path>:<line> <claim>` line per claim of the doc-deriver's reply, its receipt included. The outputs are files the verifier reads at their paths; name no branch. Read the first and last verdict lines.
3. `[VERDICT: VERIFIED] claims=<n>`: record the counts and go to Stage 4.
4. `[VERDICT: REFUTED] <rows>`: no round budget applies (0133). Put each row to the operator through the per-finding audit prompt of `/daedalus:catalog`: `Fix it now (Recommended)`, `Skip, track or exempt it` or `Stop the train`, with the tracking question (`Skip it`, `Track it` or `Exempt it`) after `Skip, track or exempt it`. An exempted row is listed in the present stage with its tracking answer. `Stop the train` stops the train.
5. A fix round, for the rows the operator picked `Fix it now` on: apply verifier findings of ten lines or fewer yourself, with Edit on the output only and the row's exact edit, nothing more (0136 item 2). Send larger findings to the doc-deriver as SendMessage(doc-deriver, "FIX. The verifier refuted: <rows>") and record its new `Claim:` lines.
6. Then run step 1 again, and send the warm verifier only the edited claims, by SendMessage with the first line `CLAIMS MODE.` and one `Claim:` line per edited claim. Rounds 2 and 3 read the claims the verifier rejected in the prior round plus a random 20 percent sample of the rest; the verifier draws that sample and names it in its table (0136 item 3). After round 3, a further fix round starts a new Agent(`verifier`), whose round 1 checks every claim. Read the verdict from step 3.

## Stage 4: Change gate

Runs only when the manifest declares a `baseline` role; a document with no prior version has nothing to gate against. Write the brief: the manifest block, the `## Priorities` section, the baseline alias, the derived document's path, the drafting log when one exists, and the change log path under the output folder. With `--baselines-only`, name the two baseline aliases instead, the earlier one first, and no derived path. Agent(`change-logger`) with a prompt naming the brief path.
- `[STATUS: COMPLETE] change_log=<path> rows=<n> open=<k>`: send its `Claim:` lines, which cover the change log's "Baseline says" column only, through Stage 3 steps 2 to 6, with the change logger in the doc-deriver's place for fixes.
- `[STATUS: BLOCKED] <detail>`: stop with the detail. Next: give the brief what it lacks, then rerun.

## Stage 5: Docs writer

The docs writer is named as a stage and runs only when the operator's task says the outputs change what the project's four public docs describe. Then follow the documentation stage of the Build Train recipe in `agents/orchestrator.md`: its docs worktree, its brief with the `Literacy:` line and the `## Priorities` section, Agent(`docs-writer`), and the verifier's claims mode over the writer's claims. Otherwise record `Docs: not run` in the State Block.

## Stage 6: Present

1. One message: the outputs with their paths; the verifier counts per round; every `[judgment]` line; every `ASSUMED` tag; every exempted row with its tracking answer; the change log's rows grouped by status; the State Block; and the audit log path `<repo>/.claude/daedalus/audit/<audit session>.jsonl`.
2. Every `open, needs a ruling` row and every `[judgment]` line goes to the operator with AskUserQuestion as a decision brief: the context sentences, the options with their consequences, and no recommendation unless the operator asked for one. Record each answer in the change log's status column with Edit, never in the derived document, until the operator says the row is agreed.
3. Nothing is pushed, staged, committed or sent. Run `python3 ${CLAUDE_PLUGIN_ROOT}/scripts/daedalus_workspace.py unmark --repo <repo>` and show its line. Next: review the outputs; nothing derived is used anywhere until its rows read agreed.
