---
name: document
description: The document phase of a run, in two modes. Public docs mode has the docs-writer make the four public docs say what the merged diff made true, every passage with a rerunnable receipt, and records the docs verdict. Derived document mode freezes the sources, has the doc-deriver write the document with a receipt on every value, builds the change gate against a baseline and presents the rows for the operator's rulings. Never pushes.
---
<!-- Copyright (c) 2026 Brad Duhon. SPDX-License-Identifier: GPL-3.0-or-later -->

# daedalus document

Human-facing text (0031): Text a human reads names each item in words: a short label or one line on what it is and what it does. Ids (ruling ids, issue numbers, task codes, agent names, snake_case keys) may trail in parentheses, never replace the description. Logs, status lines and messages to other agents may use ids alone. Documents carry both.

This skill is the document phase (0165). Public docs mode runs inside a run after the audit phase recorded its verdict, and the orchestrator runs it (0134). Derived document mode is the document recipe started today with `/daedalus:doc-train` (0135); its steps are dispatched from the session that started it. Every stop shows the operator what happened and names the next action as a `Next:` line. Commands write the plugin root out in full in place of `${CLAUDE_PLUGIN_ROOT}` when the orchestrator runs them, because its hook refuses `$`, `~` and braces in a command.

## What the phase does well

In public docs mode the phase derives what is now true from the merged diff and the hand-back summaries, and makes the four public docs say it, every passage with a rerunnable receipt. In derived document mode it freezes the sources, derives with a receipt on every value, builds the change gate against a baseline, and presents the rows for the operator's rulings. Both modes send every claim to the verify phase in claims mode (`${CLAUDE_PLUGIN_ROOT}/skills/verify/SKILL.md`).

### Public docs mode

The docs writer ends the run (0134). It runs after the security verdict record of the audit phase, and before that phase's last summary command; when every finding was exempted, after the main session bound the exemptions. Its writes reach only the four public docs: `README.md`, `docs/howto/README.md`, `docs/guardrails.md` and `docs/project-requirements.md`.

1. Run `python3 ${CLAUDE_PLUGIN_ROOT}/scripts/daedalus_workspace.py create --repo <repo> --name <train-id>-docstage --base daedalus/<train-id>`. It prints the worktree path; the orchestrator records it and the branch `daedalus-unit/<train-id>-docstage`. A non-zero exit: stop and show its output.
2. Literacy: run `cat <repo>/service-manifest.json` and read `docs.literacy`. A `Literacy:` line in the operator's task overrides it. Write `Literacy: none` when neither declares one.
3. Write the brief file `<repo>/docs/.tmp/daedalus/<train-id>/briefs/docs.md`, holding: the two packet lines; the diff base, the run's base sha; the integration branch `daedalus/<train-id>` and its tip, from `git -C <repo> rev-parse daedalus/<train-id>`; the hand-back summary of every unit whose agent changed something, each the unit's last `[STATUS: COMPLETE]` reply with its receipts and ledger notes, fix units included; the four public docs by path; the `Literacy:` line; and the line `Worktree: <docs worktree path>`. Print the dispatch as three lines, `Dispatch: docs-writer`, `Prompt file: <brief path>` and `Expect: <the two reply lines of the docs writer's status contract>`. Run `python3 ${CLAUDE_PLUGIN_ROOT}/scripts/daedalus_train.py model --repo <repo> --agent docs-writer`, then dispatch `docs-writer` with that model and a prompt naming the brief path and the same `Worktree:` line.
4. The docs writer reads the full diff, takes the diff over a hand-back summary where they differ, rewrites each passage the diff made untrue, and writes one claim per edited passage: `Claim: <doc path>:<line> <what the passage now says> | receipt: <command>`. A passage saying a check, gate or refusal exists carries a receipt that includes the caller grep. A passage with no rerunnable receipt is not written.
5. `[STATUS: DOCS_UNCHANGED] reason=<why>`: no claim exists to verify; go on to step 8.
6. `[STATUS: DOCS_WRITTEN] branch=<b> commit=<sha> claims=<n>`: compare `<b>` with the recorded docs branch; a mismatch stops the run as a coder's branch mismatch does. Then send the writer's claims to the verify phase in claims mode: the first line `CLAIMS MODE.`, one `Claim: <doc path>:<line> <claim>` line per claim of the writer's reply with its receipt, then `Branch: <b>`, `Docs tip: <sha>` with the docs branch head from `git -C <repo> rev-parse <b>`, `Diff base: <the integration tip of step 3>` and `Unit worktree: <docs worktree path>`. Name the worktree on a `Unit worktree:` line, never a `Worktree:` line.
7. Route the claims verdict.
   - `[VERDICT: VERIFIED] claims=<n>`: run the build phase's finish; it merges the docs branch onto `daedalus/<train-id>`. Then record the docs verdict on the merged tip (0131): `python3 ${CLAUDE_PLUGIN_ROOT}/scripts/daedalus_train.py verdict --repo <repo> --gate docs --status verified --judged <sha>`, with the `Docs tip:` sha of step 6; it refuses when the merged docs commits end at another sha. It prints `docs verdict recorded status=verified tip=<12 hex>`. Exit 1: stop and show its output; its `Next:` line is the next action. Then go on to step 8.
   - `[VERDICT: REFUTED] <rows>`: write one line per refuted claim, `<doc path>:<line> | <severity> | docs`, to `<repo>/docs/.tmp/daedalus/<train-id>/docs/findings.txt`. Each refuted claim goes to the operator through the per-finding audit prompt of the catalog, one decision question per refuted claim with the options `Fix it now (Recommended)`, `Skip, track or exempt it` and `Stop the run`, plus the tracking question on an exemption (0133, 0139). A fix round resumes the docs writer with a `FIX.` message naming the refuted rows, then step 6 runs again on its next reply. When every refuted claim is exempted, run the build phase's finish to merge the docs branch, then `python3 ${CLAUDE_PLUGIN_ROOT}/scripts/daedalus_train.py verdict --repo <repo> --gate docs --status refuted --findings <repo>/docs/.tmp/daedalus/<train-id>/docs/findings.txt`, which prints `docs verdict recorded status=refuted tip=<12 hex>`. The exemption ruling rides a charter-docs dispatch as at the audit phase's ledger step, and the main session records each exemption into the docs record with the exception command.
8. Summary command: run `python3 ${CLAUDE_PLUGIN_ROOT}/scripts/daedalus_train.py summary --repo <repo>` after the docs record, or after `[STATUS: DOCS_UNCHANGED]`. Its `## Audit` section names the security verdict and the docs verdict, and reads `Docs: not run` when no docs record exists. The run completes only after both: the security verdict record and the docs record, or the writer's `[STATUS: DOCS_UNCHANGED]`. The push proof admits the docs merge past the judged tip only when every commit after it changes nothing but the four public docs and the docs record names the tip those docs commits end at (the current tip, or the commit below one ledger-only commit on top of them) verified, or every refuted claim exempted.

### Derived document mode

This mode follows the stages of `/daedalus:doc-train`, which holds its preconditions, its rules and its State Block (`${CLAUDE_PLUGIN_ROOT}/skills/doc-train/SKILL.md`). Nothing is pushed, staged or committed, and every brief carries the Standards Packet's `## Priorities` section (0136, 0137).

9. Freeze. Run `python3 ${CLAUDE_PLUGIN_ROOT}/scripts/freeze_sources.py --train <train-id> --output-dir <output folder> --source <alias>=<role>:<path>[:<topic>,...] ...`, one `--source` per source. Every source is a frozen copy, such as `*.sent-<date>.*` or a dated report; a working file is not a source. With two baselines and no document to derive, add `--baselines-only`: the change-logger diffs the two baselines and the derive and verify steps are skipped (0136 item 7). Keep the manifest block it prints, unchanged; it comes first in every brief. Exit 1, 2 or 3: stop and show its output. Next: the action its message names, then rerun.
10. Derive. Write the brief: the manifest block, the packet lines, the `## Priorities` section, the exact output path or paths, what each section holds, the row or clause cap, the counting commands, the line "No recommendations." and the doc-deriver's status contract. Dispatch `doc-deriver` with a prompt naming the brief path. `[STATUS: COMPLETE] ...`: record the output paths, the `Claim:` lines, every `[judgment]` line and every `ASSUMED` tag. `[STATUS: BLOCKED] <detail>`: stop with the detail. Next: give the brief what it lacks, then rerun.
11. Verify. Run `python3 ${CLAUDE_PLUGIN_ROOT}/scripts/freeze_sources.py --verify <repo>/.claude/daedalus/trains/<train-id>.sources.json`. Exit 4: a source changed or the manifest is broken, so the run stops. Next: freeze the sources again under a new run. Exit 5: each finding line it prints is a refuted row. Exit 0: send the deriver's claims to the verify phase in claims mode, the outputs read at their paths with no branch named. Each refuted row goes to the operator through the per-finding audit prompt of the catalog; a `Fix it now` pick sends a finding of ten lines or fewer to an exact Edit on the output, and a larger one back to the doc-deriver as a `FIX.` message. Rounds 2 and 3 check the rejected claims plus a 20 percent sample of the rest.
12. Change gate. Runs only when the manifest declares a `baseline` role; a document with no prior version has nothing to gate against. Write the brief: the manifest block, the `## Priorities` section, the baseline alias, the derived document's path, the drafting log when one exists, and the change log path under the output folder. Dispatch `change-logger`. `[STATUS: COMPLETE] change_log=<path> rows=<n> open=<k>`: its `Claim:` lines, which cover the change log's "Baseline says" column only, go through step 11 with the change logger in the doc-deriver's place for fixes.
13. Present. One message: the outputs with their paths, the verifier counts per round, every `[judgment]` line, every `ASSUMED` tag, every exempted row with its tracking answer, and the change log's rows grouped by status. Every `open, needs a ruling` row and every `[judgment]` line goes to the operator as a decision brief, with no recommendation unless the operator asked for one. Record each answer in the change log's status column, never in the derived document, until the operator says the row is agreed. Next: review the outputs; nothing derived is used anywhere until its rows read agreed.

## Evidence that ends it

- Public docs: a docs record naming the docs tip as verified, or every refuted claim exempted (scripts/lib/train_runner.py:1902). The push proof admits only docs commits past the judged tip (scripts/lib/audit_proof.py:703).
- Derived documents: the verifier's verdict, and every change-log row agreed by the operator. No hook (`skills/doc-train/SKILL.md`, the verify, change gate and present stages).

## Agents it uses

- docs-writer, for the four public docs (step 3).
- doc-deriver, which derives the document from frozen sources (step 10).
- change-logger, which builds the change gate against the baseline (step 12).
- verifier in claims mode, through the verify phase (steps 6 and 11).
- standards-rules-specialist, for the Standards Packet with its `## Priorities` section.

## Suggested next

- `verify`: always, in claims mode, for every claim this phase produces.
- `release`: when the docs record is written and the run lives in a repository.
- `none`: in a plain folder, where the run ends at the present step.
