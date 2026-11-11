---
name: derived
description: The derived document kind of the writer. Derives one document from frozen, manifest-declared sources with a file:line receipt on every value, and writes only under the declared output directory. Never recommends, never pushes.
---
<!-- Copyright (c) 2026 Brad Duhon. SPDX-License-Identifier: GPL-3.0-or-later -->

# Derived document kind

Self-Assessment mode (standing rule, binds only the model in the user's session, never a helper or an agent this skill starts): When this skill begins, run `python3 ${CLAUDE_PLUGIN_ROOT}/scripts/daedalus_findings.py start --repo <path>`, where `<path>` is the project folder. Keep the `since=` stamp and the `handover=` path it prints. When it prints `self-assessment: off` or `self-assessment: refused`, do nothing more for findings in this skill. Write a finding with `kind` set to `bug` when you work around this skill's text because the text failed. Write a finding with `kind` set to `feature` when the user passes over a proposal, a choice list or a step order this skill offered. Never write a finding for a change to the user's own plan. To write a finding, use the Write tool to put one JSON object with the seven fields `kind`, `skill`, `step`, `text_said`, `happened`, `model_did` and `result_changed` at the `handover=` path, then run `python3 ${CLAUDE_PLUGIN_ROOT}/scripts/daedalus_findings.py save --repo <path> --since <stamp>`, where `<stamp>` is the `since=` stamp. Fill each field with one line in this skill's own words, and name no project folder. Never pass finding text on the command line, and never write a finding file in the project. When `result_changed` is `yes`, print one warning line at once saying you worked around the skill. When save prints a `refused:` line, fix the field it names and save once more. When it refuses a second time, drop that finding and name it at the close. At the close of this skill, run `python3 ${CLAUDE_PLUGIN_ROOT}/scripts/daedalus_findings.py show --repo <path> --since <stamp>` and print its lines unchanged, then name any finding that was refused twice. Never stop the user's work for a finding.

You write this kind in a document run (0135, Addendum D.4.2). The Source Manifest at the top of
your brief is law: it names every source by alias, role, path, sha256 and line count, and the
one `output_dir` you may write under.

1. **Sources**: read only the manifest paths. `baseline` supplies every value. `amendment`
   text may replace baseline text only for its `allowed_for` topics. `style` sources give
   register only; take no term, number, period, or mechanism from them. `correspondence` is
   quotable for what a party agreed, with its line. `reference` is anything else, read-only.
2. **Receipts**: every value, count, period, percentage, actor, and deciding phrase carries
   `<alias>:<line>` or `<alias>:<start>-<end>`, read from the file in this session. A clause
   id may sit beside a receipt, never replace it. Where a phrase decides the meaning (a
   carve-out, a condition, an actor), quote it. A claim you cannot receipt is written
   `ASSUMED:` and listed in your return.
3. **Output**: exactly the files the brief names, under `output_dir`. Nothing else is written.
   The document outputs hook refuses a write outside `output_dir` and any write to a source.
4. **No judgment**: where the baseline contradicts itself or the brief leaves a choice, carry
   both readings or tag the line `[judgment: <one line>]` and list it. Never resolve it.
5. **Counts**: run the counting command the brief names and paste its output. A number typed
   from memory is a defect.
6. **Priorities**: the brief carries the Standards Packet's `## Priorities` section (0137).
   Where the brief leaves a trade between two drivers open, follow its ranking and cite the
   ranking line or rule number in a `[judgment]` line.
7. **Shell**: Bash runs read-only inspection only, such as `grep -n`, `wc -l`, `sha256sum`
   and `cat`; no git, no gh, no network. No shell redirects (`>`, `<`, `2>&1`,
   `2>/dev/null`); the Bash tool already returns stderr. Write files with Write or Edit.
8. **Fix rounds**: a resume that starts `FIX.` lists verifier rows. Apply each row's exact
   edit and nothing more, then return again with every claim of the output as it now stands.

Your return lists one claim per receipted value, one line each, so the verifier can check it in
its claims mode: `Claim: <output path>:<line> <claim> | receipt: <alias>:<line or range>`.

## Status lines
This kind ends with one of these two lines of the writer's status contract. Above it: the
output paths with `wc -l`, every count with its command, every `[judgment]` line verbatim,
every `ASSUMED`, the `Claim:` lines, and a five-item spot-check (recorded by the orchestrator,
not treated as evidence).
- `[STATUS: COMPLETE] outputs=<path>[,<path>] claims=<n> judgments=<k> assumed=<m>`
- `[STATUS: BLOCKED] <what the manifest or brief leaves out>`
