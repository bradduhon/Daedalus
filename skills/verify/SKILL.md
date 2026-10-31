---
name: verify
description: The verify phase of a run. Has the verifier judge each finished unit's diff against its brief, never against the coder's report, and routes its verdict. In claims mode it checks each listed claim of a producer at its line, for the writer, the comparer or a planner spec. Read-only; writes no code.
---
<!-- Copyright (c) 2026 Brad Duhon. SPDX-License-Identifier: GPL-3.0-or-later -->

# daedalus verify

Human-facing text (0031): Text a human reads names each item in words: a short label or one line on what it is and what it does. Ids (ruling ids, issue numbers, task codes, agent names, snake_case keys) may trail in parentheses, never replace the description. Logs, status lines and messages to other agents may use ids alone. Documents carry both.

This skill is the verify phase (0165). The orchestrator runs it inside a run, once per unit the moment the unit returns `[STATUS: COMPLETE]`, while later units build (0060). A producer's claims pass runs it in claims mode. Every stop here is the orchestrator's stop line, and the main session runs the stop command. Commands write the plugin root out in full in place of `${CLAUDE_PLUGIN_ROOT}`, because the orchestrator's hook refuses `$`, `~` and braces in a command.

## What the phase does well

The verifier judges each unit's diff against its brief, never against the coder's report (0128). The brief is the claim list: the unit's requirement section, its files list, the contract pins that bind it and the Standards Packet. The coder's report is receipts only, and agreement earns nothing.

### Unit mode

1. When it runs (spec 5). Once per unit, after its `[STATUS: COMPLETE]` passes the branch, packet, descent and jail check rows of the build phase (`${CLAUDE_PLUGIN_ROOT}/skills/build/SKILL.md`, step 7), and before the build phase's finish merges it.
2. Map check. Before each verifier dispatch, run the map command with `--check` added: `python3 ${CLAUDE_PLUGIN_ROOT}/scripts/daedalus_map.py --repo <repo> --out <repo>/docs/.tmp/daedalus/<train-id>/map --plan <plan path> --check`. Exit 0 prints `OK map: ... is current`; exit 1 means the map is stale against the tree, so rerun it without `--check` and record the new hash before the dispatch.
3. The `Read:` line. Asset exclusion (0192): first run `python3 ${CLAUDE_PLUGIN_ROOT}/scripts/daedalus_train.py assets --repo <repo> --base <lock sha> --tip <b>`. Exit 0 prints `Assets: none`, or an `Assets: <tail>` line with one `Over size: <file> (<n> bytes)` line per changed file over the size limit; exit 1: stop and show its output. With a tail, the `-U0` command below ends with it, copied exactly, so no asset file reaches the `Read:` or `Open:` line. Build it with `git -C <repo> diff -U0 <lock sha>...<b>`, the short form of `--unified=0` the hook admits: each hunk header `+<first>,<count>` gives `<file>:<first>-<first + count - 1>`, and a count of 0 gives `<file>:<first>-<first>`. Then, for each changed module, add the line of each importer its map entry `imports.<module path>.fan_in` names that imports it, from `git -C <repo> grep -n <module name> <b>`. The `Read:` line names where to look first and never replaces the full diff, whose `-` lines show a removed guard. Then build the `Open:` line (item 15), which names once, as absolute paths, every file the verifier opens: the brief file, the Contract and Standards files its packet lines name (no contract file under `Contract: none`), each file of the unit's `files:` list in the unit worktree that exists on `<b>`, and each test file the coder's `- test` receipts run that is not on that list. The verifier opens the set in one turn and never searches for a file it names.
4. Dispatch. The first time, run `python3 ${CLAUDE_PLUGIN_ROOT}/scripts/daedalus_train.py model --repo <repo> --agent verifier` and pass its word as `model:` (spec 4). Dispatch `verifier` with:
   - the unit's branch `<b>`, and its diff base, the recorded lock sha;
   - the line `Unit worktree: <unit worktree path>`;
   - the line `Brief: <the unit's brief path from the build phase>`;
   - the line `Map: <repo>/docs/.tmp/daedalus/<train-id>/map/map.json` when that file exists;
   - the line `Read: <file>:<first>-<last>[, ...]` from step 3;
   - the line `Open: <path>[, ...]` from step 3;
   - the `Assets: <tail>` line and its `Over size:` lines from step 3, unchanged, when it printed a tail; the verifier ends its full diff command with that tail;
   - the coder's `[STATUS: COMPLETE]` line with its ledger notes and the `## Receipts` block above it, as receipts only;
   - and "Read the full diff `git -C <unit worktree path> diff <lock sha>...<b>`, removed lines included; the `Read:` ranges guide your attention and never bound it. Open every file of the `Open:` line in one turn of parallel Read calls before anything else, and never search with Grep, Glob or find for a file it names. Judge every requirement, the files list, every pin and every Standards Packet rule of the brief against the branch. Typecheck and lint receipts are judged from the coder's receipts block, not rerun; only a pytest run is reproduced. Class each refuted row `code` or `scope`; correct a wrong receipt and count it on the `corrected=<k>` line. Reply with `[VERDICT: VERIFIED] claims=<n>` or `[VERDICT: REFUTED] <rows>` as your first and last line."

   Name the worktree on a `Unit worktree:` line, never a `Worktree:` line, because the hook reads a resume's `Worktree:` line as a coder moving to a new unit. The verifier stays warm (0086): every later unit goes to it by the orchestrator's message with the same items.
5. Route the verdict. Read it from the last line; the verifier's verdict line is also its first line, and a reply whose first and last lines differ is off its contract: stop and show its last 10 lines.
   - `[VERDICT: VERIFIED] claims=<n>`: the orchestrator records the unit as verified with `<n>` claims and the `<k>` of the `corrected=<k>` line above the verdict. A correction never goes back to the coder and never counts as a refutation (0127). The unit is ready for the build phase's merge once its operator checks below are answered.
   - Operator checks (0164, 0192). After a VERIFIED verdict, the unit has one operator check per entry of its plan line's `operator_checks:` field. It has one more, the manifest's `dev_server` check, when `dev_server` is set and the unit touches web code: the stack declares a `vitest` or `tsc` command, or the unit's files include a `.ts`, `.tsx` or `.html` file. Read `dev_server` and `stack` from `<repo>/service-manifest.json` with `cat`. For each check, write one decision brief question in the shape of the per-finding audit prompt of the catalog, at the manifest's literacy level, such as "Open http://localhost:5173 in your browser. Does the scene load, and can the player move?", with the options `Pass`, `Fail` and `Skip`. A dev server question names its url and its check text; a plan check question names the url too when `dev_server` is set. The main session asks it. `Pass` records the answer. `Fail` is a refuted `code` row routed like a verifier refutation, by the same count of refutations on the unit: the first goes back to that unit's warm coder as a `FIX.` message naming the failed check and the operator's words, and the second and third take the steps above. `Skip` records the operator's reason. Write each answer into the unit's evidence as `operator check | <url or none> | <check text> | <pass, fail or skip> | <the operator's words>`. Daedalus never starts, polls or fetches the site; the operator hosts it.
   - `[VERDICT: REFUTED] <rows>`: only rows of class `code` or `scope` count (0127); a REFUTED with neither is off its contract. The first REFUTED on a unit sends that unit's coder one fix pass with the `code` and `scope` rows, as a `FIX.` message: SendMessage(that unit's coder, "FIX. The verifier refuted: <code and scope rows>"). Its next `[STATUS: COMPLETE]` runs the build phase's checks and this phase again. The second REFUTED on the same unit goes to a fresh coder on the `escalated` model through the build phase's second-refutation step (`${CLAUDE_PLUGIN_ROOT}/skills/build/SKILL.md`, step 5), and the run goes on (0187, issue 115). A third REFUTED on the same unit goes to the operator as a decision (0161, 0133): one question per refuted row, through the per-finding audit prompt of the catalog (`${CLAUDE_PLUGIN_ROOT}/skills/catalog/SKILL.md`), with the options `Fix it now (Recommended)`, `Skip, track or exempt it` and `Stop the run`. Only the operator's pick starts another fix pass, records an exemption or ends the run.

### Claims mode

6. A producer's claims go to the verifier in a prompt whose first line is `CLAIMS MODE.`, with one `Claim: <output path>:<line> <claim>` line per claim (pin VER -> DOCT; 0136). The producers are the writer in either kind, the comparer and a planner spec at the brainstorm hand-off. The prompt carries no requirement section, so the verifier checks only the listed claims.
7. The verifier prints each named line, through `git -C <worktree> show <branch>:<file> | sed -n <first>,<last>p` for a path on a branch, else a Read at that line. Each claim gets one verdict: MATCH, WRONG VALUE, WRONG LINE, MISSING, OVERSTATED, NARROWED or WIDENED. A clause number beside a claim gets two checks: the line holds the claim, and the number names that line's clause. A claim that a mechanism enforces, refuses, checks or gates something gets two checks: existence (its definition) and attachment (a caller on the path it governs); existence alone is OVERSTATED. A claim that is not MATCH is a `code` row.
8. Rounds. The first `CLAIMS MODE.` prompt over a set of output paths is round 1 and checks every listed claim. The next prompt over the same output paths is round 2, then round 3. In rounds 2 and 3 the verifier checks every listed claim and every claim it rejected in the prior round, plus a random 20 percent sample of the rest of the prior round's claims, rounded up and at least one when the rest is not empty.
9. The reply carries the usual first and last verdict lines over the claims checked this round only. Each refuted claim over the public docs goes to the operator through the per-finding audit prompt of the catalog (`${CLAUDE_PLUGIN_ROOT}/skills/catalog/SKILL.md`).

## Evidence that ends it

- Unit mode: a `[VERDICT: VERIFIED]` verdict per unit, or every refuted row exempted by the operator's `Skip, track or exempt it` pick at a later refutation, recorded as the per-finding prompt records an exemption (0161). Each operator check of the unit has an `operator check` evidence row with the url, the check text and a pass or skip answer (0164). No hook at dispatch. The finish script refuses to merge a unit with no recorded VERIFIED reply for its worktree (scripts/lib/workspace.py:966, :1062); this is a script refusal, not a hook.
- Claims mode: a `[VERDICT: VERIFIED]` verdict over the claims, or every refuted row exempted by the operator. For claims over the public docs, the docs record (scripts/lib/train_runner.py:1902) and the push proof's docs rule (scripts/lib/audit_proof.py:703, :740) apply.

## Agents it uses

- verifier, warm across units and claims rounds (steps 4 and 6).

## Suggested next

- `build`: for a unit the verifier refuted: the first time on its own for one fix pass, the second time by a fresh coder on the escalated model, a third time on the operator's Fix it now pick (step 5).
- `audit`: when every unit is verified and the build phase merged them.
- `release`: when a document phase's claims are verified in a repository.
