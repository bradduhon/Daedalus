---
name: build-train
description: Runs a Build Train on this repository. Locks the contract and the project standards first, gives each work unit to a repo-coder in its own worktree, answers their questions through specialists, and runs compliance and an adversarial security audit before merging the units locally. Never pushes.
argument-hint: Describe the feature, bugfix, or change to build in this repository.
---
<!-- Copyright (c) 2026 Brad Duhon. SPDX-License-Identifier: GPL-3.0-or-later -->

# daedalus Build Train

You are the orchestrating session. You do not write application code; the jail blocks writes under `src/` and `tests/` for you. You keep the State Block, give each agent everything it needs in its prompt, route every question through yourself, and check every result adversarially.

Rules for the whole train:
- Start personas with the Agent tool only, written below as `Agent(<name>)`. Claude Code loads them as `daedalus:<name>`. Never start `claude` from Bash.
- Resume a persona with SendMessage. Personas cannot message each other.
- Warm roster (0059): a persona stays warm after its first use in this train. `Agent(<name>)` at a step means the first dispatch of that persona; once it has replied, that step's work goes to the same agent by SendMessage with the same items. Each repo-coder is warm for its own unit only. The security-auditor stays warm only after its first verdict; until then a new round dispatches it fresh. If SendMessage to a warm persona other than a coder fails, dispatch it once as a first dispatch and record its new handle.
- The train never pushes and never merges into `main` or `master` (0001). The operator merges. The Push Train (`/daedalus:push-train`), a separate step after this one, pushes.
- Every stop shows the operator what happened and names the next action as a `Next:` line.
- Human-facing text (0031): Text a human reads names each item in words: a short label or one line on what it is and what it does. Ids (ruling ids, issue numbers, task codes, agent names, snake_case keys) may trail in parentheses, never replace the description. Logs, status lines and messages to other agents may use ids alone. Documents carry both.
- If a persona's reply does not end with one of its contract lines or contract sections, stop and show the operator the reply's last 10 lines. The auditor brief from standards-rules-specialist ends with its rule list and has no status line. The security-auditor's verdict line is both the first line and the last line of every reply, fix rounds included; read it from the last line, and a reply whose first line is not the same verdict is off-contract. The Push Train's approval check reads the same verdict from the head or the tail of the auditor's final reply record. Next: rerun the step or report the persona.
- The first standards-rules-specialist dispatch of a train carries the config path, the `ledger:` line and the `standards packs:` line from begin, because it boots empty; a declared pack has no path in config.json (0019). Every later standards question resumes that same specialist by SendMessage, and each resume message names the rule files changed since its last read: every file an amend-global pick edited, and every file under a `standards_sources` path in config.json that `find <source path> -type f -newermt '<last read>'` prints.
- Every stop: run `python3 ${CLAUDE_PLUGIN_ROOT}/scripts/daedalus_workspace.py stop --repo <repo> --reason "<what happened>" --next "<next action>"` and show its output unchanged; its `Next:` line is the next action. It shows and discards the unit worktrees, switches this repo and the Charter back to their base branches unless a dirty tree or an uncommitted contract keeps them on `daedalus/<train-id>`, and clears the train marker (0023, 0024). When the operator says continue after a stop, run `python3 ${CLAUDE_PLUGIN_ROOT}/scripts/daedalus_workspace.py resume --repo <repo>` first; it marks the train active again and switches back to `daedalus/<train-id>`.
- `charter_root` governs only writes into the Charter repo. The Build Train saves the Locked Contract Packet to a file and the main session commits it (0011): `contracts/<name>.md` on `daedalus/<train-id>` in this repo, or `<charter_root>/specs/<name>.md` on the Charter branch when `charter_root` is declared. Without `charter_root`, charter-docs appends to this repo's own ledger (declared or probed); nothing is written to a charter.

## Preconditions

1. Set `<repo>` to the parent of the directory `git rev-parse --path-format=absolute --git-common-dir` prints (the main working tree; every worktree shares it). Not a repo: stop. Next: start the session inside the target repository, then run `/daedalus:build-train` again.
2. Run `python3 ${CLAUDE_PLUGIN_ROOT}/scripts/daedalus_workspace.py begin --repo <repo>` (0024). It refuses a dirty tree, reads `<repo>/.claude/daedalus/config.json` (0010; an absent config.json means the defaults: no `charter_root`, no `standards_sources`, no `policy`), probes the decision ledger (0004), creates `<repo>/.claude/daedalus/`, the folder for train state and the audit log (0035), sets `<train-id>` to the UTC time as `YYYYMMDD-HHMMSS`, creates `<repo>/docs/.tmp/daedalus/` with its `docs/.tmp/daedalus/.gitignore` so git ignores the train's scratch files and summary, branches a declared Charter to `daedalus/<train-id>` and marks the train active (0023).
   - Exit 0: it prints the first six State Block lines; copy them unchanged. The first line ends in `audit session: pending`; step 3 fills it in.
   - Exit 3: begin found no decision ledger and wrote nothing; ask the operator the question it prints, exactly.
     - An existing file: Next: add a `ledger` block naming it to `<repo>/.claude/daedalus/config.json` from your own shell (docs/project-requirements.md), then run `/daedalus:build-train` again.
     - Create: write `<repo>/docs/decisions.md` holding only the two table lines it prints, the header and its separator. Run `python3 ${CLAUDE_PLUGIN_ROOT}/scripts/append_ledger.py --probe` and show its line; it reads `seq=0`. Next: review and commit docs/decisions.md from your own shell, then run `/daedalus:build-train` again.
   - Exit 1: show its output unchanged and stop; begin left no train behind, so the stop command does not run. Its `Next:` line is the next action.
3. Run `python3 ${CLAUDE_PLUGIN_ROOT}/scripts/verify_audit_chain.py --hooks-live --repo <repo>`. It checks that this session's hooks are writing the audit log. Exit 0 prints `OK hooks live: session <id>, ...`; record `<id>` in the State Block as `audit session: <id>`. Exit 1: stop and show its output; its `Next:` line is the next action.

Keep this **State Block** in your context and print it after Preconditions and after each phase. The first six lines are begin's output, with the audit session id from step 3. On the `standards specialist:` line, the handle is the agent id the first Agent call returns, and SendMessage addresses it; `last read` is the UTC time of the specialist's latest reply, updated after every reply:

    train: <train-id>  base: <branch> @ <sha>  audit session: <id>
    ledger: <path> (<origin>, <format>, seq=<n>)
    charter_root: <path or none>  charter base: <recorded branch or none>
    policy: <engine and path, or none declared>  standards: <n> sources
    cache: <path>/frameworks (or: cache: unresolved)
    standards packs: <name> at <path>, or none declared
    standards specialist: <agent handle>  last read: <UTC time>   (or: standards specialist: pending)
    codes: --repo <R> --type <T> (or pending)
    packet_version: <n>  contract: <contract path>  lock: <sha>
    units: <id> | <branch> | <status> | built against packet <n>
    open yields: <unit>: <kind> <question>

## Phase 1: Standards and contract lock

1. Agent(`standards-rules-specialist`) with: the config path, the ledger line, the `standards packs:` line, and "Emit a `## Standards Packet` (active rules, governing ledger ids, current ledger sequence, declared policy pack) relevant to: $ARGUMENTS. Flag every spec-versus-standard contradiction." Record its agent handle and the time of its reply in the State Block `standards specialist:` line.
   - Contradiction prompt (0057). Every `[STANDARDS: CONTRADICTION] <spec ref> vs <source:line>` line is a decision only the operator makes. Never resolve it yourself.
     - Read both sides: the task or spec text at `<spec ref>`, and the rule text at `<source:line>`.
     - Ask all contradictions with AskUserQuestion, one question per contradiction, at most four questions per call. More contradictions take more calls.
     - Each question is a brief. Its `question` text is a plain question ending in `?`, then two or three context sentences quoting both sides. Those sentences carry no ids, no snake_case and no agent names. Its `header` is a short plain label for the decision.
     - When one side is the operator's global Claude environment (the rules folder, CLAUDE.md, settings), offer these three options, each with its consequence in the option description:
       - `Follow Global`: the plan or the plugin changes to comply with the global rule.
       - `Follow Plugin`: the plugin's way stands. Its ledger row records it, with a `Deviation:` line in the pull request body and, where the site is a file, a one-line comment at the site pointing at the row. No tracked-risk issue is filed. The global rule is unchanged.
       - `Follow Plugin + amend global`: the plugin's way stands. Right after the pick, the main session edits the one global rule line by hand from its own shell and shows the diff (0066). A plugin agent never makes this edit.
     - Any other contradiction (plan against spec, ruling against ruling, a stale receipt) keeps the same three-way shape under three labels that name the decision in plain words: comply with the governing side, keep the other side with a recorded deviation, or keep it and amend the governing source. The word "Global" appears in a label only when one side is the operator's global Claude environment.
     - A fourth option appears only when a real fourth path exists. AskUserQuestion allows at most four.
     - List the recommended option first. Its label ends `(Recommended)`, and its description ends with a one-sentence why, then the spec ref and source:line in parentheses. Recommend complying with the global rule. The exception is a plan that already carries a ruling choosing the deviation; then recommend `Follow Plugin`, and the why names that ruling in words.
   - Picks become rulings. Every pick is a ruling; number them `pick 1`, `pick 2` and so on, in the order asked. If the State Block `codes:` line is pending, derive the codes now by the Phase 3 step 4 rule and record them.
     - Timing depends on where the ledger lies. Both timings come before any coder starts. The skill carries no git state handling for either.
       - Ledger under `charter_root`: record the picks right after the last pick, before step 2 and the contract lock. The commit lands on the Charter branch `daedalus/<train-id>` that begin created.
       - Repo-local ledger: record the picks right after the step 3 `lock`, which has already switched this repo to `daedalus/<train-id>`.
     - To record the picks, run Agent(`charter-docs`) with: one ledger note per pick (the question in plain words, the option picked, the operator's reason when given, and `Ruled by the operator in the Phase 1 contradiction prompt of Build Train <train-id>`), the codes as `--repo <R> --type <T>`, the scratch directory `docs/.tmp/daedalus/`, and the Phase 3 step 4 probe, retry and commit instruction.
     - Route its reply as in Phase 3 step 4, with two differences: no summary exists yet to edit, and the Charter stays on `daedalus/<train-id>` until Phase 3. `[STATUS: COMMITTED] <sha> ids=<ids>` records the sha and the ids beside the picks.
     - Print each pick with its ledger id. No coder starts before `[STATUS: COMMITTED]`. With the ledger under `charter_root`, no contract is locked before it either.
   - Re-check. Next, send SendMessage(standards specialist, "RECHECK. Picks:\n<one line per pick: the contradiction line, the option picked, its ledger id or pending>\nRule files changed since your last read: <absolute paths, or none>\nRe-emit the Standards Packet for the same task with each pick applied. Flag only contradictions no pick answers.").
     - Its reply ends with the `## Standards Packet` section.
     - New contradiction lines go through the contradiction prompt and the pick recording again.
     - A contradiction line that a pick already answered stops the train. Next: report the standards specialist as a defect.
     - The packet in the last re-check reply is the Standards Packet that step 4 stores. Coders receive it byte-identical.
   - Picks reach the plan. The step 2 contract-spec dispatch carries the pick list.
     - With a repo-local ledger, the re-check and the contract run before the ids exist, so they name the picks `pick 1`, `pick 2` and so on.
     - For each `Follow Plugin` pick with a file site, the packet names the comment `<ledger id of pick k>: <one-line deviation>` at that site.
     - Every coder prompt carries the line `Pick ledger ids: pick 1 = <id>, pick 2 = <id>` (or `Pick ledger ids: none`) after the two packets. The packets stay byte-identical.
2. Choose `<name>`, a short contract name of lowercase letters, digits and hyphens. The contract path is `contracts/<name>.md` in this repo, or `<charter_root>/specs/<name>.md` when `charter_root` is declared; record it in the State Block. Then Agent(`contract-spec`) with the task, the Standards Packet, and "Save the packet to <contract path>, then end the reply with the packet." Require a reply ending in `## Locked Contract Packet` with `packet_version=<n>`, target services, wire contract (schemas, headers, status codes, auth and mTLS requirements) and ledger invariants.
3. Commit the contract. The main session owns this commit; contract-spec never commits. Run `python3 ${CLAUDE_PLUGIN_ROOT}/scripts/daedalus_workspace.py lock --repo <repo> --contract <contract path> --version <packet_version>` (0011, 0024). It switches this repo to the integration branch `daedalus/<train-id>`, creating it at the base commit when absent; Phase 2 creates every coder worktree from it, and the train verifies it on every `[STATUS: COMPLETE]`. It commits the contract there, or on the Charter branch for a Charter contract, as `Lock contract <name> v<packet_version>` before any coder starts; an unchanged file prints `contract unchanged, no commit`. Exit 0: record its `lock:` line as `lock: <sha>` in the State Block: the `Lock contract` commit, or the base commit when the contract was unchanged or lives in the Charter. Every unit branch must descend from it. With a repo-local ledger and picks from step 1, record the picks now as step 1 says, before step 4. Exit 1: stop and show its output; its `Next:` line is the next action.
4. Store both packets verbatim. Every worker prompt starts with them byte-identical: Locked Contract Packet first, Standards Packet second.

## Phase 2: Work units and yield routing

A later Daedalus release adds service manifests and TRAIT_RULES; until then, scope is the operator's words and the Contract Packet.

Divide the task into at most 5 work units by module boundary. For each unit, first create its worktree (0022): run `python3 ${CLAUDE_PLUGIN_ROOT}/scripts/daedalus_workspace.py create --repo <repo> --name <train-id>-<unit-slug> --base daedalus/<train-id>`, where `<unit-slug>` is the unit id in lowercase letters, digits and hyphens. It runs `git worktree add -q -b daedalus-unit/<train-id>-<unit-slug> <repo>/.claude/worktrees/<train-id>-<unit-slug> daedalus/<train-id>` and prints the worktree path; record the path and the branch `daedalus-unit/<train-id>-<unit-slug>` in the State Block as the unit's branch. A non-zero exit: stop and show its output. Next: the action the output names. Then Agent(`repo-coder`) with: both packets, then the `Pick ledger ids:` line from Phase 1 step 1, then the line `Worktree: <path>` naming its working directory, the unit id, its scope, its acceptance tests, and this reminder: "Work only in <path>: every file path and every git pathspec you use is absolute or goes through `git -C <path>`. When blocked, commit WIP and return one `[STATUS: YIELD_*]` line; you will be resumed with the answer." The coder boots empty, so include everything.

Read the last line of every coder reply and route it:

| Status line | Route |
|---|---|
| `[STATUS: YIELD_WEB] <query>` | Agent(`web-researcher`) with the query. Its `[STATUS: RESEARCH] <payload>` goes back with SendMessage(coder, "RESUME. Research payload:\n<payload>"). |
| `[STATUS: YIELD_CONTRACT] <mismatch>` | SendMessage(each affected coder, "HOLD"). Agent(`contract-spec`) with the mismatch, the current packet, and "Save the revised packet to <contract path>, overwriting it, then end the reply with the packet." When <N> is not greater than the State Block packet_version <n>, SendMessage(contract-spec, "packet_version must exceed <n>; revise and save again") once. A second reply whose <N> is still not greater stops the train. Otherwise run the Phase 1 step 3 `lock` command with `--version <N>`; it commits `Revise contract <name> v<N>`. The new `packet_version` goes to each affected coder: SendMessage(coder, "RESUME with revised packet v<N>:\n<packet>"). Never let a coder improvise a contract. |
| `[STATUS: YIELD_COMPLIANCE] <question>` | Resolve the cache path (below). Cryptography, key custody, tenant isolation or audit logging: Agent(`nist-specialist`). Cloud IAM, network rules or OS and container hardening: Agent(`cis-specialist`). Its `[STATUS: COMPLIANCE] <list>` goes back with SendMessage(coder, "RESUME. Requirement:\n<list with control ids>"). |
| `[STATUS: YIELD_STANDARDS] <question>` | SendMessage(standards specialist, "<question>\nRule files changed since your last read: <absolute paths, or none>"). Its `[STATUS: STANDARD] <answer>` goes back with SendMessage(coder, "RESUME. Standard:\n<answer with source refs>"). |
| `[STATUS: COMPLETE] branch=<b> packet_version=<n> files=<list> tests=<summary> ledger_notes=<text>` | First compare `<b>` with the branch the State Block recorded for that unit in Phase 2. A mismatch: stop with "Unit <unit> reported branch <b>; the train created daedalus-unit/<train-id>-<unit-slug>. Next: rerun the train; if it repeats, file an issue with the train summary." Then run `git merge-base --is-ancestor <lock sha> <b>` with the State Block `lock:` sha. A non-zero exit: stop with "Unit <b> does not descend from the integration branch. Next: rerun the train; if it repeats, file an issue with the train summary." Otherwise record packet_version, files, tests and ledger notes in the State Block; the unit's branch stays the one Phase 2 recorded. A unit built against an older packet_version goes back with the current packet. |

If SendMessage to a coder fails, never start a replacement coder; a replacement coder would start without the first coder's context and the unit's half-done state. The train stops, and the stop command removes that unit's worktree with the rest: "Coder for unit <b> cannot be resumed. Next: rerun the train; the unit branch <b> is kept for reference."

Cache path, resolved once before the first nist-specialist or cis-specialist dispatch: run `python3 ${CLAUDE_PLUGIN_ROOT}/scripts/daedalus_doctor.py --print-cache-dir`. Exit 0 prints one absolute path; put `<that path>/frameworks` into every nist and cis prompt as written, an absolute path with no `~` and no `$`. Exit 1: stop and show its message. Next: run `/daedalus:doctor` first, then run `/daedalus:build-train` again. A specialist's `[STATUS: CACHE_INVALID] <detail>` also stops the train and shows the detail:
- From nist-specialist. Next: from your own shell, run `python3 ${CLAUDE_PLUGIN_ROOT}/scripts/refresh_frameworks.py --only nist-800-53 --cache-root <that path>` with both paths written out in full, then run `/daedalus:build-train` again.
- From cis-specialist. Next: place the benchmark files and their manifest under `<that path>/frameworks/cis/` per docs/project-requirements.md "Machine caches", then run `/daedalus:build-train` again.

## Phase 3: Compliance and adversarial security gate

1. Policy gate: a later Daedalus release adds the deterministic policy gate; record `[POLICY: none declared]` or `[POLICY: declared, gate not yet shipped]` in the summary. Then, if any unit touched IAM, KMS, mTLS, key custody or infrastructure config, run Agent(`nist-specialist`) and Agent(`cis-specialist`) on those units' diffs (`git diff daedalus/<train-id>...<branch>`), with the cache path. Keep each `[STATUS: COMPLIANCE]` report.
2. SendMessage(standards specialist, "Auditor brief. Units and their changed files: <unit ids, each with its changed files>\nRule files changed since your last read: <absolute paths, or none>") for an auditor brief; it returns the rules each unit is judged against. Then Agent(`security-auditor`) with: the diff base `daedalus/<train-id>`, so each diff leaves out the contract commits on the integration branch, every unit branch, the Locked Contract Packet with its packet_version, the Standards Packet, the auditor brief, and the compliance reports. That dispatch is the first auditor round; a round after its first verdict resumes the same auditor by SendMessage with the same items as they now stand. Read the verdict from the last line of the auditor's reply; its first line carries the same verdict.
3. `[VERDICT: REJECTED] <findings>`: SendMessage(each responsible coder, its itemized file:line findings). A coder's reply during a fix round routes exactly like a Phase 2 reply, yields included, until it returns `[STATUS: COMPLETE]`. Then repeat step 2. After 3 rejected rounds, stop and show the last findings. Next: fix the findings by hand on the named branches, or rerun the train with a narrower task. The unit branches stay as they are.
4. `[VERDICT: APPROVED] <paragraph>`: you merge, then charter-docs records.
   - Run `python3 ${CLAUDE_PLUGIN_ROOT}/scripts/daedalus_workspace.py finish --repo <repo>` (0024). It refuses a dirty main checkout (a coder changed it instead of its worktree), checks that every unit branch descends from the lock, switches to `daedalus/<train-id>`, merges each unit with `--no-ff` in recorded order and discards the unit worktrees. On a merge conflict it names the conflicting files, aborts the merge and switches back to the base branch. Exit 0 prints `merged <n> units into daedalus/<train-id>`. Exit 1: stop and show its output; its `Next:` line is the next action. When the merges succeeded and only a worktree removal failed, the operator runs the commands it names and says continue; after `resume`, go on at the next bullet.
   - Codes: when the State Block `codes:` line already holds codes from Phase 1, use them. Otherwise take `--repo` and `--type` from the governing ledger id named first in the Standards Packet (for `0004-DAE-PLT`, repo `DAE` and type `PLT`). If the packet names none, or its ids disagree on the codes, ask the operator once for both and record them in the State Block. A heading-entry ledger still receives the codes, because the jail requires them, and ignores them.
   - Charter ledger: when the ledger path lies under `charter_root`, run `git -C <charter_root> status --porcelain`; it is empty when the contract commit landed. Any output: stop with the listed files as the reason and `--next "say continue to resume at the Charter ledger step"`; the stop keeps the Charter on `daedalus/<train-id>` while it is dirty, and its `Next:` names the files. On continue, after `resume`, resume at this step.
   - Write the summary now, in the step 5 shape, with the line `Ledger ids: pending. Codes: --repo <R> --type <T>.`, before charter-docs runs. Every stop after this point leaves a summary.
   - Agent(`charter-docs`) with: the ledger notes from every unit, the codes as `--repo <R> --type <T>`, the scratch directory `docs/.tmp/daedalus/` for entry files, and "Run `--probe` first. On exit 2 re-probe and retry once. Commit the ledger change in the repo that holds the ledger: stage the ledger file by its path with `git add <path>` (or `git -C <charter_root> add <path>`), then `git commit -m`."
   - `[STATUS: COMMITTED] <sha> ids=<id>[,<id>]`: record the sha and the ids, and replace the summary's `Ledger ids: pending` line with `Ledger ids: <ids> in commit <sha>.` using the Edit tool. If you created a Charter branch, run `git -C <charter_root> switch <recorded branch>` now. `[STATUS: LEDGER_APPENDED] <id>`: SendMessage(charter-docs, "Commit the ledger change and return COMMITTED."). `[STATUS: LEDGER_MISMATCH] expected=<n> ledger=<m>`: stop with `--next "say continue; the train probes the ledger again and retries the append once"`. On continue, after `resume`, resume charter-docs with: probe again and retry the append once with the new sequence. `[STATUS: BLOCKED] <detail>`: stop with the detail as the reason and the action it names as `--next`; the stop keeps a dirty Charter, the uncommitted ledger row included, on `daedalus/<train-id>` and names its files. The integration branch is already merged. Any other reply: the off-contract stop.
5. The summary lives at `<repo>/docs/.tmp/daedalus/<train-id>-summary.md`, first written in step 4. The Push Train passes this file to `gh pr create --body-file`, so it becomes a public pull request body and carries no absolute path: `<charter name>` is the last component of `charter_root`, and `<ledger repo name>` is the last component of the repo that holds the ledger. Shape:

       # Build Train <train-id>
       Task: <the operator's words>
       Base: <branch> @ <sha>. Integration branch: daedalus/<train-id>.
       charter: <charter name>, branch daedalus/<train-id>, charter base: <recorded branch> (ledger under charter_root)
         or: charter: <charter name>, branch daedalus/<train-id>, charter base: <recorded branch> (ledger repo-local)
         or: charter: none (repo-local ledger)
       Packet: v<n>. Ledger: <ledger repo name>/<ledger path relative to that repo>.
       Contract: contracts/<name>.md v<packet_version>
         or, when charter_root is declared: Contract: <charter name>/specs/<name>.md v<packet_version>
       Ledger ids: <ids> in commit <sha>.
         or, until charter-docs commits: Ledger ids: pending. Codes: --repo <R> --type <T>.
       [POLICY: none declared] or [POLICY: declared, gate not yet shipped]
       ## Rulings
       One line per contradiction pick: the question, the option picked, its ledger id. Or: none.
       Deviation: <what the plugin keeps, against which rule, in words> (<ledger id>), one line per pick that keeps the plugin's way.
       ## Units
       | Unit | Branch | Packet | Files | Tests |
       ## Yields
       One line per yield: unit, kind, question, who answered.
       ## Compliance
       Each specialist's PASS/FAIL list, or "not run (no IAM, KMS, mTLS, key custody or infrastructure change)".
       ## Audit
       [VERDICT: APPROVED] after <n> round(s), with the auditor's paragraph.
       ## Audit log
       Session <id>: .claude/daedalus/audit/<id>.jsonl

6. Print the State Block, the summary path, and the audit log path. Then end the train: run `python3 ${CLAUDE_PLUGIN_ROOT}/scripts/daedalus_workspace.py stop --repo <repo> --reason "train complete" --next "review the integration branch, run /daedalus:audit-report <id> to read this session's audit log, then run /daedalus:push-train to push the branch and open the pull request"` and show its output.
