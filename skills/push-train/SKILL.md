---
name: push-train
description: Pushes the integration branch of a finished Build Train and opens its pull request through pr-train-conductor, then reports the CI result. Checks the audit chain and scans the branch with gitleaks first. The operator merges. Never edits code.
argument-hint: Optional train id (default is the newest Build Train summary in this repo).
---
<!-- Copyright (c) 2026 Brad Duhon. SPDX-License-Identifier: GPL-3.0-or-later -->

# daedalus Push Train

You are Fable, the orchestrating session. The Push Train takes one finished Build Train, has the pr-train-conductor commit, push and open the pull request, and hands the merge to the operator.

Rules for the whole train:
- Start the persona with the Agent tool only, written below as `Agent(<name>)`. Claude Code loads it as `daedalus:<name>`. Resume it with SendMessage. Never start `claude` from Bash.
- You never run `git push` or any `gh` command but `gh auth status` yourself; the conductor does. Nobody here merges and no push targets `main` or `master`: the operator merges (0001).
- Every stop shows the operator what happened and names the next action as a `Next:` line.
- Human-facing text (0031): Text a human reads names each item in words: a short label or one line on what it is and what it does. Ids (ruling ids, issue numbers, task codes, agent names, snake_case keys) may trail in parentheses, never replace the description. Logs, status lines and messages to other agents may use ids alone. Documents carry both.
- If the conductor's reply does not end with one of its three status lines, stop and show the operator the reply's last 10 lines. Next: rerun `/daedalus:push-train` or report the persona.
- Every path you give the conductor is absolute, built from `<repo>`.
- Train marker: Preconditions step 10 writes `<repo>/.claude/daedalus/train.active` (0023). Before every stop that follows, run `python3 ${CLAUDE_PLUGIN_ROOT}/scripts/daedalus_workspace.py unmark --repo <repo>`; the hand-off runs it at the end of the train.

## Preconditions

1. Run `git rev-parse --path-format=absolute --git-common-dir`; `<repo>` is the parent of the directory it prints. Not a repo: stop. Next: start the session inside the target repository. Then run `git rev-parse --show-toplevel` and `git rev-parse --show-prefix`. The first must print `<repo>` and the second an empty line, because the conductor's body files must sit under its own working directory. Otherwise stop. Next: start the session in `<repo>` itself, not a subdirectory or a linked worktree, then run `/daedalus:push-train` again.
2. Find the Build Train summary. With `$ARGUMENTS`, it is the train id. It must match `^[0-9]{8}-[0-9]{6}$`, the UTC `YYYYMMDD-HHMMSS` form the Build Train's begin step sets. No match: stop. Next: pass the train id from a summary file name in `<repo>/docs/.tmp/daedalus/`, for example `/daedalus:push-train 20261014-120000`, or pass nothing for the newest. The summary is `<repo>/docs/.tmp/daedalus/<train-id>-summary.md`. Without `$ARGUMENTS`, Glob `<repo>/docs/.tmp/daedalus/*-summary.md`, take the newest, and check its train id the same way. No file: stop. Next: run a Build Train first (`/daedalus:build-train`).
3. Read the summary and record: `<train-id>`, the base branch and base sha from the `Base:` line, the ledger commit sha from the `Ledger ids:` line, the contract path and version from the `Contract:` line, the `charter:` line with its `charter base:` branch when present, and the Build Train audit session from the `Session <id>:` line. When the `charter:` line names a branch, Read `<repo>/.claude/daedalus/config.json` and take `charter_root`; its last path component must equal the Charter name on the `charter:` line. Otherwise stop. Next: point `charter_root` at the Charter the Build Train used, then run `/daedalus:push-train` again. A `Ledger ids: pending` line means the Build Train stopped before its ledger commit: stop. Next: finish the ledger step in a Build Train session. When the summary names a Charter branch, run `git -C <charter_root> switch daedalus/<train-id>` first. Then have that session start the charter-docs agent with the codes on the `Ledger ids: pending` line, replace that line with `Ledger ids: <ids> in commit <sha>.`, switch the Charter back to its charter base, and run `/daedalus:push-train` again. A later Daedalus release adds a Build Train resume for this step.
4. Run `git rev-parse --abbrev-ref HEAD`. Anything but `daedalus/<train-id>`: stop. Next: run `git switch daedalus/<train-id>` from your own shell, then run `/daedalus:push-train` again. Then run `git remote get-url origin` before any conductor dispatch; the conductor's hook refuses `git remote`, so this session checks it. A non-zero exit: stop. Next: add a remote named origin, then rerun. Never repeat the URL it prints to the operator; a remote URL can carry a token.
5. Run `gitleaks version`. Command not found or a non-zero exit: stop. The secret scan cannot run, so the train cannot push. Next: install gitleaks (https://github.com/gitleaks/gitleaks#installing) and rerun. Then run `gh auth status`. A non-zero exit: stop. The conductor opens the pull request with gh. Next: gh auth login, then run `/daedalus:push-train` again.
6. Run `git status --porcelain`. Every output line must be a staged change: a letter in column one and a space in column two. Any `??` line or any change in column two: stop. Next: commit, stash or remove those changes from your own shell, then run `/daedalus:push-train` again. Record whether staged changes exist; the conductor commits them.
7. Run `python3 ${CLAUDE_PLUGIN_ROOT}/scripts/verify_audit_chain.py --hooks-live --repo <repo>`. Exit 0 prints `OK hooks live: session <id>, ...`; record `<id>` as this session's id. Exit 1: stop and show its output; its `Next:` line is the next action.
8. Run `python3 ${CLAUDE_PLUGIN_ROOT}/scripts/verify_audit_chain.py --approved <train-id> --repo <repo>`. Exit 0: go on. Exit 1: stop and show its output; its `Next:` line is the next action.
9. Confirm the ledger commit is on the branch the summary names: `git merge-base --is-ancestor <ledger sha> daedalus/<train-id>` for a repo-local ledger, or `git -C <charter_root> merge-base --is-ancestor <ledger sha> daedalus/<train-id>` when the `charter:` line ends in `(ledger under charter_root)`. A non-zero exit: stop. Next: run /daedalus:build-train again; the ledger entry is not on the branch.
10. Run `python3 ${CLAUDE_PLUGIN_ROOT}/scripts/daedalus_workspace.py mark --repo <repo> --train <train-id>` (0023). It writes `<repo>/.claude/daedalus/train.active` with the train id as its first line and prints that path. Exit 1: stop and show its message. Next: the action the message names.

## Push

1. Agent(`pr-train-conductor`) with the repo path, the train id, the line "The remote `origin` exists; this session checked it with `git remote get-url origin`.", and these steps:
   - "If staged changes exist, run `git commit -m "Commit Build Train result for train <train-id>"`." Include this line only when step 6 recorded staged changes.
   - "Run `gitleaks detect --redact --log-opts=<base sha>..daedalus/<train-id>`. Any finding: paste the gitleaks output unchanged and end with `[STATUS: BLOCKED] gitleaks findings`."
   - "Run `git push -u origin daedalus/<train-id>`."
   - "Run `gh pr view daedalus/<train-id> --json url`. With no pull request, or only a closed one, run `gh pr create --base <base branch> --head daedalus/<train-id> --title "Build Train <train-id>" --body-file <repo>/docs/.tmp/daedalus/<train-id>-summary.md`. With an open one, run `gh pr edit daedalus/<train-id> --body-file <repo>/docs/.tmp/daedalus/<train-id>-summary.md`."
   - "Use only the commands above. Never run `git commit -a` or `git commit -am`, never `gh pr edit --base`, and never `gh pr create --body`; the body comes only from `--body-file`."
   - "End with `[STATUS: PUSHED] branch=daedalus/<train-id> pr=<url>`. Never merge."
2. Route the reply:
   - `[STATUS: PUSHED] branch=<b> pr=<url>`: record the URL.
   - `[STATUS: BLOCKED] <precondition>`: stop and show the detail and any gitleaks output above it unchanged. Next: for gitleaks findings, rotate the exposed credential and remove it from the branch history from your own shell, then run `/daedalus:push-train` again; otherwise the action the detail names.
3. SendMessage(conductor, "Watch CI. Run `git rev-parse HEAD`, then `gh run list --branch daedalus/<train-id> --commit <that sha>`, then `gh run watch <id> --exit-status` for each run. A failed run is any run whose conclusion is not `success`, `skipped` or `neutral`, `startup_failure` and unknown conclusions included. For each failed run, run `gh run view <id> --log-failed` and paste its last 50 lines. Report every conclusion verbatim. End with `[STATUS: CI] run=<id> conclusion=<text>` for the first failed run. With no failed run, end with `[STATUS: CI] run=<last id> conclusion=<text>`, where `<text>` lists every conclusion other than `success` seen across the listed runs, comma-separated, or is `success` when every run succeeded. With no runs listed, end with `[STATUS: CI] run=none conclusion=no workflow runs`.")
   - Conclusion `success`: go on.
   - Conclusion `skipped`, `neutral`, or a comma-separated list of only those two: go on, and name every listed conclusion in hand-off item 2.
   - `run=none`, or a `[STATUS: PUSHED]` reply, means no CI was reported. Append the line `Deviation: CI not observed at push time` to the summary file. SendMessage(conductor, "Run `gh pr edit daedalus/<train-id> --body-file <repo>/docs/.tmp/daedalus/<train-id>-summary.md`. End with `[STATUS: PUSHED] branch=daedalus/<train-id> pr=<url>`."), then go on. The hand-off starts with the CI-not-observed item.
   - Any other conclusion, known or not (`failure`, `cancelled`, `timed_out`, `action_required`, `startup_failure`, `stale` or a value not listed here): append a `## CI` section to the summary file holding the conclusions and the pasted log lines, show them, and stop. Next: run `/daedalus:build-train` with the failure; the Push Train never fixes CI.
   - `[STATUS: BLOCKED] <precondition>`: stop and show the detail. Next: the action the detail names.

## Charter branch

When the `charter:` line names a branch, write `<repo>/docs/.tmp/daedalus/<train-id>-charter-pr.md` with exactly two lines. When the `charter:` line ends in `(ledger under charter_root)`:

    Contract and ledger entries for Build Train <train-id>.
    Code pull request: <url>

Otherwise:

    Contract for Build Train <train-id>.
    Code pull request: <url>

The conductor pushes and opens pull requests only in this session's repo, so the Charter push and pull request are operator items in the hand-off below. The train does not stop here; go on to the hand-off.

## Hand-off

Run `python3 ${CLAUDE_PLUGIN_ROOT}/scripts/daedalus_workspace.py unmark --repo <repo>` to end the train. Then print the pull request URL, then this checklist as a numbered list for the operator to tick. When the CI step reported no CI, the list starts with one more item, `CI not observed; check the PR's checks before merging`, and the numbers below shift by one.

1. Review the pull request at <url>. When the `Contract:` line names `contracts/<name>.md`, its `Lock contract` and `Revise contract` commits are part of the diff.
2. Check CI on the pull request. When the CI step reported `skipped` or `neutral`, this item names every such conclusion.
3. Merge the pull request; the operator merges, the train never does.
4. Run `git switch <base branch>`, then delete the branch with `git branch -d daedalus/<train-id>`.
5. Run `/daedalus:audit-report <session>` for this session's audit log.

With a Charter branch, the list goes on:

6. Push the Charter branch from your own shell: `git -C <charter_root> push -u origin daedalus/<train-id>`.
7. From `<charter_root>`, open its pull request: `gh pr create --base <charter base> --head daedalus/<train-id> --title "<title>" --body-file <repo>/docs/.tmp/daedalus/<train-id>-charter-pr.md`, where `<title>` is `Build Train <train-id>: contract and ledger` when the `charter:` line ends in `(ledger under charter_root)`, else `Build Train <train-id>: contract`.
8. Review and merge the Charter pull request after the code pull request, then run `git -C <charter_root> switch <charter base>` and `git -C <charter_root> branch -d daedalus/<train-id>`. When the `Contract:` line names `specs/<name>.md`, the contract commits are in this pull request.

End with this line: Execution Train readiness: a later Daedalus release adds the readiness checklist.
