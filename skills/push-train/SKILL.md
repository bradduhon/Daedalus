---
name: push-train
description: Pushes the integration branch of a finished Build Train and opens its pull request through pr-train-conductor, then reports the CI result. Checks the audit chain first, and scans the branch with gitleaks when the service manifest turns the secret scan on. The operator merges. Never edits code.
argument-hint: Optional train id (default is the newest Build Train summary in this repo).
---
<!-- Copyright (c) 2026 Brad Duhon. SPDX-License-Identifier: GPL-3.0-or-later -->

# daedalus Push Train

You are the orchestrating session. The Push Train takes one finished Build Train, has the pr-train-conductor commit, push and open the pull request, and hands the merge to the operator.

Rules for the whole train:
- Start the persona with the Agent tool only, written below as `Agent(<name>)`. Claude Code loads it as `daedalus:<name>`. Resume it with SendMessage. Never start `claude` from Bash.
- You never run `git push` or any `gh` command but `gh auth status` yourself; the conductor does. One exception: you run the three commands the release step prints only when `<repo>` is the Daedalus plugin repository itself; in any other project you show them to the operator to run from their own shell (0068, 0093). Nobody here merges and no push targets `main` or `master`: the operator merges (0001).
- Every stop shows the operator what happened and names the next action as a `Next:` line.
- Human-facing text (0031): Text a human reads names each item in words: a short label or one line on what it is and what it does. Ids (ruling ids, issue numbers, task codes, agent names, snake_case keys) may trail in parentheses, never replace the description. Logs, status lines and messages to other agents may use ids alone. Documents carry both.
- If the conductor's reply does not end with one of its three status lines, stop and show the operator the reply's last 10 lines. Next: rerun `/daedalus:push-train` or report the persona.
- Every path you give the conductor is absolute, built from `<repo>`.
- Train marker: Preconditions step 7 writes `<repo>/.claude/daedalus/train.active` (0023). Before every stop that follows, run `python3 ${CLAUDE_PLUGIN_ROOT}/scripts/daedalus_workspace.py unmark --repo <repo>`; the hand-off runs it at the end of the train.

## Preconditions

1. Run `git rev-parse --path-format=absolute --git-common-dir`; `<repo>` is the parent of the directory it prints. Not a repo: stop. Next: start the session inside the target repository. Then run `git rev-parse --show-toplevel` and `git rev-parse --show-prefix`. The first must print `<repo>` and the second an empty line, because the conductor's body files must sit under its own working directory. Otherwise stop. Next: start the session in `<repo>` itself, not a subdirectory or a linked worktree, then run `/daedalus:push-train` again.
2. Find the Build Train summary. With `$ARGUMENTS`, it is the train id. It must match `^[0-9]{8}-[0-9]{6}$`, the UTC `YYYYMMDD-HHMMSS` form the Build Train's begin step sets. No match: stop. Next: pass the train id from a summary file name in `<repo>/docs/.tmp/daedalus/`, for example `/daedalus:push-train 20261014-120000`, or pass nothing for the newest. The summary is `<repo>/docs/.tmp/daedalus/<train-id>-summary.md`. Without `$ARGUMENTS`, Glob `<repo>/docs/.tmp/daedalus/*-summary.md`, take the newest, and check its train id the same way. No file: stop. Next: run a Build Train first (`/daedalus:build-train`).
3. Read the summary and record: `<train-id>`, the base branch and base sha from the `Base:` line, the ledger commit sha from the `Ledger ids:` line, the contract path and version from the `Contract:` line, the `charter:` line with its `charter base:` branch when present, and the Build Train audit session from the `Session <id>:` line. When the `charter:` line names a branch, Read `<repo>/.claude/daedalus/config.json` and take `charter_root`; its last path component must equal the Charter name on the `charter:` line. Otherwise stop. Next: point `charter_root` at the Charter the Build Train used, then run `/daedalus:push-train` again. A `Ledger ids: pending` line means the Build Train stopped before its ledger commit: stop. Next: in the Build Train session that stopped, ask for the ledger resume of `/daedalus:build-train`, which finishes the ledger step and rewrites the summary, then run `/daedalus:push-train` again.
4. Run `git rev-parse --abbrev-ref HEAD`. Anything but `daedalus/<train-id>`: stop. Next: run `git switch daedalus/<train-id>` from your own shell, then run `/daedalus:push-train` again. Then run `git remote get-url origin` before any conductor dispatch; the conductor's hook refuses `git remote`, so this session checks it. A non-zero exit: stop. Next: add a remote named origin, then rerun. Never repeat the URL it prints to the operator; a remote URL can carry a token. When the `charter:` line names a branch, also run `git -C <charter_root> remote get-url origin` and record `<charter slug>`: the `<owner>/<name>` at the end of that URL without `.git`, with `<host>/` in front when the host is not `github.com`. A non-zero exit: stop. Next: add a remote named origin to the Charter, then rerun. Never repeat this URL either.
5. Run `python3 ${CLAUDE_PLUGIN_ROOT}/scripts/daedalus_doctor.py --print-secrets-scan --repo <repo>`. It prints `secrets scan: on` when the service manifest sets `secrets_scan` to `true` in its `features` object, and `secrets scan: off` otherwise (0069). Exit 1: stop and show its output. Next: fix the service manifest as the output says, then run `/daedalus:push-train` again. Record whether the scan is on. With the scan on, run `gitleaks version`. Command not found or a non-zero exit: stop. The secret scan cannot run, so the train cannot push. Next: install gitleaks (https://github.com/gitleaks/gitleaks#installing) and rerun. With the scan off, gitleaks is not run and need not be installed. Then run `gh auth status`. A non-zero exit: stop. The conductor opens the pull request with gh. Next: gh auth login, then run `/daedalus:push-train` again.
6. Run `git status --porcelain`. Every output line must be a staged change: a letter in column one and a space in column two. Any `??` line or any change in column two: stop. Next: commit, stash or remove those changes from your own shell, then run `/daedalus:push-train` again. Record whether staged changes exist; the conductor commits them.
7. Run `python3 ${CLAUDE_PLUGIN_ROOT}/scripts/daedalus_workspace.py mark --repo <repo> --train <train-id>` (0023). It writes `<repo>/.claude/daedalus/train.active` with the train id as its first line and prints that path. The audit log records only while this file exists, so this step comes before the hooks check. Exit 1: stop and show its message. Next: the action the message names.
8. Run `python3 ${CLAUDE_PLUGIN_ROOT}/scripts/verify_audit_chain.py --hooks-live --repo <repo>`. Exit 0 prints `OK hooks live: session <id>, ...`; record `<id>` as this session's id. Exit 1: stop and show its output; its `Next:` line is the next action.
9. Run `python3 ${CLAUDE_PLUGIN_ROOT}/scripts/verify_audit_chain.py --approved <train-id> --repo <repo>`. It passes on one of two paths and prints which one it took: an approved audit verdict on the current tip, or a rejected round on the current tip whose every finding carries the operator's exemption (issue 62, 0133). Exit 0: show its output and go on. On the exemption path, read the summary's `## Audit` section before the push: it lists each exempted finding with its ledger id and its tracking answer. For each `GitHub tracked-risk issue` answer, check that the four-field tracked-risk issue is filed before the pull request opens; when one is missing, stop. Next: file the four-field tracked-risk issue for that finding, then run /daedalus:push-train again. For each `Silently dropped` or `Recorded locally` answer, check that the section carries the `Deviation:` line naming the finding and its exemption row, which rides the pull request body (0142). Exit 1 whose output says the tip moved past the judged tip (a commit landed on `daedalus/<train-id>` after the audit): run the Recovery round below once, then run this step again. Any other exit 1: stop and show its output; its `Next:` line is the next action.
10. Confirm the ledger commit is on the branch the summary names: `git merge-base --is-ancestor <ledger sha> daedalus/<train-id>` for a repo-local ledger, or `git -C <charter_root> merge-base --is-ancestor <ledger sha> daedalus/<train-id>` when the `charter:` line ends in `(ledger under charter_root)`. A non-zero exit: stop. Next: run /daedalus:build-train again; the ledger entry is not on the branch.

## Recovery round

One audit round on the moved tip, run from this session (issue 73). Exit 1 of any command here: stop and show its output; its `Next:` line is the next action.

1. Run `python3 ${CLAUDE_PLUGIN_ROOT}/scripts/daedalus_train.py reaudit --repo <repo>` and show its line, `reaudit round=<n> tip=<40 hex>`. It admits one auditor dispatch, and a second reaudit on the same tip exits 1.
2. Run `python3 ${CLAUDE_PLUGIN_ROOT}/scripts/daedalus_workspace.py refresh --repo <repo> --name <train-id>-audit`; it prints the audit worktree path.
3. Run `python3 ${CLAUDE_PLUGIN_ROOT}/scripts/daedalus_train.py model --repo <repo> --agent security-auditor`, then Agent(`security-auditor`) with `model: <that word>` and: the diff base, the base sha from the summary's `Base:` line; the one branch `daedalus/<train-id>`; the contract file the `Contract:` line names and the Standards Packet at `<repo>/docs/.tmp/daedalus/<train-id>/standards-packet.md`; the round number `<n>` and its findings file `<repo>/docs/.tmp/daedalus/<train-id>/audit/round<n>/findings.txt`; and the line `Worktree: <audit worktree path>`. Read the verdict from the last line of its reply.
4. `[VERDICT: APPROVED] tip=<sha>`: run `python3 ${CLAUDE_PLUGIN_ROOT}/scripts/daedalus_train.py verdict --repo <repo> --status approved --round <n> --findings <findings path> --tip <judged tip>` with the tip from the verdict line, and show its line. Then run `python3 ${CLAUDE_PLUGIN_ROOT}/scripts/daedalus_train.py summary --repo <repo>` and show its line; never write the summary by hand (0046). It rewrites the whole summary from train state: its `## Audit` section names the recovery round `<n>` and the new judged tip, and the first line under `## Audit log` is `Session <id>: .claude/daedalus/audit/<id>.jsonl` with this session's id from step 8, the Build Train's session line after it. The push proof reads the log of the first `Session <id>:` line, and this session's log holds the recovery verdict and the summary command record the proof anchors on. Then run Preconditions step 9 again.
5. `[VERDICT: REJECTED] tip=<sha>`: run the same verdict command with `--status rejected` and show its line. Stop and show each finding with the three choices of the per-finding audit prompt (`/daedalus:catalog`): `Exempt the finding`, `Run a fix round` or `End the train`, and the tracking question after an exemption. Next: the operator picks for each finding and runs the picks through `/daedalus:build-train`, which records one exemption per exempted finding; the Push Train runs no second recovery round.

## Push

1. Run `python3 ${CLAUDE_PLUGIN_ROOT}/scripts/daedalus_train.py model --repo <repo> --agent pr-train-conductor`; it prints one model word, the `agent_models` setting for the conductor or else its agent file's `model:` line (spec 4). Exit 1: stop and show its output; its `Next:` line is the next action. Then Agent(`pr-train-conductor`) with `model: <that word>`, the repo path, the train id, the line "The remote `origin` exists; this session checked it with `git remote get-url origin`.", and these steps:
   - "If staged changes exist, run `git commit -m "Commit Build Train result for train <train-id>"`." Include this line only when step 6 recorded staged changes.
   - "Run `gitleaks detect --redact --log-opts=<base sha>..daedalus/<train-id>`. Any finding: paste the gitleaks output unchanged and end with `[STATUS: BLOCKED] gitleaks findings`." Include this line only when step 5 recorded the scan on.
   - "Run `git push -u origin daedalus/<train-id>`."
   - "Run `gh pr view daedalus/<train-id> --json url`. With no pull request, or only a closed one, run `gh pr create --base <base branch> --head daedalus/<train-id> --title "Build Train <train-id>" --body-file <repo>/docs/.tmp/daedalus/<train-id>-summary.md`. With an open one, run `gh pr edit daedalus/<train-id> --body-file <repo>/docs/.tmp/daedalus/<train-id>-summary.md`."
   - "Use only the commands above. Never run `git commit -a` or `git commit -am`, never `gh pr edit` with any flag but `--body-file`, and never `gh pr create --body`; the body comes only from `--body-file`."
   - "End with `[STATUS: PUSHED] branch=daedalus/<train-id> pr=<url>`. Never merge."
2. Route the reply:
   - `[STATUS: PUSHED] branch=<b> pr=<url>`: record the URL.
   - `[STATUS: CI] run=<id> conclusion=<text>`: the conductor pushed and watched CI in one reply (issue 20). Record the pull request URL its `gh pr` output shows; when it shows none, SendMessage(conductor, "Run `gh pr view daedalus/<train-id> --json url`. End with `[STATUS: PUSHED] branch=daedalus/<train-id> pr=<url>`.") and record that URL. Then route this CI line by the step 3 conclusion rules, without sending the Watch CI message.
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

The code pull request exists now, so the conductor pushes the Charter branch and opens its pull request (0078). Send the conductor one of two messages, picked by the `charter:` line (issue 13). When it ends in `(ledger under charter_root)`:

    SendMessage(conductor, "When charter_root is declared, run `git -C <charter_root> push -u origin daedalus/<train-id>`. When charter_root is declared, run `gh pr create --repo <charter slug> --base <charter base> --head daedalus/<train-id> --title "Build Train <train-id>: contract and ledger" --body-file <repo>/docs/.tmp/daedalus/<train-id>-charter-pr.md`. Use only these two commands. End with `[STATUS: PUSHED] branch=daedalus/<train-id> pr=<url>`.")

Otherwise:

    SendMessage(conductor, "When charter_root is declared, run `git -C <charter_root> push -u origin daedalus/<train-id>`. When charter_root is declared, run `gh pr create --repo <charter slug> --base <charter base> --head daedalus/<train-id> --title "Build Train <train-id>: contract" --body-file <repo>/docs/.tmp/daedalus/<train-id>-charter-pr.md`. Use only these two commands. End with `[STATUS: PUSHED] branch=daedalus/<train-id> pr=<url>`.")

Route the reply:
- `[STATUS: PUSHED] branch=<b> pr=<url>`: record the URL as `<charter url>`.
- `[STATUS: BLOCKED] <precondition>`: stop and show the detail. Next: the action the detail names.

The train does not stop here; go on to the hand-off.

## Hand-off

Run `python3 ${CLAUDE_PLUGIN_ROOT}/scripts/daedalus_workspace.py unmark --repo <repo>` to end the train. Then print the pull request URL, then this checklist as a numbered list for the operator to tick. When the CI step reported no CI, the list starts with one more item, `CI not observed; check the PR's checks before merging`, and the numbers below shift by one.

1. Review the pull request at <url>. When the `Contract:` line names `contracts/<name>.md`, its `Lock contract` and `Revise contract` commits are part of the diff.
2. Check CI on the pull request. When the CI step reported `skipped` or `neutral`, this item names every such conclusion.
3. Merge the pull request; the operator merges, the train never does.
4. Check that the pull request is merged with `gh pr view <url> --json state`; its state reads `MERGED` once it is. Then, from your own shell, run `git switch <base branch>` and delete the branch with `git branch -D daedalus/<train-id>`. A squash or rebase merge leaves the branch unmerged in git's eyes, so `-d` refuses it (issue 19).
5. Run `/daedalus:audit-report <session>` for this session's audit log.

With a Charter branch, the list goes on:

6. Review and merge the Charter pull request at <charter url> after the code pull request. Check that it is merged with `gh pr view <charter url> --json state`, then, from your own shell, run `git -C <charter_root> switch <charter base>` and `git -C <charter_root> branch -D daedalus/<train-id>`. When the `Contract:` line names `specs/<name>.md`, the contract commits are in this pull request.

Release step (0068, 0071, 0075): after the operator reports the merge, ask for the merge commit sha on `<base branch>` and run `python3 ${CLAUDE_PLUGIN_ROOT}/scripts/daedalus_workspace.py release --repo <repo> --merge-sha <merge sha>`. It reads the version only from the `VERSION` file at that sha. When the version changed, the summary must carry the class line `Version class: <version> <X, Y or Z>: <one-line reason>`; with X it must also carry `Migration: <what an operator edits>`. The digit rules: X when an operator must edit the service manifest, the operator config or their repository for a passing train to pass again; Y for capability an operator can ignore, or a change that can make a passing train refuse with the same inputs; Z when every train that passed before still passes. Add a missing line to the summary with the Edit tool before the run. Exit 0 with `release: skipped` means the pull request left `VERSION` unchanged, and nothing is published. Exit 0 otherwise writes the release notes to `<repo>/docs/.tmp/daedalus/<train-id>/release-notes.md` and prints the tag, tag push and release commands. It runs none of them. When `<repo>` is the Daedalus plugin repository itself, show them to the operator, then run them in the printed order yourself. In any other project, show them to the operator to run from their own shell, and run none of them yourself. Exit 1: stop and show its output; its `Next:` line is the next action.

End with this line: Execution Train readiness: a later Daedalus release adds the readiness checklist.
