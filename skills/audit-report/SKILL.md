---
name: audit-report
description: Shows a readable digest of one session's audit log for this repo, after checking that the log's hash chain is intact. Lists the agents that ran, their Write, Edit and Bash calls, every block, every status line, and totals.
argument-hint: Optional session id (default is the newest session log for this repo).
---
<!-- Copyright (c) 2026 Brad Duhon. SPDX-License-Identifier: GPL-3.0-or-later -->

# daedalus audit report

Human-facing text (0031): Text a human reads names each item in words: a short label or one line on what it is and what it does. Ids (ruling ids, issue numbers, task codes, agent names, snake_case keys) may trail in parentheses, never replace the description. Logs, status lines and messages to other agents may use ids alone. Documents carry both.

1. Run `python3 ${CLAUDE_PLUGIN_ROOT}/scripts/audit_report.py --session "<id>"` with Bash, where `<id>` is `$ARGUMENTS` when the operator gave one; otherwise omit `--session` and tell the operator it reports the newest session log for this repo. The script checks the hash chain before it renders anything.
2. If the script exits 0, show the digest to the operator unchanged. Take `<session>` from the digest's `session:` line, with any backslashes removed; steps 5 to 7 use it.
3. If the script exits 1 with a `BROKEN` line, show that line and nothing else from the log. Tell the operator the audit log failed its chain check, so a record was changed, removed, or reordered after it was written. The operator can rerun the check by hand with `python3 ${CLAUDE_PLUGIN_ROOT}/scripts/verify_audit_chain.py <repo>/.claude/daedalus/audit/<session>.jsonl`, where `<session>` is the id given or, with none given, the newest `.jsonl` in that directory. Then give the three next actions: keep the file, report it, do not edit it.
4. If the script exits 1 with any other message, show the message unchanged. Its `Next:` part is the next action.
5. After a digest is shown, read `<repo>/.claude/daedalus/config.json`, where `<repo>` is the main working tree; a linked worktree shares that file. `python3 ${CLAUDE_PLUGIN_ROOT}/scripts/daedalus_doctor.py` prints the resolved data directory on its `project data dir:` line, and config.json lives inside it. A missing file means no `charter_root`: go to step 7. When the file declares `charter_root`, ask the operator: "Render this session's report again and save it to <charter_root>/audit/<session>.md? (yes/no)". Add that a live session will have gained a few records since the digest on screen.
6. On yes, run `python3 ${CLAUDE_PLUGIN_ROOT}/scripts/audit_report.py --session <session> --out <charter_root>/audit/<session>.md`. Name the session so a newer log cannot take its place. If the message says `<charter_root>/audit` does not exist, offer to create it; on yes, create it with `mkdir -p` and rerun the command. For any other exit 1, show the message unchanged; its `Next:` part is the next action. On success, show the `wrote` line, then say the file is ready for the charter-docs agent to commit in a later Build Train. Do not commit it and do not start an agent from this skill.
7. On no, or when there is no `charter_root`, say the digest stays on screen only. Name the raw log: `<repo>/.claude/daedalus/audit/<session>.jsonl`. Next: run `/daedalus:audit-report <session>` again to see it.
