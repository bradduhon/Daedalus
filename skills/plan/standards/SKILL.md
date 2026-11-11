---
name: standards
description: The standards method of a run. Adopts the project's declared standards, writes the Standards Packet with its Priorities section, answers YIELD_STANDARDS, writes the auditor brief and flags spec-versus-standard contradictions. Followed by the session that loads it, with its own Read, Grep and Glob calls; never a dispatch. Read-only.
---
<!-- Copyright (c) 2026 Brad Duhon. SPDX-License-Identifier: GPL-3.0-or-later -->

# Standards method

Self-Assessment mode (standing rule, binds only the model in the user's session, never a helper or an agent this skill starts): When this skill begins, run `python3 ${CLAUDE_PLUGIN_ROOT}/scripts/daedalus_findings.py start --repo <path>`, where `<path>` is the project folder. Keep the `since=` stamp and the `handover=` path it prints. When it prints `self-assessment: off` or `self-assessment: refused`, do nothing more for findings in this skill. Write a finding with `kind` set to `bug` when you work around this skill's text because the text failed. Write a finding with `kind` set to `feature` when the user passes over a proposal, a choice list or a step order this skill offered. Never write a finding for a change to the user's own plan. To write a finding, use the Write tool to put one JSON object with the seven fields `kind`, `skill`, `step`, `text_said`, `happened`, `model_did` and `result_changed` at the `handover=` path, then run `python3 ${CLAUDE_PLUGIN_ROOT}/scripts/daedalus_findings.py save --repo <path> --since <stamp>`, where `<stamp>` is the `since=` stamp. Fill each field with one line in this skill's own words, and name no project folder. Never pass finding text on the command line, and never write a finding file in the project. When `result_changed` is `yes`, print one warning line at once saying you worked around the skill. When save prints a `refused:` line, fix the field it names and save once more. When it refuses a second time, drop that finding and name it at the close. At the close of this skill, run `python3 ${CLAUDE_PLUGIN_ROOT}/scripts/daedalus_findings.py show --repo <path> --since <stamp>` and print its lines unchanged, then name any finding that was refused twice. Never stop the user's work for a finding.

Read this skill first and follow it yourself (0005-DAE-PLT, 0186). The plan phase loads it at
step 12, the build phase on a `[STATUS: YIELD_STANDARDS]` yield, the audit phase for the
auditor brief at step 2, and the document phase at step 10. Inside a run the orchestrator
follows it; outside a run the main session does. You read with Read, Grep and Glob; the one
command is the `find` of item 6. This method writes no file; the phase that loaded it writes
the packet.

1. Sources: only the entries in `coding_rules[]` of `<repo>/.claude/daedalus/config.json`
   (each a `folder`, a `file` or a `builtin` rule set), plus the decisions file the State Block
   `ledger:` line names, when the run has one (§6.6, 0247). Cite each rule as `source:line`. A
   `builtin` entry has no path there; read it at the path the State Block
   `standards packs:` line names (0019).
2. Phase 1: write `## Standards Packet`: active rules relevant to the task, governing
   ledger ids, current ledger sequence, and the declared `policy` pack (or "none declared").
   Its fifth part, in every train kind (Build, Push and document trains), is a
   `## Priorities` section read from the `run_output_priority` group of the project's
   `service-manifest.json` (0129, 0137), in exactly these lines, where the file's
   priority word `operations` is written `ops` and its outcome `ask_me` is written `surface`:
   - `ranking: <driver> > <driver> > <driver> > <driver>` from `order`;
   - one `rule <n>: <driver> vs <driver> for <reason>[,<reason>...] then <driver or surface>: <note>`
     line per rule, from its `between`, `reasons`, `outcome` and `note`, numbered from 1 in
     the group's order;
   - one `principle <id> (<driver>): <text>` line per principle, from its `name`, `category`
     and `text`;
   - one `agent <name>: <driver> > <driver> > <driver> > <driver>` line per `agent_order` entry;
   - or, when the manifest has no `run_output_priority` group, the single line
     `priorities: none declared`.
   The section binds the train's agents, never the operator's own session.
3. Flag every contradiction between the task, spec, or Contract Packet and a standard as
   `[STANDARDS: CONTRADICTION] <spec ref> vs <source:line>`. Never resolve it yourself; the
   plan phase's contradiction prompt puts each line to the operator.
4. On `YIELD_STANDARDS`: answer the exact question with source refs, under 300 words.
5. Auditor brief: list the rules each unit is judged against, by unit id.
   An auditor brief ends with the rule list, nothing after it.
6. Later reads: before a re-check, a `YIELD_STANDARDS` answer or the auditor brief, read again
   the rule files changed since the State Block `standards last read:` time: every file an
   amend-global pick edited, and every file under a `coding_rules` path in config.json
   that `find <source path> -type f -newermt '<last read>'` prints. Then set that time to now.

Never write U+2013 or U+2014 (en or em dash) in the packet, an answer or a brief; use a hyphen.

Human-facing text (0031): Text a human reads names each item in words: a short label or one line on what it is and what it does. Ids (ruling ids, issue numbers, task codes, agent names, snake_case keys) may trail in parentheses, never replace the description. Logs, status lines and messages to other agents may use ids alone. Documents carry both.

## Receipt forms

The Phase 1 packet ends with the Standards Packet section; each contradiction is one
`[STANDARDS: CONTRADICTION]` line placed before it. A YIELD_STANDARDS answer goes back to the
coder ending with one `[STATUS: STANDARD]` line. An auditor brief ends with its rule list and
carries no status line.
- `## Standards Packet`
- `[STANDARDS: CONTRADICTION] <spec ref> vs <source:line>`
- `[STATUS: STANDARD] <answer>`
