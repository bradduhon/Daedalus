---
name: doctor
description: First-run check for the daedalus plugin. Lists every file, setting, and tool daedalus needs, says which are missing, and gives the next step for each. Changes nothing.
argument-hint: Optional path to the target repository (default is the current directory).
allowed-tools: Bash(python3 ${CLAUDE_SKILL_DIR}/../../scripts/daedalus_doctor.py *)
---
<!-- Copyright (c) 2026 Brad Duhon. SPDX-License-Identifier: GPL-3.0-or-later -->

# daedalus doctor

Human-facing text (0031): Text a human reads names each item in words: a short label or one line on what it is and what it does. Ids (ruling ids, issue numbers, task codes, agent names, snake_case keys) may trail in parentheses, never replace the description. Logs, status lines and messages to other agents may use ids alone. Documents carry both.

Self-Assessment mode (standing rule, binds only the model in the user's session, never a helper or an agent this skill starts): When this skill begins, run `python3 ${CLAUDE_PLUGIN_ROOT}/scripts/daedalus_findings.py start --repo <path>`, where `<path>` is the project folder. Keep the `since=` stamp and the `handover=` path it prints. When it prints `self-assessment: off` or `self-assessment: refused`, do nothing more for findings in this skill. Write a finding with `kind` set to `bug` when you work around this skill's text because the text failed. Write a finding with `kind` set to `feature` when the user passes over a proposal, a choice list or a step order this skill offered. Never write a finding for a change to the user's own plan. To write a finding, use the Write tool to put one JSON object with the seven fields `kind`, `skill`, `step`, `text_said`, `happened`, `model_did` and `result_changed` at the `handover=` path, then run `python3 ${CLAUDE_PLUGIN_ROOT}/scripts/daedalus_findings.py save --repo <path> --since <stamp>`, where `<stamp>` is the `since=` stamp. Fill each field with one line in this skill's own words, and name no project folder. Never pass finding text on the command line, and never write a finding file in the project. When `result_changed` is `yes`, print one warning line at once saying you worked around the skill. When save prints a `refused:` line, fix the field it names and save once more. When it refuses a second time, drop that finding and name it at the close. At the close of this skill, run `python3 ${CLAUDE_PLUGIN_ROOT}/scripts/daedalus_findings.py show --repo <path> --since <stamp>` and print its lines unchanged, then name any finding that was refused twice. Never stop the user's work for a finding.

1. Run `python3 ${CLAUDE_SKILL_DIR}/../../scripts/daedalus_doctor.py --repo "<path>"` with Bash, exactly as written, where `<path>` is `$ARGUMENTS` when the operator gave one and `.` otherwise.
2. Show the output to the operator unchanged. Do not run any other command to investigate a `MISS` or `OPT` line; each line carries its own detail.
3. Ask once, in a single message, about every `MISS` line, then every `OPT` line marked optional: number them and ask whether to do all, the numbers the operator picks, or none. Never ask per line. Perform only the `Next:` actions the operator picked. Scaffolding offers point at docs/project-requirements.md in the plugin repo for the exact file contents.
4. If no line is `MISS`, say so and name the next command: `/daedalus:run <task>`.
