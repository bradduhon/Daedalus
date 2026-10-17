---
name: doctor
description: First-run check for the daedalus plugin. Lists every file, setting, and tool daedalus needs, says which are missing, and gives the next step for each. Changes nothing.
argument-hint: Optional path to the target repository (default is the current directory).
allowed-tools: Bash(python3 ${CLAUDE_SKILL_DIR}/../../scripts/daedalus_doctor.py *)
---
<!-- Copyright (c) 2026 Brad Duhon. SPDX-License-Identifier: GPL-3.0-or-later -->

# daedalus doctor

Human-facing text (0031): Text a human reads names each item in words: a short label or one line on what it is and what it does. Ids (ruling ids, issue numbers, task codes, agent names, snake_case keys) may trail in parentheses, never replace the description. Logs, status lines and messages to other agents may use ids alone. Documents carry both.

1. Run `python3 ${CLAUDE_SKILL_DIR}/../../scripts/daedalus_doctor.py --repo "<path>"` with Bash, exactly as written, where `<path>` is `$ARGUMENTS` when the operator gave one and `.` otherwise.
2. Show the output to the operator unchanged. Do not run any other command to investigate a `MISS` or `OPT` line; each line carries its own detail.
3. Ask once, in a single message, about every `MISS` line, then every `OPT` line marked optional: number them and ask whether to do all, the numbers the operator picks, or none. Never ask per line. Perform only the `Next:` actions the operator picked. Scaffolding offers point at docs/project-requirements.md in the plugin repo for the exact file contents.
4. If no line is `MISS`, say so and name the next command: `/daedalus:build-train <task>`.
