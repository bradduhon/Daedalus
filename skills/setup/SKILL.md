---
name: setup
description: Writes the two starter project files Daedalus reads, service-manifest.json at the project root with every feature off and .claude/daedalus/config.json with every setting at its default. Writes only a file that is missing and never overwrites one.
argument-hint: Optional path to the target project (default is the current directory).
allowed-tools: Bash(python3 ${CLAUDE_SKILL_DIR}/../../scripts/daedalus_setup.py *)
---
<!-- Copyright (c) 2026 Brad Duhon. SPDX-License-Identifier: GPL-3.0-or-later -->

# daedalus setup

Human-facing text (0031): Text a human reads names each item in words: a short label or one line on what it is and what it does. Ids (ruling ids, issue numbers, task codes, agent names, snake_case keys) may trail in parentheses, never replace the description. Logs, status lines and messages to other agents may use ids alone. Documents carry both.

1. Run `python3 ${CLAUDE_SKILL_DIR}/../../scripts/daedalus_setup.py --repo "<path>"` with Bash once, exactly as written, where `<path>` is `$ARGUMENTS` when the operator gave one and `.` otherwise.
2. Show the output to the operator unchanged. Each line names one file: `written:` means the script created it, and `kept:` means the file already existed and was left as it was (0076). The one other line, `docs.literacy: null; examples: <examples>`, follows a written service manifest: it names the literacy values the docs writer reads from `docs.literacy`, since the file itself holds no comments (0134). Do not edit either file and do not run any other command.
3. If the script exits 1, show its message unchanged; the part after `Next:` is the next action.
4. After the output, tell the operator that the key reference in the plugin README explains every key in both files, and name the health check as the next command: `/daedalus:doctor`.
