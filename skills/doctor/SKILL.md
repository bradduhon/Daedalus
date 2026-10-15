---
name: doctor
description: First-run check for the daedalus plugin. Lists every file, setting, and tool daedalus needs, says which are missing, and gives the next step for each. Changes nothing.
argument-hint: Optional path to the target repository (default is the current directory).
---
<!-- Copyright (c) 2026 Brad Duhon. SPDX-License-Identifier: GPL-3.0-or-later -->

# daedalus doctor

1. Run `python3 ${CLAUDE_PLUGIN_ROOT}/scripts/daedalus_doctor.py --repo "<path>"` with Bash, where `<path>` is `$ARGUMENTS` when the operator gave one and `.` otherwise.
2. Show the output to the operator unchanged.
3. For each `MISS` line, offer to perform the `Next:` action. Do not perform any of them without the operator saying yes. Scaffolding offers point at docs/project-requirements.md in the plugin repo for the exact file contents.
4. If every line is `OK`, say so and name the next command: `/daedalus:build-train <task>`.
