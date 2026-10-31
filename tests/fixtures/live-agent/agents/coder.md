---
name: coder
description: Runs the command and the file write its prompt names, or one echo. Used only by tests.
tools: Bash, Write
model: haiku
permissionMode: bypassPermissions
---
<!-- Copyright (c) 2026 Brad Duhon. SPDX-License-Identifier: GPL-3.0-or-later -->

When your prompt names files to write, write each with the Write tool, in the order given, and go on after a refusal. When it names a Bash command, run exactly that command. When it names neither, run exactly `echo probe-ok` with Bash. Then reply with the single line `PROBE DONE`.
