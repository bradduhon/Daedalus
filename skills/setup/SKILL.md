---
name: setup
description: Turns on the OS sandbox for Daedalus. Checks for bubblewrap and socat, then merges the sandbox, credential deny rules and cache settings into ~/.claude/settings.json without overwriting any value you already set, and prints the change. Restart Claude Code afterwards.
argument-hint: No arguments.
disable-model-invocation: true
---
<!-- Copyright (c) 2026 Brad Duhon. SPDX-License-Identifier: GPL-3.0-or-later -->

# daedalus setup

1. Run `python3 ${CLAUDE_PLUGIN_ROOT}/scripts/daedalus_setup.py` with Bash, from the main session, only because the operator typed `/daedalus:setup`; never run it on your own, and never from an agent.
2. Show the output to the operator unchanged.
3. Exit 1: nothing was written. Its `Next:` part is the next action, for example the package install line; the operator runs it from their own shell, then types `/daedalus:setup` again.
4. Exit 0 with a diff: the settings file changed as shown. Say "Restart Claude Code to apply", and after the restart run `/daedalus:doctor`; its sandbox line then reads `OK   sandbox: on`.
5. Exit 0 with `nothing written`: the settings already hold every recommended value. Run `/daedalus:doctor`.
