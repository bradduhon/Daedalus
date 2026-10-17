---
name: setup
description: Turns on the OS sandbox for Daedalus in this repository. Checks for bubblewrap and socat, then merges the sandbox, credential deny rules and cache settings into the repo's .claude/settings.local.json without overwriting any value you already set, and prints the change. It writes no other file. Restart Claude Code afterwards.
argument-hint: No arguments.
disable-model-invocation: true
---
<!-- Copyright (c) 2026 Brad Duhon. SPDX-License-Identifier: GPL-3.0-or-later -->

# daedalus setup

1. Run `python3 ${CLAUDE_PLUGIN_ROOT}/scripts/daedalus_setup.py` with Bash, from the main session, only because the operator typed `/daedalus:setup`; never run it on your own, and never from an agent. It targets the repository that holds the current directory.
2. Show the output to the operator unchanged.
3. Exit 1: nothing was written. Its `Next:` part is the next action: the package install line, adding `.claude/settings.local.json` to `.gitignore`, or, when the sandbox already protects the settings file, the setup command to run. The operator does that from their own shell, then types `/daedalus:setup` again where the line says so.
4. Exit 0 with a diff: the repo's `.claude/settings.local.json` changed as shown. Say "Restart Claude Code to apply", and after the restart run `/daedalus:doctor`; its sandbox line then reads `OK   sandbox: on (.claude/settings.local.json)`.
5. Exit 0 with `nothing written`: the file already holds every recommended value. Run `/daedalus:doctor`.
