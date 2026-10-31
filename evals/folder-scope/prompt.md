---
name: "folder-scope"
description: "A spec in a plain folder runs the plan phase in folder scope: no git command, no orchestrator, the plan lands in the output folder."
tags: ["fold-planner"]
runs: 2
max_turns: 80
timeout_seconds: 1800
allowed_tools: ["Bash", "Write", "Edit"]
append_system_prompt: "No operator is at the keyboard for this session. When Daedalus asks where a folder run's outputs go, the operator's answer is the project's docs folder, choice 1."
---
/daedalus:run specs/greeting.md
