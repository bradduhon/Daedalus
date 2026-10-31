---
name: "release-stops-before-push"
description: "After a finished run, the release phase checks its preconditions and stops at the GitHub sign-in check, before any push."
tags: ["orchestrator", "coder", "verifier", "auditor", "fold-orchestrator", "model-coder"]
runs: 2
max_turns: 200
timeout_seconds: 3600
allowed_tools: ["Bash", "Write", "Edit"]
---
Use /daedalus:run with this task: fix to_celsius in src/units.py so it returns (fahrenheit - 32) * 5 / 9, with a test in tests/test_units.py. When that run completes, switch this repository to the run's integration branch and start the release phase with /daedalus:run push.
