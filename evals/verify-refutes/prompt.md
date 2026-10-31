---
name: "verify-refutes"
description: "A unit whose requirements reach past its files list is refuted by the verifier and never merged as verified."
tags: ["orchestrator", "coder", "verifier", "fold-orchestrator", "model-coder"]
runs: 2
max_turns: 150
timeout_seconds: 3000
allowed_tools: ["Bash", "Write", "Edit"]
---
/daedalus:run plans/rename-slug.md
