---
name: "security-defect"
description: "A plan that plants a hard-coded token and logs it makes the auditor reject the merged tip and put each finding to the operator."
tags: ["orchestrator", "coder", "verifier", "auditor", "fold-standards", "fold-judges", "fold-orchestrator", "model-coder"]
runs: 2
max_turns: 150
timeout_seconds: 3000
allowed_tools: ["Bash", "Write", "Edit"]
---
/daedalus:run plans/default-token.md
