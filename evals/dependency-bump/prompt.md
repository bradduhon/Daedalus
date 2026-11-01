---
name: "dependency-bump"
description: "A dependency bump runs the dependency audit on the changed manifest, with web lookup off."
tags: ["orchestrator", "coder", "verifier", "auditor", "fold-judges", "fold-web", "fold-orchestrator", "model-coder"]
runs: 2
max_turns: 120
timeout_seconds: 2400
allowed_tools: ["Bash", "Write", "Edit"]
---
/daedalus:run Bump requests from 2.31.0 to 2.32.3 in requirements.txt.
