---
name: "small-fix"
description: "A one-file fix runs small: one coder unit, a verifier check, the short audit and no contract packet."
tags: ["orchestrator", "coder", "verifier", "auditor", "fold-orchestrator", "model-coder"]
runs: 2
max_turns: 120
timeout_seconds: 2400
allowed_tools: ["Bash", "Write", "Edit"]
---
/daedalus:run Fix word_count in src/textkit.py: runs of spaces, tabs and newlines between words count as one separator, and a blank string has 0 words. Cover both cases in tests/test_textkit.py.
