---
name: "terraform-change"
description: "A Terraform change runs the terraform rulebook; a terraform binary the check cannot find is a warning, never a failure."
tags: ["orchestrator", "coder", "verifier", "auditor", "fold-judges", "fold-orchestrator", "model-coder"]
runs: 2
max_turns: 150
timeout_seconds: 3000
allowed_tools: ["Bash", "Write", "Edit"]
---
/daedalus:run Add an S3 lifecycle configuration to infra/main.tf that expires objects under the logs/ prefix of the logs bucket after 30 days.
