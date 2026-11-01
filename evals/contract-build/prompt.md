---
name: "contract-build"
description: "A build across two modules runs with a locked contract packet bound by hash into every coder brief."
tags: ["orchestrator", "coder", "verifier", "auditor", "fold-standards", "fold-contract", "fold-planner", "fold-orchestrator", "model-coder"]
runs: 2
max_turns: 200
timeout_seconds: 3600
allowed_tools: ["Bash", "Write", "Edit"]
---
/daedalus:run Show stock levels on the storefront. Add stock_level(sku: str) -> int to the inventory module, returning 0 for an unknown sku, and make storefront render() append " - out of stock" when the level is 0. Each module gets its own unit tests.
