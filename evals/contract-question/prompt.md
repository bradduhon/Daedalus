---
name: "contract-question"
description: "A contract with an undecided field makes the run ask the operator before any coder starts."
tags: ["orchestrator", "fold-contract", "fold-planner", "fold-orchestrator"]
runs: 2
max_turns: 120
timeout_seconds: 2400
allowed_tools: ["Bash", "Write", "Edit"]
---
/daedalus:run Have the orders module publish the invoice event of contracts/invoice-event.md when an order is paid, and have the billing module record each event it receives.
