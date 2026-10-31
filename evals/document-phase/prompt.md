---
name: "document-phase"
description: "The doc composition freezes the sources, has the writer derive the FAQ, checks its claims and builds the change log against the old FAQ."
tags: ["writer", "verifier", "comparer"]
runs: 2
max_turns: 150
timeout_seconds: 3000
allowed_tools: ["Bash", "Write", "Edit"]
---
/daedalus:run doc the updated customer FAQ as out/faq.md, derived from the old FAQ and the October pricing change, sources faq=baseline:sources/faq.sent-2026-09-01.md and pricing=amendment:sources/pricing-change.sent-2026-10-01.md, folder out
