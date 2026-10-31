---
type: regex
target: {"source": "file", "path": "out/faq.md"}
match: "contains"
---
\b12 dollars\b[^\n]{0,160}?\bpricing:\d+
