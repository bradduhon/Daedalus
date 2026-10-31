---
type: regex
target: "trace"
match: "contains"
---
TF-0[^\n]{0,120}\b(?:WARN|PASS)\b
