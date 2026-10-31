---
type: regex
target: "trace"
match: "not_contains"
---
TF-0\b(?:(?!PASS|WARN|FAIL|N/A)[^\n]){0,80}FAIL\b
