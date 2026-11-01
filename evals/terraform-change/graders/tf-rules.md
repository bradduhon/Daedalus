---
type: regex
target: "trace"
match: "contains"
---
TF-[3-6]\b[^\n]{0,80}?\b(?:PASS|FAIL)\b[^\n]{0,200}?infra/main\.tf:\d+
