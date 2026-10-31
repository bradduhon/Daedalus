---
type: regex
target: "trace"
match: "contains"
---
DEP-[1-7]\b[^\n]{0,80}?\b(?:PASS|FAIL)\b[^\n]{0,200}?requirements\.txt:\d+
