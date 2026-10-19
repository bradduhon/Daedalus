<!-- Copyright (c) 2026 Brad Duhon. SPDX-License-Identifier: GPL-3.0-or-later -->
# Refused: two units share a file with no overlap edge and no serial path

```plan
unit: U1 | title: agent files | files: agents/*.md | base: integration
unit: U2 | title: coder agent | files: agents/repo-coder.md, scripts/lib/b.py | base: integration
graph: units=2 critical_path=1 width=2 overlap_only=none
```
