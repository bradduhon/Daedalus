<!-- Copyright (c) 2026 Brad Duhon. SPDX-License-Identifier: GPL-3.0-or-later -->
# Refused: an overlap edge names no merge order

```plan
unit: U1 | title: shell grammar | files: scripts/lib/shell.py | base: integration
unit: U2 | title: jail rules | files: scripts/lib/shell.py, scripts/lib/jail.py | base: integration
edge: U1 ~ U2 | kind: overlap | files: scripts/lib/shell.py
graph: units=2 critical_path=1 width=2 overlap_only=U1~U2
```

### U1: shell grammar

Requirements:
1. Add the grammar rows to `scripts/lib/shell.py`.

### U2: jail rules

Requirements:
1. Name the new rows of `scripts/lib/shell.py` in `scripts/lib/jail.py`.
