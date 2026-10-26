<!-- Copyright (c) 2026 Brad Duhon. SPDX-License-Identifier: GPL-3.0-or-later -->
# Refused: the serial edges form a cycle

```plan
unit: U1 | title: plan parser | files: scripts/lib/a.py | base: integration
unit: U2 | title: plan gate | files: scripts/lib/b.py | base: integration
unit: U3 | title: catalog | files: scripts/lib/c.py | base: integration
edge: U1 -> U2 | kind: serial | why: b imports a
edge: U2 -> U3 | kind: serial | why: c imports b
edge: U3 -> U1 | kind: serial | why: a imports c
graph: units=3 critical_path=3 width=1 overlap_only=none
```

### U1: plan parser

Requirements:
1. Make `scripts/lib/a.py` import `scripts/lib/c.py`.

### U2: plan gate

Requirements:
1. Make `scripts/lib/b.py` import `scripts/lib/a.py`.

### U3: catalog

Requirements:
1. Make `scripts/lib/c.py` import `scripts/lib/b.py`.
