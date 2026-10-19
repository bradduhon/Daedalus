<!-- Copyright (c) 2026 Brad Duhon. SPDX-License-Identifier: GPL-3.0-or-later -->
# Refused: the graph line's numbers do not match the computed graph

```plan
unit: U1 | title: plan parser | files: scripts/lib/a.py | base: integration
unit: U2 | title: plan gate | files: scripts/lib/b.py | base: U1
unit: U3 | title: catalog | files: scripts/lib/c.py | base: integration
edge: U1 -> U2 | kind: serial | why: b imports a
graph: units=3 critical_path=3 width=3 overlap_only=none
```
