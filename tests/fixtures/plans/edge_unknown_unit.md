<!-- Copyright (c) 2026 Brad Duhon. SPDX-License-Identifier: GPL-3.0-or-later -->
# Refused: an edge names a unit the plan does not declare

```plan
unit: U1 | title: plan parser | files: scripts/lib/a.py | base: integration
unit: U2 | title: plan gate | files: scripts/lib/b.py | base: U1
edge: U1 -> U9 | kind: serial | why: b imports a.load
graph: units=2 critical_path=1 width=2 overlap_only=none
```
