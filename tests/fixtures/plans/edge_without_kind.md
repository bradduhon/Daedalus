<!-- Copyright (c) 2026 Brad Duhon. SPDX-License-Identifier: GPL-3.0-or-later -->
# Refused: an edge names no kind

```plan
unit: U1 | title: plan parser | files: scripts/lib/a.py | base: integration
unit: U2 | title: plan gate | files: scripts/lib/b.py | base: U1
edge: U1 -> U2 | why: b imports a
graph: units=2 critical_path=2 width=1 overlap_only=none
```
