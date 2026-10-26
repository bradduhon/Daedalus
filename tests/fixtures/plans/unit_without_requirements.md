<!-- Copyright (c) 2026 Brad Duhon. SPDX-License-Identifier: GPL-3.0-or-later -->
# Refused: a unit has no requirement section

```plan
unit: U1 | title: plan parser | files: scripts/lib/a.py | base: integration
unit: U2 | title: plan gate | files: scripts/lib/b.py | base: integration
graph: units=2 critical_path=1 width=2 overlap_only=none
```

### U1: plan parser

Requirements:
1. Add `a.load()` to `scripts/lib/a.py`.

### U2 plan gate

The heading above has no colon, so it is not a requirement section.
