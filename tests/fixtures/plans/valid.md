<!-- Copyright (c) 2026 Brad Duhon. SPDX-License-Identifier: GPL-3.0-or-later -->
# A valid plan

Five units: two serial chains, one overlap on a shared file, one pin.

```plan
unit: U1 | title: plan parser | files: scripts/lib/a.py, tests/test_a.py | base: integration
unit: U2 | title: plan gate | files: scripts/lib/b.py, tests/test_b.py | base: U1
unit: U3 | title: shell grammar | files: scripts/lib/shell.py, README.md | base: integration
unit: U4 | title: jail rules | files: scripts/lib/shell.py, scripts/lib/jail.py | base: integration
unit: U5 | title: docs and catalog | files: docs/*.md, README.md, tests/fixtures/u5/ | base: U3
edge: U1 -> U2 | kind: serial | why: b imports a.load
edge: U3 -> U5 | kind: serial | why: U5 edits the README blocks U3 regenerates
edge: U3 ~ U4 | kind: overlap | files: scripts/lib/shell.py | merge: U3 then U4
pin: U1 -> U5 | `a.load(path: Path) -> A`
graph: units=5 critical_path=2 width=3 overlap_only=U3~U4
```

The prose around the block is for the reader.

### U1: plan parser

Requirements:
1. Add `a.load()` to `scripts/lib/a.py`.
2. Cover it in tests/test_a.py.

### U2: plan gate

Requirements:
1. Make `scripts/lib/b.py` refuse a plan that `a.load()` cannot read.

### U3: shell grammar

Requirements:
1. Add the new grammar rows to `scripts/lib/shell.py` and its README rows.

### U4: jail rules

Requirements:
1. Name the new rows of `scripts/lib/shell.py` in scripts/lib/jail.py.

### U5: docs and catalog

Requirements:
1. Regenerate the catalog in `README.md` and the docs pages.
