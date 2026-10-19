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
