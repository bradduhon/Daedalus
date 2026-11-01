<!-- Copyright (c) 2026 Brad Duhon. SPDX-License-Identifier: GPL-3.0-or-later -->
# Eleven operator checks on one unit

```plan
unit: W1 | title: scene loader | files: web/src/scene.ts | base: integration | operator_checks: c1; c2; c3; c4; c5; c6; c7; c8; c9; c10; c11
graph: units=1 critical_path=1 width=1 overlap_only=none
```

### W1: scene loader

Requirements:
1. Load the scene models in `web/src/scene.ts`.
