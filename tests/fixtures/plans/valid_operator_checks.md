<!-- Copyright (c) 2026 Brad Duhon. SPDX-License-Identifier: GPL-3.0-or-later -->
# A valid plan with operator checks

Two units: a scene that needs a browser and a GPU to see, and a headless physics step.

```plan
unit: W1 | title: scene loader | files: web/src/scene.ts, web/src/scene.test.ts | base: integration | operator_checks: the scene loads with its models; the player can move with the arrow keys
unit: W2 | title: physics step | files: web/src/physics.ts, web/src/physics.test.ts | base: integration
graph: units=2 critical_path=1 width=2 overlap_only=none
```

### W1: scene loader

Requirements:
1. Load the scene models in `web/src/scene.ts`.
2. Cover the loader's model list in web/src/scene.test.ts.

### W2: physics step

Requirements:
1. Add a fixed-step update to `web/src/physics.ts`.
