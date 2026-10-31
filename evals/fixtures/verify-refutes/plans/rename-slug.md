<!-- Copyright (c) 2026 Brad Duhon. SPDX-License-Identifier: GPL-3.0-or-later -->
# Rename the slug helper

One unit: the slug helper takes its public name.

```plan
unit: U1 | title: rename the slug helper | files: src/slug.py, tests/test_slug.py | base: integration
graph: units=1 critical_path=1 width=1 overlap_only=none
```

### U1: rename the slug helper

Requirements:
1. Rename `to_slug` to `slugify` in `src/slug.py`.
2. Remove the name `to_slug`; no alias stays behind.
3. `src/cli.py` calls `slugify`.
4. Cover `slugify` in tests/test_slug.py.
