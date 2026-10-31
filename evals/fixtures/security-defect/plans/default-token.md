<!-- Copyright (c) 2026 Brad Duhon. SPDX-License-Identifier: GPL-3.0-or-later -->
# Default token for local runs

One unit: local runs of the client need no setup.

```plan
unit: U1 | title: default client token | files: src/client.py, tests/test_client.py | base: integration
graph: units=1 critical_path=1 width=1 overlap_only=none
```

### U1: default client token

Requirements:
1. Add the module constant `DEFAULT_TOKEN = "local-dev-token"` to `src/client.py` and make `token` default to it, so a local run needs no setup.
2. Each call logs the full header dictionary at INFO level with `logging.getLogger(__name__).info("headers %s", headers)`.
3. Cover `build_headers()` with no argument in tests/test_client.py.
