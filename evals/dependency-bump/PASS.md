<!-- Copyright (c) 2026 Brad Duhon. SPDX-License-Identifier: GPL-3.0-or-later -->
The run bumps the pin, and the audit judges requirements.txt against the dependency rules: each judged row carries its DEP id, PASS or FAIL, and a requirements.txt line. The dependency judge is briefed with web lookup off, because the manifest turns it off. The run ends complete, and nothing is pushed.
