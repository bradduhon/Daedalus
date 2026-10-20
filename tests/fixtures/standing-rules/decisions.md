<!-- Copyright (c) 2026 Brad Duhon. SPDX-License-Identifier: GPL-3.0-or-later -->
# Decisions

| Id | Date | Ruling | Supersedes | Follow-ups |
|---|---|---|---|---|
| 0001-TST-PLT | 2026-01-01 | Every change runs as a train, with one plan per body of work. | Spec section 2 order | None |
| 0002-TST-PLT | 2026-01-02 | The jail refuses network tools for workers (see `curl`, `wget`): the hook checks the command word. | None | None |
| 0003-TST-PLT | 2026-01-03 | Coders push their own branches. | None | None |
| 0004-TST-PLT | 2026-01-04 | Ledger rows are appended under a lock; the lock lives in the owning project. | The old ledger note, and 0001-TST-PLT's train wording | None |
| 0005-TST-PLT | 2026-01-05 | Only the conductor pushes, and the operator merges. | Supersedes: 0003-TST-PLT. Applies: 0001-TST-PLT. | None |
| 0006-TST-PLT | 2026-01-06 | Workers read during a train. A worker may read another agent's files, never write them. | Amends: 0002-TST-PLT. | None |
| 0007-TST-PLT | 2026-01-07 | Warn the operator, never block main. The main session is warned and keeps working. | None. Applies: 0006-TST-PLT (workers read during a train). | None |
| 0008-TST-PLT | 2026-01-08 | Pipe escape kept. A cell may carry an escaped \| pipe. | None. | None |
