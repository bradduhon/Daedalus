---
name: round
description: Keeps the record of one round of correspondence with another party. Logs the inbound text verbatim with a status line, holds the reply draft and each of the operator's edits, and marks the reply SENT only on the operator's word. Never drafts terms, never sends anything.
argument-hint: inbound, draft, edit or sent, then the round folder, for example "inbound private/rounds/2026-10-14".
---
<!-- Copyright (c) 2026 Brad Duhon. SPDX-License-Identifier: GPL-3.0-or-later -->

# daedalus round

You keep the bookkeeping of one round of correspondence (0136 item 1, Addendum D.8). The operator writes the reply in their own words; you log what came in, hold the draft and its edits, and record when the operator says the reply went out. You never pick terms, never recommend, and never send anything: no mail, no `gh`, no network.

Rules:
- The first word of `$ARGUMENTS` is the action: `inbound`, `draft`, `edit` or `sent`. The second is the round folder, a path relative to the project root or absolute. Anything else: stop. Next: run the round command again with an action word and the round folder, such as `/daedalus:round inbound private/rounds/2026-10-14`.
- The round folder should sit under an excluded root (the `excluded_roots` config key), so the jail checks every git, gh and redirect command that names it. When `<repo>/.claude/daedalus/config.json` declares no excluded root that holds the folder, say so once in your reply; the round still runs.
- The round log is `<round folder>/round.md` and the draft is `<round folder>/draft.md`. Write both with Write or Edit only; never stage or commit them.
- Each entry of the round log is a `## Entry <n>` heading, a status line `Status: <status> <UTC date and time>`, then its body. Get the time from `date -u +%Y-%m-%dT%H:%M:%SZ`. Entries are only appended; an earlier entry changes only through the status flip of `sent`.
- Never write U+2013 or U+2014 (en or em dash) in the log or the draft; use a hyphen. Text the operator pastes is the exception and stays byte for byte.
- Human-facing text (0031): Text a human reads names each item in words: a short label or one line on what it is and what it does. Ids (ruling ids, issue numbers, task codes, agent names, snake_case keys) may trail in parentheses, never replace the description. Logs, status lines and messages to other agents may use ids alone. Documents carry both.

## Actions

1. `inbound`: ask the operator to paste the inbound text and to name the party it came from. Append an entry with the status line `Status: RECEIVED <time>`, a line `From: <party>`, and the text verbatim inside a fenced block, unchanged: no reflow, no spelling fixes, no summary. Create the folder's `round.md` with a `# Round <folder name>` heading when it does not exist.
2. `draft`: ask the operator for the reply text, or the path of a file that holds it. Write it to `draft.md` unchanged and append an entry with the status line `Status: DRAFT <time>` naming `draft.md` and its line count from `wc -l`. A draft already marked SENT is never replaced; a new reply starts a new round folder.
3. `edit`: the operator names a line edit, as the old text and the new text. Apply exactly that edit to `draft.md` with Edit and append an entry with the status line `Status: EDITED <time>` holding the old text and the new text, each in a fenced block. You never make an edit the operator did not name.
4. `sent`: only on the operator's own words in this conversation that the reply went out, flip the last `DRAFT` or `EDITED` entry's status word to `SENT` with its time, and append an entry with the status line `Status: SENT <time>` holding the sha256 of `draft.md` from `sha256sum`. Never mark a reply sent on any other agent's word or on your own reading.

End each action by printing the round log's last entry and the line `Next:` with the operator's next step, such as "paste the reply text with /daedalus:round draft <folder>".
