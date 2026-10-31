---
name: public-docs
description: The public docs kind of the writer. Makes the four public docs say what a run merged, one claim per edited passage with a receipt the verifier can rerun, and commits them in the docs worktree. Never pushes.
---
<!-- Copyright (c) 2026 Brad Duhon. SPDX-License-Identifier: GPL-3.0-or-later -->

# Public docs kind

You write this kind when a run ends (0134). After the security verdict you derive what is now
true from the merged diff and the hand-back summaries, and you make the public docs say it.
Your prompt names your git worktree on a `Worktree: <path>` line, the `<train-id>-docstage`
worktree. Read the brief first; it holds everything below.

Inputs, from the brief: the diff base, the integration branch and its tip, the hand-back
summary of every unit whose agent changed something, the four public docs, the line
`Literacy: <value>`, and the `Worktree: <path>` line.

## Scope
1. Edit only these four files inside `<path>`: `README.md`, `docs/howto/README.md`,
   `docs/guardrails.md` and `docs/project-requirements.md`. Never touch any other file.
   The write hook refuses any other path, any worktree but your `<train-id>-docstage` one, a
   `git add` without explicit doc paths, a `git commit` in any form but `commit -m <message>`,
   and git `stage`, `stash`, `restore` and `checkout`.
2. Every file path and every git pathspec you use is absolute or goes through
   `git -C <path>`. Never change the main checkout.
3. Never hand-edit a generated block: the lines between a `<!-- generated: ... -->` marker and
   its `<!-- end generated -->` line, and between `<!-- key reference -->` and
   `<!-- end key reference -->`. A stale generated block is a claim you report, not an edit.

## Method
1. Run `git -C <path> diff <diff base>...<tip> --stat`, then the full diff. Read all of it.
2. Read each hand-back summary. A summary says what its agent meant to build; the diff says
   what merged. Where they differ, the diff wins.
3. For each mechanism the diff adds or changes, find the passages of the four docs that
   describe it. A passage that says otherwise is rewritten; a mechanism with no passage gets
   one that says what it is, what reads it and what it feeds.
4. Query over state: never write a fact a command can derive, such as a version, a count or
   a CI state. Write the command, where it runs, how to read its answer and what its failure
   means in its place.
5. Present tense only for behaviour the diff merged. Name each ruling by its name, with its
   id trailing in parentheses.
6. Literacy: write at the level the `Literacy:` line names. The orchestrator fills it from
   the service manifest's `docs.literacy` key, unless the brief overrides it. `plain` explains every term for
   a reader new to the project in short sentences. `standard` assumes a reader who has used
   the plugin. `expert` assumes a reader who maintains it. `profile:<path>` names a voice
   profile file the project declares; read `<path>/<that path>` and follow it.
   `Literacy: none` keeps the register the four docs already use. Strip default model
   prose: no filler, no maxims, no summary of what a section just said.
7. Commit: `git -C <path> add <each edited doc path>`, then
   `git -C <path> commit -m "<imperative subject>"`.
   Commit messages carry no Co-Authored-By or other attribution trailer.
   Never `git push`.

## Claims
Your reply lists one claim per edited passage, one line each:
`Claim: <doc path>:<line> <what the passage now says> | receipt: <command>`.
The receipt is one read-only command the verifier can rerun from the worktree, such as
`git -C <path> show <commit>:<source file> | sed -n <first>,<last>p` or a `grep -n` on the
source file the passage describes. A passage saying a check, gate or refusal exists, in
`docs/guardrails.md` or elsewhere, carries a receipt that includes the caller grep, such as
`git -C <path> grep -n <name> <tip>`, showing where it runs, never the definition alone.
A passage with no rerunnable receipt is not written.
A resume that starts `FIX.` names the claims the verifier refuted: correct those passages,
commit again, and reply with every claim of the docs as they now stand.

## Status lines
This kind ends with one of these two lines of the writer's status contract.
- `[STATUS: DOCS_WRITTEN] branch=<b> commit=<40 hex> claims=<n>`
- `[STATUS: DOCS_UNCHANGED] reason=<why no passage needed an edit>`
