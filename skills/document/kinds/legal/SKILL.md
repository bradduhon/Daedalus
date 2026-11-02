---
name: legal
description: The legal document kind of the writer. Derives one contract document, such as a draft agreement, a statement of work, a reply to the counterparty's draft or a term summary, from frozen sources only, with a receipt or an operator tag on every clause, a gap question where no source settles a term, and a References section that points each clause at its source. Never recommends a term, never advises on law, never pushes.
---
<!-- Copyright (c) 2026 Brad Duhon. SPDX-License-Identifier: GPL-3.0-or-later -->

# Legal document kind

This kind specialises the derived kind (0190): every rule of
`${CLAUDE_PLUGIN_ROOT}/skills/document/kinds/derived/SKILL.md` binds you, and the rules below
add to it. Your dispatch carries no `Worktree:` line, so it records the derived kind and its
hooks hold you. The Source Manifest at the top of your brief is law.

The output is one contract document the brief names: a draft agreement, a statement of work, a
reply to the counterparty's draft, or a term summary.

1. **Sources**: read only the manifest paths. The counterparty's draft is the `baseline` when
   one exists; otherwise a prior agreement is, when one exists. You quote the baseline by
   receipt, like any other frozen source. The operator's term sheet or notes are an
   `amendment` source; each topic in its `allowed_for` list is a term the operator sets. The
   round records are `correspondence`: quote a line only from an entry whose status line reads
   `RECEIVED` or `SENT`. A prior agreement that is not the baseline is a `reference`. Nothing
   outside the manifest is a source, the brief's prose included.
2. **Clause receipts**: every clause carries a `Claim:` line as the derived kind defines it,
   with a receipt to a frozen source. A clause whose term comes from the operator's term sheet
   carries the tag `[operator term]` on its References line, beside its receipt to that sheet.
3. **Gaps**: a term no source settles is written `[gap: <the question for the operator>]` in
   the clause text and listed in the References section too. A `[gap]` is a question for the
   operator, never a drafted term: write no proposed wording, no default and no example value
   beside it.
4. **No advice**: whether a term is standard, enforceable, fair or favourable is a judgment
   only the operator or counsel makes. You never recommend a term, never advise on law, and
   never state that a clause is standard, enforceable or favourable.
5. **First line**: every output starts with this line, unchanged:
   `Draft from the operator's sources. Every term is the operator's; nothing here is a recommendation or legal advice.`
6. **Values**: numbers, dates, amounts, durations, rates and the names of the parties come
   only from a receipted source or an `[operator term]`. Anything else is a `[gap]`. A clean
   draft carries no square-bracket text but `[gap: ...]`, and `[operator term]` on its
   References lines: run `grep -n -o -E "\[[^]]*\]" <clean draft path>` and paste its output;
   every hit starts `[gap` or sits on a References line and reads `[operator term]`.
7. **Defined terms**: the document has one definitions section. Each defined term is defined
   there once, as `"<Term>" means`, and every later use carries the same capitalisation. For
   each term the brief lists, run `grep -c "\"<Term>\" means" <draft path>`, which must print
   1, and `grep -n -o -i -w "<term>" <draft path>`, whose every hit must read `<Term>`. Paste
   both outputs; they are the receipt.
8. **Clauses**: number clauses `1.`, `1.1`, `1.1.1`. Cross-references cite the number. Draft
   no signature block; the operator adds it.
9. **References**: every draft ends with a final section titled `References`, one line per
   clause number in clause order, `<clause number>: <source alias>:<line or range> <tag>`. The
   source is the line or range the clause rests on; the tag is `[operator term]`, a `[gap]`
   clause's `[gap: <question>]` verbatim, or nothing. The References section is the receipt
   surface the verifier reads in claims mode: each `Claim:` line's receipt matches its
   clause's References line.
10. **No change gate**: the document phase skips the change gate for a legal document, so you
    write no change log. The References section stands in its place.
11. **Term summary**: one table, columns `| Term | Value | Source |`, one row per term the
    brief names, each value receipted, tagged `[operator term]` or written `[gap]`.
12. **Outputs**: exactly the files the brief names, under `output_dir`. The document outputs
    hook refuses a write outside `output_dir` and any write to a source. Bash runs read-only
    inspection only: no git, no gh, no network, nothing staged, committed or pushed.

Your return lists one claim per receipted clause value, one line each:
`Claim: <output path>:<line> <claim> | receipt: <alias>:<line or range>`.

## Status lines
This kind ends with one of the derived kind's two lines of the writer's status contract. Above
it: the output paths with `wc -l`, the bracket grep and the defined-term greps with their
output, every `[gap]` line verbatim, every `[judgment]` line verbatim, every `ASSUMED`, and the
`Claim:` lines. Each `[gap]` counts in `judgments=`, so the present step puts it to the
operator with the `[judgment]` lines.
- `[STATUS: COMPLETE] outputs=<path>[,<path>] claims=<n> judgments=<k> assumed=<m>`
- `[STATUS: BLOCKED] <what the manifest or brief leaves out>`
