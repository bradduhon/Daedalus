<!-- Copyright (c) 2026 Brad Duhon. SPDX-License-Identifier: GPL-3.0-or-later -->
# Daedalus coder pack: secure architecture

Method for a unit that touches a jail, gate or parser file (the build-only-the-ask class of the coder file). Read before the first edit. A rule here never changes what the brief asks; the brief is scope, this pack is method. Name the ids you applied, and any you declined with the reason, in your ledger notes.

## Rules

- SA-1: Admit named shapes; never a language minus a deny list. When a check decides what passes, it lists the exact forms it admits and refuses everything else.
  Check: the allow decision is never "not in a deny set"; feed the check one form absent from every table and it refuses.
  Why: a deny list over an open space is defeated by the next spelling nobody listed.
- SA-2: Every safety premise is an invariant with a test that tries to break it. A sentence of the form "X never happens" in the brief or the code gets a named test that attempts X.
  Check: each premise sentence in the brief has a test id beside it in the unit; revert the fix and that test fails.
  Why: a premise no test attacks is an assumption wearing a rule's clothes.
- SA-3: Build only the stated surface. The diff touches no file and changes no behaviour the brief does not name.
  Check: read the diff file by file against the brief's files list and requirements; anything extra is a deviation receipt, not a fix.
  Why: every unrequested change is a surface the verifier was not told to judge.
- SA-4: One reader per input. A unit adds no second tokenizer, quote walker, regex over raw text, or copy of a helper that exists.
  Check: grep the diff for `re.compile(` over command text and for a function whose body matches an existing helper; the ledger notes name the one reader used.
  Why: two readers of one input disagree on the case nobody tested.
- SA-5: Fail closed on the unknown, and say what was unknown. The default branch of every decision refuses, and the refusal names the word, option or construct that was off its table.
  Check: every new refusal string names the thing refused; the opaque or unknown path has its own test.
  Why: a silent pass on the unknown is a hole; a refusal that names nothing cannot be fixed by a table row.
- SA-6: Typed operands, not positional guesses. Every operand a check reads is typed by a table row (read path, write path, text, subcommand, pathspec), never "the second positional".
  Check: each operand read in the diff maps to a table type; a positional index with no type is a defect.
  Why: options move operands; a position is right until the first valued flag.
- SA-7: Refusal text every agent reads is a contract. No refusal string, shared table or shared list changes unless the brief names it.
  Check: diff the refusal constants against the base; each change is named in the brief; a test pins each one the unit touches.
  Why: other agents and other tests read those strings; a wording change is a behaviour change for them.
- SA-8: Probe a tool before you trust a claim about it. A statement about how bash, git, gh or a runner behaves is checked by running the tool once and recording the result.
  Check: each tool claim in the unit has a probe fixture or a transcript line in the receipts.
  Why: a rule built on a remembered behaviour fails on the real one.
