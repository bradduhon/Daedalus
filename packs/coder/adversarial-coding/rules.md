<!-- Copyright (c) 2026 Brad Duhon. SPDX-License-Identifier: GPL-3.0-or-later -->
# Daedalus coder pack: adversarial coding

Method for attacking your own change before the hand-back, for a unit of the build-only-the-ask class. Read before the first edit and again before COMPLETE. The brief is scope; this pack is method. Name the ids you applied, and any you declined with the reason, in your ledger notes.

## Rules

- AC-1: Hunt before you hand back. For each requirement, build at least two hiding forms from the hunt list of the coder file and prove each refused with a test row.
  Check: the receipts hold one `- hunt` line per form and the COMPLETE line's `hunt=<n>` equals their count.
  Why: the verifier runs the same hunt; every form it finds first is a round you pay for.
- AC-2: Test the negative, not the example. Every admitted form in the brief gets a sibling refused form that differs by one token: one flag, one quote, one separator.
  Check: for each admitted test row there is a refused row one token away.
  Why: a check that only sees the example passes everything that looks like it.
- AC-3: The oracle is the real tool, not your model of it. A parsing or grammar rule is proved against the tool's own output in a probe, never reasoned from memory.
  Check: each parsing claim has a probe fixture or transcript; none rests on a comment that says "bash does X".
  Why: the cases that matter are the ones memory gets wrong.
- AC-4: Revert the fix; the new test must fail. Every new test is run against the base commit before the hand-back.
  Check: `git stash` or a checkout of the base, run the new tests, and each fails; a test that passes on the base proves nothing and is rewritten.
  Why: a test that cannot fail is documentation, not a guard.
- AC-5: Two deep. Every construct that nests (a body, a substitution, a wrapper, a group) is tested at depth one and depth two.
  Check: the test set has a depth-two row per nesting construct the unit touches.
  Why: the first level is where the author looked; the second is where the bypass lives.
- AC-6: Read your own diff as the verifier will. Put the brief beside the diff and judge each requirement done, not done, added or subtracted before the hand-back.
  Check: the hand-back names every added or subtracted item on a deviation line; the verifier finds none you did not name.
  Why: the verifier judges the diff against the brief, never against your report.
- AC-7: Stop hunting at the table's edge. A hiding form the table cannot name is refused by construction; it is not a new rule to write.
  Check: no hunt receipt names a fix that adds a deny rule; a fix adds a table row or an opaque path.
  Why: writing one more deny rule is how the open space wins.
