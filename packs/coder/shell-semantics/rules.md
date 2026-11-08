<!-- Copyright (c) 2026 Brad Duhon. SPDX-License-Identifier: GPL-3.0-or-later -->
# Daedalus coder pack: shell semantics

Method for a unit that judges shell command text. Read before the first edit. The brief is scope; this pack is method. Each rule names a class of hiding form; hunt every class against each requirement and prove each form refused or judged by a test row. Name the ids you applied, and any you declined with the reason, in your ledger notes.

## Rules

- SS-1: A variable has many writers. Before judging a guarded name, hunt every writer: plain and appending assignment, the declaring builtins, the reading builtins, formatted output stored into a name, option parsing into a name, array loading, default-assigning expansion, unsetting, and the auto-export options in every spelling.
  Check: one refused row per writer for the guarded name, and one where the writer's target name is built by expansion.
  Why: a check that watches only `NAME=value` misses every other way the shell sets the same name.
- SS-2: The command word is looked up when it runs. Anything earlier in the same command that can change lookup (sourcing a file, any write to the search path, the hash table, a slash or relative command name) leaves every later command word unknown.
  Check: a refused or opaque row for each lookup changer, and for the sourcing builtin behind each prefix form (negation, timing, redirections, a redirection that names its descriptor by variable).
  Why: a guard keyed on the name `git` judges whatever that name resolves to at run time, not the tool.
- SS-3: A command string can run later or elsewhere. Handlers registered for a signal or exit, argument runners that build a command from input, a command substitution inside any argument even of a read-only command, string evaluation, a sourced file, and a payload decoded just before it runs are each a body.
  Check: one row per route; a literal body is walked, any other is refused.
  Why: the text that runs is not the text the check read.
- SS-4: A word with an unquoted expansion, glob character, brace form or tilde prefix is unknown until the shell builds it. Match guards on literal words only. An unknown word may become an option, the guarded name, another letter case or another path, and an unmatched glob stays literal, so judge both outcomes.
  Check: for each literal the check matches, a row where one character of it is produced by expansion, glob or tilde.
  Why: the shell, not the check, decides what the word becomes.
- SS-5: Take a tool's global options from the installed tool's own help and probe each one that takes a value. An option the table does not know leaves the subcommand position unknown.
  Check: a probe fixture lists the tool's global options; each valued one has a row with the subcommand after its value.
  Why: an unknown valued option shifts every later position by one.
- SS-6: Split on every separator the shell honours, the newline included, before judging segment by segment.
  Check: each refused row also refuses with its separators replaced by newlines.
  Why: a check that reads one line sees a different program than the shell runs.
