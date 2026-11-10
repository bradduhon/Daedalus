---
name: setup
description: The settings wizard. Explains the three settings files Daedalus reads (the project's service-manifest.json, this checkout's .claude/daedalus/config.json and your personal ~/.claude/daedalus/operator.json) and which one wins where two overlap. Creates each missing file, the personal one only after asking, then asks the settings that change what Daedalus does on day one, one question at a time, and offers every other group. Changes one setting per answer, checks the whole file first, and never rewrites a whole file.
argument-hint: Optional path to the target project (default is the current directory).
allowed-tools: Bash(python3 ${CLAUDE_SKILL_DIR}/../../scripts/daedalus_setup.py *), Bash(python3 ${CLAUDE_SKILL_DIR}/../../scripts/daedalus_train.py ask-check *), AskUserQuestion
---
<!-- Copyright (c) 2026 Brad Duhon. SPDX-License-Identifier: GPL-3.0-or-later -->

# daedalus setup

Human-facing text (0031): Text a human reads names each item in words: a short label or one line on what it is and what it does. Ids (ruling ids, issue numbers, task codes, agent names, snake_case keys) may trail in parentheses, never replace the description. Logs, status lines and messages to other agents may use ids alone. Documents carry both.

This skill is the settings wizard (0242). It runs in the main session, one question per turn. The setup script is the only writer: this session never edits a settings file itself and never runs any other command on one. Set `<path>` to `$ARGUMENTS` when the operator gave one and `.` otherwise.

## The question shape

Every setting is asked in the shape the brainstorm conversation uses:

- One AskUserQuestion call with exactly one question, multiSelect false. The header is `Setting <n>`, counting from 1 across the session.
- The question text says what the setting is in plain words, drawn from its `governs` text. Then it says what changes, from its `affects` sentence. Then it says the value now in words, or that nothing is set. It ends with the sentence "Pick an answer, or choose Other and type your own."
- The first choice is `Accept: <the proposal, cut to five words>`. Its description spells the proposal out and gives its reason in one sentence. The proposal is the key's `detected` value when the describe output has one, and the reason names the file it came from. Otherwise propose the value that fits what the describe output and the repository show, and say what you saw. Never propose a value you cannot ground that way.
- Then one to three alternatives, each a value the setting accepts, with a one-sentence description of what it does. The tool's own Other box is the only way to type a value; add no generic choice.
- Question text rules: plain sentences only. No key name, file path, ruling id or JSON goes in a question, a choice label or a choice description. A key name may trail in parentheses in a context line printed before the question, never inside it. You turn each answer into its JSON value yourself.
- Reading level: the value of the manifest's reading-level key (`docs.literacy`) in the describe output when it is set, else plain. At plain, write the question text and its choices to `<path>/docs/.tmp/daedalus/setup-<YYYYMMDD>/ask-<n>.md` with the Write tool, with today's UTC date, and run `python3 ${CLAUDE_SKILL_DIR}/../../scripts/daedalus_train.py ask-check --repo "<path>" --file "<that file>"`. Exit 0 prints `question ok`. Each `question:` line names a sentence to reword: reword it once and check again, and a second failure asks the question anyway. Exit 1 with no `question:` line means the file itself failed: write it again once, and a second such failure asks the question anyway.
- A setting whose `active` value is false is not active: nothing in Daedalus acts on it yet. Never ask it. Name it as not active when its group is walked and once more at the close.

## Writing an answer

- One setting: run `python3 ${CLAUDE_SKILL_DIR}/../../scripts/daedalus_setup.py --set <file> <key> --value '<json>' --repo "<path>"`, where `<file>` is the entry's `file` value (`manifest`, `config` or `operator`), `<key>` is its `key` value and `<json>` is the answer as JSON.
- Use `--value` only when the JSON value consists of letters, digits, spaces and the characters `"[]{}:,._-/`, and otherwise write the JSON value with the Write tool to `<path>/docs/.tmp/daedalus/setup-<YYYYMMDD>/value-<n>.json` and pass that file instead, as in `python3 ${CLAUDE_SKILL_DIR}/../../scripts/daedalus_setup.py --set <file> <key> --value-file "<value file>" --repo "<path>"`.
- Show the `changed:` or `kept:` line unchanged. If the command exits 1, the file's own check refused the value: show the message as written, then ask the same question once more with that message printed before it. A second refusal moves on to the next key.
- A block: a key whose `block` value is not null belongs to a group of settings saved together. The describe output's `blocks` entry with the same `file` and `key` lists its `members` in asking order and names the `required` ones. Before the first of them, print one plain line: "These next <n> settings are saved together.", with `<n>` the number of members. Ask each member in the question shape, and offer leaving it out as one choice for a member that is not required. Hold the answers and write nothing yet. Then write the block once: `python3 ${CLAUDE_SKILL_DIR}/../../scripts/daedalus_setup.py --set <file> <block> --value-file "<value file>" --repo "<path>"`, where `<block>` is the block's `key` and the value is one JSON object of the held answers, a member left out omitted. The value rule above decides between `--value` and `--value-file` here too. A refusal of the block is shown as written and the block's questions are asked once more; a second refusal moves on. A block already set offers each member's value now as its proposal, and the value `null` clears a block.

## Steps

1. **Describe.** Run `python3 ${CLAUDE_SKILL_DIR}/../../scripts/daedalus_setup.py --describe --repo "<path>"` with Bash. It prints one JSON document: `files`, `overlaps`, `blocks`, `keys`, `detected` and `moot`. If it exits 1, show its message unchanged and stop; the part after `Next:` is the next action. Tell the operator what the three files are in at most six short lines, from each file's `holds`, `where`, `whose` and `shared` values, then print each `overlaps` text as written. A file whose `malformed` value is not null: print that message as written, and say its settings are skipped until the file is fixed by hand.
2. **Create.** Run `python3 ${CLAUDE_SKILL_DIR}/../../scripts/daedalus_setup.py --repo "<path>"` with Bash once, exactly as written. Show the output to the operator unchanged. Each line names one file: `written:` means the script created it, and `kept:` means the file already existed and was left as it was (0076). The one other line, `docs.literacy: null; examples: <examples>`, follows a written service manifest: it names the literacy values the docs writer reads from `docs.literacy`, since the file itself holds no comments (0134). If the script exits 1, show its message unchanged and stop; the part after `Next:` is the next action. When the describe output shows the personal file with `exists` false and no `malformed` message, ask one question: "Daedalus can keep your own preferences in one file in your home folder, used by every project. Create it now?" The choices are `Accept: create it now` (description: "The file starts with every preference off, and nothing acts on it yet.") and `Not now` (description: "Every project works the same without it."). On accept, run `python3 ${CLAUDE_SKILL_DIR}/../../scripts/daedalus_setup.py --create-operator` and show its line unchanged; an exit 1 shows its message and goes on. Then run the describe command of the first step again, so the later steps read the files as they are now.
3. **Day one.** Take each key whose `day_one` value is true, in the order the describe output lists them, one at a time:
   - its file is malformed: skip it;
   - `moot` names it: skip it and print one line with the reason `moot` gives;
   - its `state` is `set`: skip it, since the operator already chose a value;
   - otherwise ask it in the question shape above.
   Write each answer as "Writing an answer" says. When the decision-ledger switch (`features.ledger`) is answered on, the ledger block's questions follow it at once: take the `overlaps` entry whose `id` is `ledger`, and ask the `blocks` entry with key `ledger` in the file its `wins` value names, unless that block's `state` is already `set`.
4. **More.** Print the groups not walked yet, one line each, in `order`: the group's `title` and how many of its settings are active. Ask one question, "Which group of settings do you want to walk next?", with the choice `Done` first (description: "End here and see what changed.") and then up to three groups not walked yet, in order; the Other box takes the title or line number of any group in the list. Walking a group asks each of its keys in the question shape above, one at a time, the ones already set included, and then returns to the list:
   - a key whose `active` value is false: print one line naming it as not active, and do not ask it;
   - a key whose `settable` value is false: print one line saying it sits inside a list or a named entry and is changed by hand, as the examples folder shows, and do not ask it;
   - a key of a malformed file: skip it;
   - a key whose `block` value is not null: when the walk reaches the block's first member, ask and write the whole block as "Writing an answer" says, once per block.
   `Done` runs the close.
5. **Close.** Show every `changed:` and `written:` line of this session, in the order they were printed. Name the settings that are not active yet in one sentence, in plain words, with their keys trailing in parentheses. Then name the health check as the next command: `/daedalus:doctor`.

The operator may say `stop` at any question: run the close. Running the wizard again starts at the first step with the values as they are now, and the day-one step asks nothing already set away from its default.
