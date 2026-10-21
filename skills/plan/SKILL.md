---
name: plan
description: Cuts a design spec into work units a Build Train can run. Sends the spec to the planner agent, checks the plan it writes with the plan validator, and shows the unit graph and a plain-words unit table. Writes no code.
argument-hint: Path of the design spec to cut into units, then optionally --model and one of sonnet, opus, haiku or fable.
---
<!-- Copyright (c) 2026 Brad Duhon. SPDX-License-Identifier: GPL-3.0-or-later -->

# daedalus plan

Human-facing text (0031): Text a human reads names each item in words: a short label or one line on what it is and what it does. Ids (ruling ids, issue numbers, task codes, agent names, snake_case keys) may trail in parentheses, never replace the description. Logs, status lines and messages to other agents may use ids alone. Documents carry both.

This skill runs outside a train, and inside a Build Train at Phase 1 before the lock (0086). It dispatches one agent, the planner, and nothing else. It never edits the spec and never writes the plan itself.

1. Set `<spec>` to the first word of `$ARGUMENTS`. When the words after it are `--model <value>`, set `<override>` to `<value>`; any other words after the path: stop. Next: run `/daedalus:plan` again with the spec path, optionally followed by `--model` and a model name. When `<spec>` is empty or names no readable file, stop. Next: run `/daedalus:plan` again with the path of the design spec to cut.
2. Set `<repo>` to the parent of the directory `git rev-parse --path-format=absolute --git-common-dir` prints (the main working tree). Not a repo: stop. Next: start the session inside the target repository, then run `/daedalus:plan` again.
3. Set `<path>`, the one file the planner writes. Inside a Build Train (the State Block names `<train-id>`) it is `<repo>/docs/.tmp/daedalus/<train-id>/plan.md`. Outside a train it is `<repo>/docs/.tmp/daedalus/plan-<YYYYMMDD>.md`, with today's UTC date.
4. Set `<n>`, how many coders may run at once: the `max_concurrent_builders` value in `<repo>/.claude/daedalus/config.json`. An absent file or key means 5.
5. Choose the planner's model (spec 4): run `python3 ${CLAUDE_PLUGIN_ROOT}/scripts/daedalus_train.py model --repo <repo> --agent planner`, adding `--override <override>` when step 1 set one. It prints one model word: the override, else the `agent_models` setting for the planner, else the planner file's `model:` line. Exit 1: stop and show its output; its `Next:` line is the next action. Dispatch `Agent(planner)` with `model: <that word>`; Claude Code loads it as `daedalus:planner`. Its prompt carries, each on its own line:
   - the spec path `<spec>`;
   - the standing-rules file path, when the repository has one;
   - `max_concurrent_builders: <n>`;
   - the repository's file areas: the `entrypoints` block of `<repo>/service-manifest.json`, pasted as it stands, or `none declared` when the file or block is absent;
   - `Write exactly one file: <path>`;
   - the rule: cut into bodies that touch non-overlapping file areas; name every edge's kind; prefer an interface pin (a named function, flag or line shape both sides build to) over a file overlap; print the graph.
   - the reply contract: end with exactly one of `[STATUS: PLAN] path=<path> units=<n> critical_path=<k> width=<w>` or `[STATUS: QUESTION] <what the task leaves open>`.
6. Read the planner's last line.
   - `[STATUS: QUESTION] ...`: ask the operator that question in plain words, with what the spec says around it. Send the answer to the same planner by SendMessage and read its next reply from this step.
   - `[STATUS: PLAN] ...`: go to step 7.
   - Anything else: stop and show the reply's last 10 lines. Next: rerun `/daedalus:plan` or report the planner's reply.
7. Run `python3 ${CLAUDE_PLUGIN_ROOT}/scripts/validate_plan.py <path> --max-concurrent <n>`.
   - Exit 0 prints `OK plan: graph: units=<n> critical_path=<k> width=<w> overlap_only=<pairs>`. Check its units, critical_path and width against the planner's reply line. A mismatch counts as a defect: send both lines to the planner as below.
   - Exit 1 prints one defect line per failed check and a `Next:` line. Send the defect lines to the same planner by SendMessage and ask for the corrected file at the same path, then rerun this step once. A second exit 1 or mismatch: show the validator's output unchanged and stop. Next: fix the plan by hand or rerun `/daedalus:plan` with a narrower spec.
8. Show the operator the validator's graph line, then a unit table in plain words, one row per unit line of the plan block:

   | Unit | What it builds | Starts from | Waits on | Shares files with |
   |---|---|---|---|---|

   What it builds is the unit's title. Starts from reads "the integration branch" for `base: integration`, else "unit <id>'s branch". Waits on lists the units with a serial edge into this one, with each edge's why. Shares files with lists each overlap edge's other unit, its files and the merge order. Under the table, list each pin as the shape both units build to, so the operator sees no unit waits on it.
9. Inside a Build Train only: run `python3 ${CLAUDE_PLUGIN_ROOT}/scripts/daedalus_train.py plan --repo <repo> --path <path>` and show its output unchanged. It records the plan's path and hash in train state; a coder dispatch is refused until it has (0089). Exit 1: show its output and stop; its `Next:` line is the next action.
10. End. Outside a train, Next: start `/daedalus:build-train` and name `<path>` as the plan to build. Inside a train, Next: continue Phase 1 of the Build Train with the recorded plan.
