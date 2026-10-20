---
name: catalog
description: Shows the session every Daedalus agent with what it does, its tools, its reply lines and the phases it suits, then the six phases with their exit conditions, the musts, the composition rules and the audit escalation prompt. Read it at the start of any body of work.
---
<!-- Copyright (c) 2026 Brad Duhon. SPDX-License-Identifier: GPL-3.0-or-later -->

# daedalus catalog

Human-facing text (0031): Text a human reads names each item in words: a short label or one line on what it is and what it does. Ids (ruling ids, issue numbers, task codes, agent names, snake_case keys) may trail in parentheses, never replace the description. Logs, status lines and messages to other agents may use ids alone. Documents carry both.

Read this at the start of any body of work, inside a train or not. Daedalus is an open composition over the agents below (0088): you compose each body of work yourself, and the Build Train (`/daedalus:build-train`) is one saved recipe over this catalog, not the required shape. In a Build Train the orchestrator agent runs that recipe and the session relays each operator decision (0060). Hooks check four exit conditions today: a plan record before a coder, a worktree binding for every coder, an approved verdict on the exact tip (or the operator's exception) before a push or pull request, and the conductor as the only agent that pushes. Capturing each ruling and the merge are your duty and the operator's; no hook checks them. No hook checks the order of your steps.

When the operator runs `/daedalus:catalog`, print the agent table, the six phases and the musts unchanged.

## The agents

Dispatch an agent as `daedalus:<name>`. Its tools are the only tools it is offered, and its hooks decide what it may touch: a producer writes only where its write hook allows, a judge and a finder read, a mover commits and pushes, a shaper writes one scratch file, and the dispatcher (the orchestrator) starts and resumes the other agents under its dispatch gate and writes only its train's scratch folder and summary file. The table is generated from the agent files by `python3 ${CLAUDE_PLUGIN_ROOT}/scripts/catalog.py table`, and a test fails when this copy goes stale.

<!-- generated: catalog.py table -->
| Agent | Shape | Model | Tools | Job | Reply lines | Phases |
|---|---|---|---|---|---|---|
| charter-docs | producer | sonnet | Bash, Edit, Glob, Grep, Read, Write | Single-writer custodian of the Charter repository, the architectural decision ledger, and Build Train commits. | `[STATUS: LEDGER_PROBED] <probe line>`; `[STATUS: LEDGER_APPENDED] <id>`; `[STATUS: LEDGER_MISMATCH] expected=<n> ledger=<m>`; `[STATUS: COMMITTED] <sha> ids=<id>[,<id>]`; `[STATUS: BLOCKED] <detail>` | clarification, commit, release |
| cis-specialist | judge | sonnet | Bash, Grep, Read | Evaluates cloud infrastructure, IAM/RCP policies, and OS/container hardening against operator-supplied CIS Benchmarks. | `[STATUS: CACHE_INVALID] <detail>`; `[STATUS: COMPLIANCE] <PASS/FAIL list with control ids and file:line>` | clarification, audit |
| contract-spec | producer | sonnet | Edit, Glob, Grep, Read, Write | Reads and updates service handshake contracts, API schemas, and specifications. | `## Locked Contract Packet` | clarification, plan |
| nist-specialist | judge | sonnet | Bash, Grep, Read | Evaluates architecture, IAM, and cryptographic boundaries against the pinned NIST SP 800-53 OSCAL catalog and SP 800-57 key-management guidance. | `[STATUS: CACHE_INVALID] <detail>`; `[STATUS: COMPLIANCE] <PASS/FAIL list with control ids and file:line>` | clarification, audit |
| orchestrator | dispatcher | fable | Agent, Bash, Edit, Glob, Grep, Read, SendMessage, Write | Runs one Build Train from its plan to the audited integration tip. | `[STATUS: DECISION] brief=<path> questions=<n>`; `[STATUS: EXCEPTION] ledger_id=<id>`; `[STATUS: TRAIN_COMPLETE] summary=<path> audit_log=<path>`; `[STATUS: STOP] reason=<what happened> next=<next action>` | context, clarification, plan, implementation, audit |
| planner | shaper | opus | Glob, Grep, Read, Write | Cuts a design spec into work units that coders can build in parallel. | `[STATUS: PLAN] path=<path> units=<n> critical_path=<k> width=<w>`; `[STATUS: QUESTION] <what the task leaves open>` | plan |
| pr-train-conductor | mover | opus | Bash, Glob, Grep, Read | GitHub specialist for the Push Train. | `[STATUS: PUSHED] branch=<b> pr=<url>`; `[STATUS: CI] run=<id> conclusion=<text>`; `[STATUS: BLOCKED] <precondition that failed>` | commit, release |
| repo-coder | producer | opus | Bash, Edit, Glob, Grep, Read, Write | Scoped implementation worker. | `[STATUS: YIELD_WEB] <query>`; `[STATUS: YIELD_CONTRACT] <mismatch>`; `[STATUS: YIELD_COMPLIANCE] <question>`; `[STATUS: YIELD_STANDARDS] <question>`; `[STATUS: COMPLETE] branch=<b> packet_version=<n> files=<list> tests=<summary> ledger_notes=<text> contract=<12 hex> standards=<12 hex>` | implementation |
| security-auditor | judge | opus | Bash, Glob, Grep, Read | Adversarial pre-commit security and contract verifier. | `[VERDICT: APPROVED]`; `[VERDICT: REJECTED]` | audit |
| standards-rules-specialist | finder | sonnet | Glob, Grep, Read | Adopts the project's declared standards. | `## Standards Packet`; `[STANDARDS: CONTRADICTION] <spec ref> vs <source:line>`; `[STATUS: STANDARD] <answer>` | clarification, plan |
| web-researcher | finder | haiku | Read, WebFetch, WebSearch | Fast external documentation lookup on Haiku. | `[STATUS: RESEARCH] <payload under 300 words with URLs>` | context |
<!-- end generated -->

The Phases column is guidance for your choice of agent, never a gate on which agent a phase may use (0089). Permission stays with the hooks.

## The six phases

Every body of work passes through six phases, each open inside (0089).

| Phase | What happens | Exit condition |
|---|---|---|
| Context | Read the task, the code and the rulings that govern it. A yield in the middle of a build is context work. | None; it overlaps every other phase. |
| Clarification | Put each fork to the operator the moment it appears. Standards and contract questions go to their specialists. | Every ruling the operator made is in the ledger, captured in the session it was made; your duty, no hook checks it. |
| Plan | `/daedalus:plan <spec path>` has the planner cut the work into units, with edge kinds and a graph line. | A validated plan record in train state before any coder starts; the hook refuses a coder dispatch without one. |
| Implementation | One repo-coder per unit, each in its own worktree. | Every coder has a worktree binding; the hook refuses a coder whose prompt names no worktree. |
| Audit | The units merge first; the security-auditor judges the merged integration tip against the train's base. The compliance specialists judge units that touch IAM, keys, mTLS or infrastructure settings. | An approved verdict on the exact tip being pushed, or the operator's accepted exception recorded as a ruling. |
| Commit and release | The conductor alone pushes and opens pull requests. The operator merges. | The operator merges; no hook checks it. |

The phase words on agent files are `context`, `clarification`, `plan`, `implementation`, `audit`, `commit` and `release`; the last two together make the commit and release phase.

Phases overlap freely. A phase's weight scales with the task: a one-file fix carries a one-unit plan and no contract packet, and a cross-module build carries the packet. Choose the weight before the phase starts and print it with its reason through the choice record.

## The musts

These are musts, not suggestions.

1. All work is audited and passes before it leaves a workspace, or the operator accepts the exception as a ruling with the findings it waives. Nothing is pushed and no pull request is opened until train state holds an approved verdict on the exact tip being pushed, or that exception. The hooks refuse such a push or pull request from an agent, and ask the operator before the main session's own (0106); never argue with a refusal and never work around it.
2. No coder starts without a plan record and a worktree binding.
3. Every ruling is captured in the ledger in the session it is made.
4. Every choice is printed with its alternative and its cost before it is taken. Inside a train, run `python3 ${CLAUDE_PLUGIN_ROOT}/scripts/daedalus_train.py choice --repo <repo> --chose "<what>" --over "<alternative>" --cost "<time or tokens>"` and add `--phase <name>` for a weight choice; it records the choice and prints `Chose <what> over <alternative>: <cost>`. Outside a train, print that same line in your reply.

## Composition rules

- Phase 1 overlap (0082): the contract stage starts the moment the last contradiction pick is made, in parallel with the pick recording and the standards re-check. The re-checked Standards Packet reaches contract-spec as an amendment it folds in before saving, and the lock waits on both.
- Packets by hash (0083): the Standards Packet is written once to `docs/.tmp/daedalus/<train-id>/standards-packet.md` after the pick commit. Every worker brief carries `Contract: <path> sha256=<hex>` and `Standards: <path> sha256=<hex>` in place of a pasted packet. The coder's `[STATUS: COMPLETE]` line ends `contract=<12 hex> standards=<12 hex>`, and a mismatch stops that unit.
- Brief by file: each dispatch's brief is a file under `docs/.tmp/daedalus/<train-id>/briefs/`, holding the unit's section of the plan verbatim, the two packet lines, the `Pick ledger ids:` line and one reminder line. Print each dispatch as three lines, `Dispatch: <agent>`, `Prompt file: <path>` and `Expect: <reply lines>`.
- Warm dispatch (0086): a unit whose dependency a running coder built goes to that coder as a resume, carrying its context. A cold coder starts only when no warm coder built a dependency of the unit.
- Rebinding (0086): a warm resume onto a new unit rebinds the coder only through the orchestrator's SendMessage, whose dispatch gate moves the coder's binding as the message goes out. The main session's SendMessage does not rebind, so a recipe the main session drives by hand cold-dispatches each new unit.
- Verifier step (spec 5): once per unit, after its `[STATUS: COMPLETE]` passes the branch, packet and merge-base checks and before finish merges it, the verifier checks each cited file:line, test count and negative claim. `[VERDICT: REFUTED] <rows>` sends the coder one FIX pass; a second REFUTED on the same unit stops the train. The verifier stays warm across units.
- Jail check units (spec 3.3): a unit whose changed files include a path under `scripts/checks/`, or `scripts/lib/jail.py`, `scripts/lib/shell.py` or `scripts/enforce_agent_jail.py`, runs `python3 -m pytest tests/adversarial -q` and ends its COMPLETE line with ` adversarial=pass`.
- Audit loop (0109, 0112): the auditor works in the audit worktree `<train-id>-audit`, created before the first round. Before each later round its refresh fast-forwards the audit branch to the integration branch, and a diverged or dirty audit worktree stops the refresh instead of losing a commit. Each blocking finding is a failing test under `docs/.tmp/daedalus/<train-id>/audit/round<n>/`, and a fix brief carries the node ids and test file paths. The verdict command's printed word decides the next step: `continue` runs a fix round and `escalate` puts the escalation prompt below to the operator.
- Models (spec 4): each persona's model comes from `daedalus_train.py model --repo <repo> --agent <name>`, which prints the `agent_models` setting for that agent or else the agent file's `model:` line.
- Charter-docs reads (0084): charter-docs may read what it is told to append or edit. Its brief names the absolute path of append_ledger.py.
- Ledger entry files read-only before the agent: write each ruling's entry file under `docs/.tmp/daedalus/`, make it read-only, and brief charter-docs with the ruling id and the file path only.

## Commands and reply lines the records answer to

Paths here are relative to the plugin root.

- The plan validator: `python3 scripts/validate_plan.py <path> [--max-concurrent N]` prints `OK plan: <graph line>`, or one defect line per failed check and a line naming the next action.
- The planner ends with `[STATUS: PLAN] path=<path> units=<n> critical_path=<k> width=<w>` or `[STATUS: QUESTION] <what the task leaves open>`.
- The train runner records the operator view and the gates' inputs: `daedalus_train.py progress`, `choice`, `plan` and `exception`, each with `--repo <repo>`.
- The verdict record: `daedalus_train.py verdict --repo <repo> --status rejected --round <n> --findings <path> --tip <sha>` prints exactly one of `continue round=<n+1> budget_left=<k>`, `escalate reason=recurring key=<key>`, `escalate reason=new-high key=<key>` or `escalate reason=budget`; `--status approved --round <n> --tip <sha>` records the judged tip.
- The model choice: `daedalus_train.py model --repo <repo> --agent <name> [--override <model>]` prints the effective model word alone on one line, inside or outside a train.
- The audit worktree refresh: `daedalus_workspace.py refresh --repo <repo> --name <train-id>-audit` fast-forwards the audit branch with `git merge --ff-only` and prints the worktree path.
- The control cost table: `python3 scripts/audit_report.py --repo <R> --session <S> --controls` prints the blocks per hook, the seconds each block cost, the seconds each agent took to its first write, and the mean judge time.

## The audit escalation prompt

The prompt fires only on an `escalate` line from the verdict command; until then each rejected round runs a fix round. The line names one of three stall reasons: a finding that came back after its fix (`reason=recurring`), a new high or critical finding (`reason=new-high`), or a round budget that ran out (`reason=budget`, the `audit_round_budget` setting, default 5). The operator then decides what happens to the remaining findings (0096, as amended by 0103 and 0109). In a Build Train the orchestrator writes it as a decision brief and the session asks it.
Put it to the operator with AskUserQuestion, in the decision-brief shape (0103):
- Question: a plain question ending in a question mark, such as "The security audit stopped making progress on this work; how should the findings that remain be handled?"
- Context: Two or three context sentences in the operator's words: what the work builds, what the audit checks, and why the audit stopped, as the escalate line's reason says: a finding that came back after its fix, a new high or critical finding that appeared, or a round budget that ran out. They carry no ruling ids, agent names or snake_case keys.
- Findings: each remaining finding in plain words, with what it protects and why the fix fell short.
- Choices, each with its consequence:
  - One more fix-and-audit round: each responsible coder resumes warm with its findings and the audit runs again; the verdict stays rejected until a round passes.
  - Merge with each finding as a tracked-risk issue: the merged work goes on to the ledger step, charter-docs records the operator's exception as a ruling that names each finding it waives, the train runner's exception command binds that ruling to the integration tip, and the main session files one tracked-risk issue per finding before the pull request opens.
  - Stop with the branches kept: the train stops through its stop command, and every unit branch stays for fixes by hand or a narrower rerun.
- Recommendation: The recommendation and its reason, in one sentence. The recommended choice is listed first, its label ending `(Recommended)`.

Record the operator's pick through the choice record, then act on it. Never run a round after an escalate line without the operator's pick, and never stop the train on your own authority. The same prompt follows every later escalate line.
