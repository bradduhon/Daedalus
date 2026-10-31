<!-- Copyright (c) 2026 Brad Duhon. SPDX-License-Identifier: GPL-3.0-or-later -->
# The golden set

## Before the first run

The eval harness stages each job's workspace by running a file named `scaffold.sh` with bash. Each of the ten job folders needs one. The file only hands off to `evals/scaffold.py`, which copies the job's fixture and makes its git repository. These shell files are not in the repository yet, because a new shell file needs your go-ahead. Create all ten from your own shell:

```
cd /home/bduhon/MyProjects/Daedalus && for c in small-fix contract-build terraform-change dependency-bump contract-question security-defect verify-refutes folder-scope document-phase release-stops-before-push; do printf '%s\n' '# Copyright (c) 2026 Brad Duhon.' '# SPDX-License-Identifier: GPL-3.0-or-later' '# 0186: the harness runs this with bash in the eval workspace; scaffold.py stages the fixture.' 'set -eu' 'here=$(cd "$(dirname "$0")" && pwd)' 'exec python3 "$here/../scaffold.py" "$(basename "$here")"' > "evals/$c/scaffold.sh"; done
```

The unit test `tests/test_evals.py` checks each file's text once it exists, and skips that check until then.

## What the set is for

The golden set is ten end-to-end jobs that start Daedalus the way you do, with `/daedalus:run`. Each job has a fixture, a pass rule in its `PASS.md`, and graders that check the rule. Each job runs twice, so a job that passes once and fails once shows up as unstable rather than as a pass.

The set is release evidence. It is not a check you run after every change.

## When it runs

- The full set runs once, before the final release, each job twice. The release notes quote how often each job gave the same result on both of its runs.
- After the three narrow judges move into the auditor, only the jobs tagged `fold-judges` run: the planted security defect, the Terraform change and the dependency bump. That is about six runs. A judge that stops catching a planted defect stays silent in ordinary use, so this one change gets a check.
- No other change runs the set.
- The trial of folding the orchestrator into the main session is judged on the token reports of real runs, not on this set.

## The command

Every run uses `--ablation none`: each job runs with the plugin only, never a second time without it. Every run also passes `--scaffold`, so the harness runs the staging files, and `--allow-tools Bash Write Edit`, so the jobs can write code. The cost ceiling stops the run and keeps the partial result when it is reached.

The full set, before the final release, with a ceiling of 150 US dollars:

```
claude plugin eval /home/bduhon/MyProjects/Daedalus --runs 2 --model opus --json /tmp/daedalus-golden/release.json --output-dir /tmp/daedalus-golden/release --max-cost-usd 150 --no-publish --trust-plugin --ablation none --scaffold --allow-tools Bash Write Edit
```

The judge check, after the judges move into the auditor, with a ceiling of 50 US dollars:

```
claude plugin eval /home/bduhon/MyProjects/Daedalus --tag fold-judges --runs 2 --model opus --json /tmp/daedalus-golden/judges.json --output-dir /tmp/daedalus-golden/judges --max-cost-usd 50 --no-publish --trust-plugin --ablation none --scaffold --allow-tools Bash Write Edit
```

Both ceilings are guesses until the first probe below reports what one run costs. `--model` sets the session's model only; each agent keeps the model its own file names. Use the same model for every run you compare.

## Reading the result

The harness writes `aggregate-result.json` into the `--output-dir` folder, and the same content to the `--json` file. Each job is one entry in `cases`, with its `name` and its `aggregates`. Its runs are under `arms.with`, one entry per run. Each run lists its `graders`, each with `passed` and an `explanation`, and carries its `score`, `turns`, `costUsd`, `durationSeconds` and `tracePath`. The trace is the full record of the session: every tool call, every agent reply and every command output.

To see each job's scores in one line per job:

```
jq -r '.cases[] | "\(.name) \([.arms.with[].score] | map(tostring) | join(" "))"' /tmp/daedalus-golden/release.json
```

A job passes when every one of its graders passes. A score of 1 on both runs is a stable pass. A score below 1 on both runs is a stable fail; open that job's failing graders and its trace.

## A flipped job

A job flips when it gives a different result from the last recorded run of the set, or when its two runs disagree. A flip after a change means the change altered what Daedalus does on that job. Read the failing grader first, then the trace around it. When the new behaviour is right and the grader is wrong, fix the grader in the same change and say so in the pull request. When the behaviour is wrong, the change is not ready.

## Three questions the first probe answers

The harness does not document three things the set depends on. Run one job once, with a small ceiling, before the full set:

```
claude plugin eval /home/bduhon/MyProjects/Daedalus --case small-fix --runs 1 --model opus --json /tmp/daedalus-golden/probe.json --output-dir /tmp/daedalus-golden/probe --max-cost-usd 10 --no-publish --trust-plugin --ablation none --scaffold --allow-tools Bash Write Edit
```

Then read its trace file, the `tracePath` of its one run.

1. Do the plugin's hooks run inside the sandbox? Every run checks that its hooks are writing the audit log. Search the trace for `OK hooks live: session`. Found means the hooks run. A `Next:` line from the same check, or a run that stops at that step, means they do not, and no job can pass until they do.
2. Do the plugin's agents start, and does the trace show their work? Search the trace for `daedalus:orchestrator`, then for `daedalus:coder`. The orchestrator starts the coder, so a trace that shows the first and not the second records only the session's own calls. In that case the graders that look for the coder, the verifier and the auditor, and the verdict lines they print, cannot pass. They need rewriting against what the orchestrator reports back to the session.
3. Does the result carry tokens and time? Search `/tmp/daedalus-golden/probe.json` for `tokens` and for `durationSeconds`. The report's field list inside this harness version has a time and a cost per run and no token count, but its docs do not say so, so the probe confirms it. A field that is found can be quoted from the result. Token counts that are absent come from the run's own token report, `/daedalus:token-report`, read in a workspace kept with `--keep-temp`.

One more check from the same trace: two jobs need the session to ask you a question, and the harness may not offer that tool. Search the trace for `AskUserQuestion`. If the harness refused it, the question graders of the contract question job and the planted defect job need a different check.

## The ten jobs

Tags name each agent a job exercises and each change it measures. `--tag <name>` runs only the jobs that carry it.

| Job | What passing means | Tags |
|---|---|---|
| [small-fix](small-fix/PASS.md) | A one-file fix runs small, with one coder and no contract, and ends complete. | orchestrator, coder, verifier, auditor, fold-orchestrator, model-coder |
| [contract-build](contract-build/PASS.md) | A two-module build locks a contract and binds it into every coder brief. | orchestrator, coder, verifier, auditor, fold-standards, fold-contract, fold-planner, fold-orchestrator, model-coder |
| [terraform-change](terraform-change/PASS.md) | The Terraform rules judge the change; a missing terraform binary is a warning. | orchestrator, coder, verifier, auditor, fold-judges, fold-orchestrator, model-coder |
| [dependency-bump](dependency-bump/PASS.md) | The dependency rules judge the bump, with no web lookup. | orchestrator, coder, verifier, auditor, fold-judges, fold-web, fold-orchestrator, model-coder |
| [contract-question](contract-question/PASS.md) | An undecided contract field is put to you before any coder starts. | orchestrator, fold-contract, fold-planner, fold-orchestrator |
| [security-defect](security-defect/PASS.md) | The auditor rejects a hard-coded token and puts each finding to you. | orchestrator, coder, verifier, auditor, fold-standards, fold-judges, fold-orchestrator, model-coder |
| [verify-refutes](verify-refutes/PASS.md) | The verifier refutes a unit that cannot meet its brief. | orchestrator, coder, verifier, fold-orchestrator, model-coder |
| [folder-scope](folder-scope/PASS.md) | A plain folder gets a plan with no git command and no orchestrator. | fold-planner |
| [document-phase](document-phase/PASS.md) | A derived FAQ is written, its claims checked and its changes logged. | writer, verifier, comparer |
| [release-stops-before-push](release-stops-before-push/PASS.md) | The release phase stops at a failed check and never pushes. | orchestrator, coder, verifier, auditor, fold-orchestrator, model-coder |

The fixtures live in `fixtures/<job>/`, with shared files in `fixtures/_base/`. Files there carry plain names, such as `manifest.json`, and `scaffold.py` gives them their real names in the workspace, such as `service-manifest.json`. A folder of this repository then never looks like a project to Daedalus. No fixture holds a real secret. The token in the planted defect job is a plain made-up word.
