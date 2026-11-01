<!-- Copyright (c) 2026 Brad Duhon. SPDX-License-Identifier: GPL-3.0-or-later -->

# Dependencies rulebook for the auditor (0132, 0186, 0196, 0197)

The audit phase names this file in the auditor's dispatch when the merged diff touches a dependency manifest or a lockfile, with the changed dependency files, a line `Web lookup: on` or `Web lookup: off`, a line `Minimum release age: <days>`, and, when the project supplies one, an `Advisory export: <path>` line naming a file of advisories it exported. Read; never write, fetch or install. Never run a package manager: no install, update, audit or resolve command of any ecosystem. Write each row's verdict in the reply's `## Compliance` section.
The dispatch also carries one `Rulebook: <path>` line per ecosystem under `packs/dependencies/`. Read each and judge its rows beside the rows below, with the same rubric (0189).

## Method
1. Run `git -C <repo> diff <diff base>...<branch> -- <each changed dependency file>` and read all of it.
2. List each dependency the diff adds, removes or moves: its ecosystem, name, old and new version, and its source (the registry, a git URL, a URL or a local path).
3. Give each row below PASS, FAIL or N/A for every listed dependency, with `file:line`.
4. Advisories. With `Web lookup: on`, ask for the advisories of one dependency at a time: reply `[STATUS: YIELD_WEB] <ecosystem> <name> <version> security advisories and publish date`, alone as the first and the last line. You are resumed with `RESUME. Research payload:` and the facts; cite each advisory id and its URL, and the version's publish date, from the payload. With `Web lookup: off`, judge from the lockfile and the advisory export alone; with neither, DEP-5 and DEP-8 are N/A with the reason `web lookup off and no advisory export` (0196).
5. Unjudged rows (0196, 0197). An N/A on DEP-5 or DEP-8 is never a pass: the dependency diff went unjudged, so it is a blocking finding of class compliance, filed as Procedure step 5 of the auditor says.

## Rows
- DEP-1: each new or changed dependency resolves to one exact version in the lockfile.
- DEP-2: each manifest change has its lockfile change in the same diff, and the reverse.
- DEP-3: each locked entry carries its integrity hash or checksum where the ecosystem has one.
- DEP-4: each source is the ecosystem's declared registry; a git, URL or path source is a FAIL unless the diff names why.
- DEP-5: no published advisory names the resolved version.
- DEP-6: an override, resolution or constraint pin that supersedes what a direct dependency would resolve is a FAIL; the operator decides whether it is kept and tracked.
- DEP-7: the license each new dependency declares, read from its manifest or lock entry; an absent or ambiguous license is a FAIL.
- DEP-8: each resolved version the diff adds or changes, in every ecosystem, carries its publish date and its source, the research payload or the advisory export; a version published fewer days ago than `Minimum release age` is a FAIL naming the date it comes of age, a held-back security fix included; with no date source the row is N/A (0197).

## Rubric
- FAIL means the diff contradicts the row; give the `file:line` and the evidence.
- PASS needs an evidence line; never PASS on absence of evidence.
- N/A needs a one-line reason.
- Never quote advisory text at length; cite its id and URL.
