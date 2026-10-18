<!-- Copyright (c) 2026 Brad Duhon. SPDX-License-Identifier: GPL-3.0-or-later -->
# What your project needs for daedalus

Every file and setting daedalus reads, with the smallest example that works. `/daedalus:doctor` checks the ones marked below, optional ones included; an optional one that is absent passes. Each marked heading or key carries **(checked)**.

## In the repo's `.claude/daedalus/` directory

`<repo>` is the main working tree of the git repository you run Claude Code in; every worktree shares it (0010-DAE-PLT). The Build Train's start creates `<repo>/.claude/daedalus/` (mode 0700) and a `.gitignore` inside it holding `*`; until then no hook writes anything into the repository (0035-DAE-PLT). `config.json` is optional. Without it the defaults apply: no `charter_root`, no `standards_sources`, no `policy`, and the ledger probe below finds the ledger. Create it there from your own shell when you need any of those.

### config.json, optional **(checked)**

```json
{
  "charter_root": "/absolute/path/to/your/decisions/repo",
  "ledger": {
    "path": "/absolute/path/to/your/decisions/repo/decision-log.md",
    "format": "markdown-table-row",
    "id_scheme": "{seq:04d}-{repo}-{type}",
    "sequence_source": "last-row-id"
  },
  "standards_sources": [
    { "kind": "rules-dir", "path": "/absolute/path/to/rules" },
    { "kind": "file", "path": "/absolute/path/to/repo/CLAUDE.md" }
  ],
  "policy": { "engine": "conftest", "path": "/absolute/path/to/your/decisions/repo/policy" },
  "operator_signing_keys": []
}
```

| Key | What it is | If absent |
|---|---|---|
| `charter_root` | Repo where decisions and specs live. Agents may write there. | contract-spec and charter-docs can write only inside the target repo |
| `ledger` **(checked)** | Where rulings are appended. `format` is `markdown-table-row` (one table row per ruling) or `heading-entry` (one `## Entry N` section per ruling). `sequence_source` is `last-row-id` or `frontmatter:<key>`. | The Build Train stops and asks before creating one |
| `standards_sources` **(checked)** | Directories or files holding your rules. `kind` is `rules-dir`, `file` or `pack`. | The Standards Packet is empty and the auditor judges against the spec only; the doctor offers the baseline pack on an `OPT` line |
| `policy` **(checked)** | Deterministic policy pack. `engine` is `cfn-guard` or `conftest`. daedalus ships no rules; the directory is yours. | No effect today; a later Daedalus release adds the deterministic gate for infrastructure diffs |
| `operator_signing_keys` | Fingerprints allowed to sign merges. | No effect today; a later Daedalus release adds the merge-gate check that reads it |

### Ledger formats

The Build Train appends rulings to your ledger with `append_ledger.py`, in one of two formats.

`markdown-table-row`: a table whose header has an `Id` cell, with a separator row directly under it. Column 1 is `Id` and column 2 is `Date`; the remaining columns are yours. The sequence is the leading number of the last row's id (`last-row-id`), and the default id scheme is `{seq:04d}-{repo}-{type}`.
```markdown
| Id | Date | Ruling | Supersedes | Follow-ups |
|---|---|---|---|---|
| 0001-SVC-PLT | 2026-01-01 | First ruling. | None | None |
```

`heading-entry`: one `## Entry N` section per ruling, id scheme `{seq}`. The sequence is the `N` of the last `## Entry N` heading in the file (`last-row-id`):
```markdown
## Entry 7 - 2026-01-02T00:00:00Z

Seven.
```
To keep the sequence in frontmatter instead, start the file with a `---` block holding `sequence_id: 7` and set `sequence_source` to `frontmatter:sequence_id`. The `---` must be the file's first line; a heading ledger with anything above it is not read as frontmatter.

### standards_sources kinds

Each entry has a `kind` and a `path`, except `pack`, which has a `name`. The standards specialist reads only these entries, and cites each rule as `source:line`.

- `rules-dir`: a directory of rule files. Example: `{ "kind": "rules-dir", "path": "/absolute/path/to/rules" }`
- `file`: one file. Example: `{ "kind": "file", "path": "/work/my-service/CLAUDE.md" }`
- `pack`: a rules pack shipped inside the plugin, resolved to `<plugin>/packs/<name>/`. Daedalus ships one, `baseline`: five baseline checks (no hardcoded secrets, no wildcard access grants, TLS 1.2 or newer, encryption at rest, no personal data or key material in logs) and the Daedalus cloud security standards (a role per workload, no public object storage, logging on every data store, scheduled rotation of customer-data keys, private networking for data stores, multi-factor sign-in for people). Each rule is one line in `packs/baseline/rules.md`, in Daedalus's own words, citing NIST SP 800-53 control ids and OWASP ASVS requirement ids. It applies only when you declare it: `{ "kind": "pack", "name": "baseline" }`. Any other name is refused with `Next: name the shipped baseline pack, "baseline".`

### What the ledger probe detects

    python3 <plugin>/scripts/append_ledger.py --probe

Run it from the repo. It resolves the ledger in this order and prints the first hit:

1. A `ledger` block in `<repo>/service-manifest.json` (origin `manifest`).
2. The `ledger` block in config.json (origin `config`).
3. The first file found of `decision-log.md`, `docs/decisions.md`, `LEDGER.md`, under the repo root and then under `charter_root` (origin `probe`). A file with an `Id` table is read as `markdown-table-row`. Otherwise it is read as `heading-entry`, with `frontmatter:sequence_id` when its frontmatter holds `sequence_id`.

A hit prints `ledger: <path> (<origin>, <format>, seq=<n>)`, for example `ledger: /work/my-service/docs/decisions.md (probe, markdown-table-row, seq=2)`. No hit prints `ledger: none declared and none found.` with a `Next:` line, and the Build Train asks you before creating one. Both exit 0. Exit 1 means the ledger was found but could not be read, for example an empty Id table above another table; the message ends with `Next:`. A file whose only Id table has a header and separator but no rows is a new ledger: it reads as `seq=0` and the first append writes `0001`.

## Machine caches

The NIST and CIS specialists read reference files from the plugin's machine cache. Find its path with:

    python3 <plugin>/scripts/daedalus_doctor.py --print-cache-dir

It prints one absolute path, called `<cache>` below. Exit 1 means no cache exists yet; run `/daedalus:doctor` inside Claude Code once.

The specialists verify every hash before they answer. A mismatch or a missing file stops the train with `CACHE_INVALID`.

### NIST catalogs (`<cache>/frameworks/nist/`)

Run the refresh script from your own shell. It uses the network:

    python3 <plugin>/scripts/refresh_frameworks.py

Each adapter downloads one framework from a pinned upstream release on GitHub and writes it under `<cache>/frameworks/<family>/`. The NIST adapters pin `usnistgov/oscal-content` tag `v1.5.0`:

- `nist-800-53` writes `catalog.json`, the NIST SP 800-53 rev5 OSCAL catalog.
- `nist-csf-2.0` writes `csf-2.0.json`, the NIST Cybersecurity Framework 2.0 OSCAL catalog.

Next to them it writes `manifest.json`, a JSON list with one entry per file: `file`, `sha256`, `version` (the catalog's own `metadata.version`), `pinned_on` (UTC date), `source_url`, `upstream_ref` (the pinned tag) and `license` (`public domain (17 U.S.C. 105)`). A run replaces only the entries of the adapters it ran.

`--only nist-800-53,nist-csf-2.0` runs the named adapters; with no `--only` every adapter runs. `--cache-root <dir>` writes under `<dir>/frameworks/` instead of the cache found by `--print-cache-dir`. The pinned URLs are `https` on `raw.githubusercontent.com`. The script refuses:

- a redirect off `github.com`, `raw.githubusercontent.com` or `api.github.com`, or one with a user name, query, fragment, `.` or `..` segment, backslash or encoded slash;
- a response over 64 MiB;
- a NIST download that is not a JSON object with a printable `catalog.metadata.version` of 64 characters or fewer (or a top-level `metadata.version` when the file has no `catalog` key);
- a symlink anywhere from the cache directory down to the family directory (with `--cache-root`, from its first existing parent down), or at a cache file, `manifest.json` or `.refresh.lock`.

Each line `pinned <adapter> <version> sha256=<hash> at <path>` names a written file. Every failure prints the adapter name and a `Next:` line, and the script exits 1 after the other adapters run. A run holds `.refresh.lock` in the family directory, so a second run waits up to 60 s for it and fails that adapter if it is still held. An adapter that fails before its files are replaced leaves its previous files and manifest entries in place. Run the script again whenever you want to re-pin; the doctor marks a family older than 90 days.

### OWASP references (`<cache>/frameworks/owasp/`)

The same script holds two OWASP adapters. OWASP publishes both under the Creative Commons Attribution-ShareAlike 4.0 license (CC BY-SA 4.0), so each manifest entry carries `license` (`CC BY-SA 4.0`) and an `attribution` line naming the OWASP Foundation, the project and the source URL. Keep that attribution with any copy you make.

- `owasp-asvs` writes `asvs-5.0.0.json`, the Application Security Verification Standard 5.0.0 JSON export from `OWASP/ASVS` tag `v5.0.0_release`. The script refuses a file without the keys `Name`, `ShortName`, `Version`, `Description` and a non-empty `Requirements` list. `version` is its `Version` key.
- `owasp-top10` reads the ten 2025 English pages from `OWASP/Top10` commit `3a31f35` (the project has no release tag for 2025) and writes `top10-2025.json`: a list of `{"id": "A01:2025", "title": "...", "source_file": "..."}`, with each title taken from the page's first level-one heading. A page without one fails the adapter. `version` is `2025@3a31f35`, and `source_url` is the directory the ten pages came from.

### CIS benchmarks (`<cache>/frameworks/cis/`)

CIS benchmarks are licensed, so you place them by hand:

1. Create the directory: `mkdir -p -m 700 <cache>/frameworks/cis`.
2. Copy in each benchmark file you hold a license for.
3. Hash each file: `sha256sum <cache>/frameworks/cis/<file>`. The first field of the output is the hash.
4. Write `<cache>/frameworks/cis/manifest.json` as a JSON list with one entry per file, using the file name relative to `cis/`:

       [
         { "file": "benchmark.json", "sha256": "<sha256sum output>", "version": "3.0.0", "pinned_on": "2026-10-14" }
       ]

Repeat steps 2 to 4 when you replace a benchmark.

## In each target repository

### service-manifest.json (repo root), optional **(checked)**

Minimal:
```json
{ "manifest_version": 1, "service_name": "my-service", "purpose": "One sentence.",
  "stack": { "language": "python", "runtime": "python3.12", "package_registries": ["pypi.org"],
             "unit_test_cmd": "pytest -q", "typecheck_cmd": null, "lint_cmd": "ruff check .", "build_cmd": null },
  "entrypoints": { "handlers": "src/handlers/", "models": "src/models/", "infra": "infra/", "contracts": "contracts/" },
  "exposure_and_traits": { "is_public": false, "has_website": false, "operator_panel_integrated": false,
                            "contains_customer_data": false, "touches_key_material": false,
                            "data_classification": "INTERNAL" },
  "jail_narrowing": { "forbidden_extensions": [], "forbidden_paths": [] },
  "upstream_dependencies": [], "downstream_dependencies": [] }
```
`jail_narrowing` adds paths a coder may not write (0054-DAE-PLT). Each `forbidden_paths` entry is relative to the repository root, uses forward slashes, and holds no leading slash, `..` or glob characters. An entry ending in a slash covers that folder and everything under it; an entry without one names one file. Each `forbidden_extensions` entry starts with a dot and covers every file name ending in it. Matching ignores case. The jail reads this file from the main checkout, never from a coder's worktree. A manifest that is not valid JSON, or whose `jail_narrowing` has the wrong shape, refuses every coder write until it is fixed, and the doctor reports it as a `MISS`. When the file is present, the doctor's line counts the entries: `OK   service-manifest.json: jail_narrowing <n> paths, <m> extensions`.

A later Daedalus release reads missing exposure flags as the stricter value. Coders cannot edit this file (enforced for file tools and the common copy/edit commands; a script the coder writes and runs is not blocked yet). In that later release, a change to it goes through contract-spec and the ledger.

### contracts/ (directory), optional **(checked)**

Holds `openapi.yaml`, `events/*.schema.json`, `errors.yaml`. May be empty to start. Coders cannot write here (enforced for file tools and the common copy/edit commands; a script the coder writes and runs is not blocked yet).

### .gitleaks.toml (repo root), optional **(checked)**

Minimal:
```toml
[extend]
useDefault = true
```
The Push Train runs `gitleaks detect` over every commit on the train branch before it pushes, and stops without the binary.

### Coder write boundary

A coder writes only inside its own unit worktree, which the Build Train creates at `<repo>/.claude/worktrees/<train-id>-<unit-slug>`. Inside it, every path is writable except the protected ones (0054-DAE-PLT): `contracts/`, `.github/` (workflows, CODEOWNERS, dependabot and templates), `.claude/`, `service-manifest.json`, the repository's own decision ledger when it lives inside the repository, and every `jail_narrowing` entry in `service-manifest.json`. A write to a folder that holds a protected path, such as `rm -r docs` when the ledger is `docs/decisions.md`, is refused too. A refused write names the path and says whether the rule is built in or comes from `jail_narrowing`.

## Claude Code settings

Daedalus writes no Claude Code settings file, in the repository or in your home directory. The Build Train creates its own coder worktrees from the integration branch, and the jail keeps every Daedalus agent from starting agents, so neither needs a setting.

Outside a train, Daedalus leaves your session and your repository alone, with one exception: it refuses reads and searches of credential files (`~/.ssh`, all of `~/.aws`, `~/.gnupg`, `~/.config/gh` and `~/.claude/.credentials.json`) for every agent and the main session. Outside a train, Daedalus writes no files and keeps no audit log in any repository, including one where a train ran before. Inside a train, the jail judges every tool call and the audit log records each step. A train works in three folders: `<repo>/.claude/worktrees/` for the unit worktrees, `<repo>/.claude/daedalus/` for train state and the audit log, and the git-ignored `<repo>/docs/.tmp/daedalus/` for scratch files and summaries. To have the plugin's hooks in some repositories only, enable the plugin at project scope in each of those repositories' `.claude/settings.json` (Claude Code's `enabledPlugins`) instead of for your user (0035-DAE-PLT).

While a train runs, the jail refuses tool writes and the known Bash write routes into `<repo>/.claude/daedalus/`; Daedalus's own agents meet that refusal at all times. The `*` gitignore marker keeps it out of git, and the hooks refuse to run when the directory is a symlink, is tracked by git, or holds a marker other than `*`. Daedalus's own agents always, and the main session while a train runs, are also refused writing the credential files above or naming them in the Bash forms the jail models.

### Test-only

`DAEDALUS_LIVE_TEST=1` enables the `daedalus-probe` agent namespace that this repo's live tests use. Do not set it in normal use.

## Text a person reads

Text a human reads names each item in words: a short label or one line on what it is and what it does. Ids (ruling ids, issue numbers, task codes, agent names, snake_case keys) may trail in parentheses, never replace the description. Logs, status lines and messages to other agents may use ids alone. Documents carry both.

Every agent file and every skill carries that rule. A test reads each `Next:` line and stop message in the scripts and skills, and fails on one that has fewer than four plain words once ids and paths are set aside.

## Reviewing changes to Daedalus

A finding about git or file state is closed by a script change and a script test, never by a skill sentence.

An agent file for a judge (the nist and cis specialists and the security auditor) must carry a method and a rubric. An agent file for an actor stays thin, because its tools and the hooks bound what it can do.
