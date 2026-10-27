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
  "operator_signing_keys": [],
  "max_concurrent_builders": 5,
  "audit_retention_days": null,
  "agent_models": { "repo-coder": "sonnet", "security-auditor": "opus" }
}
```

Every key in this file is a row of the generated key reference in the plugin [README](../README.md#key-reference): what it governs, its type, its allowed values, its default and an example. The doctor checks `ledger`, `standards_sources`, `policy` and `audit_retention_days` **(checked)**. A key set to `null` counts as absent (0076). Four notes the table has no room for:

- `ledger`: with no ledger declared and none found, the Build Train stops and asks before creating one.
- `standards_sources`: with none declared, the Standards Packet is empty, the auditor judges against the spec only, and the doctor offers the baseline pack on an `OPT` line.
- `audit_retention_days`: a whole number of at least 90 (AU-11). When a new session writes its first record, each older log is deleted under its own lock, and one `AuditRotation` record in the new session's chain names every deleted session with its final seq and hash (AU-9(4)). A log named on a summary's `Session <id>:` line, a log changed since an unmerged train started, the current session's log, and a log another session holds are kept. Any read or parse error deletes nothing.
- `agent_models`: an object from an agent name the catalog lists to `sonnet`, `opus`, `haiku` or `fable`. For example, `"agent_models": { "repo-coder": "sonnet" }` runs the coding agent on sonnet while every other agent keeps the model its agent file names. An unknown agent name or model refuses the config with a `Next:` line naming the key. Run `python3 scripts/catalog.py table --repo <repo>` from the plugin folder to see the model each agent runs on.

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

The refresh script downloads NIST and OWASP reference files into the plugin's machine cache. Those files are input for the pack importer: `scripts/import_pack.py oscal` turns a downloaded NIST catalog into a control pack (see "Framework control packs" below). Find the cache path with:

    python3 <plugin>/scripts/daedalus_doctor.py --print-cache-dir

It prints one absolute path, called `<cache>` below. Exit 1 means no cache exists yet; run `/daedalus:doctor` inside Claude Code once.

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

### CIS id maps (`import_pack.py cis-map`)

CIS benchmarks are licensed, so no benchmark text enters a pack. You map each CIS id you hold a license for to a control in another pack, and the importer writes an id-map pack:

1. Write a UTF-8 CSV file whose header is exactly `cis_id,control_id`, with one line per CIS id, such as `1.4,AWS-IAM-1`. The importer refuses any other column.
2. From inside the project, run:

       python3 <plugin>/scripts/import_pack.py cis-map --map <csv file> --benchmark <benchmark name> --version <x.y.z> --out <pack folder>

Each CSV line becomes one control: its `id` and `refs.cis` are the CIS id, its `maps_to` is the control id, and its title is the benchmark name plus the CIS id. The pack's `license` is `operator-licensed, ids only`. Each `control_id` must name a control in a pack beside `--out` or in a shipped pack. Run the command again with a new `--version` when you change the map.

### Framework control packs

A pack is a folder holding `pack.json` and `controls.json`. The folder name is the pack id. Daedalus ships two packs under `<plugin>/packs/frameworks/`: `aws-default` and `nist-distilled`.

`pack.json` is one JSON object with exactly these keys:

- `id`: the pack name, lowercase letters, digits and dashes, 1 to 40 characters.
- `version`: three dot-separated numbers, such as `1.0.0`.
- `source`: `daedalus` for a shipped pack, else the file the importer read.
- `license`: one line, such as `GPL-3.0-or-later`, `public domain (17 U.S.C. 105)` or `operator-licensed, ids only`.
- `pinned_on`: the `YYYY-MM-DD` date the pack was written.
- `sha256`: the 64 lowercase hex SHA-256 of `controls.json`.

`controls.json` is `{"schema": "daedalus-controls/1", "controls": [...]}`. Each control holds:

- `id` (required): unique in the pack, such as `AWS-IAM-1`.
- `service` (required): one of `iam`, `s3`, `kms`, `cloudtrail`, `vpc`, `lambda`, `dynamodb`, `apigateway`, `ec2`, `ecs`, `ecr`, `logs` or `any`.
- `title` (required): one line in the pack author's words.
- `statement`, `look_for` and `verify` (required unless `maps_to` is set): the requirement in the author's words, what in a diff shows the control met or broken, and one read-only command that tests the control against the tree.
- `live_check` (optional): one read-only cloud command for the operator to run.
- `refs` (required): `{"nist": [...], "cis": [...], "asvs": [...]}`, ids only; any list may be empty. Each `nist` id must be in `tests/fixtures/nist-control-ids.txt`.
- `maps_to` (optional): the id of a control in another pack, for an id-map pack.

A pack is refused when a file is missing, a link, or over 4 MiB; when the hash does not match; when a key is off these lists or repeated; when a control id repeats; when a `maps_to` names no control in the packs beside it or the shipped packs; or when a `statement` runs over 400 characters in a pack whose license starts with `operator-licensed`.

To build a pack from a NIST catalog, download the catalog with the refresh script, then import the controls you want, from inside the project:

    python3 <plugin>/scripts/refresh_frameworks.py --only nist-800-53 --cache-root <dir>
    python3 <plugin>/scripts/import_pack.py oscal --catalog <dir>/frameworks/nist/catalog.json --ids AC-2,AC-3 --out <pack folder>

`--version <x.y.z>` sets the pack version; without it the importer uses the catalog's own version. Both importers refuse an `--out` outside the project or under an excluded root, and an `--out` folder name that is not a pack id. Each prints `wrote <pack folder> (<n> controls)`.

The `frameworks` block of `service-manifest.json` picks the packs a train reads:

- `frameworks.pack_dir`: a project-relative folder; each subfolder of it holding `pack.json` is one pack. A linked subfolder is skipped.
- `frameworks.default_packs`: `true` (the default) also reads the shipped packs; `false` reads only the packs under `frameworks.pack_dir`.

With no `frameworks` block, only the shipped packs are read. The manifest reader refuses any other key in the block.

The doctor prints one line per pack, after the framework cache lines:

- `OK   framework pack <id>: <version>, <n> controls` for a pack that loads.
- `MISS framework pack <id>: <problem>. Next: <action>` for each problem; the run fails. For a pack built from a NIST catalog, the action is the two commands above.
- `MISS framework packs: <pack_dir> is not a folder. Next: create it or remove frameworks.pack_dir from service-manifest.json`; the run fails.
- `OLD  framework pack <id>: pinned <date> (<days> days). Next: <action>` once `pinned_on` is more than 90 days old. The action re-runs the importer, or updates the plugin for a shipped pack. The run still passes.

## In each target repository

### service-manifest.json (repo root), optional **(checked)**

Example:
```json
{ "manifest_version": 1, "service_name": "my-service", "purpose": "One sentence.",
  "stack": { "language": "python", "runtime": "python3.12", "package_registries": ["pypi.org"],
             "unit_test_cmd": "pytest -q", "typecheck_cmd": null, "lint_cmd": "ruff check .", "build_cmd": null },
  "entrypoints": { "handlers": "src/handlers/", "models": "src/models/", "infra": "infra/", "contracts": "contracts/" },
  "exposure_and_traits": { "is_public": false, "has_website": false, "operator_panel_integrated": false,
                            "contains_customer_data": false, "touches_key_material": false,
                            "data_classification": "INTERNAL" },
  "features": { "scope": null, "secrets_scan": false, "scrub_file": null, "ledger": null },
  "trains_dir": null,
  "frameworks": { "pack_dir": "compliance/packs", "default_packs": true },
  "jail_narrowing": { "forbidden_extensions": [], "forbidden_paths": [] },
  "upstream_dependencies": [], "downstream_dependencies": [] }
```
The manifest reader checks `jail_narrowing`, `features`, `trains_dir`, `frameworks`, the three stack commands and the `ledger` block; each of those keys is a row of the generated key reference in the plugin [README](../README.md#key-reference). The reader refuses an unknown key inside `jail_narrowing`, `features` or `frameworks`. The `frameworks` keys are described under "Framework control packs" above. The keys below describe the project for the people and agents who read the file. No reader checks them, so a wrong value is never refused.

| Key | What it governs | Type | Allowed values | Default | Example |
|---|---|---|---|---|---|
| `manifest_version` | The version of the manifest format; no Daedalus code reads it yet | integer | `1` | none | `1` |
| `service_name` | The project's name, for people reading the manifest; no Daedalus code reads it yet | string | Any short name | none | `"my-service"` |
| `purpose` | One sentence on what the project does; no Daedalus code reads it yet | string | One sentence | none | `"Serves the billing API."` |
| `stack.language` | The project's main language; no Daedalus code reads it yet | string | Any language name | none | `"python"` |
| `stack.runtime` | The runtime the project ships on; no Daedalus code reads it yet | string | Any runtime name | none | `"python3.12"` |
| `stack.package_registries` | The registries the project installs packages from; no Daedalus code reads it yet | list of strings | Registry host names | none | `["pypi.org"]` |
| `stack.build_cmd` | The command that builds the project; a coding agent never runs it, because only the test, typecheck and lint commands are run as declared | string or null | A command string, or `null` | none | `null` |
| `entrypoints` | The project's file areas by name; `/daedalus:plan` pastes this block into the planner's prompt, and the planner cuts units along these areas | object of strings | Each key names an area, and each value is a project-relative path | Absent: the planner is told `none declared` | `{"handlers": "src/handlers/", "infra": "infra/"}` |
| `exposure_and_traits.is_public` | Whether the project is reachable from the internet; no Daedalus code reads it yet | boolean | `true` or `false` | none | `false` |
| `exposure_and_traits.has_website` | Whether the project serves a website; no Daedalus code reads it yet | boolean | `true` or `false` | none | `false` |
| `exposure_and_traits.operator_panel_integrated` | Whether the project plugs into an operator panel; no Daedalus code reads it yet | boolean | `true` or `false` | none | `false` |
| `exposure_and_traits.contains_customer_data` | Whether the project stores or handles customer data; no Daedalus code reads it yet | boolean | `true` or `false` | none | `false` |
| `exposure_and_traits.touches_key_material` | Whether the project creates, holds or uses key material; no Daedalus code reads it yet | boolean | `true` or `false` | none | `false` |
| `exposure_and_traits.data_classification` | The project's data classification label; no Daedalus code reads it yet | string | Your own classification labels | none | `"INTERNAL"` |
| `upstream_dependencies` | The services this project calls; no Daedalus code reads it yet | list | Service names or objects of your choosing | none | `[]` |
| `downstream_dependencies` | The services that call this project; no Daedalus code reads it yet | list | Service names or objects of your choosing | none | `[]` |

`jail_narrowing` adds paths a coder may not write (0054-DAE-PLT). Each `forbidden_paths` entry is relative to the repository root, uses forward slashes, and holds no leading slash, `..` or glob characters. An entry ending in a slash covers that folder and everything under it; an entry without one names one file. Each `forbidden_extensions` entry starts with a dot and covers every file name ending in it. Matching ignores case. The jail reads this file from the main checkout, never from a coder's worktree. A manifest that is not valid JSON, or whose `jail_narrowing` has the wrong shape, refuses every coder write until it is fixed, and the doctor reports it as a `MISS`. When the file is present, the doctor's line counts the entries: `OK   service-manifest.json: jail_narrowing <n> paths, <m> extensions`. When `stack.typecheck_cmd` is declared, the doctor prints it on an `OPT` line and does not run it; it runs the command only when you pass `--run-typecheck` to `daedalus_doctor.py` yourself, because that flag executes a command the repository chose (0076).

A later Daedalus release reads missing exposure flags as the stricter value. Coders cannot edit this file (enforced for file tools and the common copy/edit commands; a script the coder writes and runs is not blocked yet). In that later release, a change to it goes through contract-spec and the ledger.

### contracts/ (directory), optional **(checked)**

Holds your own interface files, such as `openapi.yaml`, `events/*.schema.json` and `errors.yaml`. May be empty to start; the doctor shows an `OPT` line while the folder is missing. Coders cannot write here (enforced for file tools and the common copy/edit commands; a script the coder writes and runs is not blocked yet).

A Build Train writes its contract here only when config.json declares no `charter_root`; with `charter_root` the contract goes to `<charter_root>/specs/<name>.md` instead. The contract-spec agent saves the Locked Contract Packet to `contracts/<name>.md`, where `<name>` is a short name of lowercase letters, digits and hyphens. The lock command (`daedalus_workspace.py lock`) commits it on the integration branch `daedalus/<train-id>` as `Lock contract <name> v<packet_version>` before any coder starts. Each revision is committed as `Revise contract <name> v<N>`. The file holds the packet as contract-spec wrote it: `packet_version=<n>`, the target services, the wire contract and the ledger invariants.

Read the contract during a train, but do not edit it. Every coder brief names the file with its sha256, and a coder refuses to start when the hash does not match. A coder that reports a different hash stops the train. A revision comes only from contract-spec, when a coder's contract question needs one.

### .gitleaks.toml (repo root), optional **(checked)**

Minimal:
```toml
[extend]
useDefault = true
```
gitleaks reads this file, not Daedalus. The Push Train runs `gitleaks detect --redact --log-opts=<base sha>..daedalus/<train-id>` from the repository root, and gitleaks picks up `.gitleaks.toml` from the folder it scans. The scan runs only when `features.secrets_scan` is `true` in `service-manifest.json`; the Push Train then stops without the binary (0069-DAE-PLT). With the scan off, the default, the Push Train runs no scan and the doctor's gitleaks line is an `OPT` line. The doctor checks only that the file exists.

| Key | What it governs | Type | Allowed values | Default | Example |
|---|---|---|---|---|---|
| `[extend]` `useDefault` | Whether gitleaks keeps its own built-in rules and adds yours on top | boolean | `true` or `false` | gitleaks's own default | `true` |

Every other key, such as your own rules or an allowlist for a known false positive, is gitleaks's own format: https://github.com/gitleaks/gitleaks#configuration.

### Project train definitions

When `service-manifest.json` sets `trains_dir` to a project-relative folder, a train named `<name>` is looked up first as `<trains_dir>/<name>.json`, then in the plugin's own `trains/` folder (0073-DAE-PLT). A project definition's brief templates resolve beside the definition file, and a definition whose real path leaves the project is refused. Check a definition with:

    python3 <plugin>/scripts/validate_train.py <trains_dir>/<name>.json

Exit 0 prints `OK train <name> v<version>: <n> stages`. Exit 1 prints one defect line per failed check, each starting with its check number, and a `Next:` line. The train runner starts a definition with `python3 <plugin>/scripts/daedalus_train.py start --repo <repo> --train <name>`. The plugin repository's `tests/fixtures/trains/valid.json` is a complete example.

A definition is one JSON object holding exactly these top-level keys:

| Key | What it governs | Type | Allowed values | Example |
|---|---|---|---|---|
| `name` | The train's name | string | A slug of lowercase letters, digits and hyphens, equal to the file name without `.json` | `"release-check"` |
| `version` | The definition's own version | integer | A whole number of at least 1 | `1` |
| `description` | What the train does, in words | string | A line of at least four plain words, ids and paths aside | `"Checks a release before the tag"` |
| `scopes` | Which projects the train may run in | list of strings | Distinct values from `"repository"` and `"folder"`, at least one | `["repository"]` |
| `gates` | The train's checkpoints, in order; every stage belongs to one, and stages run in this order | list of strings | Distinct gate names, at least one | `["build", "merge"]` |
| `consults` | The agents a stage may consult while its gate is open | object | Each key is a declared gate, and each value is a list of agent names with an agent file in the plugin | `{"build": ["web-researcher"]}` |
| `stages` | The steps the runner takes | list of objects | At least one stage, in the shape below | see below |
| `off_contract` | Where the train goes when a reply ends off its contract | string | A `stop:`, `ask:` or `consult:` route; never `back:`, because it belongs to no stage | `"stop: Next: rerun the train after reading the agent reply"` |

Each stage object holds `id`, `gate`, `agent`, `scope`, `proof` and `on_fail`, and may add `verifies`, `when`, `repeat` and `parallel`. Any other key is refused.

| Key | What it governs | Type | Allowed values | Example |
|---|---|---|---|---|
| `id` | The stage's name, used by routes and records | string | A slug, unique in the definition | `"code"` |
| `gate` | The checkpoint the stage belongs to | string | A gate named in `gates` | `"build"` |
| `agent` | Who runs the stage | string | `"main"` for a step the runner runs itself, or the name of an agent file in the plugin | `"repo-coder"` |
| `scope` | What the agent is told, where it may write and how it may reply | object | Exactly `told`, `touch` and `reply`, below | see below |
| `proof` | The command that proves the stage passed | object | Exactly `script`, `exit` and `records`, below | see below |
| `on_fail` | Where each failing outcome or reply line goes | object | Each key is a failing exit outcome or a reply line of the stage; each value is a route, below | `{"[STATUS: YIELD_WEB]": "consult:web-researcher"}` |
| `verifies` | What the stage checks, in words | string | Non-empty text | `"the merged tip passes its tests"` |
| `when` | A condition that skips the stage when it is off | string | `features.<name>` with a feature from the key reference, or a field an earlier stage records | `"features.ledger"` |
| `repeat` | Runs the stage once for each unit of the recorded plan | string | `"per-unit"` | `"per-unit"` |
| `parallel` | Runs the units of a `per-unit` stage at the same time | boolean | `true` or `false`; `true` needs `repeat` | `true` |

Inside `scope`:

- `told`: the brief template the agent receives, as a path relative to the definition file, or `"none"` for a `main` stage. Each `{field}` placeholder in it must name a train state field or a field an earlier stage records.
- `touch`: the folders the stage may write, as a list drawn from `none`, `unit-src-tests`, `contracts`, `charter-specs`, `charter`, `docs` and `scratch`. The agent's own hooks must grant each one.
- `reply`: the reply lines the stage accepts, each one a line of the agent's status contract or its leading part, such as `[STATUS: COMPLETE]`.

Inside `proof`:

- `script`: the command the runner runs or reads, with `{field}` placeholders, such as `daedalus_train.py check-reply --stage code`.
- `exit`: an object that maps each exit code, written as text, to an outcome name. `pass` passes the stage, `off-contract` goes to `off_contract`, and every other outcome needs a route in `on_fail`.
- `records`: the state field names the stage writes, which later placeholders and `when` conditions may use.

A route is one of four forms: `stop: Next: <at least four plain words>`, `back:<earlier stage id> rounds=<n>`, `ask: <a question for the operator>` and `consult:<agent name>`.

### Standing-rules backfill file

`standing_rules.py` derives a standing-rules file from a markdown-table ledger (0090, 0094). The ledger table needs `Id`, `Date`, `Ruling` and `Supersedes` columns. The output groups every ruling in force by area, adds an `Amended by` line under each amended ruling, and lists the superseded rulings at the end. Run it from your own shell:

    python3 <plugin>/scripts/standing_rules.py --ledger <ledger path> --backfill <backfill path> --out <standing-rules path>

`--check` writes nothing and exits 1 when the file at `--out` differs from what the script would write. `--id-scheme` overrides the ledger id pattern, by default `{seq:04d}-{repo}-{type}`.

The backfill file is one JSON object holding exactly four keys; any other key is refused:

| Key | What it governs | Type | Allowed values | Example |
|---|---|---|---|---|
| `relations_from` | The first ledger row that carries its own relations; every earlier row takes its relations from `relations` | string | A ledger id that is a row of the ledger | `"0090-DAE-PLT"` |
| `names_from` | The first ledger row whose Ruling cell starts with its name as its first sentence; earlier rows are named by the first clause of their Ruling cell | string | A ledger id that is a row of the ledger | `"0094-DAE-PLT"` |
| `areas` | The area each ruling in force is filed under | object | Each key is a ledger id; each value is one of the eight area names below. Every ruling in force needs one, and an id that is not in the ledger is refused | `{"0004-DAE-PLT": "the ledger and charter"}` |
| `relations` | What each row before `relations_from` supersedes and amends | object | Each key is a ledger id before `relations_from`; each value is an object holding exactly a `supersedes` list and an `amends` list of earlier ledger ids | `{"0012-DAE-PLT": {"supersedes": ["0007-DAE-PLT"], "amends": []}}` |

From `relations_from` on, a row reads its own Supersedes cell: a sentence starting `Supersedes: ` or `Amends: ` lists the ids it supersedes or amends. A row from `relations_from` on that also appears in `relations` is refused.

The eight area names, exactly as written: `composition and phases`, `planning and dispatch`, `the jail and grammars`, `the audit log and proofs`, `the ledger and charter`, `GitHub and release`, `the project files`, `operator interaction`.

### Coder write boundary

A coder writes only inside its own unit worktree, which the Build Train creates at `<repo>/.claude/worktrees/<train-id>-<unit-slug>`. Inside it, every path is writable except the protected ones (0054-DAE-PLT): `contracts/`, `.github/` (workflows, CODEOWNERS, dependabot and templates), `.claude/`, `service-manifest.json`, the repository's own decision ledger when it lives inside the repository, and every `jail_narrowing` entry in `service-manifest.json`. A write to a folder that holds a protected path, such as `rm -r docs` when the ledger is `docs/decisions.md`, is refused too. A refused write names the path and says whether the rule is built in or comes from `jail_narrowing`.

## Claude Code settings

Daedalus writes no Claude Code settings file, in the repository or in your home directory. The Build Train creates its own coder worktrees from the integration branch, and the jail keeps every Daedalus agent from starting agents, so neither needs a setting.

Outside a train, Daedalus leaves your session and your repository alone, except that catalog agents keep their own hooks and a read or search of a credential file (`~/.ssh`, all of `~/.aws`, `~/.gnupg`, `~/.config/gh` and `~/.claude/.credentials.json`) meets one check, which warns the main session in its context and refuses an agent. Outside a train, Daedalus writes no files and keeps no audit log in any repository, including one where a train ran before. Inside a train, the jail judges every tool call and the audit log records each step. A train works in three folders: `<repo>/.claude/worktrees/` for the unit worktrees, `<repo>/.claude/daedalus/` for train state and the audit log, and the git-ignored `<repo>/docs/.tmp/daedalus/` for scratch files and summaries. To have the plugin's hooks in some repositories only, enable the plugin at project scope in each of those repositories' `.claude/settings.json` (Claude Code's `enabledPlugins`) instead of for your user (0035-DAE-PLT).

While a train runs, the jail refuses tool writes and the known Bash write routes into `<repo>/.claude/daedalus/`; Daedalus's own agents meet that refusal at all times. The `*` gitignore marker keeps it out of git, and the hooks refuse to run when the directory is a symlink, is tracked by git, or holds a marker other than `*`. Daedalus's own agents are always refused writing the credential files above or naming them in the Bash forms the jail models; while a train runs, the main session is warned in context when it does either, and never prompted (Main never prompted, amending 0105-DAE-PLT and 0106-DAE-PLT).

### Test-only

`DAEDALUS_LIVE_TEST=1` enables the `daedalus-probe` agent namespace that this repo's live tests use. Do not set it in normal use.

## Text a person reads

Text a human reads names each item in words: a short label or one line on what it is and what it does. Ids (ruling ids, issue numbers, task codes, agent names, snake_case keys) may trail in parentheses, never replace the description. Logs, status lines and messages to other agents may use ids alone. Documents carry both.

Every agent file and every skill carries that rule. A test reads each `Next:` line and stop message in the scripts and skills, and fails on one that has fewer than four plain words once ids and paths are set aside.

## Reviewing changes to Daedalus

A finding about git or file state is closed by a script change and a script test, never by a skill sentence.

An agent file for a judge (the nist and cis specialists and the security auditor) must carry a method and a rubric. An agent file for an actor stays thin, because its tools and the hooks bound what it can do.
