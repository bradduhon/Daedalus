<!-- Copyright (c) 2026 Brad Duhon. SPDX-License-Identifier: GPL-3.0-or-later -->
# What your project needs for daedalus

Every file and setting daedalus reads, with the smallest example that works. `/daedalus:doctor` checks the ones marked below, optional ones included; an optional one that is absent passes. Each marked heading or key carries **(checked)**.

## In the repo's `.claude/daedalus/` directory

`<repo>` is the main working tree of the git repository you run Claude Code in; every worktree shares it (0010-DAE-PLT). The Build Train's start creates `<repo>/.claude/daedalus/` (mode 0700) and a `.gitignore` inside it holding `*`; until then no hook writes anything into the repository (0035-DAE-PLT). `config.json` is optional. Without it the defaults apply: no `local_docs_folder`, no `coding_rules`, no `policy`, and the decisions file, when the manifest names one, lives in the project's docs folder. Create it there from your own shell when you need any of those.

### config.json, optional **(checked)**

```json
{
  "local_docs_folder": "/absolute/path/to/your/decisions/repo",
  "git_excluded_folders": [{ "kind": "path", "path": "<repo_root>/private/" }],
  "coding_rules": [
    { "folder": "/absolute/path/to/rules" },
    { "file": "/absolute/path/to/repo/CLAUDE.md" },
    { "builtin": "baseline" }
  ],
  "personal_overrides": {},
  "models": {
    "agents": { "planner": "sonnet", "auditor": "opus" },
    "coder": "sonnet",
    "plugin_file_coder": "opus",
    "coder_after_rejection": "opus",
    "fable_available": null
  },
  "limits": { "parallel_coders": 5, "task_tokens": null, "log_retention_days": null },
  "test_readable_folders": ["~/.local/share/pnpm/store", "~/.nvm"],
  "policy": { "engine": "conftest", "path": "/absolute/path/to/your/decisions/repo/policy" }
}
```

Every key in this file is a row of the generated key reference in the plugin [README](../README.md#key-reference): what it governs, whether it is a starter setting or an override, its type, its allowed values, its default and an example. `/daedalus:setup` writes the four starter keys; `models`, `limits`, `test_readable_folders` and `policy` are overrides, left out until you set one. The reader refuses an unknown key at every level and lists the valid names. The doctor checks `local_docs_folder`, `coding_rules`, `models`, `policy` and `personal_overrides`.

- `local_docs_folder`: an absolute path to a docs folder kept elsewhere on this machine, such as a clone of a separate decisions repository. When set, the decisions file the manifest names lives there instead of in the project's own docs folder. A relative path or a symlink is refused. A folder inside the project is allowed, such as a git-ignored clone.
- `coding_rules`: with none declared, the Standards Packet is empty, the auditor judges against the spec only, and the doctor offers the baseline rules on an `OPT` line.
- `limits.log_retention_days`: a whole number of at least 90 (AU-11). When a new session writes its first record, each older log is deleted under its own lock, and one `AuditRotation` record in the new session's chain names every deleted session with its final sha256 and record count. A log a running train still writes, or one a summary still names, is kept. `null`, the default, keeps every log.
- `models.coder`, `models.plugin_file_coder` and `models.coder_after_rejection`: pick the model for each coding agent a run starts. A unit runs on `models.coder`, sonnet unless you change it. A unit that changes a file under `agents/`, `skills/`, `hooks/` or `scripts/checks/`, or one of the three jail files, runs on `models.plugin_file_coder`. A unit refused twice by its verifier goes to a fresh coding agent on `models.coder_after_rejection`.
- `models.agents`: an object from an agent name the catalog lists to `sonnet`, `opus`, `haiku` or `fable`. For example, `"agents": { "planner": "sonnet" }` inside `models` runs the planner on sonnet while every other agent keeps the model its agent file names. Inside a run the coding agent takes its model from the `models.coder` keys instead.
- `test_readable_folders`: folders outside the project that a coder's test runner needs, such as the pnpm package store and a Node.js install. The kernel wrapper lets a runner such as `pnpm test`, `vitest run` or `node --test` read those folders and run programs from them, and never write there; any other command gets no such grant. A `~/` path is expanded to your home folder. A path that holds or sits inside a credential store, such as `~/.ssh` or `~/.aws`, refuses the config with a `Next:` line (0164). Installing packages stays with you: a coder's `pnpm install`, `npm ci` or `yarn add` is refused.

### The decisions file

A run records decisions only in the file `docs.decisions_filename` names in `service-manifest.json` (0247). The file lives in the project's docs folder, `docs.folder`, or in `local_docs_folder` when this checkout's config sets it. Nothing is searched for by a usual name: with no file named, no decision is recorded, no step asks about one, and the audit phase ends with no ledger step. A named file that does not exist yet is created as a table on its first decision; its folder must already exist, or the append stops with a `Next:` line.

`append_ledger.py` reads the file's layout from the file itself, in one of two formats.

`markdown-table-row`: a table whose header has an `Id` cell, with a separator row directly under it. Column 1 is `Id` and column 2 is `Date`; the remaining columns are yours. The sequence is the highest leading number of any `Id` cell in any such table (`last-row-id`), and the id pattern is `{seq:04d}-{repo}-{type}`. A new file is created as this table:
```markdown
| Id | Date | Ruling | Supersedes | Follow-ups |
|---|---|---|---|---|
| 0001-SVC-PLT | 2026-01-01 | First ruling. | None | None |
```

`heading-entry`: one `## Entry N` section per ruling, id pattern `{seq}`. The sequence is the `N` of the last `## Entry N` heading in the file (`last-row-id`):
```markdown
## Entry 7 - 2026-01-02T00:00:00Z

Seven.
```
A headings file that starts with a `---` block holding `sequence_id: 7` keeps its sequence there instead. The `---` must be the file's first line; a file with anything above it is not read as frontmatter.

`docs.git_branch`, an override, names the branch the decisions file is written on. With it set, `append_ledger.py` reads the branch of the checkout that holds the file from its `HEAD` file, and runs no git command. When that checkout is on another branch, the append and the probe stop with a `Next:` line naming both branches; Daedalus never switches it. It cannot be set together with `local_docs_folder`, because a run branches that folder.

### coding_rules entries

Each entry is an object holding exactly one key. The run reads only these entries, and cites each rule as `source:line`.

- `folder`: a directory of rule files. Example: `{ "folder": "/absolute/path/to/rules" }`
- `file`: one file. Example: `{ "file": "/work/my-service/CLAUDE.md" }`
- `builtin`: a rule set shipped inside the plugin, resolved to `<plugin>/packs/<name>/`. Daedalus ships one, `baseline`: five baseline checks (no hardcoded secrets, no wildcard access grants, TLS 1.2 or newer, encryption at rest, no personal data or key material in logs) plus the Daedalus cloud security standards. Example: `{ "builtin": "baseline" }`

### The decisions-in-force summary

`standing-rules.md` beside the decisions file is the summary of decisions in force, which `scripts/standing_rules.py` writes from it (see the standing-rules backfill file below). The plan and brainstorm skills hand its path to the planner when it exists. When it is absent, the planner cites no standing rule and the doctor prints an `OPT` line naming the script.

### What the probe prints

    python3 <plugin>/scripts/append_ledger.py --probe

Run it from the repo. A named file prints `ledger: <path> (manifest, <format>, seq=<n>, ids=<shape>)`, for example `ledger: /work/my-service/docs/decisions.md (manifest, markdown-table-row, seq=2, ids=plain)`; a named file not written yet reads `seq=0, ids=plain`. The shape is `ids=plain` when the last id is a plain number such as 0002, and for an empty table, a heading-entry file or a file not written yet. It is `ids=three-part` when the last id carries a repository code and a type, such as 0002-SVC-PLT. An append to an `ids=plain` file takes no `--repo` and no `--type`; an append to an `ids=three-part` file takes both. No file named prints `decisions: no decisions file is named, so no decision is recorded.` with a `Next:` line.

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

A pack is a folder holding `pack.json` and `controls.json`. The folder name is the pack id. Daedalus ships four packs under `<plugin>/packs/frameworks/`:

- `aws-default`: AWS hardening controls. It is read by default.
- `nist-distilled`: a NIST SP 800-53 checklist. It is read by default.
- `stripe-default`: Stripe key handling, webhook signatures and server-set prices. It is read by default, but only when a change touches a path its triggers name: a file with `stripe` in its name, a `.env` file, `package.json` or an npm lockfile.
- `cost-tier`: cost rules for Terraform on AWS, such as service-default keys, on-demand tables and log retention. It is off by default. To read it, add `"extra_builtin": ["cost-tier"]` to the `compliance_rules` group.

`pack.json` is one JSON object with these keys:

- `id`: the pack name, lowercase letters, digits and dashes, 1 to 40 characters.
- `version`: three dot-separated numbers, such as `1.0.0`.
- `source`: `daedalus` for a shipped pack, else the file the importer read.
- `license`: one line, such as `GPL-3.0-or-later`, `public domain (17 U.S.C. 105)` or `operator-licensed, ids only`.
- `pinned_on`: the `YYYY-MM-DD` date the pack was written.
- `sha256`: the 64 lowercase hex SHA-256 of `controls.json`.
- `default` (optional, shipped packs only): `false` keeps a shipped pack off until `compliance_rules.extra_builtin` names it. Absent means `true`.
- `triggers` (optional, shipped packs only): a list of 1 to 32 path globs, such as `**/*stripe*`. The audit reads the pack only when a changed path matches one, and then the auditor judges the change against it even when no unit touched IAM, keys or infrastructure. Matching ignores letter case, and a leading `**/` also matches a file at the project root. Absent means the pack is read whenever the specialist runs.

A pack under `compliance_rules.folder` that holds `default` or `triggers` fails its check.

`controls.json` is `{"schema": "daedalus-controls/1", "controls": [...]}`. Each control holds:

- `id` (required): unique in the pack, such as `AWS-IAM-1`.
- `service` (required): one of `iam`, `s3`, `kms`, `cloudtrail`, `vpc`, `lambda`, `dynamodb`, `apigateway`, `ec2`, `ecs`, `ecr`, `logs`, `payments` or `any`.
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

The `compliance_rules` group of `service-manifest.json`, an override, picks the packs a train reads:

- `compliance_rules.folder`: a project-relative folder; each subfolder of it holding `pack.json` is one pack. A linked subfolder is skipped.
- `compliance_rules.use_builtin`: `true` (the default) also reads the shipped packs that are on by default; `false` reads only the packs under `compliance_rules.folder` and the packs `compliance_rules.extra_builtin` names.
- `compliance_rules.extra_builtin`: a list of shipped pack ids to read even though they are off by default, such as `["cost-tier"]`. An id Daedalus does not ship stops the train, and the doctor names it.

With no `compliance_rules` group, only the shipped packs are read. The manifest reader refuses any other key in the block.

The doctor prints one line per pack, after the framework cache lines:

- `OK   framework pack <id>: <version>, <n> controls` for a pack that loads.
- `MISS framework pack <id>: <problem>. Next: <action>` for each problem; the run fails. For a pack built from a NIST catalog, the action is the two commands above.
- `MISS framework packs: <folder> is not a folder. Next: create it or remove compliance_rules.folder from service-manifest.json`; the run fails.
- `OLD  framework pack <id>: pinned <date> (<days> days). Next: <action>` once `pinned_on` is more than 90 days old. The action re-runs the importer, or updates the plugin for a shipped pack. The run still passes.

## In each target repository

### service-manifest.json (repo root), optional **(checked)**

Example:
```json
{ "commands": { "unit_test": ["pytest -q", "pnpm vitest run"], "typecheck": ["mypy src", "pnpm tsc --noEmit"],
                "lint": "ruff check ." },
  "docs": { "folder": "docs", "decisions_filename": "decisions.md", "reading_level": "standard" },
  "checks": { "secret_scan": false, "online_advisory_lookup": true, "terraform_format": true,
              "terraform_validate": false },
  "prohibited_writes": { "paths": [], "file_types": [] },
  "code_review_exemptions": { "folders": ["assets/", "public/models/"],
                              "file_types": [".glb", ".gltf", ".png", ".ktx2", ".wav", ".ogg", ".wgsl", ".spv"] },
  "packages": { "allowed_installers": ["npm"] },
  "local_testing": { "url": "http://localhost:5173", "instructions": "The scene loads and the player can move." },
  "code_areas": { "handlers": "src/handlers/", "models": "src/models/", "infra": "infra/", "contracts": "contracts/" } }
```
This file holds only Daedalus's settings, so a key such as a service name, a purpose line or a language is refused (0248). Every key in this file is a row of the generated key reference in the plugin [README](../README.md#key-reference), marked starter or override. The manifest reader refuses an unknown key at the top level and inside every group, and names the valid keys; there is no alias for an old name. The doctor's two gh lines are a `MISS` in repository scope and `OPT` in folder scope (0074); scope is worked out from git, never read from this file. The `compliance_rules` keys are described under "Framework control packs" above, and the decisions keys under "The decisions file". `code_areas`, an override, names the project's file areas: `/daedalus:plan` pastes it into the planner's prompt, and the planner cuts units along these areas.

`prohibited_writes` adds paths a coder may not write (0054-DAE-PLT). Each `paths` entry is relative to the repository root, uses forward slashes, and holds no leading slash, `..` or glob characters. An entry ending in a slash covers that folder and everything under it; an entry without one names one file. Each `file_types` entry starts with a dot and covers every file name ending in it. Matching ignores case. The jail reads this file from the main checkout, never from a coder's worktree. A manifest that is not valid JSON, or whose `prohibited_writes` has the wrong shape, refuses every coder write until it is fixed, and the doctor reports it as a `MISS`. When the file is present, the doctor's line counts the entries: `OK   service-manifest.json: prohibited_writes <n> paths, <m> file types`. When `commands.typecheck` is declared, the doctor prints it on an `OPT` line and does not run it; it runs the command only when you pass `--run-typecheck` to `daedalus_doctor.py` yourself, because that flag executes a command the repository chose (0076).

Commands as lists. Each of `commands.unit_test`, `commands.typecheck` and `commands.lint` takes one command or a list of commands, so a Python and TypeScript project can declare `["pytest -q", "pnpm vitest run"]`. A coder may run each entry exactly as written. An empty list, or a list holding anything but non-empty strings, is refused. The doctor prints one `OPT` typecheck line per declared typecheck command, and one line with the counts: `OK   commands: 2 unit test, 2 typecheck, 1 lint`.

Asset files. The `code_review_exemptions` group keeps models, textures, sounds and shader binaries out of the diffs the verifier and the auditor read, and out of the secret scan. `folders` names asset folders and `file_types` names asset file endings. A file with a source ending, such as `.py`, `.ts`, `.js`, `.json`, `.env`, `.sh` or `.md`, is never kept out, wherever it sits and however large it is. A `file_types` entry with a source ending is refused. `report_over_bytes`, an override, lists each kept-out asset file larger than it by name and size, so the judges know it changed. Each run prints the exclusion with `daedalus_train.py assets --repo <repo> --base <sha> --tip <branch>`: `Assets: none`, or `Assets: -- . ':(exclude)assets/' ...` and an `Assets log-opts:` line for the secret scan. Then come one `Over size: <file> (<n> bytes)` line per large asset file and one `Asset root source: <file>` line per source file under an asset folder. The judges copy those lines, so nobody composes the exclusion by hand. Keep source files out of asset folders. A source file under one stays in every diff, the auditor reports a change to it as a finding, and the doctor prints one `OPT  asset root source file <path>` line for each one it finds.

Operator checks and the local site. A coder never starts a dev server and never writes a test that needs a GPU or a browser. The plan lists such checks on the unit's line as `operator_checks: the scene loads; the player can move`, at most ten. Set `local_testing` to the site you host on your own machine: its `url` must be `http` or `https` on `localhost` or `127.0.0.1`, and `instructions` says what to look at. Both members are required, so `/daedalus:setup` saves the group whole. After the verifier passes a unit, the session asks you each check in plain words: open the url, do the check, and answer pass, fail or skip. It also asks the `local_testing` check when the unit changes web code. A fail counts as one rejection of the unit, the same as a rejection by the checker, and the session records it with `daedalus_train.py refuted --repo <repo> --unit <unit id> --operator-check "<check text>"`. The first rejection goes back to the unit's coder as a fix, and later ones follow the `models.coder_after_rejection` note above. A skip is recorded with your reason. Daedalus never starts, polls or fetches the site. The doctor prints `OK   local_testing: <url>; the verify step asks you to open it and check: <instructions>` when the group is set.

Package installs. No agent runs a package install, update, add or resolve command: the jail refuses every one of them, for pip, uv, poetry, pdm, pipenv, pipx, npm, pnpm, yarn, bun, corepack, deno, cargo, go, gem, bundle, composer and `terraform init -upgrade` (0196). A coder may run one frozen, scripts-off install when `packages.allowed_installers` names its ecosystem. `npm` covers `npm ci --ignore-scripts`, `pnpm install --frozen-lockfile --ignore-scripts`, `yarn install --immutable --mode=skip-build` (or `yarn install --frozen-lockfile --ignore-scripts` for classic yarn) and `bun install --frozen-lockfile --ignore-scripts`. `python` covers `pip install --require-hashes --only-binary=:all: -r <file>` (or `--only-binary :all:`), the same through `python3 -m pip`, `uv sync --frozen --no-build` and `uv pip sync --require-hashes --no-build <file>`; the binary-only flags keep a source package's build script from running. `cargo` covers `cargo fetch --locked` and `cargo build --locked` (or `--frozen`), and `go` covers `go mod download`. The form must be the first word of its command, so a wrapper such as `pnpm exec` or a `VAR=value` prefix such as `GOFLAGS=-mod=mod` refuses it; the safe prefixes `CI`, `NODE_ENV`, `TZ`, `LANG`, `LC_ALL` and `PYTHONDONTWRITEBYTECODE` are allowed. Each form also admits a short list of extra flags, and any other flag refuses it: `npm ci` admits `--no-audit`, `--no-fund`, `--prefer-offline`, `--offline` and `--silent`; `pnpm install` admits `--offline`, `--prefer-offline` and `--silent`; `yarn install` admits `--offline`, `--silent` and `--non-interactive`; `bun install` admits `--silent` and `--no-progress`; `pip install` admits `--no-deps`, `-q`, `--quiet`, `--no-input` and `--disable-pip-version-check`; `uv sync` admits `--no-install-project`, `--no-dev`, `--all-extras`, `--offline`, `-q` and `--quiet`; `uv pip sync` admits `--offline`, `-q` and `--quiet`; `cargo fetch` and `cargo build` admit a leading `+toolchain` word, such as `+stable`, and `--offline`, `--release`, `-q`, `--quiet`, `--workspace` and `--all-targets`; `go mod download` admits `-x` and `-json`. poetry, pdm, pipenv, pipx, deno, gem, bundle and composer have no accepted form, so you run those yourself. The frozen form runs bare, never under the kernel wrapper, because it reaches the registry. Leave `allowed_installers` empty, the default, to keep every install with you. A command that downloads a package and runs it is refused the same way: `npx`, `pnpx`, `npm exec`, `pnpm dlx`, `yarn dlx`, `bunx`, `bun x`, `npm create`, `npm init <initializer>`, `pnpm create`, `yarn create`, `bun create`, `uvx`, `uv tool run`, `uv run` with `--with`, `--with-requirements` or `--with-editable`, `pipx run` and `deno run` on a remote module. A plain `uv run <command>`, `cargo test` and `go test` can still resolve and fetch packages; they are test commands, so on a machine where the kernel rules line reads OK they run under the kernel wrapper, which opens no network socket. A coder runs a project tool from its installed copy instead: `pnpm exec <bin>`, `npm exec --no-install <bin>` (or `npx --no-install <bin>`), `yarn run <bin>`, `bun run <bin>`, `node_modules/.bin/<bin>`, `.venv/bin/<bin>` or `python3 -m <module>`.

Release age. The auditor reads the publish date of every package version a change adds or updates, in every ecosystem, and fails a version younger than `packages.minimum_age_days`, seven days by default (0197). The date comes from the registry through the web lookup, or from an advisory export you name in the task. With the lookup off and no export, the auditor cannot check advisories or ages, and the audit files that as a blocking finding and asks you how to clear it (0196). You may set the age as low as `0`, but any value below seven needs `packages.minimum_age_reason`, one line of at least twenty characters; without it the manifest reader and the doctor refuse the file. A security fix newer than the age still fails; track it as a risk and upgrade once it comes of age. The doctor prints `OK   packages: allowed installers <ecosystems or none>; minimum age <n> days`, with the reason when the age is lowered.

Coders cannot edit this file (enforced for file tools and the common copy/edit commands; a script the coder writes and runs is not blocked yet).

### contracts/ (directory), optional **(checked)**

Holds your own interface files, such as `openapi.yaml`, `events/*.schema.json` and `errors.yaml`. May be empty to start; the doctor shows an `OPT` line while the folder is missing. Coders cannot write here (enforced for file tools and the common copy/edit commands; a script the coder writes and runs is not blocked yet).

A Build Train writes its contract here only when config.json sets no `local_docs_folder`; with `local_docs_folder` (the `<charter_root>` here) the contract goes to `<charter_root>/specs/<name>.md` instead. The contract-spec agent saves the Locked Contract Packet to `contracts/<name>.md`, where `<name>` is a short name of lowercase letters, digits and hyphens. The lock command (`daedalus_workspace.py lock`) commits it on the integration branch `daedalus/<train-id>` as `Lock contract <name> v<packet_version>` before any coder starts. Each revision is committed as `Revise contract <name> v<N>`. The file holds the packet as contract-spec wrote it: `packet_version=<n>`, the target services, the wire contract and the ledger invariants.

Read the contract during a train, but do not edit it. Every coder brief names the file with its sha256, and a coder refuses to start when the hash does not match. A coder that reports a different hash stops the train. A revision comes only from contract-spec, when a coder's contract question needs one.

### .gitleaks.toml (repo root), optional **(checked)**

Minimal:
```toml
[extend]
useDefault = true
```
gitleaks reads this file, not Daedalus. The Push Train runs `gitleaks detect --redact --log-opts=<base sha>..daedalus/<train-id>` from the repository root, and gitleaks picks up `.gitleaks.toml` from the folder it scans. The scan runs only when `checks.secret_scan` is `true` in `service-manifest.json`; the Push Train then stops without the binary (0069-DAE-PLT). With the scan off, the default, the Push Train runs no scan and the doctor's gitleaks line is an `OPT` line. The doctor checks only that the file exists.

| Key | What it governs | Type | Allowed values | Default | Example |
|---|---|---|---|---|---|
| `[extend]` `useDefault` | Whether gitleaks keeps its own built-in rules and adds yours on top | boolean | `true` or `false` | gitleaks's own default | `true` |

Every other key, such as your own rules or an allowlist for a known false positive, is gitleaks's own format: https://github.com/gitleaks/gitleaks#configuration.

### Project train definitions

When `service-manifest.json` sets `custom_workflows_folder`, an override, to a project-relative folder, a train named `<name>` is looked up first as `<custom_workflows_folder>/<name>.json`, then in the plugin's own `trains/` folder (0073-DAE-PLT). A project definition's brief templates resolve beside the definition file, and a definition whose real path leaves the project is refused. Check a definition with:

    python3 <plugin>/scripts/validate_train.py <custom_workflows_folder>/<name>.json

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
| `agent` | Who runs the stage | string | `"main"` for a step the runner runs itself, or the name of an agent file in the plugin | `"coder"` |
| `scope` | What the agent is told, where it may write and how it may reply | object | Exactly `told`, `touch` and `reply`, below | see below |
| `proof` | The command that proves the stage passed | object | Exactly `script`, `exit` and `records`, below | see below |
| `on_fail` | Where each failing outcome or reply line goes | object | Each key is a failing exit outcome or a reply line of the stage; each value is a route, below | `{"[STATUS: YIELD_WEB]": "consult:web-researcher"}` |
| `verifies` | What the stage checks, in words | string | Non-empty text | `"the merged tip passes its tests"` |
| `when` | A condition that skips the stage when it is off | string | `features.<name>` with a field of the run's recorded features (`secrets_scan`, `scrub_file`, `ledger`, which is on when a decisions file is named, `dependency_web_lookup`, `terraform_tools` or `terraform_validate`), or a field an earlier stage records | `"features.ledger"` |
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

The backfill file is one JSON object holding four required keys and an optional `names`; any other key is refused:

| Key | What it governs | Type | Allowed values | Example |
|---|---|---|---|---|
| `relations_from` | The first ledger row that carries its own relations; every earlier row takes its relations from `relations` | string | A ledger id that is a row of the ledger | `"0090-DAE-PLT"` |
| `names_from` | The first ledger row whose Ruling cell starts with its name as its first sentence; earlier rows take their name from `names`, else from the first clause of their Ruling cell | string | A ledger id that is a row of the ledger | `"0094-DAE-PLT"` |
| `areas` | The area each ruling in force is filed under | object | Each key is a ledger id; each value is one of the eight area names below. Every ruling in force needs one, and an id that is not in the ledger is refused | `{"0004-DAE-PLT": "the ledger and charter"}` |
| `relations` | What each row before `relations_from` supersedes and amends | object | Each key is a ledger id before `relations_from`; each value is an object holding exactly a `supersedes` list and an `amends` list of earlier ledger ids | `{"0012-DAE-PLT": {"supersedes": ["0007-DAE-PLT"], "amends": []}}` |
| `names` | The hand-written name of a ruling before `names_from`, used in its heading and wherever it is named (0181) | object | Optional. Each key is a ledger id before `names_from` whose ruling is in force; each value is a name of two to five words with no period. A row left out is named by its first clause | `{"0004-DAE-PLT": "Ledger declared per project"}` |

From `relations_from` on, a row reads its own Supersedes cell: a sentence starting `Supersedes: ` or `Amends: ` lists the ids it supersedes or amends. A row from `relations_from` on that also appears in `relations` is refused.

The eight area names, exactly as written: `composition and phases`, `planning and dispatch`, `the jail and grammars`, `the audit log and proofs`, `the ledger and charter`, `GitHub and release`, `the project files`, `operator interaction`.

### Coder write boundary

A coder writes only inside its own unit worktree, which the Build Train creates at `<repo>/.claude/worktrees/<train-id>-<unit-slug>`. Inside it, every path is writable except the protected ones (0054-DAE-PLT): `contracts/`, `.github/` (workflows, CODEOWNERS, dependabot and templates), `.claude/`, `service-manifest.json`, the repository's own decisions file when it lives inside the repository, and every `prohibited_writes` entry in `service-manifest.json`. A write to a folder that holds a protected path, such as `rm -r docs` when the ledger is `docs/decisions.md`, is refused too. A refused write names the path and says whether the rule is built in or comes from the service manifest's prohibited writes.

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

An agent file for a judge, any file under `agents/` whose frontmatter reads `shape: judge`, must carry a method and a rubric. List the judges from the plugin root of a clone; it needs no credential:

    grep -l "^shape: judge" agents/*.md

Each line names one judge's agent file. Empty output means no file declares the judge shape. `No such file or directory` means the command ran outside the plugin root. An agent file for an actor stays thin, because its tools and the hooks bound what it can do.
