<!-- Copyright (c) 2026 Brad Duhon. SPDX-License-Identifier: GPL-3.0-or-later -->
# What your project needs for daedalus

Every file and setting daedalus reads, with the smallest example that works. `/daedalus:doctor` checks the ones marked below, optional ones included; an optional one that is absent passes. Each marked heading or key carries **(checked)**.

## In the repo's `.claude/daedalus/` directory

`<repo>` is the main working tree of the git repository you run Claude Code in; every worktree shares it (0010-DAE-PLT). The first hook creates `<repo>/.claude/daedalus/` (mode 0700) and a `.gitignore` inside it holding `*`. `config.json` is optional. Without it the defaults apply: no `charter_root`, no `standards_sources`, no `policy`, and the ledger probe below finds the ledger. Create it there from your own shell when you need any of those.

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
| `standards_sources` **(checked)** | Directories or files holding your rules. `kind` is `rules-dir` or `file`. | The Standards Packet is empty and the auditor judges against the spec only |
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

Each entry has a `kind` and a `path`. The standards specialist reads only these entries, and cites each rule as `source:line`.

- `rules-dir`: a directory of rule files. Example: `{ "kind": "rules-dir", "path": "/absolute/path/to/rules" }`
- `file`: one file. Example: `{ "kind": "file", "path": "/work/my-service/CLAUDE.md" }`

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

### NIST catalog (`<cache>/frameworks/nist/`)

Run the refresh script from your own shell. It uses the network:

    python3 <plugin>/scripts/refresh_nist_oscal.py

It downloads the NIST SP 800-53 rev5 OSCAL catalog from `usnistgov/oscal-content` on GitHub and writes two files:

- `catalog.json`: the catalog itself.
- `manifest.json`: `catalog_file` (`catalog.json`), `catalog_sha256`, `revision` (the catalog's own version), `pinned_on` (UTC date), `upstream_commit` (the oscal-content commit that last changed the file, or `null` when the GitHub API lookup fails or the source is not oscal-content `main`) and `source_url`.

With no `--dest`, the files go to `<cache>/frameworks/nist/`, using the same lookup as `--print-cache-dir`. `--dest <dir>` writes elsewhere. `--source-url <url>` takes another `https` URL on `github.com`, `raw.githubusercontent.com` or `api.github.com`, with no user name, query, fragment, `.` or `..` segment, space or control character. The script refuses:

- a redirect that breaks the same URL rules;
- a response over 64 MiB;
- a download that is not a JSON object with a printable `catalog.metadata.version` of 64 characters or fewer (or a top-level `metadata.version` when the file has no `catalog` key);
- a symlink anywhere from the cache directory down to the target directory (with `--dest`, from its first existing parent down), or at `catalog.json`, `manifest.json` or `.refresh.lock`.

Every failure exits 1 with a `Next:` line. A run holds `.refresh.lock` in the target directory, so a second run waits up to 60 s for it and exits 1 if it is still held. A failure before the files are replaced leaves the previous pair in place. A run killed between the two replaces leaves a new catalog with the old manifest, and the specialist reports `CACHE_INVALID` until you run the script again. Run it again whenever you want a newer catalog; the nist specialist notes a `pinned_on` older than 90 days.

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

### service-manifest.json (repo root) **(checked)**

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
A later Daedalus release reads missing flags as the stricter value. Coders cannot edit this file (enforced for file tools and the common copy/edit commands; a script the coder writes and runs is not blocked yet). In that release, a change goes through contract-spec and the ledger.

### contracts/ (directory) **(checked)**

Holds `openapi.yaml`, `events/*.schema.json`, `errors.yaml`. May be empty to start. Coders cannot write here (enforced for file tools and the common copy/edit commands; a script the coder writes and runs is not blocked yet).

### .gitleaks.toml (repo root) **(checked)**

Minimal:
```toml
[extend]
useDefault = true
```
The Push Train runs `gitleaks detect` over every commit on the train branch before it pushes, and stops without the binary.

### src/ and tests/

The only directories a coder may write, and only inside its own unit worktree, which the Build Train creates at `<repo>/.claude/worktrees/<train-id>-<unit-slug>`. A later Daedalus release reserves `tests/adversarial/` for the boundary tester; today repo-coder may write anywhere under `tests/`.

## In your user settings

`/daedalus:setup` merges `settings.recommended.json` from the plugin into `~/.claude/settings.json` once `bwrap` and `socat` are on PATH; while either is missing it writes nothing. It adds missing keys, appends missing deny entries, and never overwrites a value you set. The merge enables the sandbox, denies the credential stores to the sandbox and to the Read tool, denies writes to the plugin cache directory, and sets two prompt cache settings. All of it is optional: without it the doctor reports `sandbox: off`, the Build Train runs and says so in its summary, and the Push Train refuses. The Build Train creates its own coder worktrees from the integration branch, and the jail keeps every Daedalus agent from starting agents, so neither needs a setting.

User-level sandbox settings cannot name `<repo>/.claude/daedalus/`, since it differs per repo. Instead, the jail refuses tool writes and the known Bash write routes there; the OS sandbox does not cover the repo-local directory. The `*` gitignore marker keeps it out of git, and the hooks refuse to run when the directory is a symlink, is tracked by git, or holds a marker other than `*`.

### Settings

- `sandbox.enabled` **(checked)** is `true`. The doctor reads `~/.claude/settings.json`, then the repo's `.claude/settings.json` and `.claude/settings.local.json`; the last one that sets it wins. Its `sandbox` line reads `on`, `off` or `configured-unavailable` (enabled, but `bwrap` or `socat` missing).
- `sandbox.failIfUnavailable` is `true`. If the sandbox cannot start (no `bwrap` or `socat` on PATH), Bash commands do not run at all. The doctor checks for both tools, and `/daedalus:setup` writes nothing while either is missing.
- `permissions.deny` holds Read rules for `~/.ssh/**`, `~/.aws/credentials`, `~/.gnupg/**`, `~/.config/gh/**` and `~/.claude/.credentials.json`. The jail refuses the same stores, all of `~/.aws` included, whether or not you merge these settings.

### Test-only

`DAEDALUS_LIVE_TEST=1` enables the `daedalus-probe` agent namespace that this repo's live tests use. Do not set it in normal use.

## Reviewing changes to Daedalus

A finding about git or file state is closed by a script change and a script test, never by a skill sentence.

An agent file for a judge (the nist and cis specialists and the security auditor) must carry a method and a rubric. An agent file for an actor stays thin, because its tools and the hooks bound what it can do.
