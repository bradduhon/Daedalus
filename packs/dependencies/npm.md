<!-- Copyright (c) 2026 Brad Duhon. SPDX-License-Identifier: GPL-3.0-or-later -->

# npm rulebook for the dependency auditor (0189, 0192)

The audit phase names this file in the dependency auditor's dispatch when the merged diff changes `package.json`, `package-lock.json`, `pnpm-lock.yaml` or `yarn.lock`. Judge these rows beside DEP-1 to DEP-7, with the same rubric: PASS, FAIL or N/A per changed dependency, with `file:line`.

## Rows
- DEP-NPM-1: a lockfile (`package-lock.json`, `pnpm-lock.yaml` or `yarn.lock`) is committed beside each changed `package.json`, and the diff changes it in step: every dependency added, removed or re-ranged in `package.json` has its lock entry change in the same diff. A `package.json` change with no lockfile change, or two lockfiles of different managers for one package, is a FAIL.
- DEP-NPM-2: no dependency source is `git+`, `git:`, `github:`, `file:`, `link:` or a plain `http:` or `https:` URL in place of a registry version. Such a source is a FAIL, because it skips the registry's integrity hash and can change under the same name.
- DEP-NPM-3: a new dependency that runs an install script (`preinstall`, `install` or `postinstall`, marked `hasInstallScript` or `requiresBuild` in the lockfile) is a FAIL unless the diff names why in a row the operator can see, such as a pnpm `onlyBuiltDependencies` entry or a note in the change. An install script runs code on every machine that installs the package.
- DEP-NPM-4: when the project sets a release-age cooldown (pnpm `minimumReleaseAge`, or an equivalent setting in `.npmrc`, `pnpm-workspace.yaml` or the package manager's config), give one PASS line that names the setting and its value and states both sides of the trade; with no cooldown set, the row is N/A. The cooldown keeps out a package version published minutes ago by a hijacked account. It also holds back a security fix newer than the cooldown, so the project runs a version with a published advisory for that window. A changed dependency whose fix is held back by the cooldown is a FAIL that names the advisory and the date the cooldown lifts.
