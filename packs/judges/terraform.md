<!-- Copyright (c) 2026 Brad Duhon. SPDX-License-Identifier: GPL-3.0-or-later -->

# Terraform rulebook for the auditor (0132, 0158, 0164, 0186)

The audit phase names this file in the auditor's dispatch when the merged diff touches a `.tf` or `.tfvars` file, with the changed Terraform files, a line `Terraform tools: on` or `Terraform tools: off`, and a line `Terraform binary: present` or `Terraform binary: missing` (184). Read the files and run the Terraform checks; never change infrastructure. Write each row's verdict in the reply's `## Compliance` section.

## Commands
The jail admits these Terraform commands, each naming its module folder with `-chdir=` (0132): `terraform -chdir=<absolute module folder> fmt -check`, `terraform -chdir=<absolute module folder> validate`, and, under the kernel wrapper only, `terraform -chdir=<absolute module folder> init -backend=false -input=false -lockfile=readonly` (184). The folder lies inside the project.
Run each one under the kernel wrapper, which keeps its writes in a unit worktree and its private temp folder and opens no network socket: `<plugin root>/scripts/daedalus_confine.py --unit <unit worktree> -- terraform -chdir=<absolute module folder> validate`, the unit worktree a folder under `<repo>/.claude/worktrees/` (0164). The wrapper runs the terraform the session PATH names and keeps its data folder in that temp folder, one per module folder (184). The hook admits the wrapped forms and the two bare forms `fmt -check` and `validate`, refuses every other form, and refuses all of them while `checks.terraform_format` is false.
It refuses `validate` and the wrapped `init` form unless `checks.terraform_validate` is true (0158), because both start the provider programs under the data folder.
Never run `plan`, `apply`, `destroy`, `import`, `state`, `taint`, `refresh`, any other `init` form or any other Terraform subcommand.
No shell redirects (`>`, `<`, `2>&1`, `2>/dev/null`); the Bash tool already returns stderr.

## Binary check (before any tool run)
1. With `Terraform tools: off`, run no Terraform command; judge by reading the files, and mark TF-0, TF-1 and TF-2 N/A with the reason `terraform tools off in the service manifest`.
2. Read `<repo>/service-manifest.json` with the Read tool and find `checks.terraform_validate`. When the file, the `checks` group or the key is absent, or the value is anything but `true`, run no `init` and no `validate`, and mark TF-2 N/A with the reason `terraform validate off in the service manifest` (0158). `fmt -check` still runs.
3. With the tools on, read the dispatch's `Terraform binary:` line; never search folders for the binary yourself (184).
4. `Terraform binary: missing`, or no such line, means no check can run: run no Terraform command, and write TF-0 as `FAIL terraform binary missing: fmt -check and validate not run; put terraform on the session PATH, or set checks.terraform_format to false in service-manifest.json`. File it as a blocking compliance finding, `round<n>/test_compliance_tf0_unjudged.py`, whose failure message names those two ways to clear it (184).
5. A Terraform run the hook refuses is a WARN row naming the refusal, never a FAIL.

## Method
1. Run `git -C <repo> diff <diff base>...<branch> -- <each changed Terraform file>` and read all of it.
2. List each module folder the diff touches.
3. With `Terraform binary: present` and the tools on, run `terraform -chdir=<module folder> fmt -check` once in each module folder, the folder written as an absolute path.
4. Only when `checks.terraform_validate` is `true`, run under the kernel wrapper, for each module folder, `terraform -chdir=<module folder> init -backend=false -input=false -lockfile=readonly` and then `terraform -chdir=<module folder> validate` with the same `-chdir` folder (184). Never run validate bare. An init error, such as a provider the lock file names that the wrapper cannot fetch, is a WARN row on TF-2 naming the error.
5. Give each row below PASS, FAIL, WARN or N/A, with `file:line`.

## Rows
- TF-0: the terraform binary is present (FAIL when missing with the tools on, 184).
- TF-1: `terraform fmt -check` passes in each touched module folder.
- TF-2: `terraform validate` passes in each touched module folder.
- TF-3: no secret, key, token or password literal in a `.tf` or `.tfvars` line.
- TF-4: each provider carries a version constraint, and each module source pins a version or ref.
- TF-5: state is remote with locking; no `.tfstate` file and no local backend is added.
- TF-6: IAM statements in the diff name no `*` action or resource without a stated reason.

## Rubric
- FAIL means the diff contradicts the row; give the `file:line` and the evidence.
- PASS needs an evidence line; never PASS on absence of evidence.
- WARN and N/A need a one-line reason.
