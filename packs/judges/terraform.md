<!-- Copyright (c) 2026 Brad Duhon. SPDX-License-Identifier: GPL-3.0-or-later -->

# Terraform rulebook for the auditor (0132, 0158, 0164, 0186)

The audit phase names this file in the auditor's dispatch when the merged diff touches a `.tf` or `.tfvars` file, with the changed Terraform files and a line `Terraform tools: on` or `Terraform tools: off`. Read the files and run two Terraform checks; never change infrastructure. Write each row's verdict in the reply's `## Compliance` section.

## Commands
The jail admits only these two Terraform commands, each naming its module folder with `-chdir=` (0132): `terraform -chdir=<absolute module folder> fmt -check` and `terraform -chdir=<absolute module folder> validate`. The folder lies inside the project.
Run each one under the kernel wrapper, which keeps its writes in a unit worktree and opens no network socket: `<plugin root>/scripts/daedalus_confine.py --unit <unit worktree> -- terraform -chdir=<absolute module folder> validate`, the unit worktree a folder under `<repo>/.claude/worktrees/` (0164). The hook admits that wrapped form and the two bare forms above, refuses every other form, and refuses all of them while `features.terraform_tools` is false.
It refuses `validate` unless `features.terraform_validate` is true (0158), because validate starts the provider programs under `.terraform/providers`.
Never run `init`, `plan`, `apply`, `destroy`, `import`, `state`, `taint`, `refresh` or any other Terraform subcommand.
No shell redirects (`>`, `<`, `2>&1`, `2>/dev/null`); the Bash tool already returns stderr.

## Binary check (before any tool run)
1. With `Terraform tools: off`, run no Terraform command; judge by reading the files, and mark TF-1 and TF-2 N/A with the reason `terraform tools off in the service manifest`.
2. Read `<repo>/service-manifest.json` with the Read tool and find `features.terraform_validate`. When the file, the `features` object or the key is absent, or the value is anything but `true`, run no `terraform validate`, and mark TF-2 N/A with the reason `terraform validate off in the service manifest` (0158). `fmt -check` still runs.
3. With the tools on, before the first Terraform command, run `find /usr/local/bin /usr/bin /bin /opt/homebrew/bin /snap/bin -maxdepth 1 -name terraform`.
4. An empty result means the binary is missing: run no Terraform command, and write TF-0 as `WARN terraform binary missing: fmt -check and validate not run` in the section. A missing binary is a warning, never a FAIL and never a blind failing call. A binary outside those folders reads as missing too, so the warning names the folders searched.
5. A Terraform run the hook refuses is a WARN row naming the refusal, never a FAIL.

## Method
1. Run `git -C <repo> diff <diff base>...<branch> -- <each changed Terraform file>` and read all of it.
2. List each module folder the diff touches.
3. With the binary present and the tools on, run `terraform -chdir=<module folder> fmt -check` once in each module folder, and, only when `features.terraform_validate` is `true`, `terraform -chdir=<module folder> validate` after it, the folder written as an absolute path. A validate error that the folder is not initialized is a WARN row; never initialize it.
4. Give each row below PASS, FAIL, WARN or N/A, with `file:line`.

## Rows
- TF-0: the terraform binary is present (WARN when missing).
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
