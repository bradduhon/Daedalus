# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# spec 3.3: the shared adversarial corpus; one test module per bypass class, rows assert a deny.
# pin C1 -> C6: never a row for git grep, git worktree list, git merge-base, git show | sed -n,
# the --test-runner pytest forms or an auditor write under the train's audit folder.
from __future__ import annotations

import shlex
from typing import Any

from tests.conftest import CFG
from tests.hook_chain import decide
from tests.payloads import _cred

CLASSES = (
    "brace_glob",
    "quoting",
    "symlinks",
    "env_expansion",
    "path_traversal",
    "nested_sessions",
    "wrapper_options",
)
# spec 3.3: the agents whose Bash grammar is widest; credential reads judge them all.
READERS = ("coder", "auditor", "framework-specialist")
CREDENTIAL = "credential path"
REPLY_KEY = "the train's reply key"
NESTED = "nested session"
OUTSIDE = "outside your unit worktree"
PROTECTED = "protected path"


# issue 80 (unit H1): env -S hides a write inside one word; {repo} is a repository a train marks.
H1_ENV_SPLIT = (
    "env -S 'touch {repo}/x'",
    "env -S'touch {repo}/x'",
    "env --split-string='touch {repo}/x'",
    "env --split-string 'touch {repo}/x'",
    "env --spl='touch {repo}/x'",
    "env -iS 'touch {repo}/x'",
    "env -u HOME -S 'touch {repo}/x'",
    "nice -n 5 env -S 'rm -rf {repo}/x'",
)
# issue 81 (unit H1): a shell -c body, flock's included, hides its write targets.
H1_SHELL_BODY = (
    "bash -c 'touch {repo}/x'",
    "sh -c 'touch {repo}/x'",
    "bash -lc 'touch {repo}/x'",
    "sh -ec 'rm -rf {repo}/x'",
    "bash --norc -c 'touch {repo}/x'",
    "bash --frobnicate -c 'touch {repo}/x'",
    "dash -c 'touch {repo}/x'",
    "setsid sh -c 'touch {repo}/x'",
    "flock /tmp/l -c 'touch {repo}/x'",
    "flock /tmp/l --command 'touch {repo}/x'",
)


def nest_bodies(command: str, levels: int, shell: str = "sh") -> str:
    # issue 81: the command inside `levels` shell -c bodies, each level quoted once more.
    for _ in range(levels):
        command = f"{shell} -c {shlex.quote(command)}"
    return command


# issue 81 (unit H1): bodies nested past the walk's depth cap of three fail closed.
H1_DEEP_BODY = (
    nest_bodies("touch {repo}/x", 4),
    nest_bodies("touch {repo}/x", 6, "bash"),
    "env -S " + shlex.quote(nest_bodies("touch {repo}/x", 3)),
)
# issue 82 (unit H1): one row per runner wrapper row, then options kept off a row.
H1_WRAPPERS = (
    "setsid -f touch {repo}/x",
    "chroot / touch {repo}/x",
    "ionice -c 3 touch {repo}/x",
    "taskset -c 0 touch {repo}/x",
    "flock -w 5 /tmp/l touch {repo}/x",
    "unshare --fork touch {repo}/x",
    "chrt -o 0 touch {repo}/x",
    "nsenter -t 1 -m touch {repo}/x",
)
H1_WRAPPERS_OFF_ROW = (
    "chroot {repo} touch /x",
    "unshare --root {repo} touch /x",
    "unshare -w {repo} touch x",
    "nsenter --wd={repo} touch x",
    "ionice --frobnicate touch {repo}/x",
    "taskset touch {repo}/x",
)
# issue 83 (unit H1): {other}/deep links to {repo}/sub, so deep/.. is {repo} on disk.
H1_SYMLINK = ("touch {other}/deep/../x", "mkdir {other}/deep/../y", "rm -rf {other}/deep/../x")
# issue 97 (unit H1): an icase pathspec names notes/a.md under another case; notes is excluded.
H1_ICASE = (
    "git add ':(icase)NOTES/a.md'",
    "git add ':(top,icase)Notes/a.md'",
    "git add ':(ICASE)nOtes'",
    "git commit -m m -- ':(icase)NOTES/a.md'",
    "git stash push -- ':(icase)notes'",
    "git add ':i:NOTES/a.md'",
    "git add ':/i:NOTES'",
    "git --icase-pathspecs add NOTES/a.md",
    "GIT_ICASE_PATHSPECS=1 git add NOTES/a.md",
    "git add ':(icase)NOTES/a.md' $(true)",
)
# SC-12 (fix round 1, finding 1): an rg whitelist glob reaches the hidden .claude folder.
FIX1_RG_GLOBS = (
    "rg -g .claude -g '*.key' -l . .",
    "rg --glob=.claude --glob='*.key' -l . .",
    "rg --iglob .claude --iglob '*.KEY' -l . .",
    "rg -g '.claude' -g 'reply-hmac.key' -n . .",
    "rg -g.claude -g'*.key' -l token",
    "rg -ig .claude -g '*.key' token .",
    "rg -g '{.claude,x}' -g '*.key' token .",
    "rg -g '.*' token .",
    "rg -g '**/*.key' token .",
    # SC-12 (fix round 1, verifier): gitignore **/ matches zero folders; a trailing / is a folder.
    "rg -g '**/.claude' -g '**/.claude/**' -l . .",
    "rg -g '.claude/' -g '**/.claude/**/reply-hmac.key' -l . .",
    "rg -g=.claude -g='*.key' -l . .",
    # SC-12 (fix round 1, operator ruling): a glob character the matcher does not model.
    "rg -g '\\.claude' -g '\\.claude/**' -l . .",
    "rg -g '.clau[d]e' -g '*.key' -l . .",
)
# SC-12 (fix round 1, verifier): the same gitignore spellings for the Grep tool's glob.
FIX1_GREP_GLOBS = ("**/.claude/**", "**/.claude", ".claude/", "**/.claude/**/reply-hmac.key")
FIX1_GREP_GLOBS += ("\\.claude/**", ".clau[d]e/**")
# SC-12 (fix round 1, finding 1): positive globs that name no hidden folder or key still pass.
FIX1_RG_GLOBS_ALLOWED = (
    "rg -g '*.tf' -g '*.yml' -l token .",
    "rg -g '!.claude' token .",
    "rg -e -g token .",
    "rg -g '**/*.py' -g '*Dockerfile*' -g '*requirements*.txt' token .",
    "rg -g 'src/' token .",
)

# prepush-2026-10-27 finding 1: a .rgignore or .ignore `!` line outranks the data folder marker.
PREPUSH_IGNORE_FILES = (".rgignore", ".ignore")
PREPUSH_IGNORE_BODIES = ("!.claude\n!.claude/**\n",)
# prepush2-2026-10-27 item 7: rg 14 reads a leading-space `!` as a plain glob, never a
# negation; the jail still refuses it, fail closed, and claims no attack.
PREPUSH_IGNORE_FAIL_CLOSED = ("  !*\n",)
PREPUSH_IGNORE_SEARCHES = ("rg -l token .", "rg -n token", "rg -l token src/..")
# prepush-2026-10-27 finding 1: a coder writing either name anywhere in its unit worktree.
PREPUSH_IGNORE_WRITES = (
    "{wt}/.rgignore",
    "{wt}/.ignore",
    "{wt}/src/.rgignore",
    "{wt}/src/deep/.IGNORE",
)
# 113, prepush-2026-10-27 finding 2: rg flags and config that read hidden or ignored files.
PREPUSH_RG_REACH = (
    "rg --ignore-file /tmp/ig -n . .",
    "rg --ignore-file=/tmp/ig token .",
    "rg -L token .",
    "rg --follow token .",
    "rg -nL token .",
    "RIPGREP_CONFIG_PATH=/tmp/rc rg token .",
    "env RIPGREP_CONFIG_PATH=/tmp/rc rg token .",
)

# prepush2-2026-10-27 item 1: words bash rewrites into a reach flag the jail never reads.
PREPUSH2_RG_OPAQUE = (
    "rg $'-uu' -l token .",
    "rg $'--hidden' -l token .",
    "rg $'--follow' -l token .",
    "rg $'-g' $'.claude/**' -l token .",
    "rg $'--no-ignore' -l token .",
    'rg $"-uu" -l token .',
    "rg {-uu,} -l token .",
    "rg --{hidden,count} token .",
    "rg $X -l token .",
    'rg "$X" -l token .',
    "rg * -l token .",
    "grep $'-r' -l token .",
    'grep $"-r" -l token .',
)
# prepush2-2026-10-27 item 2: rg options that run a program or load one.
PREPUSH2_RG_PROGRAM = (
    "rg --hostname-bin=/tmp/x -n token .",
    "rg --hostname-bin /tmp/x -n token .",
    "rg --hyperlink-format=default --hostname-bin=/tmp/x -n token .",
    "rg --hyperlink-format default --hostname-bin /tmp/x -n token .",
    "rg --pre /tmp/x token .",
    "rg --pre-glob '*' --pre /tmp/x token .",
    "rg --other-bin=/tmp/x token .",
)
# prepush2-2026-10-27 item 3: archive and multi-call writes the coder write check never models.
PREPUSH2_ARCHIVE_WRITES = (
    "unzip -o {wt}/z.zip -d /tmp/out",
    "busybox cp {wt}/a /tmp/out",
    "tar -C {wt} -cf /tmp/out/x.tar a",
    "tar -xPf {wt}/x.tar",
    "tar --transform s/a/.rgignore/ -xf {wt}/x.tar",
    "zip /tmp/out/z.zip {wt}/a",
    "cpio -o -F /tmp/out/x.cpio",
    "7z a /tmp/out/a.7z {wt}/a",
    "ar rc /tmp/out/a.a {wt}/a",
    "bsdtar -xf {wt}/x.tar -C /tmp/out",
)


def assert_denied(hook_input: dict[str, Any], *markers: str) -> None:
    # pin C1 -> C6: a deny through tests/hook_chain.py, never a warning; a marker names the finding.
    d = decide(hook_input, CFG)
    reason = str(d.reason)
    assert not d.allow and not d.warn, (hook_input, reason)
    assert not markers or any(m in reason for m in markers), (hook_input, reason)


# H2, issue 91: coder runners the confine check sends through the kernel wrapper.
CONFINE_RUNNERS = (
    "make",
    "make test",
    "tox -e py312",
    "nox -s tests",
    "just test",
    "uv run pytest -q",
    "uv run python -m unittest",
    "npx jest",
    "go test ./...",
    "cargo test",
    "timeout 60 cargo test",
    "nice -n 5 just test",
    "cargo -q test",
    "cargo +nightly test",
    "go -C . test ./...",
    "uv --quiet run pytest",
)
# 0164: the game stack runner rows; must-admit under the wrapper, refused bare.
GAME_RUNNERS = (
    "node --test",
    "node --test tests/a.test.js",
    "pnpm test",
    "pnpm run test",
    "pnpm exec vitest run",
    "pnpm exec tsc --noEmit",
    "pnpm -C . test",
    "vitest run",
    "vitest run src/a.test.ts",
    "tsc --noEmit",
    "tsc -p tsconfig.json --noEmit",
    "vite build",
    "npx vitest run",
    "timeout 120 pnpm test",
    # 0164 fix round: pnpm wraps like npm; terraform's allowlisted fmt forms.
    "pnpm run build",
    "pnpm build:dev",
    "pnpm run build:dev",
    "pnpm lint",
    "pnpm exec eslint .",
    "pnpm exec node --test",
    "pnpm run install",
    "npm run build:dev",
    "terraform fmt -check",
    "terraform fmt -check -recursive",
    "terraform fmt -recursive -check",
)
CONFINE_RUNNERS = CONFINE_RUNNERS + GAME_RUNNERS
# 0164, 0158: dev servers, watch modes and terraform state changes; refused bare and wrapped.
DEV_SERVERS = (
    "vite",
    "vite dev",
    "vite serve",
    "vite preview",
    "vite --port 5173",
    "vite build --watch",
    "pnpm dev",
    "pnpm run dev",
    "pnpm start",
    "pnpm preview",
    "pnpm exec vite",
    "pnpm vite serve",
    "npx vite",
    "npm run dev",
    "npm start",
    "timeout 60 vite dev",
    "pnpm run -- dev",
    "pnpm -- dev",
    "npm run -- dev",
    "pnpm run -- start",
    "npm run -- preview",
)
WATCH_MODES = (
    "vitest",
    "vitest watch",
    "vitest dev",
    "vitest run --watch",
    "pnpm exec vitest",
    "npx vitest",
    "tsc --watch",
    "tsc -w",
    "tsc --noEmit --watch",
    "tsc",
    "pnpm exec tsc -w",
    "node --test --watch",
    "node --test --watch-path=.",
    "vitest run --watch=true",
    "tsc --noEmit -watch",
    "tsc --noEmit --Watch",
    "tsc --noEmit false",
    "pnpm test --watch",
    "pnpm test -- --watch",
    "npm test -- --watch",
    "pnpm run test -w",
)
# 0164: what each watch row is refused with.
WATCH_REASONS = {"tsc": "R_TSC", "vitest": "R_VITEST_WATCH"}
TERRAFORM_MUTATIONS = (
    "terraform apply",
    "terraform apply -auto-approve",
    "terraform -chdir=. destroy",
    "terraform import aws_s3_bucket.a a",
    "terraform state rm a.b",
    "terraform taint a.b",
    "terraform untaint a.b",
    "terraform force-unlock 1",
    "terraform refresh",
)
# 0158, 0164: the coder's terraform is an allowlist; every other form names the operator.
TERRAFORM_OPERATOR_FORMS = (
    "terraform plan",
    "terraform init",
    "terraform console",
    "terraform test",
    "terraform workspace list",
    "terraform login",
    "terraform logout",
    "terraform output",
    "terraform graph",
    "terraform providers",
    "terraform fmt",
    "terraform fmt -recursive",
    "terraform fmt -write=true",
    "terraform fmt -check=false",
    "terraform fmt -check -write=true",
    "terraform fmt -check -recursive /tmp",
    "terraform fmt -check -check",
    "terraform version",
    "terraform",
)
# 0164: a package manager running an interpreter meets the interpreter rule.
INTERPRETER_BINS = (
    "pnpm exec node -e 1",
    "pnpm exec node t.js",
    "pnpm exec -- node t.js",
    "pnpm node t.js",
    "npx node t.js",
    "pnpm exec bash -c ls",
    "pnpm exec python3 -c 1",
    "yarn node -e 1",
)
# 0164: download-and-run forms stay with the operator.
PACKAGE_DOWNLOADS = (
    "pnpm dlx cowsay",
    "yarn dlx cowsay",
    "bunx cowsay",
    "bun x cowsay",
    "npm exec cowsay",
    "npm x cowsay",
    "npx -y cowsay",
    "npx --yes cowsay",
    "npx --yes=true vitest run",
)
# 0164: package installs stay with the operator, through any wrapper.
PACKAGE_INSTALL_CMDS = (
    "pnpm install",
    "pnpm i",
    "pnpm add vite",
    "pnpm update",
    "pnpm --filter web install",
    "npm install",
    "npm i -D vitest",
    "npm ci",
    "npm update",
    "yarn",
    "yarn add three",
    "yarn install --frozen-lockfile",
    "bun install",
    "bun add rapier",
    "timeout 60 pnpm install",
    "pnpm exec pnpm install",
    "pnpm exec npm install",
    "pnpm exec -- yarn add three",
    "corepack pnpm install",
    "corepack install",
    "corepack enable",
    "npm install-test",
    "npm it",
    "npm cit",
    "npm clean-install",
    "npm in",
    "npm isntall",
    "npm ins",
    "npm inst",
    "npm up",
    "npm upgrade",
    "pnpm up",
    "pnpm upgrade",
    "yarn up",
    "yarn upgrade",
    "pnpm fetch",
    "pnpm import",
)
# H2, issue 87: Python run inside the wrapper; each opens an AF_UNIX socket() the filter refuses.
UNIX_SOCKETS = (
    "import socket\nsocket.socket(socket.AF_UNIX, socket.SOCK_STREAM)",
    "import socket\nsocket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)",
    "import socket\nsocket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)",
    "import socket\nsocket.socket(1, socket.SOCK_STREAM)",
    "import ctypes\nlibc = ctypes.CDLL(None, use_errno=True)\n"
    "assert libc.socket(1, 1, 0) == -1\nraise PermissionError(ctypes.get_errno(), 'socket')",
)
# H2, issue 86: test commands refused, wrapped or bare, on a kernel that cannot hold the rules.
UNUSABLE_KERNEL = (
    "python3 -m pytest -q",
    "pytest -q",
    "make test",
    "{wrap} python3 -m pytest -q",
)


def assert_store_read_denied(agent: str, template: str, **fields: object) -> None:
    # W1.4: the one body of every "Bash read into a credential store is denied" row.
    assert_denied(_cred(agent, "Bash", command=template.format(**fields)), CREDENTIAL)
