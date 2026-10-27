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
READERS = ("repo-coder", "security-auditor", "framework-specialist")
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
