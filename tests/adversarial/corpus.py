# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# spec 3.3: the shared adversarial corpus; one test module per bypass class, rows assert a deny.
# pin C1 -> C6: never a row for git grep, git worktree list, git merge-base, git show | sed -n,
# the --test-runner pytest forms or an auditor write under the train's audit folder.
from __future__ import annotations

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
READERS = ("repo-coder", "security-auditor", "nist-specialist")
CREDENTIAL = "credential path"
REPLY_KEY = "the train's reply key"
NESTED = "nested session"
OUTSIDE = "outside your unit worktree"
PROTECTED = "protected path"


def assert_denied(hook_input: dict[str, Any], *markers: str) -> None:
    # pin C1 -> C6: a deny through tests/hook_chain.py, never a warning; a marker names the finding.
    d = decide(hook_input, CFG)
    reason = str(d.reason)
    assert not d.allow and not d.warn, (hook_input, reason)
    assert not markers or any(m in reason for m in markers), (hook_input, reason)


def assert_store_read_denied(agent: str, template: str, **fields: object) -> None:
    # W1.4: the one body of every "Bash read into a credential store is denied" row.
    assert_denied(_cred(agent, "Bash", command=template.format(**fields)), CREDENTIAL)
