# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# issue 204, 107: a read verb or wrapper never writes a file through an option value or operand.
from __future__ import annotations

import shlex
from pathlib import Path

import pytest
from lib import jail, shell

from tests.adversarial.corpus import (
    A1_ISSUE_107,
    A1_ISSUE_204,
    A1_READ_ADMITTED,
    A1_READ_P1,
    A1_READ_P2,
    A1_READ_P3,
    A1_READ_P4,
    A1_READ_P9,
    A1_WRAPPER_ROWS,
    assert_denied,
)
from tests.conftest import CFG
from tests.hook_chain import decide
from tests.payloads import _b, _cred

pytestmark = pytest.mark.usefixtures("jail_fakes")
READ_ROWS = A1_ISSUE_204 + A1_READ_P1 + A1_READ_P2 + A1_READ_P3 + A1_READ_P4 + A1_READ_P9
# issue 107: the reproduction row with its file in the marked repository.
ISSUE_107 = A1_ISSUE_107.replace("<file>", "{repo}/l").replace("<command>", "true")


@pytest.mark.parametrize("command", READ_ROWS)
def test_a_read_verb_never_writes_through_an_option_or_operand(command: str) -> None:
    # P1 to P4: refused to the auditor, and by the read grammar itself for a read verb.
    assert_denied(_b("auditor", command))
    tokens = shlex.split(command)
    if tokens[0] in shell.READ_ONLY_CMDS:
        assert not jail._read_only_segment(tokens, frozenset(), "/c", None), command


@pytest.mark.parametrize("command", A1_READ_ADMITTED)
def test_a_read_verb_with_one_input_is_admitted(command: str) -> None:
    decision = decide(_b("auditor", command), CFG)
    assert decision.allow and not decision.warn, (command, decision.reason)


@pytest.mark.parametrize("form", (*A1_WRAPPER_ROWS, ISSUE_107))
def test_a_wrapper_file_in_a_marked_repository_is_a_write(
    marked_repo: Path, other_repo: Path, form: str
) -> None:
    # P9, issue 107: the lock or namespace file joins the write accounting beside time -o.
    command = form.format(repo=marked_repo)
    targets = jail._bash_write_dirs(command, str(other_repo))
    assert any(t.startswith(f"{marked_repo}/") for t in targets), (command, targets)
    hook_input = _cred("Explore", "Bash", str(other_repo), command=command)
    assert_denied(hook_input, "read-only while", "shell -c body")


def test_a_coder_creates_no_flock_file_outside_its_worktree() -> None:
    assert_denied(
        _b("coder", A1_ISSUE_107.replace("<file>", "/tmp/l").replace("<command>", "true"))
    )


@pytest.mark.parametrize("command", ["flock 9", "flock -u 9"])
def test_a_lone_numeric_flock_fd_is_no_write(
    marked_repo: Path, other_repo: Path, command: str
) -> None:
    # P9: with no command after it, a numeric operand names a file descriptor, never a path.
    assert jail._bash_write_dirs(command, str(other_repo)) == []
    decision = jail.decide(_cred("Explore", "Bash", str(other_repo), command=command), CFG)
    assert decision.allow and not decision.warn, decision.reason


@pytest.mark.parametrize("command", ["flock 9 true", "flock -x 9 true", "flock 9 -c true"])
def test_a_numeric_flock_operand_before_a_command_is_a_file(
    marked_repo: Path, command: str
) -> None:
    # P9: flock 9 true creates the file 9 (orchestrator probe, run 20261107-145205).
    assert f"{marked_repo}/9" in jail._bash_write_dirs(command, str(marked_repo))
    hook_input = _cred("Explore", "Bash", str(marked_repo), command=command)
    assert_denied(hook_input, "read-only while", "shell -c body")
