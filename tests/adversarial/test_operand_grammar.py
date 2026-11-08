# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# issue 204, 107: a read verb or wrapper never writes a file through an option value or operand.
from __future__ import annotations

import shlex
from pathlib import Path

import pytest
from lib import jail, shell

from tests.adversarial.corpus import (
    A1_EXPANSION,
    A1_EXPANSION_ADMITTED,
    A1_ISSUE_107,
    A1_ISSUE_204,
    A1_READ_ADMITTED,
    A1_READ_P1,
    A1_READ_P2,
    A1_READ_P3,
    A1_READ_P4,
    A1_READ_P9,
    A1_WRAPPER_ROWS,
    CLAIMS_ADMITTED,
    CLAIMS_REFUSED,
    assert_denied,
)
from tests.conftest import CFG, SCRIPTS_DIR, WT
from tests.hook_chain import decide, evaluate
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
        assert not jail.admitted(command, "comparer", "/c"), command


@pytest.mark.parametrize("command", A1_EXPANSION)
def test_an_expanding_word_beside_a_writing_read_verb_is_refused(
    marked_repo: Path, command: str
) -> None:
    # P1, 0084: refused to a read-only agent and to an agent Daedalus did not start.
    assert_denied(_b("auditor", command))
    foreign = _cred("Explore", "Bash", str(marked_repo), command=command)
    assert_denied(foreign, "read-only while", "could be a credential path")
    assert not jail.admitted(command, "comparer", str(marked_repo)), command


@pytest.mark.parametrize("command", A1_EXPANSION_ADMITTED)
def test_a_quoted_brace_or_glob_is_one_literal_word(marked_repo: Path, command: str) -> None:
    assert jail.admitted(command, "foreign", str(marked_repo)), command
    decision = jail.decide(_cred("Explore", "Bash", str(marked_repo), command=command), CFG)
    assert decision.allow and not decision.warn, (command, decision.reason)
    # O4, prepush2: hygiene and the search glob rule still judge Daedalus agents' other rows.
    if '"' not in command and command.split()[0] in shell.READ_ONLY_WRITE_OPTS:
        decision = decide(_b("auditor", command), CFG)
        assert decision.allow and not decision.warn, (command, decision.reason)


@pytest.mark.parametrize("command", A1_READ_ADMITTED)
def test_a_read_verb_with_one_input_is_admitted(command: str) -> None:
    decision = decide(_b("auditor", command), CFG)
    assert decision.allow and not decision.warn, (command, decision.reason)


@pytest.mark.parametrize("form", (*A1_WRAPPER_ROWS, ISSUE_107))
def test_a_wrapper_file_in_a_marked_repository_is_a_write(
    marked_repo: Path, other_repo: Path, form: str
) -> None:
    # P9, issue 107, 0224: the wrapper row is unadmitted for an agent, so it scopes nothing
    # from elsewhere; in its own repo the grammar refuses it and names the wrapper.
    command = form.format(repo=marked_repo)
    assert jail._scope_paths(command, str(other_repo)) == (), command
    hook_input = _cred("Explore", "Bash", str(marked_repo), command=command)
    assert_denied(hook_input, "read-only while")
    assert "Refused: " in str(jail.decide(hook_input, CFG).reason)


def test_a_coder_creates_no_flock_file_outside_its_worktree() -> None:
    assert_denied(
        _b("coder", A1_ISSUE_107.replace("<file>", "/tmp/l").replace("<command>", "true"))
    )


@pytest.mark.parametrize("command", ["flock 9", "flock -u 9"])
def test_a_lone_numeric_flock_fd_is_no_write(
    marked_repo: Path, other_repo: Path, command: str
) -> None:
    # P9: with no command after it, a numeric operand names a file descriptor, never a path.
    assert not [t for t in jail._scope_paths(command, str(other_repo)) if str(marked_repo) in t]
    decision = jail.decide(_cred("Explore", "Bash", str(other_repo), command=command), CFG)
    assert decision.allow and not decision.warn, decision.reason


@pytest.mark.parametrize("command", ["flock 9 true", "flock -x 9 true", "flock 9 -c true"])
def test_a_numeric_flock_operand_before_a_command_is_a_file(
    marked_repo: Path, command: str
) -> None:
    # P9: flock 9 true creates the file 9 (orchestrator probe, run 20261107-145205).
    hook_input = _cred("Explore", "Bash", str(marked_repo), command=command)
    assert_denied(hook_input, "read-only while")
    assert "Refused: " in str(jail.decide(hook_input, CFG).reason)


def _claims(form: str) -> str:
    return form.format(claims=SCRIPTS_DIR / "daedalus_claims.py", wt=WT)


@pytest.mark.parametrize("form", CLAIMS_ADMITTED)
def test_the_verifier_claims_call_is_admitted_in_its_one_form(form: str) -> None:
    # 0230: the verifier's claims printer, three options once each in order.
    decision = decide(_b("verifier", _claims(form)), CFG)
    assert decision.allow and not decision.warn, decision.reason


@pytest.mark.parametrize("form", CLAIMS_REFUSED)
def test_the_claims_call_one_token_off_its_form_is_refused(form: str) -> None:
    # 0230: a write-shaped option, a moved option or an off-table value refuses the verifier.
    assert_denied(_b("verifier", _claims(form)))
    # 0230: the read check's own row refuses it too, not only the tripwires before it.
    flags = ("--git", "read-only", "--test-runner", "unit")
    assert evaluate("read_only_bash", _b("verifier", _claims(form)), *flags) is not None


@pytest.mark.parametrize("agent", ["coder", "auditor", "comparer", "orchestrator"])
def test_the_claims_call_is_the_verifier_s_alone(agent: str) -> None:
    assert_denied(_b(agent, _claims(CLAIMS_ADMITTED[0])))
