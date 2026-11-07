# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# issue 116, 81: a command string handed to a shell or an interpreter is found, walked or refused.
from __future__ import annotations

import shlex
from pathlib import Path

import pytest
from lib import jail, shell

from tests.adversarial.corpus import (
    A2_ADMITTED,
    A2_FIX1_RUN,
    A2_FIX1_UNMARKED,
    A2_ISSUE_81,
    A2_ISSUE_116,
    A2_PROBE,
    A2_RULE_ROWS,
    assert_denied,
)
from tests.conftest import CFG
from tests.payloads import _b, _cred

FINDINGS = {"shell": jail.R_SHELL_BODY, "inline": jail.R_INLINE_BODY, "env": shell.R_ENV_SPLIT}
# issue 81: one body form per walked kind; {cmd} is the quoted inner command.
BODY_FORMS = ("bash -c {cmd}", "sh -c {cmd}", "bash <<< {cmd}", "env -S {cmd}")


def _foreign(cwd: Path, command: str) -> dict[str, object]:
    return _cred("Explore", "Bash", str(cwd), command=command)


def _nest(form: str, command: str, levels: int) -> str:
    for _ in range(levels):
        command = form.format(cmd=shlex.quote(command))
    return command


def test_each_rule_has_a_refused_row_in_each_family() -> None:
    # spec: one refused row per owned rule per command family.
    cells = {(rule, family) for rule, family, _, _ in A2_RULE_ROWS}
    rules, families = ("P5", "P6", "P7", "P8"), ("shell", "interpreter", "env")
    assert cells == {(r, f) for r in rules for f in families}


@pytest.mark.parametrize(("rule", "family", "finding", "form"), A2_RULE_ROWS)
def test_a_hidden_body_is_refused_per_rule_and_family(
    marked_repo: Path, rule: str, family: str, finding: str, form: str
) -> None:
    # P5 to P8: a foreign agent's hidden body is refused while a train runs, named by its kind.
    command = form.format(repo=marked_repo)
    assert jail._hidden_reason(command) == FINDINGS[finding], (rule, family, command)
    assert_denied(_foreign(marked_repo, command), FINDINGS[finding])


@pytest.mark.parametrize("command", A2_ISSUE_116 + A2_ISSUE_81)
def test_the_issue_reproduction_rows_are_refused(marked_repo: Path, command: str) -> None:
    # issue 116, 81: the rows as the issues relay them, refused while a train runs.
    assert jail._hidden_reason(command) is not None, command
    assert_denied(_foreign(marked_repo, command), *FINDINGS.values())


def test_the_probe_rows_now_give_a_finding() -> None:
    # issue 116: the probe gave None for these and an empty list for env -a x -S.
    assert [jail._hidden_reason(c) for c in A2_PROBE] == [
        jail.R_SHELL_BODY,
        jail.R_SHELL_BODY,
        jail.R_SHELL_BODY,
        jail.R_INLINE_BODY,
        shell.R_ENV_SPLIT,
    ]
    assert shell.env_split_values(shlex.split(A2_PROBE[-1])) == ["touch y"]


@pytest.mark.parametrize("levels", (1, 2, 3))
@pytest.mark.parametrize("form", BODY_FORMS)
def test_the_walk_names_a_write_inside_each_body_to_depth_three(
    marked_repo: Path, other_repo: Path, form: str, levels: int
) -> None:
    # issue 81: from an unmarked folder, the body's write into a marked repo scopes the call.
    command = _nest(form, f"touch {marked_repo}/x", levels)
    assert str(marked_repo / "x") in jail._bash_write_dirs(command, str(other_repo))
    assert not jail._body_past_cap(command)
    assert_denied(_foreign(other_repo, command), jail.R_SHELL_BODY, shell.R_ENV_SPLIT)


@pytest.mark.parametrize("form", BODY_FORMS)
def test_a_body_past_the_depth_cap_is_refused(other_repo: Path, form: str) -> None:
    # issue 81: past _BODY_DEPTH nothing is walked, so the call fails closed.
    command = _nest(form, f"touch {other_repo}/x", jail._BODY_DEPTH + 1)
    assert jail._body_past_cap(command)
    assert_denied(_foreign(other_repo, command), jail.R_SHELL_BODY, shell.R_ENV_SPLIT)


@pytest.mark.parametrize(("finding", "form"), A2_FIX1_RUN)
def test_a_fix_round_form_is_refused_in_a_run(marked_repo: Path, finding: str, form: str) -> None:
    # fix round 1: fd-prefixed stdin, raw expansions, off-table options, eval and source.
    command = form.format(repo=marked_repo)
    assert jail._hidden_reason(command) == FINDINGS[finding], command
    assert_denied(_foreign(marked_repo, command), FINDINGS[finding])


@pytest.mark.parametrize("form", A2_FIX1_UNMARKED)
def test_a_fix_round_form_from_an_unmarked_folder_is_refused(
    marked_repo: Path, other_repo: Path, form: str
) -> None:
    # fix round 1, issue 81: the walk reads the body, so the write into {repo} scopes the call.
    command = form.format(repo=marked_repo)
    assert str(marked_repo / "x") in jail._bash_write_dirs(command, str(other_repo)), command
    assert_denied(_foreign(other_repo, command), jail.R_SHELL_BODY)


@pytest.mark.parametrize("command", A2_ADMITTED)
def test_a_module_or_script_run_is_no_body(other_repo: Path, command: str) -> None:
    # P7: python3 -m <module> and python3 <script path> are plain segments.
    tokens = shlex.split(command)
    assert shell.interpreter_code(tokens, stdin=True) is None
    assert jail._hidden_reason(command) is None
    assert jail._policy_segments(command) == [tokens]
    assert jail.decide(_foreign(other_repo, command), CFG).allow
    assert jail.decide(_b(None, command), CFG).allow
