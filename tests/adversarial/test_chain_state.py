# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# issue 121 (P10, P11): git letter-case matching is judged across the whole chain, only for the
# subcommands the excluded roots check judges, and never inside a commit message.
from __future__ import annotations

from pathlib import Path

import pytest
from lib import jail

from tests.adversarial.corpus import (
    A3_ADMITTED,
    A3_ISSUE_121_ADMITTED,
    A3_ISSUE_121_REFUSED,
    A3_RULE_ROWS,
    assert_denied,
)
from tests.conftest import WT
from tests.payloads import _cred
from tests.test_excluded_roots import _config, _payload, _roots, repo  # noqa: F401

ICASE = jail.R_EXCLUDED_ICASE.split("{spec}")[0]
# issue 121: (root, command, refused); the issue's rows name Private, the corpus rows NOTES.
OUTCOMES = (
    *(("private", c, False) for c in A3_ISSUE_121_ADMITTED),
    *(("private", c, True) for c in A3_ISSUE_121_REFUSED),
    *(("notes", c, False) for c in A3_ADMITTED),
)


def test_each_rule_has_a_refused_row_in_the_git_family() -> None:
    # spec: one refused row per owned rule per command family; git is this unit's one family.
    assert {rule for rule, _ in A3_RULE_ROWS} == {"P10", "P11"}


@pytest.mark.parametrize(("rule", "form"), A3_RULE_ROWS)
def test_a_chain_state_row_is_refused(
    repo: Path,  # noqa: F811
    jail_fakes: None,
    rule: str,
    form: str,
) -> None:
    # P10, P11: refused for icase while a root is declared, the main session is warned with it,
    # and a coder in its unit worktree is denied (its own hooks refuse first; 0136 adds the check).
    got = jail.excluded_root_reason(form, str(repo), _roots(str(repo / "notes")))
    assert got is not None and got.startswith(ICASE), (rule, form, got)
    warned = jail.decide(_payload("main", repo, form), _config(repo))
    assert warned.warn and ICASE in str(warned.reason), (form, warned.reason)
    assert_denied(_cred("coder", "Bash", WT, command=form))


@pytest.mark.parametrize(("root", "command", "refused"), OUTCOMES)
def test_the_issue_rows_and_the_admitted_forms(
    repo: Path,  # noqa: F811
    root: str,
    command: str,
    refused: bool,
) -> None:
    # issue 121: reads and commit messages pass; an export or a prefix before git add is refused.
    got = jail.excluded_root_reason(command, str(repo), _roots(str(repo / root)))
    passed = got is None
    assert (not passed and str(got).startswith(ICASE)) if refused else passed, (command, got)


@pytest.mark.parametrize(
    ("word", "on"),
    (
        ("GIT_ICASE_PATHSPECS=1", True),
        ("GIT_ICASE_PATHSPECS=yes", True),
        ("GIT_ICASE_PATHSPECS=00", True),
        ('GIT_ICASE_PATHSPECS="$X"', True),
        ("GIT_ICASE_PATHSPECS", True),
        ('"$V"=1', True),
        ("{GIT_ICASE_PATHSPECS,X}=1", True),
        ("GIT_ICASE_PATH''SPECS=1", True),
        ("G\\IT_ICASE_PATHSPECS=1", True),
        ("GIT_ICASE_PATHSPECS+=0", True),
        ("${N}=1", True),
        ('"PATH"=x', False),
        ("GIT_ICASE_PATHSPECS=0", False),
        ("GIT_ICASE_PATHSPECS=FALSE", False),
        ("GIT_ICASE_PATHSPECS=off", False),
        ("GIT_ICASE_PATHSPECS=", False),
        ("git_icase_pathspecs=1", False),
        ("PATH=$PATH:/x", False),
    ),
)
def test_a_value_git_reads_as_false_leaves_icase_off(word: str, on: bool) -> None:
    # issue 121: git reads empty, 0, false, no and off as off (probed); an opaque name may be on.
    assert jail._icase_on(word) is on
