# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# issue 76: a wrapper option that takes a value must not hide the wrapped command from the jail.
from __future__ import annotations

from pathlib import Path

import pytest
from lib import jail

from tests.adversarial.corpus import assert_denied
from tests.conftest import CFG
from tests.test_jail import _b, _cred, marked_repo, other_repo  # noqa: F401 - fixtures

pytestmark = pytest.mark.usefixtures("jail_fakes")
# issue 76: the allowed forms, each a recursive delete of a file in a repository a train marks.
FORMS = (
    "env -C {other} rm -rf {repo}/x",
    "env --chdir {other} rm -rf {repo}/x",
    "timeout --signal KILL 5 rm -rf {repo}/x",
    "timeout --kill-after 1 5 rm -rf {repo}/x",
    "sudo -h localhost rm -rf {repo}/x",
    "sudo -p pw rm -rf {repo}/x",
    "sudo -C 3 rm -rf {repo}/x",
    "sudo -U root rm -rf {repo}/x",
    "sudo -D {other} rm -rf {repo}/x",
    "sudo -r role rm -rf {repo}/x",
    "sudo -t type rm -rf {repo}/x",
    "stdbuf -o L rm -rf {repo}/x",
    "stdbuf -i 0 -e 0 rm -rf {repo}/x",
    "stdbuf --output L rm -rf {repo}/x",
)
# issue 76: past an option off the table, each word and each option value is a path and a base.
OPAQUE = (
    "env --frobnicate {other} rm -rf {repo}/x",
    "timeout KILL rm -rf {repo}/x",
    "stdbuf -Z L rm -rf {repo}/x",
    "env --frobnicate={repo} rm -rf x",
    "sudo -Z{repo} rm -rf x",
    "env --frobnicate=../marked rm -rf x",
)
# issue 76: a unique prefix of --chdir (getopt_long) is --chdir; sudo spells it out too.
PREFIX = (
    "env --ch={repo} rm -rf {repo}/x",
    "env --chd={repo} rm -rf {repo}/x",
    "env --chdi {repo} rm -rf {repo}/x",
    "sudo --chdir={repo} rm -rf {repo}/x",
    "env --ch={repo} rm -rf x",
    "env --chd={repo} rm -rf x",
    "env --chdi {repo} rm -rf x",
    "env --c={repo} rm -rf x",
    "sudo --chdir={repo} rm -rf x",
    "sudo --chdir {repo} rm -rf x",
    "sudo --ch={repo} rm -rf x",
    "time --output={repo}/t ls",
    "time --out {repo}/t ls",
)
# issue 76: a wrapper that changes folder moves relative operands into the marked repo.
RELATIVE = (
    "env -C {repo} rm -rf x",
    "env --chdir {repo} rm -rf x",
    "env --chdir={repo} rm -rf x",
    "env -C{repo} rm -rf x",
    "sudo -D {repo} rm -rf x",
    "env -C {other} env -C ../marked rm -rf x",
    "env -C {repo} touch x",
    "env -C {repo} git commit -m x",
)
# issue 76: time is a wrapper, never a control word; its -o value is a file time writes.
TIME = (
    "time -p rm -rf {repo}/x",
    "time -o {repo}/t ls",
    "time -f %e rm -rf {repo}/x",
)
ALL = FORMS + OPAQUE + PREFIX + RELATIVE + TIME


@pytest.mark.parametrize("form", ALL)
def test_a_foreign_agent_cannot_hide_a_write_behind_a_wrapper_option(
    marked_repo: Path,  # noqa: F811
    other_repo: Path,  # noqa: F811
    form: str,
) -> None:
    command = form.format(repo=marked_repo, other=other_repo)
    d = jail.decide(_cred("Explore", "Bash", str(other_repo), command=command), CFG)
    assert not d.allow and not d.ask, (command, d.reason)
    assert "read-only while" in str(d.reason), (command, d.reason)


@pytest.mark.parametrize("form", ALL)
def test_a_worker_never_runs_the_wrapper(form: str) -> None:
    # 8.5 ruling A: Daedalus workers meet WORKER_WRAPPERS first.
    assert_denied(_b("repo-coder", form.format(repo="/work/repo", other="/tmp")))
