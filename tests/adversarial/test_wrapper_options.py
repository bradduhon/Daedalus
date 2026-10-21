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
# issue 76: an option off the wrapper table leaves the command unknown, so every word is judged.
OPAQUE = (
    "env --frobnicate {other} rm -rf {repo}/x",
    "timeout KILL rm -rf {repo}/x",
    "stdbuf -Z L rm -rf {repo}/x",
)


@pytest.mark.parametrize("form", FORMS + OPAQUE)
def test_a_foreign_agent_cannot_hide_a_write_behind_a_wrapper_option(
    marked_repo: Path,  # noqa: F811
    other_repo: Path,  # noqa: F811
    form: str,
) -> None:
    command = form.format(repo=marked_repo, other=other_repo)
    d = jail.decide(_cred("Explore", "Bash", str(other_repo), command=command), CFG)
    assert not d.allow and not d.ask, (command, d.reason)
    assert "read-only while" in str(d.reason), (command, d.reason)


@pytest.mark.parametrize("form", FORMS + OPAQUE)
def test_a_worker_never_runs_the_wrapper(form: str) -> None:
    # 8.5 ruling A: Daedalus workers meet WORKER_WRAPPERS first.
    assert_denied(_b("repo-coder", form.format(repo="/work/repo", other="/tmp")))
