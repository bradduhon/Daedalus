# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

from pathlib import Path

from tests.skill_helpers import (
    _conductor_decide,
)


def test_push_train_conductor_pr_edit_title_refused(repo_cwd: Path, project_data: Path) -> None:
    # K1: the conductor's pr edit changes the body only.
    command = "gh pr edit daedalus/<train-id> --title t --body-file <repo>/docs/.tmp/pr.md"
    d = _conductor_decide(repo_cwd, project_data, command)
    assert not d.allow and "Next: edit only the body with --body-file" in str(d.reason)
