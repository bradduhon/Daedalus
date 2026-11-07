# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from tests.conftest import REPO_ROOT
from tests.conftest import workspace_cli as _cli
from tests.test_workspace_train import _fresh, _hook, _hooks_live

RUN_SKILL = REPO_ROOT / "skills" / "run" / "SKILL.md"
RESUME = "daedalus_workspace.py resume"


@pytest.fixture(autouse=True)
def _isolated_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # 0020: a temp HOME keeps the operator's settings and plugin cache out of these tests.
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.delenv("CLAUDE_PLUGIN_DATA", raising=False)


def _bullet(start: str) -> str:
    lines = RUN_SKILL.read_text(encoding="utf-8").splitlines()
    return next(line for line in lines if line.lstrip().startswith(start))


def test_continue_bullet_runs_resume_before_the_hooks_check() -> None:
    # issue 183: the hooks check needs the run marker that only the resume command restores.
    bullet = _bullet("- `continue`:")
    assert RESUME in bullet and "steps 3 and 5" not in bullet
    assert bullet.index("step 3") < bullet.index(RESUME) < bullet.index("step 5")
    main_continue = _bullet("- Continue after a stop:")
    assert RESUME not in main_continue and "run the resume command" not in main_continue


def _stopped_run(repo: Path, project_data: Path) -> None:
    _fresh(repo)
    for args in (("begin",), ("stop", "--reason", "operator", "--next", "continue")):
        done = _cli(*args, "--repo", str(repo))
        assert done.returncode == 0, done.stdout + done.stderr
    assert not (project_data / "train.active").exists()


@pytest.mark.parametrize(("resumed", "code"), [(True, 0), (False, 1)])
def test_hooks_live_after_a_stop_needs_the_resume_first(
    repo_cwd: Path,
    project_data: Path,
    hook_input: Callable[..., dict[str, Any]],
    resumed: bool,
    code: int,
) -> None:
    # issue 183: without the resume no hook record is written, so the check reports NOT LIVE.
    _stopped_run(repo_cwd, project_data)
    if resumed:
        done = _cli("resume", "--repo", str(repo_cwd))
        assert done.returncode == 0, done.stdout + done.stderr
    verify = f"python3 /p/scripts/verify_audit_chain.py --hooks-live --repo {repo_cwd}"
    jail = _hook(hook_input(tool_input={"command": verify}))
    assert jail.returncode == 0, jail.stderr
    result = _hooks_live(repo_cwd)
    assert result.returncode == code, result.stdout + result.stderr
    if resumed:
        assert result.stdout.startswith("OK hooks live: session sess-test")
    else:
        assert "NOT LIVE" in result.stdout + result.stderr
