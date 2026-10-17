# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from tests.conftest import SCRIPTS_DIR


def test_logs_every_event_shape(run_script: Any, project_data: Path, hook_input: Any) -> None:
    events = [
        hook_input(
            hook_event_name="SessionStart", tool_name=None, tool_input=None, source="startup"
        ),
        hook_input(
            hook_event_name="UserPromptSubmit", tool_name=None, tool_input=None, prompt="build it"
        ),
        hook_input(hook_event_name="PostToolUse", tool_response={"stdout": "ok"}),
        hook_input(hook_event_name="SubagentStart", agent_id="a1", agent_type="repo-coder"),
        hook_input(
            hook_event_name="SubagentStop",
            agent_id="a1",
            agent_type="repo-coder",
            last_assistant_message="[STATUS: COMPLETE] branch daedalus/u1",
        ),
        hook_input(hook_event_name="Stop"),
        hook_input(hook_event_name="SessionEnd", reason="exit"),
    ]
    for payload in events:
        result = run_script("audit_log.py", payload)
        assert result.returncode == 0, result.stderr
        assert result.stdout == ""
    lines = (project_data / "audit" / "sess-test.jsonl").read_text().splitlines()
    assert [json.loads(line)["event"] for line in lines] == [
        "SessionStart",
        "UserPromptSubmit",
        "PostToolUse",
        "SubagentStart",
        "SubagentStop",
        "Stop",
        "SessionEnd",
    ]


def test_malformed_stdin_exits_zero_with_stderr(run_script: Any) -> None:
    result = subprocess.run(
        [sys.executable, str(SCRIPTS_DIR / "audit_log.py")],
        input="not json",
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0
    assert result.stderr.startswith("daedalus-audit:")


def test_missing_cwd_reports_to_stderr_and_exits_zero(run_script: Any, hook_input: Any) -> None:
    payload = hook_input(hook_event_name="Stop")
    del payload["cwd"]
    result = run_script("audit_log.py", payload)
    assert result.returncode == 0
    assert result.stderr.startswith("daedalus-audit: hook input cwd must be an absolute path")


def test_cwd_fallback_warns_on_stderr(run_script: Any, hook_input: Any, tmp_path: Path) -> None:
    plain = tmp_path / "plain"
    (plain / ".claude" / "daedalus").mkdir(parents=True)
    result = run_script("audit_log.py", hook_input(hook_event_name="Stop", cwd=str(plain)))
    assert result.returncode == 0
    assert result.stderr.startswith("daedalus-audit: project root fell back to cwd (")
    assert (plain / ".claude" / "daedalus" / "audit" / "sess-test.jsonl").exists()


@pytest.mark.parametrize("event", ["SessionStart", "UserPromptSubmit", "PostToolUse", "Stop"])
def test_no_data_dir_exits_zero_and_creates_nothing(
    run_script: Any, repo_cwd: Path, hook_input: Any, event: str
) -> None:
    # 0035: a repo where no train ever started keeps no Daedalus footprint.
    result = run_script("audit_log.py", hook_input(hook_event_name=event))
    assert result.returncode == 0 and result.stderr == ""
    assert not (repo_cwd / ".claude").exists()
