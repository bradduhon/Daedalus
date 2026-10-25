# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from tests.conftest import SCRIPTS_DIR, write_train_marker

_PYCACHE = shutil.ignore_patterns("__pycache__")


def test_logs_every_event_shape(run_script: Any, project_data: Path, hook_input: Any) -> None:
    write_train_marker(project_data.parent.parent)
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
    write_train_marker(plain)
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


@pytest.mark.parametrize("event", ["SessionStart", "UserPromptSubmit", "PostToolUse", "Stop"])
def test_data_dir_without_train_marker_writes_nothing(
    run_script: Any, project_data: Path, hook_input: Any, event: str
) -> None:
    # 0035: a repo that once ran a train is not logged again until a train marks it.
    result = run_script("audit_log.py", hook_input(hook_event_name=event))
    assert result.returncode == 0 and result.stderr == ""
    assert list(project_data.iterdir()) == []


def test_no_marker_imports_only_the_standard_library(project_data: Path, hook_input: Any) -> None:
    # 0035: outside a train the event logger never loads the audit modules.
    result = subprocess.run(
        [sys.executable, "-X", "importtime", str(SCRIPTS_DIR / "audit_log.py")],
        input=json.dumps(hook_input(hook_event_name="SessionStart", source="startup")),
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0
    loaded = {line.rsplit("|", 1)[-1].strip() for line in result.stderr.splitlines()}
    fast = {"lib.repo_root", "lib.project_root"}
    assert fast <= loaded
    assert not {n for n in loaded if n.startswith("lib.")} - fast
    assert "subprocess" not in loaded


def test_broken_install_is_silent_outside_a_train(
    tmp_path: Path, repo_cwd: Path, hook_input: Any
) -> None:
    # 0035: a library that fails to import costs a repo without a train nothing.
    scripts = shutil.copytree(SCRIPTS_DIR, tmp_path / "scripts", ignore=_PYCACHE)
    (scripts / "lib" / "audit.py").write_text("raise ImportError('broken install')\n")
    payload = json.dumps(hook_input(hook_event_name="SessionStart", source="startup"))

    def _run() -> subprocess.CompletedProcess[str]:
        cmd = [sys.executable, str(scripts / "audit_log.py")]
        return subprocess.run(cmd, input=payload, capture_output=True, text=True, check=False)

    quiet = _run()
    assert quiet.returncode == 0 and quiet.stderr == ""
    write_train_marker(repo_cwd)
    loud = _run()
    assert loud.returncode == 0
    assert loud.stderr == "daedalus-audit: broken install\n"


def test_hook_rotation_record_passes_the_chain_check(
    run_script: Any, project_data: Path, hook_input: Any
) -> None:
    # issue 50, AU-9(4): the rotation record is chained, so verify_audit_chain.py passes on it.
    write_train_marker(project_data.parent.parent)
    old = hook_input(session_id="old-sess")
    assert run_script("audit_log.py", old).returncode == 0
    stamp = 1_000_000_000
    os.utime(project_data / "audit" / "old-sess.jsonl", (stamp, stamp))
    (project_data / "config.json").write_text(json.dumps({"audit_retention_days": 90}))
    result = run_script("audit_log.py", hook_input(session_id="new-sess"))
    assert result.returncode == 0 and result.stderr == ""
    new = project_data / "audit" / "new-sess.jsonl"
    events = [json.loads(line)["event"] for line in new.read_text().splitlines()]
    assert events == ["PreToolUse", "AuditRotation"]
    assert not (project_data / "audit" / "old-sess.jsonl").exists()
    check = subprocess.run(
        [sys.executable, str(SCRIPTS_DIR / "verify_audit_chain.py"), str(new)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert check.returncode == 0 and check.stdout.startswith("OK: 2 records, chain intact")


def test_chain_seq_accepts_what_int_accepted() -> None:
    # 38: typing the tail read must not add a refusal; a float or numeric str seq still chains.
    from lib.audit import _seq

    assert _seq({"seq": 5.0}) == 5 and _seq({"seq": "7"}) == 7 and _seq({"seq": True}) == 1
    with pytest.raises(TypeError):
        _seq({"seq": None})
