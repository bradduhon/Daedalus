# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import pytest
from lib import audit
from lib.audit_proof import ProofError, approved, hooks_live, newest_log, read_chain

NEEDLE = "daedalus_workspace.py begin"
TRAIN = "20261016-120000"
AUDITOR = "daedalus:security-auditor"


def _bash(hook_input: Any, command: str, **kw: Any) -> None:
    audit.audit_append(hook_input(tool_input={"command": command}, **kw))


def test_hooks_live_passes_when_the_newest_bash_record_is_this_command(
    project_data: Path, hook_input: Any, repo_cwd: Path
) -> None:
    _bash(hook_input, "git status --porcelain")
    _bash(hook_input, f"python3 /p/scripts/{NEEDLE} --repo .")
    line = hooks_live(repo_cwd, NEEDLE)
    assert line == "OK hooks live: session sess-test, chain intact (2 records)"


def test_hooks_live_ignores_newer_non_bash_and_post_records(
    project_data: Path, hook_input: Any, repo_cwd: Path
) -> None:
    _bash(hook_input, f"python3 /p/scripts/{NEEDLE}")
    audit.audit_append(hook_input(hook_event_name="PostToolUse", tool_input={"command": "ls"}))
    audit.audit_append(hook_input(tool_name="Read", tool_input={"file_path": "/x"}))
    assert hooks_live(repo_cwd, NEEDLE).startswith("OK hooks live:")


def test_hooks_live_refuses_when_another_command_is_newest(
    project_data: Path, hook_input: Any, repo_cwd: Path
) -> None:
    _bash(hook_input, f"python3 /p/scripts/{NEEDLE}")
    _bash(hook_input, "ls")
    with pytest.raises(ProofError) as info:
        hooks_live(repo_cwd, NEEDLE)
    assert str(info.value).startswith("NOT LIVE:")
    assert "Next: run the Daedalus health check (/daedalus:doctor)." in str(info.value)


def test_hooks_live_refuses_without_a_log(project_data: Path, repo_cwd: Path) -> None:
    with pytest.raises(ProofError) as info:
        hooks_live(repo_cwd, NEEDLE)
    assert str(info.value).startswith("NOT LIVE:")


def test_hooks_live_reports_a_broken_chain(
    project_data: Path, hook_input: Any, repo_cwd: Path
) -> None:
    _bash(hook_input, f"python3 /p/scripts/{NEEDLE}")
    log = audit.log_path("sess-test", str(repo_cwd))
    rec = json.loads(log.read_text().splitlines()[0])
    rec["tool_name"] = "Write"
    log.write_text(json.dumps(rec) + "\n")
    with pytest.raises(ProofError) as info:
        hooks_live(repo_cwd, NEEDLE)
    assert str(info.value).startswith("BROKEN")


def test_newest_log_is_by_mtime(project_data: Path, hook_input: Any, repo_cwd: Path) -> None:
    _bash(hook_input, "a", session_id="old")
    _bash(hook_input, "b", session_id="new")
    old = audit.log_path("old", str(repo_cwd))
    os.utime(old, (1, 1))
    assert newest_log(repo_cwd).stem == "new"
    assert [r["seq"] for r in read_chain(newest_log(repo_cwd))] == [1]


def _stop(hook_input: Any, verdict: str, agent_type: str = AUDITOR) -> None:
    audit.audit_append(
        hook_input(
            hook_event_name="SubagentStop",
            tool_name=None,
            tool_input=None,
            agent_type=agent_type,
            agent_id="a1",
            last_assistant_message=verdict,
        )
    )


def _summary_write(hook_input: Any, repo_cwd: Path) -> None:
    path = f"{repo_cwd}/docs/.tmp/daedalus/{TRAIN}-summary.md"
    audit.audit_append(hook_input(tool_name="Write", tool_input={"file_path": path}))


def _summary(
    repo_cwd: Path, text: str = "Session sess-test: .claude/daedalus/audit/sess-test.jsonl\n"
) -> None:
    path = repo_cwd / "docs" / ".tmp" / "daedalus" / f"{TRAIN}-summary.md"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f"# Build Train {TRAIN}\n{text}", encoding="utf-8")


def _train(hook_input: Any, repo_cwd: Path, verdict: str) -> None:
    _stop(hook_input, verdict)
    _summary_write(hook_input, repo_cwd)
    _summary(repo_cwd)


def _refused(repo_cwd: Path, train: str = TRAIN) -> str:
    with pytest.raises(ProofError) as info:
        approved(repo_cwd, train)
    return str(info.value)


def test_approved_passes_on_an_approved_final_round(
    project_data: Path, hook_input: Any, repo_cwd: Path
) -> None:
    _train(hook_input, repo_cwd, "[VERDICT: APPROVED] ok")
    assert approved(repo_cwd, TRAIN) == (
        f"OK approved: train {TRAIN}, session sess-test, auditor record seq 1"
    )


def test_approved_refuses_a_rejected_final_round(
    project_data: Path, hook_input: Any, repo_cwd: Path
) -> None:
    _stop(hook_input, "[VERDICT: APPROVED] first")
    _train(hook_input, repo_cwd, "[VERDICT: REJECTED] a.py:1 high")
    message = _refused(repo_cwd)
    assert message.startswith("NOT APPROVED:")
    assert message.endswith(
        "Next: run /daedalus:build-train; this train has no approved audit in its log."
    )


def test_approved_ignores_auditor_stops_after_the_summary_write(
    project_data: Path, hook_input: Any, repo_cwd: Path
) -> None:
    _train(hook_input, repo_cwd, "[VERDICT: REJECTED] a.py:1 high")
    _stop(hook_input, "[VERDICT: APPROVED] late")
    assert _refused(repo_cwd).startswith("NOT APPROVED:")


def test_approved_requires_the_namespaced_agent_type(
    project_data: Path, hook_input: Any, repo_cwd: Path
) -> None:
    _stop(hook_input, "[VERDICT: APPROVED] ok", agent_type="security-auditor")
    _summary_write(hook_input, repo_cwd)
    _summary(repo_cwd)
    assert _refused(repo_cwd).startswith("NOT APPROVED:")


def test_approved_refuses_a_missing_summary(
    project_data: Path, hook_input: Any, repo_cwd: Path
) -> None:
    _stop(hook_input, "[VERDICT: APPROVED] ok")
    _summary_write(hook_input, repo_cwd)
    assert _refused(repo_cwd).startswith("NOT APPROVED:")


def test_approved_refuses_a_summary_without_a_session_line(
    project_data: Path, hook_input: Any, repo_cwd: Path
) -> None:
    _stop(hook_input, "[VERDICT: APPROVED] ok")
    _summary_write(hook_input, repo_cwd)
    _summary(repo_cwd, "Audit log: none\n")
    assert _refused(repo_cwd).startswith("NOT APPROVED:")


def test_approved_refuses_a_summary_write_never_logged(
    project_data: Path, hook_input: Any, repo_cwd: Path
) -> None:
    _stop(hook_input, "[VERDICT: APPROVED] ok")
    _summary(repo_cwd)
    assert _refused(repo_cwd).startswith("NOT APPROVED:")


def test_approved_refuses_a_bad_train_id(project_data: Path, repo_cwd: Path) -> None:
    message = _refused(repo_cwd, "../x")
    assert message == (
        "NOT APPROVED: train id ../x is not YYYYMMDD-HHMMSS. "
        "Next: pass the id from a summary file name in docs/.tmp/daedalus/."
    )


def test_approved_reports_a_broken_build_log(
    project_data: Path, hook_input: Any, repo_cwd: Path
) -> None:
    _train(hook_input, repo_cwd, "[VERDICT: APPROVED] ok")
    log = audit.log_path("sess-test", str(repo_cwd))
    lines = log.read_text().splitlines()
    log.write_text(lines[1] + "\n")
    assert _refused(repo_cwd).startswith("BROKEN")
