# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
from lib import audit

from tests.conftest import SCRIPTS_DIR, write_train_marker


@pytest.fixture
def project_data(project_data: Path, repo_cwd: Path) -> Path:
    write_train_marker(repo_cwd)
    return project_data


def _verify(*args: Path | str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPTS_DIR / "verify_audit_chain.py"), *map(str, args)],
        capture_output=True,
        text=True,
        check=False,
    )


def _write_chain(project_data: Path, hook_input: Any, n: int) -> Path:
    for i in range(n):
        audit.audit_append(hook_input(tool_use_id=f"t{i}"))
    return audit.log_path("sess-test", hook_input()["cwd"])


def test_intact_chain_verifies(project_data: Path, hook_input: Any) -> None:
    path = _write_chain(project_data, hook_input, 50)
    result = _verify(path)
    assert result.returncode == 0
    assert result.stdout.startswith("OK: 50 records, chain intact, head=")


def test_tampered_record_is_detected_at_its_line(project_data: Path, hook_input: Any) -> None:
    path = _write_chain(project_data, hook_input, 50)
    lines = path.read_text().splitlines()
    rec = json.loads(lines[24])
    rec["tool_input"]["command"] = "rm -rf /"
    lines[24] = json.dumps(rec, sort_keys=True, separators=(",", ":"))
    path.write_text("\n".join(lines) + "\n")
    result = _verify(path)
    assert result.returncode == 1
    assert result.stdout.startswith("BROKEN line 25: hash mismatch")


def test_deleted_record_breaks_sequence(project_data: Path, hook_input: Any) -> None:
    path = _write_chain(project_data, hook_input, 10)
    lines = path.read_text().splitlines()
    del lines[4]
    path.write_text("\n".join(lines) + "\n")
    result = _verify(path)
    assert result.returncode == 1
    assert "BROKEN line 5: seq 6 != 5" in result.stdout


def test_empty_file_is_ok_zero(project_data: Path) -> None:
    path = project_data / "empty.jsonl"
    path.write_text("")
    result = _verify(path)
    assert result.returncode == 0
    assert result.stdout.startswith("OK: 0 records")


def test_non_object_line_is_broken(tmp_path: Path) -> None:
    path = tmp_path / "s.jsonl"
    path.write_text("[1]\n")
    result = _verify(path)
    assert result.returncode == 1
    assert result.stdout.startswith("BROKEN line 1: not a JSON object")
    assert result.stderr == ""


def test_invalid_utf8_is_broken(tmp_path: Path) -> None:
    path = tmp_path / "s.jsonl"
    path.write_bytes(b"\xff\xfe\n")
    result = _verify(path)
    assert result.returncode == 1
    assert result.stdout == (
        f"BROKEN: {path} is not valid UTF-8. Next: keep the file, report it, do not edit it.\n"
    )
    assert result.stderr == ""


def test_help_prints_usage_and_next() -> None:
    for flag in ("-h", "--help"):
        result = _verify(flag)
        assert result.returncode == 0
        assert result.stdout.startswith("usage: verify_audit_chain.py <session.jsonl>\n")
        nxt = "Next: pass the path of a session log under .claude/daedalus/audit/."
        assert nxt in result.stdout


def test_missing_argument_prints_usage_and_next() -> None:
    result = _verify()
    assert result.returncode == 1
    assert "usage: verify_audit_chain.py" in result.stderr
    assert "Next: pass the path" in result.stderr


def test_nonexistent_path_is_broken_with_next(tmp_path: Path) -> None:
    missing = tmp_path / "nope.jsonl"
    result = _verify(missing)
    assert result.returncode == 1
    assert result.stdout == (
        f"BROKEN: {missing} does not exist. Next: list .claude/daedalus/audit/ "
        "and pass an existing log.\n"
    )
    assert "Traceback" not in result.stderr


def test_directory_path_is_broken_with_next(tmp_path: Path) -> None:
    # M11: a directory argument reports instead of raising IsADirectoryError.
    result = _verify(tmp_path)
    assert result.returncode == 1
    assert result.stdout == (
        f"BROKEN: {tmp_path} is not a regular file. Next: pass a session log (.jsonl) under "
        ".claude/daedalus/audit/.\n"
    )
    assert "Traceback" not in result.stderr


def test_cli_hooks_live_fails_outside_a_hooked_session(project_data: Path, repo_cwd: Path) -> None:
    result = _verify("--hooks-live", "--repo", repo_cwd)
    assert result.returncode == 1
    assert result.stdout.startswith("NOT LIVE:") and "Next:" in result.stdout


def test_cli_hooks_live_passes_on_its_own_record(
    project_data: Path, hook_input: Any, repo_cwd: Path
) -> None:
    command = f"python3 x/verify_audit_chain.py --hooks-live --repo {repo_cwd}"
    audit.audit_append(hook_input(tool_input={"command": command}))
    result = _verify("--hooks-live", "--repo", repo_cwd)
    assert result.returncode == 0, result.stdout
    assert result.stdout.startswith("OK hooks live: session sess-test")


def _approved_train(hook_input: Any, repo_cwd: Path, verdict: str) -> None:
    train = "20261016-120000"
    audit.audit_append(
        hook_input(
            hook_event_name="SubagentStop",
            tool_name=None,
            tool_input=None,
            agent_type="daedalus:security-auditor",
            last_assistant_message=verdict,
        )
    )
    summary = repo_cwd / "docs" / ".tmp" / "daedalus" / f"{train}-summary.md"
    audit.audit_append(hook_input(tool_name="Write", tool_input={"file_path": str(summary)}))
    summary.parent.mkdir(parents=True)
    summary.write_text("Session sess-test: .claude/daedalus/audit/sess-test.jsonl\n")


def test_cli_approved_round_trip(project_data: Path, hook_input: Any, repo_cwd: Path) -> None:
    _approved_train(hook_input, repo_cwd, "[VERDICT: APPROVED] ok")
    result = _verify("--approved", "20261016-120000", "--repo", repo_cwd)
    assert result.returncode == 0, result.stdout
    assert result.stdout == (
        "OK approved: train 20261016-120000, session sess-test, auditor record seq 1\n"
    )


def test_cli_approved_failure_exits_one_with_next(
    project_data: Path, hook_input: Any, repo_cwd: Path
) -> None:
    _approved_train(hook_input, repo_cwd, "[VERDICT: REJECTED] a.py:1 high")
    result = _verify("--approved", "20261016-120000", "--repo", repo_cwd)
    assert result.returncode == 1
    assert result.stdout.startswith("NOT APPROVED:")
    assert "Next: run /daedalus:build-train" in result.stdout


def test_cli_mode_usage_error_exits_one(repo_cwd: Path) -> None:
    result = _verify("--approved", "20261016-120000")
    assert result.returncode == 1
    assert "Next:" in result.stderr
