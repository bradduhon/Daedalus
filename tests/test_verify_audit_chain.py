# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

from lib import audit

from tests.conftest import SCRIPTS_DIR


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
