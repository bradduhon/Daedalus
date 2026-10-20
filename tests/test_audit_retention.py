# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# issue 50, AU-11, AU-9(4): session log rotation in the audit writer.
from __future__ import annotations

import fcntl
import json
import os
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from lib import audit
from lib.audit_proof import verify_lines

from tests.conftest import write_train_marker

DAY = 86400


@pytest.fixture
def repo(project_data: Path) -> Path:
    root = project_data.parents[1]
    write_train_marker(root)
    return root


def _retain(repo: Path, days: int | None) -> None:
    data = repo / ".claude" / "daedalus"
    (data / "config.json").write_text(json.dumps({"audit_retention_days": days}))


def _append(repo: Path, session: str) -> dict[str, Any]:
    payload = {
        "session_id": session,
        "hook_event_name": "PreToolUse",
        "cwd": str(repo),
        "tool_name": "Bash",
        "tool_input": {"command": "ls"},
        "tool_use_id": "t1",
    }
    record = audit.audit_append(payload)
    assert record is not None
    return record


def _log(repo: Path, session: str) -> Path:
    return audit.log_path(session, str(repo))


def _old(repo: Path, session: str, days_ago: float = 100, records: int = 2) -> dict[str, Any]:
    # The config steps aside while an old log is written, so its own first record rotates nothing.
    config = repo / ".claude" / "daedalus" / "config.json"
    saved = config.read_bytes() if config.exists() else None
    config.unlink(missing_ok=True)
    last: dict[str, Any] = {}
    for _ in range(records):
        last = _append(repo, session)
    if saved is not None:
        config.write_bytes(saved)
    stamp = time.time() - days_ago * DAY
    os.utime(_log(repo, session), (stamp, stamp))
    return last


def _records(repo: Path, session: str) -> list[dict[str, Any]]:
    return [json.loads(line) for line in _log(repo, session).read_text().splitlines()]


def _train(repo: Path, days_ago: float, merged: bool) -> None:
    start = datetime.now(UTC) - timedelta(days=days_ago)
    folder = repo / ".claude" / "daedalus" / "trains"
    folder.mkdir(exist_ok=True)
    state = folder / f"{start.strftime('%Y%m%d-%H%M%S')}.json"
    state.write_text(json.dumps({"merged": merged}))


def test_an_old_log_is_deleted_and_named_in_the_new_chain(repo: Path) -> None:
    _retain(repo, 90)
    tail = _old(repo, "old-1")
    _append(repo, "new-1")
    assert not _log(repo, "old-1").exists()
    assert not _log(repo, "old-1").with_suffix(".lock").exists()
    first, rotation = _records(repo, "new-1")
    assert first["event"] == "PreToolUse"
    assert rotation["event"] == audit.ROTATION_EVENT and rotation["seq"] == 2
    assert rotation["session_id"] == "new-1" and rotation["retention_days"] == 90
    assert rotation["rotated"] == [{"session_id": "old-1", "seq": 2, "hash": tail["hash"]}]
    ok, message = verify_lines(_log(repo, "new-1").read_text().splitlines())
    assert ok, message


def test_null_retention_keeps_every_log(repo: Path) -> None:
    _retain(repo, None)
    _old(repo, "old-1", days_ago=400)
    _append(repo, "new-1")
    assert _log(repo, "old-1").exists()
    assert [r["event"] for r in _records(repo, "new-1")] == ["PreToolUse"]


def test_an_empty_rotation_writes_nothing(repo: Path) -> None:
    _retain(repo, 90)
    _old(repo, "recent", days_ago=89)
    _append(repo, "new-1")
    assert _log(repo, "recent").exists()
    assert [r["event"] for r in _records(repo, "new-1")] == ["PreToolUse"]


def test_only_a_session_first_record_rotates(repo: Path) -> None:
    _retain(repo, 90)
    _append(repo, "new-1")
    _old(repo, "old-1")
    _append(repo, "new-1")
    assert _log(repo, "old-1").exists()


def test_a_log_a_summary_names_is_kept(repo: Path) -> None:
    # AU-9: the push gate reads the summary's Session log after the train is merged.
    _retain(repo, 90)
    _old(repo, "pushed-later")
    _old(repo, "unnamed")
    scratch = repo / "docs" / ".tmp" / "daedalus"
    scratch.mkdir(parents=True)
    (scratch / "20260101-000000-summary.md").write_text(
        "Task: x\nSession pushed-later: 4 records\n"
    )
    _append(repo, "new-1")
    assert _log(repo, "pushed-later").exists()
    assert not _log(repo, "unnamed").exists()


def test_an_unmerged_train_keeps_logs_changed_since_its_start(repo: Path) -> None:
    _retain(repo, 90)
    _old(repo, "during", days_ago=100)
    _old(repo, "before", days_ago=300)
    _train(repo, days_ago=200, merged=False)
    _train(repo, days_ago=400, merged=True)
    _append(repo, "new-1")
    assert _log(repo, "during").exists()
    assert not _log(repo, "before").exists()


@pytest.mark.parametrize("body", ["not json", "[1]"])
def test_an_unreadable_train_state_deletes_nothing(
    repo: Path, body: str, capsys: pytest.CaptureFixture[str]
) -> None:
    _retain(repo, 90)
    _old(repo, "old-1")
    folder = repo / ".claude" / "daedalus" / "trains"
    folder.mkdir()
    (folder / "20260101-000000.json").write_text(body)
    record = _append(repo, "new-1")
    assert record["seq"] == 1
    assert _log(repo, "old-1").exists()
    # The jail's stderr is its block reason, so a stopped rotation prints nothing.
    assert capsys.readouterr().err == ""
    assert [r["event"] for r in _records(repo, "new-1")] == ["PreToolUse"]


def test_an_unreadable_summary_deletes_nothing(repo: Path) -> None:
    _retain(repo, 90)
    _old(repo, "old-1")
    scratch = repo / "docs" / ".tmp" / "daedalus"
    scratch.mkdir(parents=True)
    (scratch / "x-summary.md").write_bytes(b"\xff\xfe")
    _append(repo, "new-1")
    assert _log(repo, "old-1").exists()


def test_a_corrupt_old_log_deletes_nothing(repo: Path) -> None:
    _retain(repo, 90)
    _old(repo, "good")
    bad = _log(repo, "bad")
    bad.write_text("{not json\n")
    stamp = time.time() - 100 * DAY
    os.utime(bad, (stamp, stamp))
    _append(repo, "new-1")
    assert bad.exists() and _log(repo, "good").exists()
    assert [r["event"] for r in _records(repo, "new-1")] == ["PreToolUse"]


def test_a_log_another_session_holds_is_kept(repo: Path) -> None:
    _retain(repo, 90)
    _old(repo, "held")
    _old(repo, "free")
    with open(_log(repo, "held").with_suffix(".lock"), "w") as handle:
        fcntl.flock(handle, fcntl.LOCK_EX)
        started = time.monotonic()
        _append(repo, "new-1")
        assert time.monotonic() - started < audit.LOCK_TIMEOUT_S
    assert _log(repo, "held").exists() and not _log(repo, "free").exists()
    rotation = _records(repo, "new-1")[-1]
    assert [r["session_id"] for r in rotation["rotated"]] == ["free"]


def test_a_refused_config_deletes_nothing_and_still_appends(repo: Path) -> None:
    _retain(repo, 30)
    _old(repo, "old-1")
    assert _append(repo, "new-1")["seq"] == 1
    assert _log(repo, "old-1").exists()
