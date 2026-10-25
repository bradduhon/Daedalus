# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import fcntl
import json
import os
import re
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any

import pytest
from lib import audit, train_state

from tests.conftest import (
    SCRIPTS_DIR,
    append_handback,
    audit_records,
    replay_auditor,
    write_train_marker,
)


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


def _held(path: Path) -> Any:
    handle = open(path.with_suffix(".lock"), "w")  # noqa: SIM115
    fcntl.flock(handle, fcntl.LOCK_EX)
    return handle


def test_verify_chain_takes_the_audit_lock(
    project_data: Path, hook_input: Any, monkeypatch: pytest.MonkeyPatch, capsys: Any
) -> None:
    # issue 10: a held lock is waited for, then refused at a bounded deadline with a Next line.
    import verify_audit_chain

    path = _write_chain(project_data, hook_input, 2)
    monkeypatch.setattr(audit, "LOCK_TIMEOUT_S", 0.2)
    handle = _held(path)
    try:
        assert verify_audit_chain.main(["verify_audit_chain.py", str(path)]) == 1
    finally:
        handle.close()
    out = capsys.readouterr().out
    assert "audit lock held for 0.2 s" in out and "Next:" in out
    assert verify_audit_chain.main(["verify_audit_chain.py", str(path)]) == 0


def _read_with(reader: str, path: Path) -> int:
    import audit_report
    import verify_audit_chain
    from lib.audit_proof import read_chain

    if reader == "verify":
        ok, message = verify_audit_chain.verify(path)
        assert ok, message
        return int(message.split()[1])
    if reader == "report":
        found = re.search(r"^records: (\d+)$", audit_report.render(path), re.MULTILINE)
        assert found is not None
        return int(found.group(1))
    return len(read_chain(path))


@pytest.mark.parametrize("reader", ["verify", "report", "proof"])
def test_readers_wait_for_a_held_lock_and_do_not_read_a_partial_line(
    project_data: Path, hook_input: Any, reader: str
) -> None:
    # issue 10: a reader that meets an append in flight waits for it, never for half a line.
    path = _write_chain(project_data, hook_input, 3)
    text = path.read_text(encoding="utf-8")
    cut = len(text) - 40
    handle = _held(path)
    path.write_text(text[:cut], encoding="utf-8")

    def finish() -> None:
        time.sleep(0.3)
        with open(path, "a", encoding="utf-8") as out:
            out.write(text[cut:])
        handle.close()

    writer = threading.Thread(target=finish)
    writer.start()
    try:
        assert _read_with(reader, path) == 3
    finally:
        writer.join()


def test_hooks_live_read_and_hook_appends_do_not_deadlock(
    project_data: Path, hook_input: Any, repo_cwd: Path
) -> None:
    # issue 10: the runner's hooks-live read and hook appends serialize; neither waits forever.
    from lib.audit_proof import hooks_live, read_chain
    from lib.train_runner import STEP_NEEDLE

    path = _write_chain(project_data, hook_input, 1)

    def appends() -> None:
        for i in range(30):
            audit.audit_append(hook_input(tool_use_id=f"w{i}"))

    writer = threading.Thread(target=appends)
    writer.start()
    for _ in range(30):
        assert read_chain(path)
    writer.join(timeout=30)
    assert not writer.is_alive()
    step = f"python3 /p/scripts/daedalus_train.py step --repo {repo_cwd}"
    audit.audit_append(hook_input(tool_input={"command": step}))
    assert hooks_live(repo_cwd, STEP_NEEDLE).endswith("chain intact (32 records)")
    with open(path.with_suffix(".lock"), "w") as free:
        fcntl.flock(free, fcntl.LOCK_EX | fcntl.LOCK_NB)


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


def _live_in_process(repo: Path, hook_input: Any, capsys: Any) -> tuple[int, list[str]]:
    import verify_audit_chain

    command = f"python3 x/verify_audit_chain.py --hooks-live --repo {repo}"
    audit.audit_append(hook_input(tool_input={"command": command}))
    code = verify_audit_chain.main(["verify_audit_chain.py", "--hooks-live", "--repo", str(repo)])
    return code, capsys.readouterr().out.splitlines()


def test_hooks_live_names_agent_files_changed_after_the_first_record(
    project_data: Path,
    hook_input: Any,
    repo_cwd: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: Any,
) -> None:
    # spec 6, pin D1 -> D5: the stale line names agent file stems, sorted; the exit stays 0.
    import verify_audit_chain

    agents = tmp_path / "agents"
    agents.mkdir()
    past = time.time() - 3600
    for name in ("security-auditor", "verifier", "repo-coder"):
        (agents / f"{name}.md").write_text("x\n", encoding="utf-8")
        os.utime(agents / f"{name}.md", (past, past))
    (agents / "notes.txt").write_text("x\n", encoding="utf-8")
    monkeypatch.setattr(verify_audit_chain, "AGENTS_DIR", agents)
    code, out = _live_in_process(repo_cwd, hook_input, capsys)
    assert code == 0 and len(out) == 1 and out[0].startswith("OK hooks live:")
    future = time.time() + 60
    for name in ("verifier", "repo-coder"):
        os.utime(agents / f"{name}.md", (future, future))
    os.utime(agents / "notes.txt", (future, future))
    code, out = _live_in_process(repo_cwd, hook_input, capsys)
    assert code == 0 and out[0].startswith("OK hooks live:")
    assert out[1:] == ["stale agents: repo-coder, verifier"]


APPROVED_TRAIN = "20261016-120000"


def _hooks_live_start(hook_input: Any, repo_cwd: Path) -> subprocess.CompletedProcess[str]:
    # issue 57: the train's marker and state, then the CLI hooks-live call that sets start_seq.
    (repo_cwd / ".claude" / "daedalus" / "train.active").write_text(f"{APPROVED_TRAIN}\n")
    train_state.save(repo_cwd, APPROVED_TRAIN, {"train_id": APPROVED_TRAIN})
    command = f"python3 x/verify_audit_chain.py --hooks-live --repo {repo_cwd}"
    audit.audit_append(hook_input(tool_input={"command": command}))
    return _verify("--hooks-live", "--repo", repo_cwd)


def _summary_written(hook_input: Any, repo_cwd: Path) -> None:
    # W3.2: the summary command's record anchors the proof.
    summary = repo_cwd / "docs" / ".tmp" / "daedalus" / f"{APPROVED_TRAIN}-summary.md"
    command = {"command": f"python3 {SCRIPTS_DIR}/daedalus_train.py summary --repo {repo_cwd}"}
    audit.audit_append(hook_input(tool_input=command, tool_use_id="toolu_summary"))
    path = f"docs/.tmp/daedalus/{APPROVED_TRAIN}-summary.md"
    line = f"summary written train={APPROVED_TRAIN} path={path} ledger=recorded\n"
    done = hook_input(
        hook_event_name="PostToolUse",
        tool_input=command,
        tool_use_id="toolu_summary",
        tool_response={"stdout": line, "stderr": ""},
    )
    audit.audit_append(done)
    summary.parent.mkdir(parents=True, exist_ok=True)
    summary.write_text("Session sess-test: .claude/daedalus/audit/sess-test.jsonl\n")


def test_cli_hooks_live_records_start_seq_once(
    project_data: Path, hook_input: Any, repo_cwd: Path
) -> None:
    result = _hooks_live_start(hook_input, repo_cwd)
    assert result.returncode == 0, result.stdout
    assert train_state.load(repo_cwd, APPROVED_TRAIN)["start_seq"] == 1
    command = f"python3 x/verify_audit_chain.py --hooks-live --repo {repo_cwd}"
    audit.audit_append(hook_input(tool_input={"command": command}))
    assert _verify("--hooks-live", "--repo", repo_cwd).returncode == 0
    assert train_state.load(repo_cwd, APPROVED_TRAIN)["start_seq"] == 1


def test_cli_approved_passes_on_train_a_and_refuses_without_its_hand_back(
    project_data: Path, hook_input: Any, repo_cwd: Path
) -> None:
    # issue 57: --approved finds Train A's hand-back; 59: its line names no tip, so it refuses.
    assert _hooks_live_start(hook_input, repo_cwd).returncode == 0
    tip = _tip(repo_cwd)
    replayed = replay_auditor(repo_cwd, "sess-test")
    # 73: the recorded verdict names the hand-back record the auditor's last turn carried.
    _judge(repo_cwd, tip, seq=replayed[-2]["seq"])
    _summary_written(hook_input, repo_cwd)
    result = _verify("--approved", APPROVED_TRAIN, "--repo", repo_cwd)
    assert result.returncode == 1 and "verdict names tip none" in result.stdout
    log = audit.log_path("sess-test", str(repo_cwd))
    log.unlink()
    assert _hooks_live_start(hook_input, repo_cwd).returncode == 0
    replay_auditor(repo_cwd, "sess-test")
    append_handback(hook_input, f"[VERDICT: APPROVED] tip={tip}")
    _judge(repo_cwd, tip, seq=audit_records(log)[-1]["seq"])
    _summary_written(hook_input, repo_cwd)
    result = _verify("--approved", APPROVED_TRAIN, "--repo", repo_cwd)
    assert result.returncode == 0, result.stdout
    assert result.stdout.endswith(f"judged tip {tip[:12]}\n")
    log.unlink()
    assert _hooks_live_start(hook_input, repo_cwd).returncode == 0
    _judge(repo_cwd, tip)
    replay_auditor(repo_cwd, "sess-test", handbacks=False)
    _summary_written(hook_input, repo_cwd)
    refused = _verify("--approved", APPROVED_TRAIN, "--repo", repo_cwd)
    assert refused.returncode == 1 and "is not [VERDICT: APPROVED]" in refused.stdout


def test_cli_approved_ignores_a_verdict_before_start_seq(
    project_data: Path, hook_input: Any, repo_cwd: Path
) -> None:
    # issue 57: an approval logged before this train's hooks-live belongs to an earlier train.
    replay_auditor(repo_cwd, "sess-test")
    assert _hooks_live_start(hook_input, repo_cwd).returncode == 0
    _judge(repo_cwd, _tip(repo_cwd))
    _summary_written(hook_input, repo_cwd)
    result = _verify("--approved", APPROVED_TRAIN, "--repo", repo_cwd)
    assert result.returncode == 1
    assert "no daedalus:security-auditor reply after seq 7" in result.stdout


def _tip(repo: Path) -> str:
    # 59: one commit on the integration branch, the tip the auditor judges.
    ident = ["-c", "user.name=t", "-c", "user.email=t@example.invalid"]
    git = ["git", "-C", str(repo)]
    subprocess.run([*git, *ident, "commit", "-q", "--allow-empty", "-m", "u"], check=True)
    subprocess.run([*git, "branch", "-f", f"daedalus/{APPROVED_TRAIN}", "HEAD"], check=True)
    out = subprocess.run([*git, "rev-parse", "HEAD"], capture_output=True, text=True, check=True)
    return out.stdout.strip()


def _judge(repo: Path, tip: str, status: str = "approved", seq: int = 1) -> None:
    verdict = {"status": status, "tip": tip, "round": 1, "seq": seq}
    train_state.update(repo, APPROVED_TRAIN, verdict=verdict)


def _approved_train(hook_input: Any, repo_cwd: Path, verdict: str) -> None:
    assert _hooks_live_start(hook_input, repo_cwd).returncode == 0
    audit.audit_append(
        hook_input(
            hook_event_name="SubagentStop",
            tool_name=None,
            tool_input=None,
            agent_type="daedalus:security-auditor",
            last_assistant_message=verdict,
        )
    )
    _summary_written(hook_input, repo_cwd)


def test_cli_approved_round_trip(project_data: Path, hook_input: Any, repo_cwd: Path) -> None:
    tip = _tip(repo_cwd)
    _approved_train(hook_input, repo_cwd, f"[VERDICT: APPROVED] tip={tip} ok")
    _judge(repo_cwd, tip, seq=2)
    result = _verify("--approved", "20261016-120000", "--repo", repo_cwd)
    assert result.returncode == 0, result.stdout
    assert result.stdout == (
        "OK approved: approved verdict, train 20261016-120000, session sess-test, "
        f"auditor record seq 2, judged tip {tip[:12]}\n"
    )


def test_cli_approved_prints_the_exception_path(
    project_data: Path, hook_input: Any, repo_cwd: Path
) -> None:
    # 62: a train merged on an exception ruling bound to the current tip passes, and says so.
    tip = _tip(repo_cwd)
    _approved_train(hook_input, repo_cwd, f"[VERDICT: REJECTED] tip={tip} a.py:1 high")
    _judge(repo_cwd, tip, "rejected")
    refused = _verify("--approved", APPROVED_TRAIN, "--repo", repo_cwd)
    assert refused.returncode == 1 and refused.stdout.startswith("NOT APPROVED:")
    exception = {"ledger_id": "0113-DAE-PLT", "tip": tip}
    train_state.update(repo_cwd, APPROVED_TRAIN, exception=exception)
    result = _verify("--approved", APPROVED_TRAIN, "--repo", repo_cwd)
    assert result.returncode == 0, result.stdout
    assert result.stdout == (
        f"OK approved: exception 0113-DAE-PLT, train {APPROVED_TRAIN}, integration tip {tip[:12]}\n"
    )
    train_state.update(repo_cwd, APPROVED_TRAIN, exception={**exception, "tip": "c" * 40})
    assert _verify("--approved", APPROVED_TRAIN, "--repo", repo_cwd).returncode == 1


def test_second_hooks_live_in_a_new_session_moves_the_bound(
    project_data: Path, hook_input: Any, repo_cwd: Path
) -> None:
    # issue 60: a train resumed in a new session bounds its verdict search in that session's log.
    from lib import train_runner

    _write_chain(project_data, hook_input, 20)
    assert _hooks_live_start(hook_input, repo_cwd).returncode == 0
    first = train_state.load(repo_cwd, APPROVED_TRAIN)
    assert (first["start_seq"], first["audit_session"]) == (21, "sess-test")
    tip = _tip(repo_cwd)
    audit.audit_append(hook_input(session_id="sess-new", tool_use_id="n1"))
    command = f"python3 x/verify_audit_chain.py --hooks-live --repo {repo_cwd}"
    audit.audit_append(hook_input(session_id="sess-new", tool_input={"command": command}))
    assert _verify("--hooks-live", "--repo", repo_cwd).returncode == 0
    moved = train_state.load(repo_cwd, APPROVED_TRAIN)
    assert (moved["start_seq"], moved["audit_session"]) == (2, "sess-new")
    assert moved["audit_bounds"] == {"sess-test": 21, "sess-new": 2}
    audit.audit_append(
        hook_input(
            session_id="sess-new",
            hook_event_name="SubagentStop",
            tool_name=None,
            tool_input=None,
            agent_type="daedalus:security-auditor",
            last_assistant_message=f"[VERDICT: APPROVED] tip={tip}",
        )
    )
    verdict = f"python3 x/daedalus_train.py verdict --repo {repo_cwd}"
    audit.audit_append(hook_input(session_id="sess-new", tool_input={"command": verdict}))
    # The auditor reply is seq 3 of the new log, below the old session's bound of 21.
    outcome = train_runner.record_verdict(repo_cwd, "approved", 1, tip=tip)
    assert outcome.code == 0, outcome.lines
    # A verdict call from the old session no longer owns the bound and refuses.
    audit.audit_append(hook_input(tool_input={"command": verdict}))
    stale = train_runner.record_verdict(repo_cwd, "approved", tip=tip)
    assert stale.code == 1
    assert "belongs to session sess-new, not this session sess-test" in stale.lines[0]


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
