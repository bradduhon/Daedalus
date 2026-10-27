# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from audit_report import md_escape
from lib import audit, controls

from tests.conftest import SCRIPTS_DIR, write_train_marker


@pytest.fixture
def project_data(project_data: Path, repo_cwd: Path) -> Path:
    write_train_marker(repo_cwd)
    return project_data


BLOCK_PUSH = (
    "the operator merges; never push to the default branch (0001). "
    "Next: push the unit branch instead."
)
BLOCK_CURL = "daedalus-jail: network egress is not allowed for this agent"
_TOOLS = ("Write", "Edit", "Bash", "Write", "Bash")


def _report(*args: str, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPTS_DIR / "audit_report.py"), *args],
        capture_output=True,
        text=True,
        check=False,
        cwd=cwd,
    )


def test_audit_report_takes_the_audit_lock(
    project_data: Path,
    hook_input: Any,
    repo_cwd: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: Any,
) -> None:
    # issue 10: the report waits on the writer's lock and refuses at a bounded deadline.
    import fcntl

    import audit_report

    audit.audit_append(hook_input())
    log = audit.log_path("sess-test", str(repo_cwd))
    monkeypatch.setattr(audit, "LOCK_TIMEOUT_S", 0.2)
    with open(log.with_suffix(".lock"), "w") as held:
        fcntl.flock(held, fcntl.LOCK_EX)
        assert audit_report.main(["--cwd", str(repo_cwd)]) == 1
    err = capsys.readouterr().err
    assert "audit lock held for 0.2 s" in err and "Next:" in err
    assert audit_report.main(["--cwd", str(repo_cwd)]) == 0


def _agent_calls(hook_input: Any, agent_id: str, agent_type: str) -> None:
    for i, tool in enumerate(_TOOLS):
        base = {"agent_id": agent_id, "agent_type": agent_type, "tool_name": tool}
        audit.audit_append(hook_input(tool_use_id=f"{agent_id}-{i}", **base), decision="allow")
        audit.audit_append(
            hook_input(
                hook_event_name="PostToolUse",
                tool_use_id=f"{agent_id}-{i}",
                tool_response="ok",
                **base,
            )
        )


def _subagent(hook_input: Any, event: str, agent_id: str, agent_type: str, **extra: Any) -> None:
    audit.audit_append(
        hook_input(
            hook_event_name=event,
            agent_id=agent_id,
            agent_type=agent_type,
            tool_name=None,
            tool_input=None,
            tool_use_id=None,
            **extra,
        )
    )


def _block(hook_input: Any, agent_id: str, agent_type: str, reason: str) -> None:
    audit.audit_append(
        hook_input(agent_id=agent_id, agent_type=agent_type, tool_use_id=f"{agent_id}-blk"),
        decision="block",
        reason=reason,
    )


def _synthetic_chain(hook_input: Any) -> Path:
    bare = {"tool_name": None, "tool_input": None, "tool_use_id": None}
    audit.audit_append(hook_input(hook_event_name="SessionStart", source="startup", **bare))
    _subagent(hook_input, "SubagentStart", "a1", "repo-coder")
    _agent_calls(hook_input, "a1", "repo-coder")
    _block(hook_input, "a1", "repo-coder", BLOCK_PUSH)
    _subagent(
        hook_input,
        "SubagentStop",
        "a1",
        "repo-coder",
        last_assistant_message="Built it | twice.\n[STATUS: COMPLETE]",
    )
    _subagent(hook_input, "SubagentStart", "a2", "framework-specialist")
    _agent_calls(hook_input, "a2", "framework-specialist")
    _block(hook_input, "a2", "framework-specialist", BLOCK_CURL)
    _subagent(
        hook_input,
        "SubagentStop",
        "a2",
        "framework-specialist",
        last_assistant_message="Need a source.\n[STATUS: YIELD_WEB] x",
    )
    _subagent(hook_input, "SubagentStart", "a3", "auditor")
    _subagent(
        hook_input,
        "SubagentStop",
        "a3",
        "auditor",
        last_assistant_message="All units pass.\n[VERDICT: APPROVED]",
    )
    audit.audit_append(hook_input(hook_event_name="SessionEnd", **bare))
    return audit.log_path("sess-test", hook_input()["cwd"])


def test_report_renders_every_section(project_data: Path, hook_input: Any) -> None:
    path = _synthetic_chain(hook_input)
    assert len(path.read_text().splitlines()) == 30
    result = _report("--cwd", hook_input()["cwd"])
    assert result.returncode == 0, result.stderr
    out = result.stdout
    assert out.startswith("# Daedalus audit report\n")
    assert "session: sess-test\n" in out
    assert "records: 30\n" in out
    assert re.search(r"^head=[0-9a-f]{64}$", out, re.M)
    assert f"project_root: {md_escape(hook_input()['cwd'])}\n" in out
    assert md_escape(BLOCK_PUSH) in out and md_escape(BLOCK_CURL) in out
    assert "- seq 14 repo-coder: \\[STATUS: COMPLETE\\]\n" in out
    assert "- seq 27 framework-specialist: \\[STATUS: YIELD\\_WEB\\] x\n" in out
    assert "- seq 29 auditor: \\[VERDICT: APPROVED\\]\n" in out
    assert "| a1 | repo-coder | 2 | 14 | Built it \\| twice. \\[STATUS: COMPLETE\\] |" in out
    assert "| repo-coder | Bash | 2 | 1 |" in out
    assert "| repo-coder | Write | 2 | 0 |" in out
    assert "| PreToolUse | 12 |" in out
    assert "| PostToolUse | 10 |" in out


def test_report_head_matches_verifier(project_data: Path, hook_input: Any) -> None:
    path = _synthetic_chain(hook_input)
    tail = json.loads(path.read_text().splitlines()[-1])
    out = _report("--cwd", hook_input()["cwd"], "--session", "sess-test").stdout
    assert f"head={tail['hash']}\n" in out


def test_open_subagent_shows_open(project_data: Path, hook_input: Any) -> None:
    _subagent(hook_input, "SubagentStart", "a9", "repo-coder")
    out = _report("--cwd", hook_input()["cwd"]).stdout
    assert "| a9 | repo-coder | 1 | open |  |" in out


def test_tampered_record_exits_one(project_data: Path, hook_input: Any) -> None:
    path = _synthetic_chain(hook_input)
    lines = path.read_text().splitlines()
    rec = json.loads(lines[11])
    rec["tool_name"] = "Read"
    lines[11] = json.dumps(rec, sort_keys=True, separators=(",", ":"))
    path.write_text("\n".join(lines) + "\n")
    result = _report("--cwd", hook_input()["cwd"])
    assert result.returncode == 1
    assert "BROKEN line 12" in result.stderr
    assert result.stdout == ""


def test_missing_session_exits_one(project_data: Path, hook_input: Any) -> None:
    _synthetic_chain(hook_input)
    result = _report("--cwd", hook_input()["cwd"], "--session", "nosuch")
    assert result.returncode == 1
    assert "Next: list" in result.stderr


def test_invalid_session_id_exits_one(project_data: Path, hook_input: Any) -> None:
    _synthetic_chain(hook_input)
    result = _report("--cwd", hook_input()["cwd"], "--session", "../sess-test")
    assert result.returncode == 1
    assert "Next:" in result.stderr


def test_no_audit_dir_exits_one(repo_cwd: Path) -> None:
    result = _report("--cwd", str(repo_cwd))
    assert result.returncode == 1
    assert "Next:" in result.stderr


def test_non_git_cwd_exits_one(tmp_path: Path) -> None:
    plain = tmp_path / "plain"
    plain.mkdir()
    result = _report("--cwd", str(plain))
    assert result.returncode == 1
    assert "is not inside a git repository. Next:" in result.stderr


def test_default_session_is_newest(project_data: Path, hook_input: Any) -> None:
    audit.audit_append(hook_input(session_id="older"))
    old = audit.log_path("older", hook_input()["cwd"])
    os.utime(old, (1_000_000, 1_000_000))
    audit.audit_append(hook_input(session_id="newer"))
    out = _report("--cwd", hook_input()["cwd"]).stdout
    assert "session: newer\n" in out


def test_out_writes_file_atomically(project_data: Path, hook_input: Any, tmp_path: Path) -> None:
    _synthetic_chain(hook_input)
    target = tmp_path / "report.md"
    result = _report("--cwd", hook_input()["cwd"], "--out", str(target))
    assert result.returncode == 0, result.stderr
    assert result.stdout == f"wrote {target}\n"
    assert "records: 30\n" in target.read_text()
    assert sorted(p.name for p in tmp_path.iterdir() if "report" in p.name) == ["report.md"]


def test_default_cwd_is_process_cwd(project_data: Path, hook_input: Any) -> None:
    _synthetic_chain(hook_input)
    result = _report(cwd=Path(hook_input()["cwd"]))
    assert result.returncode == 0, result.stderr
    assert "records: 30\n" in result.stdout


INJECTION = "</td><img src=x onerror=alert(1)> ![t](http://evil/x.png) ~~s~~ | a"


def _row_columns(row: str) -> int:
    return len(re.findall(r"(?<!\\)\|", row)) - 1


def test_agent_text_renders_inert(project_data: Path, hook_input: Any) -> None:
    _subagent(hook_input, "SubagentStart", "a1", "repo-coder")
    _block(hook_input, "a1", "repo-coder", f"{INJECTION} [STATUS: BLOCKED]")
    _subagent(
        hook_input,
        "SubagentStop",
        "a1",
        "repo-coder",
        last_assistant_message=f"{INJECTION} [STATUS: COMPLETE]",
    )
    result = _report("--cwd", hook_input()["cwd"])
    assert result.returncode == 0, result.stderr
    out = result.stdout
    assert "<" not in out and "![" not in out and "~~" not in out
    row = next(line for line in out.splitlines() if line.startswith("| a1 |"))
    assert _row_columns(row) == 5
    status = [line for line in out.splitlines() if line.startswith("- seq 2 repo-coder: ")]
    assert status == [f"- seq 2 repo-coder: {md_escape(INJECTION + ' [STATUS: BLOCKED]')}"]
    assert "\\!\\[t\\]\\(http://evil/x.png\\)" in status[0]


def test_out_inside_data_dir_is_refused(project_data: Path, hook_input: Any) -> None:
    log = _synthetic_chain(hook_input)
    before = log.read_bytes()
    repo = Path(hook_input()["cwd"])
    for out in (".claude/daedalus/audit/x.jsonl", ".claude/daedalus/audit/sess-test.jsonl"):
        result = _report("--out", out, cwd=repo)
        assert result.returncode == 1
        assert "Next: write the report outside .claude/daedalus/" in result.stderr
    assert log.read_bytes() == before
    assert not (log.parent / "x.jsonl").exists()


def test_invalid_utf8_is_broken(project_data: Path, hook_input: Any) -> None:
    audit_dir = project_data / "audit"
    audit_dir.mkdir()
    (audit_dir / "bad.jsonl").write_bytes(b"\xff\xfe\n")
    result = _report("--cwd", hook_input()["cwd"])
    assert result.returncode == 1
    assert "BROKEN:" in result.stderr and "is not valid UTF-8. Next: keep the file" in result.stderr


def test_empty_log_renders(project_data: Path, hook_input: Any) -> None:
    audit_dir = project_data / "audit"
    audit_dir.mkdir()
    (audit_dir / "empty.jsonl").write_bytes(b"")
    result = _report("--cwd", hook_input()["cwd"])
    assert result.returncode == 0, result.stderr
    assert "records: 0\n" in result.stdout
    assert f"head={'0' * 64}\n" in result.stdout


def test_session_start_only_renders(project_data: Path, hook_input: Any) -> None:
    bare = {"tool_name": None, "tool_input": None, "tool_use_id": None}
    audit.audit_append(hook_input(hook_event_name="SessionStart", source="startup", **bare))
    result = _report("--cwd", hook_input()["cwd"])
    assert result.returncode == 0, result.stderr
    assert "records: 1\n" in result.stdout
    assert "| SessionStart | 1 |" in result.stdout


def test_no_subagent_stop_renders_open(project_data: Path, hook_input: Any) -> None:
    _subagent(hook_input, "SubagentStart", "a1", "repo-coder")
    for i, tool in enumerate(("Write", "Edit")):
        audit.audit_append(
            hook_input(agent_id="a1", agent_type="repo-coder", tool_name=tool, tool_use_id=f"w{i}"),
            decision="allow",
        )
    result = _report("--cwd", hook_input()["cwd"])
    assert result.returncode == 0, result.stderr
    assert "| a1 | repo-coder | 1 | open |  |" in result.stdout
    assert "| repo-coder | Edit | 1 | 0 |" in result.stdout


def test_totals_count_skipped_fork_stops(
    project_data: Path, hook_input: Any, tmp_path: Path
) -> None:
    # 0114: the counter beside the log feeds one totals line; no counter reads 0.
    audit.audit_append(hook_input())
    assert "skipped fork stops: 0\n" in _report("--cwd", hook_input()["cwd"]).stdout
    gone = str(tmp_path / "never-written.jsonl")
    for n in range(3):
        _subagent(hook_input, "SubagentStop", f"f{n}", "", agent_transcript_path=gone)
    result = _report("--cwd", hook_input()["cwd"])
    assert result.returncode == 0, result.stderr
    assert "skipped fork stops: 3\n" in result.stdout
    assert "| SubagentStop |" not in result.stdout


def test_two_resumes_of_one_agent_show_as_two_rows(project_data: Path, hook_input: Any) -> None:
    # 0114: rows key on the start record; a stop with no start since the last stop is a resume.
    _subagent(hook_input, "SubagentStart", "a1", "repo-coder")
    _subagent(hook_input, "SubagentStop", "a1", "repo-coder", last_assistant_message="first")
    _subagent(hook_input, "SubagentStop", "a1", "repo-coder", last_assistant_message="second")
    _subagent(hook_input, "SubagentStop", "a1", "repo-coder", last_assistant_message="third")
    _subagent(hook_input, "SubagentStart", "a1", "repo-coder")
    out = _report("--cwd", hook_input()["cwd"]).stdout
    assert "| a1 | repo-coder | 1 | 2 | first |" in out
    assert "| a1 | repo-coder | resume | 3 | second |" in out
    assert "| a1 | repo-coder | resume | 4 | third |" in out
    assert "| a1 | repo-coder | 5 | open |  |" in out


def test_stop_with_no_earlier_record_keeps_a_dash_start(
    project_data: Path, hook_input: Any
) -> None:
    _subagent(hook_input, "SubagentStop", "a7", "verifier", last_assistant_message="done")
    out = _report("--cwd", hook_input()["cwd"]).stdout
    assert "| a7 | verifier | - | 1 | done |" in out


def test_symlinked_out_is_refused(project_data: Path, hook_input: Any, tmp_path: Path) -> None:
    _synthetic_chain(hook_input)
    outside = tmp_path / "outside.md"
    outside.write_text("keep me\n")
    link = tmp_path / "link.md"
    link.symlink_to(outside)
    result = _report("--cwd", hook_input()["cwd"], "--out", str(link))
    assert result.returncode == 1
    assert "Next: pass a regular file path, not a symlink." in result.stderr
    assert outside.read_bytes() == b"keep me\n"
    assert link.is_symlink()


def test_dangling_symlink_out_is_refused(
    project_data: Path, hook_input: Any, tmp_path: Path
) -> None:
    _synthetic_chain(hook_input)
    missing = tmp_path / "missing.md"
    link = tmp_path / "dangling.md"
    link.symlink_to(missing)
    before = sorted(p.name for p in tmp_path.iterdir())
    result = _report("--cwd", hook_input()["cwd"], "--out", str(link))
    assert result.returncode == 1
    assert "Next: pass a regular file path, not a symlink." in result.stderr
    assert not missing.exists()
    assert sorted(p.name for p in tmp_path.iterdir()) == before


def test_out_into_another_repos_data_dir_is_refused(
    project_data: Path, hook_input: Any, tmp_path: Path
) -> None:
    _synthetic_chain(hook_input)
    other = tmp_path / "other"
    other.mkdir()
    subprocess.run(["git", "init", "-q", "-b", "main", str(other)], check=True)
    (other / ".claude" / "daedalus" / "audit").mkdir(parents=True)
    out = ".claude/daedalus/audit/inj.jsonl"
    result = _report("--cwd", hook_input()["cwd"], "--out", out, cwd=other)
    assert result.returncode == 1
    assert "Next: write the report outside .claude/daedalus/" in result.stderr
    assert not (other / out).exists()


def test_symlink_to_dir_with_trailing_slash_is_refused(
    project_data: Path, hook_input: Any, tmp_path: Path
) -> None:
    _synthetic_chain(hook_input)
    target_dir = tmp_path / "realdir"
    target_dir.mkdir()
    link = tmp_path / "dirlink"
    link.symlink_to(target_dir)
    result = _report("--cwd", hook_input()["cwd"], "--out", f"{link}/")
    assert result.returncode == 1
    assert "Next: pass a file path, not a directory." in result.stderr
    assert link.is_symlink() and os.readlink(link) == str(target_dir)
    assert list(target_dir.iterdir()) == []


def test_file_with_trailing_slash_is_refused(
    project_data: Path, hook_input: Any, tmp_path: Path
) -> None:
    _synthetic_chain(hook_input)
    existing = tmp_path / "existing.md"
    existing.write_text("keep me\n")
    result = _report("--cwd", hook_input()["cwd"], "--out", f"{existing}/")
    assert result.returncode == 1
    assert "Next: pass a file path, not a directory." in result.stderr
    assert existing.read_bytes() == b"keep me\n"


def test_symlink_to_dir_with_dot_is_refused(
    project_data: Path, hook_input: Any, tmp_path: Path
) -> None:
    _synthetic_chain(hook_input)
    target_dir = tmp_path / "dotdir"
    target_dir.mkdir()
    link = tmp_path / "dotlink"
    link.symlink_to(target_dir)
    result = _report("--cwd", hook_input()["cwd"], "--out", f"{link}/.")
    assert result.returncode == 1
    assert "Next: pass a file path, not a directory." in result.stderr
    assert link.is_symlink() and os.readlink(link) == str(target_dir)
    assert list(target_dir.iterdir()) == []


def test_file_with_dot_is_refused(project_data: Path, hook_input: Any, tmp_path: Path) -> None:
    _synthetic_chain(hook_input)
    plain = tmp_path / "plain.txt"
    plain.write_text("keep me\n")
    result = _report("--cwd", hook_input()["cwd"], "--out", f"{plain}/.")
    assert result.returncode == 1
    assert plain.read_bytes() == b"keep me\n"


def test_dot_and_dotdot_out_are_refused(
    project_data: Path, hook_input: Any, tmp_path: Path
) -> None:
    _synthetic_chain(hook_input)
    work = tmp_path / "work"
    work.mkdir()
    for out in (".", ".."):
        result = _report("--cwd", hook_input()["cwd"], "--out", out, cwd=work)
        assert result.returncode == 1
        assert "Next: pass a file path, not a directory." in result.stderr
    assert list(work.iterdir()) == []


def test_fifo_out_is_refused(project_data: Path, hook_input: Any, tmp_path: Path) -> None:
    _synthetic_chain(hook_input)
    fifo = tmp_path / "pipe"
    os.mkfifo(fifo)
    result = _report("--cwd", hook_input()["cwd"], "--out", str(fifo))
    assert result.returncode == 1
    assert "Next: pass a file path, not a directory." in result.stderr
    assert fifo.is_fifo()


def test_case_folded_data_dir_is_refused(project_data: Path, hook_input: Any) -> None:
    _synthetic_chain(hook_input)
    repo = Path(hook_input()["cwd"])
    (repo / ".CLAUDE" / "Daedalus").mkdir(parents=True)
    result = _report("--out", ".CLAUDE/Daedalus/x.md", cwd=repo)
    assert result.returncode == 1
    assert "Next: write the report outside .claude/daedalus/" in result.stderr
    assert not (repo / ".CLAUDE" / "Daedalus" / "x.md").exists()


def test_trailing_backslash_is_a_filename(
    project_data: Path, hook_input: Any, tmp_path: Path
) -> None:
    _synthetic_chain(hook_input)
    target = tmp_path / "x.md\\"
    result = _report("--cwd", hook_input()["cwd"], "--out", str(target))
    assert result.returncode == 0, result.stderr
    assert target.is_file()
    target.unlink()


def test_dash_out_is_refused(project_data: Path, hook_input: Any) -> None:
    _synthetic_chain(hook_input)
    repo = Path(hook_input()["cwd"])
    result = _report("--out", "-", cwd=repo)
    assert result.returncode == 1
    assert "Next: omit --out to print to stdout." in result.stderr
    assert not (repo / "-").exists()


def test_out_under_a_file_says_not_a_directory(
    project_data: Path, hook_input: Any, tmp_path: Path
) -> None:
    _synthetic_chain(hook_input)
    blocker = tmp_path / "plain"
    blocker.write_text("x")
    result = _report("--cwd", hook_input()["cwd"], "--out", str(blocker / "r.md"))
    assert result.returncode == 1
    assert f"{blocker} is not a directory. Next: pass a path under an existing directory." in (
        result.stderr
    )
    assert "does not exist" not in result.stderr


class _Clock:
    # 6.2: one fixed tick per record, so the controls seconds are exact.
    def __init__(self, seconds: list[float]) -> None:
        self._ticks = iter(seconds)

    def now(self, tz: Any) -> datetime:
        return datetime(2026, 10, 19, 10, 0, 0, tzinfo=tz) + timedelta(seconds=next(self._ticks))


REPLY = "SECRET-REPLY-TEXT [STATUS: COMPLETE]"


def _controls_chain(hook_input: Any, monkeypatch: pytest.MonkeyPatch) -> str:
    monkeypatch.setattr(audit, "datetime", _Clock([0, 1, 2, 5, 9, 10, 12, 13, 14, 15]))
    a1 = {"agent_id": "a1", "agent_type": "repo-coder"}
    a2 = {"agent_id": "a2", "agent_type": "auditor"}
    _subagent(hook_input, "SubagentStart", "a1", "repo-coder")
    calls: list[tuple[dict[str, str], str, str, str | None, float]] = [
        (a1, "Bash", "allow", None, 2.0),
        (a1, "Bash", "block", "git_push: no remote git operations. Next: x", 4.0),
        (a1, "Bash", "allow", None, 6.0),
        (a1, "Write", "allow", None, 8.0),
        ({}, "Write", "block", "jail: application code belongs to a unit. Next: x", 10.0),
        ({}, "Bash", "allow", None, 12.0),
    ]
    for i, (who, tool, decision, reason, ms) in enumerate(calls):
        payload = hook_input(tool_name=tool, tool_use_id=f"c{i}", **who)
        audit.audit_append(payload, decision, reason, judge_ms=ms)
    _subagent(hook_input, "SubagentStart", "a2", "auditor")
    audit.audit_append(
        hook_input(tool_use_id="c9", **a2),
        "block",
        "shell_tripwires: pipes are not permitted. Next: x",
        judge_ms=14.0,
    )
    _subagent(hook_input, "SubagentStop", "a2", "auditor", last_assistant_message=REPLY)
    return str(hook_input()["cwd"])


def test_controls_counts_blocks_per_hook(
    project_data: Path, hook_input: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = _controls_chain(hook_input, monkeypatch)
    result = _report("--repo", repo, "--session", "sess-test", "--controls")
    assert result.returncode == 0, result.stderr
    out = result.stdout
    assert "## Control cost" in out and "## Subagent timeline" not in out
    assert "| git\\_push | repo-coder | 1 |" in out
    assert "| jail | main | 1 |" in out
    assert "| shell\\_tripwires | auditor | 1 |" in out
    assert "mean judge time: 8.0 ms over 7 calls" in out
    # Auditor check: no reply text and no reason body enters the controls table.
    assert "SECRET" not in out and "no remote" not in out and "pipes" not in out


def test_controls_prints_one_failure_line_per_blocking_hook(
    project_data: Path, hook_input: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    # pin B2 -> B6: the row's failure for a known hook, failure: none for an unprefixed reason.
    repo = _controls_chain(hook_input, monkeypatch)
    monkeypatch.undo()
    audit.audit_append(hook_input(tool_use_id="u1"), "block", "no hook prefix here")
    audit.audit_append(hook_input(tool_use_id="u2"), "ask", "jail: needs the operator. Next: x")
    out = _report("--repo", repo, "--session", "sess-test", "--controls").stdout
    rows = controls.load()
    section = out.split("### Failure behind each blocking hook\n\n")[1].split("\n\n###")[0]
    assert section.splitlines() == [
        "- git\\_push",
        f"  failure: {rows['checks/git_push'].failure}",
        "- jail",
        f"  failure: {rows['checks/enforce_agent_jail'].failure}",
        "- shell\\_tripwires",
        f"  failure: {rows['checks/shell_tripwires'].failure}",
        "- unprefixed",
        "  failure: none",
    ]


def test_controls_seconds_to_next_allowed_call(
    project_data: Path, hook_input: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = _controls_chain(hook_input, monkeypatch)
    out = _report("--repo", repo, "--controls").stdout
    assert "| 3 | repo-coder | git\\_push | Bash | 3.0 |" in out
    assert "| 6 | main | jail | Write | 2.0 |" in out
    assert "| 9 | auditor | shell\\_tripwires | Bash | none |" in out


def test_controls_seconds_to_first_write_per_agent(
    project_data: Path, hook_input: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = _controls_chain(hook_input, monkeypatch)
    out = _report("--repo", repo, "--controls").stdout
    assert "| a1 | repo-coder | 9.0 |" in out
    assert "| a2 | auditor | none |" in out


def test_controls_shows_ask_as_its_own_row(project_data: Path, hook_input: Any) -> None:
    # 0105: an ask decision is counted beside, not inside, the same hook's blocks.
    for i, decision in enumerate(("ask", "block", "ask")):
        audit.audit_append(
            hook_input(tool_use_id=f"k{i}"), decision, "jail: needs the operator. Next: x"
        )
    out = _report("--repo", hook_input()["cwd"]).stdout
    assert "| jail \\(ask\\) | main | 2 |" in out and "| jail | main | 1 |" in out
    assert "- seq 1 main Bash (ask): jail: needs the operator. Next: x" in out


def test_summary_carries_the_controls_table(
    project_data: Path, hook_input: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = _controls_chain(hook_input, monkeypatch)
    out = _report("--repo", repo).stdout
    assert "## Subagent timeline" in out and "## Control cost" in out
    assert "| jail | main | 1 |" in out and "| a1 | repo-coder | 9.0 |" in out


def test_containment_error_names_the_matched_path(
    project_data: Path, hook_input: Any, tmp_path: Path
) -> None:
    _synthetic_chain(hook_input)
    repo = Path(hook_input()["cwd"])
    link = tmp_path / "into-data"
    link.symlink_to(project_data / "audit")
    result = _report("--cwd", str(repo), "--out", str(link / "x.md"))
    assert result.returncode == 1
    assert f"--out {project_data / 'audit' / 'x.md'} is inside" in result.stderr
    assert not (project_data / "audit" / "x.md").exists()


def _token_report(cwd: str, tmp_path: Path) -> subprocess.CompletedProcess[str]:
    # Plan 11 A: a synthetic config dir, so the token section never reads a real transcript.
    env = {**os.environ, "CLAUDE_CONFIG_DIR": str(tmp_path / "cfg")}
    return subprocess.run(
        [sys.executable, str(SCRIPTS_DIR / "audit_report.py"), "--cwd", cwd],
        capture_output=True,
        text=True,
        check=False,
        env=env,
    )


def test_no_transcript_prints_one_token_line(
    project_data: Path, hook_input: Any, tmp_path: Path
) -> None:
    _synthetic_chain(hook_input)
    result = _token_report(hook_input()["cwd"], tmp_path)
    assert result.returncode == 0, result.stderr
    section = result.stdout.split("## Token economy\n\n", 1)[1]
    assert section.startswith("no agent transcript found for session sess-test under ")
    assert section.count("\n") == 1


def test_token_totals_follow_the_totals_section(
    project_data: Path, hook_input: Any, tmp_path: Path
) -> None:
    _synthetic_chain(hook_input)
    cwd = hook_input()["cwd"]
    slug = re.sub(r"[^A-Za-z0-9]", "-", cwd)
    folder = tmp_path / "cfg" / "projects" / slug / "sess-test" / "subagents"
    folder.mkdir(parents=True)
    stamp = "2026-10-15T12:00:0{}Z"
    lines = [
        {"type": "user", "sessionId": "sess-test", "timestamp": stamp.format(0),
         "message": {"content": "Run Build Train 20261015-120000"}},
        {"type": "assistant", "sessionId": "sess-test", "timestamp": stamp.format(5),
         "message": {"id": "m1", "usage": {"output_tokens": 7}}},
    ]  # fmt: skip
    (folder / "agent-o1.jsonl").write_text("".join(json.dumps(x) + "\n" for x in lines))
    (folder / "agent-o1.meta.json").write_text(json.dumps({"agentType": "daedalus:orchestrator"}))
    out = _token_report(cwd, tmp_path).stdout
    assert out.index("skipped fork stops:") < out.index("## Token economy")
    run = "| Build Train | 20261015-120000 |"
    assert f"{run} total | 1 agents | 0 units, 0 rounds | 1 | 0 | 7 | 0 | 0 | 0m05s |" in out
    assert f"{run} mean | per unit | 0 units | none | none | none | none | none | none |" in out
