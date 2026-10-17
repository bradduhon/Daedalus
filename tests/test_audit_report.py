# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
from audit_report import md_escape
from lib import audit

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
    _subagent(hook_input, "SubagentStart", "a2", "nist-specialist")
    _agent_calls(hook_input, "a2", "nist-specialist")
    _block(hook_input, "a2", "nist-specialist", BLOCK_CURL)
    _subagent(
        hook_input,
        "SubagentStop",
        "a2",
        "nist-specialist",
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
    assert "- seq 27 nist-specialist: \\[STATUS: YIELD\\_WEB\\] x\n" in out
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
