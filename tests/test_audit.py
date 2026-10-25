# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import pytest
from lib import audit

from tests.conftest import SCRIPTS_DIR, audit_records, write_train_marker


@pytest.fixture
def project_data(project_data: Path, repo_cwd: Path) -> Path:
    write_train_marker(repo_cwd)
    return project_data


def test_cache_dir_requires_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("CLAUDE_PLUGIN_DATA", raising=False)
    with pytest.raises(RuntimeError, match="Next:"):
        audit.cache_dir()


def test_first_record_links_to_genesis(project_data: Path, hook_input: Any) -> None:
    rec = audit.audit_append(hook_input(), "allow", None)
    assert rec["seq"] == 1
    assert rec["prev_hash"] == audit.GENESIS
    assert rec["hash"] == audit.record_hash(rec)
    assert rec["agent_type"] == "main"
    assert rec["decision"] == "allow"


def test_second_record_chains_and_increments(project_data: Path, hook_input: Any) -> None:
    first = audit.audit_append(hook_input())
    second = audit.audit_append(hook_input(tool_use_id="toolu_2"))
    assert second["seq"] == 2
    assert second["prev_hash"] == first["hash"]


def test_log_file_is_owner_only(project_data: Path, hook_input: Any) -> None:
    audit.audit_append(hook_input())
    path = audit.log_path("sess-test", hook_input()["cwd"])
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700


def test_result_head_masks_url_credentials(project_data: Path, hook_input: Any) -> None:
    # F5: git remote get-url output lands in result_head with its userinfo masked.
    body = "https://x-access-token:ghs_secret1@github.com/o/r.git\n"
    rec = audit.audit_append(
        hook_input(hook_event_name="PostToolUse", tool_response={"stdout": body})
    )
    assert "https://***@github.com/o/r.git" in rec["result_head"]
    assert "ghs_secret1" not in rec["result_head"]


def test_result_head_masks_a_url_cut_before_its_at(project_data: Path, hook_input: Any) -> None:
    # R1-M2: userinfo straddling the redaction window never reaches result_head.
    body = "x" * (audit.HEAD_BYTES - 100) + "https://user:" + "P" * 600 + "@host/x"
    rec = audit.audit_append(
        hook_input(hook_event_name="PostToolUse", tool_response={"stdout": body})
    )
    assert "P" not in rec["result_head"]
    assert rec["result_head"].endswith("://***")


def test_short_output_url_is_not_over_masked() -> None:
    # R1-M2: the tail mask applies only when the text was cut.
    assert audit._head("remote is https://h/x") == "remote is https://h/x"


def test_message_head_masks_a_url_crossing_the_cut(project_data: Path, hook_input: Any) -> None:
    # R2-M3: a credential URL straddling MESSAGE_HEAD_CHARS leaves no password behind.
    message = "m" * (audit.MESSAGE_HEAD_CHARS - 20) + "https://u:" + "P" * 600 + "@h/x"
    rec = audit.audit_append(
        hook_input(hook_event_name="SubagentStop", agent_id="a1", last_assistant_message=message)
    )
    assert "P" not in rec["last_message_head"]
    assert len(rec["last_message_head"]) <= audit.MESSAGE_HEAD_CHARS


def test_message_tail_keeps_the_last_2048_chars(project_data: Path, hook_input: Any) -> None:
    # 41: B8, the tail holds the closing verdict line of a long reply.
    message = "word " * 600
    rec = audit.audit_append(
        hook_input(hook_event_name="SubagentStop", agent_id="a1", last_assistant_message=message)
    )
    assert rec["last_message_tail"] == message[-2048:]
    assert len(rec["last_message_tail"]) == 2048


def test_message_tail_masks_a_url_crossing_the_cut(project_data: Path, hook_input: Any) -> None:
    # 41: B9, a credential URL straddling the tail cut leaves no password behind.
    message = "https://u:" + "P" * 600 + "@h/x" + "m" * (audit.MESSAGE_HEAD_CHARS - 20)
    rec = audit.audit_append(
        hook_input(hook_event_name="SubagentStop", agent_id="a1", last_assistant_message=message)
    )
    assert "P" not in rec["last_message_tail"]
    assert rec["last_message_tail"].startswith("***@h/x")
    assert len(rec["last_message_tail"]) <= audit.MESSAGE_HEAD_CHARS


def test_message_tail_masks_a_key_body_that_opens_the_window(
    project_data: Path, hook_input: Any
) -> None:
    # 41: B-1, a bare key body and its END marker past the window start never reach the tail.
    message = ("Q" * 64 + "\n") * 30 + "-----END PRIVATE KEY-----\n" + "m" * 1200
    rec = audit.audit_append(
        hook_input(hook_event_name="SubagentStop", agent_id="a1", last_assistant_message=message)
    )
    assert "Q" not in rec["last_message_tail"]


def test_message_tail_masks_a_token_cut_before_its_prefix(
    project_data: Path, hook_input: Any
) -> None:
    # 41: B-1, a bearer JWT cut inside its header leaves no payload or signature.
    message = "Bearer eyJ" + "A" * 600 + ".eyJ" + "B" * 400 + "." + "C" * 400 + "\n" + "m" * 1400
    rec = audit.audit_append(
        hook_input(hook_event_name="SubagentStop", agent_id="a1", last_assistant_message=message)
    )
    assert "B" not in rec["last_message_tail"]
    assert "C" not in rec["last_message_tail"]


def test_message_tail_is_null_with_the_head(project_data: Path, hook_input: Any) -> None:
    rec = audit.audit_append(
        hook_input(hook_event_name="SubagentStop", agent_id="a1", last_assistant_message="")
    )
    assert rec["last_message_head"] is None and rec["last_message_tail"] is None


def test_read_tool_input_is_reduced_to_path(project_data: Path, hook_input: Any) -> None:
    rec = audit.audit_append(
        hook_input(tool_name="Read", tool_input={"file_path": "/a/b.py", "offset": 10})
    )
    assert rec["tool_input"] == {"file_path": "/a/b.py"}


def test_post_tool_use_stores_digest_and_redacted_head(project_data: Path, hook_input: Any) -> None:
    body = "key AKIAABCDEFGHIJKLMNOP " + "x" * 5000
    rec = audit.audit_append(
        hook_input(hook_event_name="PostToolUse", tool_response={"stdout": body})
    )
    assert rec["result_sha256"] is not None and len(rec["result_sha256"]) == 64
    assert len(rec["result_head"]) <= audit.HEAD_BYTES + len("[REDACTED_AWS_KEY]")
    assert "[REDACTED_AWS_KEY]" in rec["result_head"]
    assert "AKIA" not in rec["result_head"]


def test_lone_surrogate_is_written_and_verifies(project_data: Path, hook_input: Any) -> None:
    audit.audit_append(hook_input(tool_input={"command": "echo \ud800"}))
    result = subprocess.run(
        [
            sys.executable,
            str(SCRIPTS_DIR / "verify_audit_chain.py"),
            str(audit.log_path("sess-test", hook_input()["cwd"])),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0
    assert result.stdout.startswith("OK: 1 records")


def test_partial_tail_line_raises_corrupt_error(project_data: Path, hook_input: Any) -> None:
    audit.audit_append(hook_input())
    path = audit.log_path("sess-test", hook_input()["cwd"])
    with open(path, "a", encoding="utf-8") as fh:
        fh.write('{"seq":2,"prev_ha')
    with pytest.raises(audit.AuditCorruptError):
        audit.audit_append(hook_input(tool_use_id="toolu_2"))


def test_reason_is_redacted(project_data: Path, hook_input: Any) -> None:
    rec = audit.audit_append(hook_input(), "deny", "blocked command export TOKEN=abc")
    assert rec["reason"] == "blocked command export TOKEN=[REDACTED]"


def test_session_id_with_path_traversal_is_rejected(project_data: Path, hook_input: Any) -> None:
    with pytest.raises(ValueError):
        audit.audit_append(hook_input(session_id="../x"))
    with pytest.raises(ValueError):
        audit.log_path("../x", "/tmp")


def test_post_tool_use_failure_stores_error(project_data: Path, hook_input: Any) -> None:
    rec = audit.audit_append(hook_input(hook_event_name="PostToolUseFailure", error="boom"))
    assert rec["error"] == "boom"
    assert rec["source"] is None and rec["stop_reason"] is None


def test_session_start_stores_source(project_data: Path, hook_input: Any) -> None:
    rec = audit.audit_append(hook_input(hook_event_name="SessionStart", source="startup"))
    assert rec["source"] == "startup"
    assert rec["error"] is None


def test_secret_in_command_is_redacted_in_tool_input(project_data: Path, hook_input: Any) -> None:
    rec = audit.audit_append(hook_input(tool_input={"command": "export TOKEN=abc123"}))
    assert rec["tool_input"]["command"] == "export TOKEN=[REDACTED]"


def test_subagent_stop_keeps_bounded_message_head(project_data: Path, hook_input: Any) -> None:
    rec = audit.audit_append(
        hook_input(
            hook_event_name="SubagentStop",
            agent_id="a1",
            agent_type="repo-coder",
            last_assistant_message="[STATUS: COMPLETE] " + "y" * 5000,
        )
    )
    assert rec["last_message_head"].startswith("[STATUS: COMPLETE]")
    assert len(rec["last_message_head"]) == 2048


def test_subagent_stop_record_carries_sha_and_tail(
    project_data: Path, repo_cwd: Path, hook_input: Any
) -> None:
    # AU-3, SC-13: a keyed digest beside the redacted head and tail; the key never leaves 0600.
    import hashlib
    import hmac

    message = "[STATUS: COMPLETE] " + "word " * 600 + "\nlast line"
    rec = audit.audit_append(
        hook_input(
            hook_event_name="SubagentStop",
            agent_id="a1",
            agent_type="daedalus:repo-coder",
            last_assistant_message=message,
        )
    )
    key_file = project_data / audit.REPLY_KEY
    key = key_file.read_bytes()
    assert len(key) == 32 and (key_file.stat().st_mode & 0o777) == 0o600
    want = hmac.new(key, message.encode("utf-8"), hashlib.sha256).hexdigest()
    assert rec["last_message_hmac"] == want
    assert want != hashlib.sha256(message.encode("utf-8")).hexdigest()
    assert rec["last_message_tail"] == message[-2048:]
    assert rec["last_message_head"].startswith("[STATUS: COMPLETE]")
    assert key.hex() not in json.dumps(rec) and "last_message_sha256" not in rec
    again = audit.audit_append(
        hook_input(hook_event_name="SubagentStop", agent_id="a2", last_assistant_message=message)
    )
    assert again["last_message_hmac"] == want and key_file.read_bytes() == key
    plain = audit.audit_append(hook_input())
    assert plain["last_message_hmac"] is None


@pytest.mark.parametrize("damage", ["symlink", "short", "wide"])
def test_damaged_reply_key_refuses_the_record(
    project_data: Path, hook_input: Any, tmp_path: Path, damage: str
) -> None:
    # SI-7: a key that is a link, the wrong size or readable by others writes no record.
    key_file = project_data / audit.REPLY_KEY
    if damage == "symlink":
        target = tmp_path / "elsewhere.key"
        target.write_bytes(b"k" * 32)
        target.chmod(0o600)
        key_file.symlink_to(target)
    else:
        key_file.write_bytes(b"k" * (8 if damage == "short" else 32))
        key_file.chmod(0o644 if damage == "wide" else 0o600)
    with pytest.raises(audit.ReplyKeyError, match="Next: delete"):
        audit.audit_append(
            hook_input(hook_event_name="SubagentStop", last_assistant_message="[STATUS: X]")
        )
    with pytest.raises(audit.ReplyKeyError):
        audit.reply_key(str(project_data.parents[1]), create=False)


def test_concurrent_appends_keep_chain_linear(project_data: Path, repo_cwd: Path) -> None:
    code = (
        "import json,os,sys;sys.path.insert(0,'scripts');from lib import audit;"
        "[audit.audit_append({'session_id':'par','hook_event_name':'PreToolUse',"
        f"'cwd':{str(repo_cwd)!r},"
        "'tool_name':'Bash','tool_input':{'command':'x'}}) for _ in range(25)]"
    )
    env = dict(os.environ)
    procs = [subprocess.Popen([sys.executable, "-c", code], env=env) for _ in range(4)]
    assert all(p.wait() == 0 for p in procs)
    lines = audit.log_path("par", str(repo_cwd)).read_text().splitlines()
    assert len(lines) == 100
    seqs = [rec["seq"] for rec in audit_records(audit.log_path("par", str(repo_cwd)))]
    assert seqs == list(range(1, 101))
    for prev, cur in zip(lines, lines[1:], strict=False):
        assert json.loads(cur)["prev_hash"] == json.loads(prev)["hash"]


def test_token_straddling_head_cut_is_redacted(project_data: Path, hook_input: Any) -> None:
    # m1: the token starts 6 chars before the 4096 cut; truncate-then-redact leaked its prefix.
    text = "a" * (audit.HEAD_BYTES - 6) + "ghp_" + "A" * 36
    post = hook_input(hook_event_name="PostToolUse", tool_response=text)
    rec = audit.audit_append(post)
    assert "ghp_" not in rec["result_head"]
    assert len(rec["result_head"]) == audit.HEAD_BYTES
    fail = hook_input(hook_event_name="PostToolUseFailure", error=text)
    rec = audit.audit_append(fail)
    assert "ghp_" not in rec["error"] and "ghp_" not in rec["result_head"]
    assert len(rec["error"]) == audit.HEAD_BYTES


def test_held_lock_raises_after_deadline(project_data: Path, hook_input: Any) -> None:
    # I6: a stuck holder turns into a RuntimeError at the 5 s deadline, not an endless wait.
    lock = project_data / "audit" / "sess-test.lock"
    lock.parent.mkdir(parents=True)
    holder = subprocess.Popen(
        [
            sys.executable,
            "-c",
            "import fcntl,sys,time;f=open(sys.argv[1],'w');fcntl.flock(f,fcntl.LOCK_EX);"
            "print('held',flush=True);time.sleep(30)",
            str(lock),
        ],
        stdout=subprocess.PIPE,
        text=True,
    )
    try:
        assert holder.stdout is not None and holder.stdout.readline().strip() == "held"
        start = time.monotonic()
        with pytest.raises(RuntimeError, match="audit lock held for 5 s") as exc:
            audit.audit_append(hook_input())
        elapsed = time.monotonic() - start
        # Deleting the lock while the holder still appends would fork the chain.
        assert "Next: find and stop the stuck hook process; do not delete the .lock file." in str(
            exc.value
        )
        assert audit.LOCK_TIMEOUT_S == 5.0
        assert 4.5 <= elapsed < 8.0, elapsed
    finally:
        holder.kill()
        holder.wait()


def _last_record(project_data: Path) -> dict[str, Any]:
    return audit_records(project_data / "audit" / "sess-test.jsonl")[-1]


@pytest.mark.parametrize(
    ("agent", "tool", "tool_input", "prefix"),
    [
        (None, "Bash", {"command": "git clean -fdx"}, "jail: "),
        ("Explore", "Write", {"file_path": "notes.md", "content": "x"}, "jail: "),
    ],
)
def test_main_block_reason_carries_a_prefix(
    run_script: Any,
    project_data: Path,
    hook_input: Any,
    agent: str | None,
    tool: str,
    tool_input: dict[str, str],
    prefix: str,
) -> None:
    # 6.1: main asks and foreign blocks both record the deciding hook as routed blocks do.
    payload = hook_input(tool_name=tool, tool_input=tool_input)
    if agent is not None:
        payload.update(agent_type=agent, agent_id="f1")
    result = run_script("enforce_agent_jail.py", payload)
    rec = _last_record(project_data)
    if agent is None:
        # 0106: the operator's own session is asked, never blocked.
        assert result.returncode == 0, result.stderr
        out = json.loads(result.stdout)["hookSpecificOutput"]
        assert out["permissionDecision"] == "ask"
        assert rec["decision"] == "ask" and rec["reason"].startswith(prefix), rec["reason"]
        return
    assert result.returncode == 2, result.stderr
    assert rec["decision"] == "block" and rec["reason"].startswith(prefix), rec["reason"]
    assert f"]: {prefix}" in result.stderr


def test_subagent_stop_resolves_agent_type_from_its_start(
    project_data: Path, hook_input: Any
) -> None:
    # 6.1: a stop payload without agent_type takes the type its start recorded, never `main`.
    bare = {"tool_name": None, "tool_input": None, "tool_use_id": None}
    audit.audit_append(
        hook_input(hook_event_name="SubagentStart", agent_id="a1", agent_type="auditor", **bare)
    )
    audit.audit_append(
        hook_input(hook_event_name="SubagentStart", agent_id="a2", agent_type="repo-coder", **bare)
    )
    stop = audit.audit_append(hook_input(hook_event_name="SubagentStop", agent_id="a1", **bare))
    assert stop is not None and stop["agent_type"] == "auditor"
    assert stop["hash"] == audit.record_hash(stop)
    orphan = audit.audit_append(hook_input(hook_event_name="SubagentStop", agent_id="zz", **bare))
    assert orphan is not None and orphan["agent_type"] is None
    main = audit.audit_append(hook_input(hook_event_name="Stop", **bare))
    assert main is not None and main["agent_type"] == "main"


def test_judge_start_is_consumed_by_the_next_pre_tool_use_record(
    project_data: Path, hook_input: Any
) -> None:
    # 6.1: the mark fills one PreToolUse record, skips other events, then resets.
    bare = {"tool_name": None, "tool_input": None, "tool_use_id": None}
    audit.mark_judge_start(time.monotonic() - 0.05)
    start = audit.audit_append(hook_input(hook_event_name="SubagentStart", agent_id="a", **bare))
    assert start is not None and start["judge_ms"] is None
    first = audit.audit_append(hook_input(), "allow", None)
    assert first is not None and first["judge_ms"] >= 50
    assert first["hash"] == audit.record_hash(first)
    second = audit.audit_append(hook_input(tool_use_id="toolu_2"), "allow", None)
    assert second is not None and second["judge_ms"] is None


def test_pre_tool_use_record_carries_judge_ms(
    run_script: Any, project_data: Path, hook_input: Any
) -> None:
    # 6.1: judge_ms sits inside the hashed body, so the chain still verifies with it.
    result = run_script("enforce_agent_jail.py", hook_input(tool_input={"command": "git status"}))
    assert result.returncode == 0, result.stderr
    rec = _last_record(project_data)
    assert isinstance(rec["judge_ms"], (int, float)) and rec["judge_ms"] >= 0
    assert '"judge_ms"' in audit.canonical(rec) and rec["hash"] == audit.record_hash(rec)
    bare = {"tool_name": None, "tool_input": None, "tool_use_id": None}
    start = audit.audit_append(hook_input(hook_event_name="SessionStart", **bare))
    assert start is not None and start["judge_ms"] is None
    log = project_data / "audit" / "sess-test.jsonl"
    verify = subprocess.run(
        [sys.executable, str(SCRIPTS_DIR / "verify_audit_chain.py"), str(log)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert verify.returncode == 0 and verify.stdout.startswith("OK: 2 records"), verify
