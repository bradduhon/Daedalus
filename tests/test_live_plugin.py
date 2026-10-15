# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import json
import os
import shutil
import subprocess
import uuid
from pathlib import Path
from typing import Any

import pytest

from tests.conftest import REPO_ROOT

FIXTURE = REPO_ROOT / "tests" / "fixtures" / "live-agent"
RECEIPT_NAME = "2026-10-14-live-plugin.md"
APPENDED = "## Appended results"
WORKER_TOOLS = ["--allowedTools", "Bash(echo *)", "Agent", "SendMessage"]
PROBE = "daedalus-probe:repo-coder"
RECORD_KEYS = (
    "event",
    "agent_type",
    "agent_id",
    "tool_name",
    "decision",
    "reason",
    "result_sha256",
    "last_message_head",
    "cwd",
)
pytestmark = pytest.mark.live


class LiveRun:
    def __init__(self, result: subprocess.CompletedProcess[str], session: str, repo: Path) -> None:
        self.result = result
        self.session = session
        self.repo = repo


def _claude(args: list[str], cwd: Path) -> LiveRun:
    env = dict(os.environ)
    # Jail accepts the daedalus-probe namespace only under this flag.
    env["DAEDALUS_LIVE_TEST"] = "1"
    session = str(uuid.uuid4())
    result = subprocess.run(
        [
            "claude",
            "-p",
            "--session-id",
            session,
            "--plugin-dir",
            str(REPO_ROOT),
            "--plugin-dir",
            str(FIXTURE),
            *args,
        ],
        capture_output=True,
        text=True,
        env=env,
        cwd=cwd,
        check=False,
        timeout=300,
    )
    print(f"session={session} exit={result.returncode}")
    print(f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}")
    return LiveRun(result, session, cwd)


def _records(run: LiveRun) -> list[dict[str, Any]]:
    # 0010: hooks write <repo>/.claude/daedalus, located from the payload cwd.
    log = run.repo / ".claude" / "daedalus" / "audit" / f"{run.session}.jsonl"
    assert log.is_file(), f"no audit log at {log}; plugin hooks did not fire for this session"
    print(f"audit log: {log}")
    recs = [json.loads(line) for line in log.read_text().splitlines()]
    for r in recs:
        print(json.dumps({k: r.get(k) for k in RECORD_KEYS}))
    return recs


def receipt_path(root: Path) -> Path:
    # Receipts: nested private clone when present, else the ignored scratch dir.
    private = root / "docs" / "private" / "verification"
    base = private if private.is_dir() else root / "docs" / ".tmp" / "verification"
    return base / RECEIPT_NAME


def _append_result(line: str, root: Path = REPO_ROOT) -> None:
    receipt = receipt_path(root)
    receipt.parent.mkdir(parents=True, exist_ok=True)
    text = receipt.read_text() if receipt.is_file() else ""
    if APPENDED not in text:
        text = (text.rstrip("\n") + f"\n\n{APPENDED}\n").lstrip("\n")
    receipt.write_text(text.rstrip("\n") + f"\n{line}\n")


@pytest.fixture
def live_repo(tmp_path: Path) -> Path:
    if shutil.which("claude") is None:
        pytest.skip("claude CLI not on PATH")
    repo = tmp_path.resolve() / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    return repo


def test_subagent_hook_payload_fields(live_repo: Path) -> None:
    run = _claude([f"Use the {PROBE} agent once, then say done.", *WORKER_TOOLS], live_repo)
    assert run.result.returncode == 0, run.result.stderr
    recs = _records(run)
    pre = [
        r
        for r in recs
        if r["event"] == "PreToolUse" and r["tool_name"] == "Bash" and r["agent_type"] == PROBE
    ]
    assert pre, "no PreToolUse record from inside the subagent (agent_type absent?)"
    agent_id = pre[0]["agent_id"]
    assert agent_id is not None
    # 0010: a log under live_repo shows hooks saw cwd; allow shows DAEDALUS_LIVE_TEST reached them.
    assert pre[0]["cwd"] is not None and Path(pre[0]["cwd"]).resolve() == live_repo
    assert pre[0]["decision"] == "allow", pre[0]["reason"]
    post = [r for r in recs if r["event"] == "PostToolUse" and r["agent_id"] == agent_id]
    assert post and post[0]["result_sha256"] is not None, "PostToolUse lacks tool_response"
    stop = [r for r in recs if r["event"] == "SubagentStop" and r["agent_id"] == agent_id]
    assert stop and stop[0]["last_message_head"], "SubagentStop lacks last_assistant_message"


def test_plugin_agent_permission_mode_frontmatter(live_repo: Path) -> None:
    # No --allowedTools, so only frontmatter permissionMode can let Bash run in -p.
    run = _claude([f"Use the {PROBE} agent once, then say done."], live_repo)
    recs = _records(run)
    pre = [r for r in recs if r["event"] == "PreToolUse" and r["agent_type"] == PROBE]
    ids = {r["agent_id"] for r in pre}
    ran = any(r["event"] == "PostToolUse" and r["agent_id"] in ids for r in recs)
    failed = [
        r.get("error") for r in recs if r["event"] == "PostToolUseFailure" and r["agent_id"] in ids
    ]
    _append_result(
        f"- session {run.session}: permissionMode honored in plugin agent frontmatter: {ran} "
        f"(exit {run.result.returncode}; probe PreToolUse jail decisions "
        f"{[r.get('decision') for r in pre]}; probe PostToolUseFailure errors {failed})"
    )


def test_sendmessage_resume_keeps_context(live_repo: Path) -> None:
    prompt = (
        f"Spawn the {PROBE} agent with the prompt 'Remember the word PELICAN. Reply PROBE DONE.' "
        "After it returns, use SendMessage to that same agent asking "
        "'What word did I ask you to remember?' Reply to me with exactly the word it returns."
    )
    run = _claude([prompt, *WORKER_TOOLS], live_repo)
    assert run.result.returncode == 0, run.result.stderr
    assert "PELICAN" in run.result.stdout, "resumed agent did not retain context"
    recs = _records(run)
    sends = [
        i
        for i, r in enumerate(recs)
        if r["event"] == "PreToolUse" and r["tool_name"] == "SendMessage"
    ]
    assert sends, "no SendMessage PreToolUse record"
    target = (recs[sends[0]].get("tool_input") or {}).get("to")
    assert target, "SendMessage PreToolUse record names no target agent"
    resumed = [
        r
        for r in recs[sends[0] + 1 :]
        if r["event"] == "SubagentStop"
        and r["agent_id"] == target
        and "PELICAN" in (r["last_message_head"] or "")
    ]
    assert resumed, "no SubagentStop after SendMessage whose reply holds PELICAN"


def _jail_hook(payload: dict[str, Any]) -> subprocess.CompletedProcess[str]:
    env = dict(os.environ, DAEDALUS_LIVE_TEST="1")
    return subprocess.run(
        ["python3", str(REPO_ROOT / "scripts" / "enforce_agent_jail.py")],
        input=json.dumps(payload),
        capture_output=True,
        text=True,
        env=env,
        check=False,
        timeout=30,
    )


def test_train_made_worktree_keeps_root_log_and_jail(live_repo: Path) -> None:
    # 0022, spec 7: a coder in a train-made worktree logs to the main root and keeps its jail.
    from lib.workspace import create

    commit = ["-c", "user.name=t", "-c", "user.email=t@example.invalid", "-c"]
    commit += ["commit.gpgsign=false", "commit", "-q", "--allow-empty", "-m", "init"]
    subprocess.run(["git", "-C", str(live_repo), *commit], check=True)
    subprocess.run(["git", "-C", str(live_repo), "branch", "daedalus/20261015-000000"], check=True)
    wt = create(live_repo, "20261015-000000-u1", "daedalus/20261015-000000")
    good, bad = wt / "src" / "a.py", live_repo / "src" / "a.py"
    # The real hook process, with the coder's cwd in the worktree and then in the main checkout.
    for cwd in (wt, live_repo):
        session = str(uuid.uuid4())
        results = {}
        for target in (good, bad):
            payload = {
                "session_id": session,
                "hook_event_name": "PreToolUse",
                "cwd": str(cwd),
                "agent_type": PROBE,
                "agent_id": "a-1",
                "tool_name": "Write",
                "tool_input": {"file_path": str(target), "content": "ok\n"},
            }
            results[target] = _jail_hook(payload)
        assert results[good].returncode == 0, results[good].stderr
        assert results[bad].returncode == 2, results[bad].stderr
        assert results[bad].stderr.startswith("daedalus-jail[repo-coder]:"), results[bad].stderr
        log = live_repo / ".claude" / "daedalus" / "audit" / f"{session}.jsonl"
        assert log.is_file() and not (wt / ".claude" / "daedalus").exists()
        recs = [json.loads(line) for line in log.read_text().splitlines()]
        for r in recs:
            print(json.dumps({k: r.get(k) for k in (*RECORD_KEYS, "tool_input", "project_root")}))
        got = [(r["tool_input"]["file_path"], r["decision"]) for r in recs]
        assert got == [(str(good), "allow"), (str(bad), "block")], got
        assert all(Path(r["project_root"]) == live_repo for r in recs), recs
    # The same rule through Claude Code itself; the coder's cwd is the main checkout.
    prompt = (
        f"Use the {PROBE} agent once with this prompt: 'Write the file {good} containing ok. "
        f"Write the file {bad} containing x.' Then say done."
    )
    run = _claude([prompt, *WORKER_TOOLS, "Write"], live_repo)
    pre = [r for r in _records(run) if r["event"] == "PreToolUse" and r["agent_type"] == PROBE]
    assert pre, "no PreToolUse record from the coder"
    assert all(Path(r["cwd"]).resolve() == live_repo for r in pre), [r["cwd"] for r in pre]
    assert all(Path(r["project_root"]) == live_repo for r in pre), pre
    writes = {
        (r.get("tool_input") or {}).get("file_path"): r["decision"]
        for r in pre
        if r["tool_name"] == "Write"
    }
    assert writes.get(str(good)) == "allow", writes
    assert writes.get(str(bad)) == "block", writes
    assert good.is_file() and not bad.exists()
    _append_result(
        f"- session {run.session}: train-made worktree coder cwd {pre[0]['cwd']}, writes {writes}"
    )
