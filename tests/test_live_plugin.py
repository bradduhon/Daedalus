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

from tests.conftest import REPO_ROOT, audit_records, git
from tests.live import LiveRun, require_claude, run_claude

FIXTURE = REPO_ROOT / "tests" / "fixtures" / "live-agent"
RECEIPT_NAME = "2026-10-14-live-plugin.md"
APPENDED = "## Appended results"
WORKER_TOOLS = ["--allowedTools", "Bash(echo *)", "Agent", "SendMessage"]
PROBE = "daedalus-probe:repo-coder"
TRAIN = "20261015-000000"
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


def _claude(args: list[str], cwd: Path) -> LiveRun:
    env = dict(os.environ)
    # Jail accepts the daedalus-probe namespace only under this flag.
    env["DAEDALUS_LIVE_TEST"] = "1"
    session = str(uuid.uuid4())
    argv = ["--session-id", session, "--plugin-dir", str(REPO_ROOT), "--plugin-dir", str(FIXTURE)]
    return run_claude([*argv, *args], session, cwd, env)


def _records(run: LiveRun) -> list[dict[str, Any]]:
    # 0010: hooks write <repo>/.claude/daedalus, located from the payload cwd.
    log = run.repo / ".claude" / "daedalus" / "audit" / f"{run.session}.jsonl"
    assert log.is_file(), f"no audit log at {log}; plugin hooks did not fire for this session"
    print(f"audit log: {log}")
    recs = audit_records(log)
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


def _train(repo: Path, *names: str) -> list[Path]:
    # issue 29: coders write only inside a train, each in the unit its dispatch named.
    from lib import train_state
    from lib.workspace import create, mark_train

    git(repo, "commit", "-q", "--allow-empty", "-m", "init")
    git(repo, "branch", f"daedalus/{TRAIN}")
    (repo / ".claude" / "daedalus").mkdir(parents=True, exist_ok=True)
    train_state.save(repo, TRAIN, {"train_id": TRAIN})
    mark_train(repo, TRAIN)
    return [create(repo, f"{TRAIN}-{name}", f"daedalus/{TRAIN}") for name in names]


@pytest.fixture
def live_repo(tmp_path: Path) -> Path:
    require_claude()
    repo = tmp_path.resolve() / "repo"
    repo.mkdir()
    git(repo, "init", "-q")
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
    from lib.unit_binding import record_dispatch

    wt, wt2 = _train(live_repo, "u1", "u2")
    assert record_dispatch(live_repo, TRAIN, f"{TRAIN}-u1") is None
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
        recs = audit_records(log)
        for r in recs:
            print(json.dumps({k: r.get(k) for k in (*RECORD_KEYS, "tool_input", "project_root")}))
        got = [(r["tool_input"]["file_path"], r["decision"]) for r in recs]
        assert got == [(str(good), "allow"), (str(bad), "block")], got
        assert all(Path(r["project_root"]) == live_repo for r in recs), recs
    # The same rule through Claude Code itself; the coder's cwd is the main checkout.
    good = wt2 / "src" / "a.py"
    prompt = (
        f"Use the {PROBE} agent once. Its prompt is exactly these three lines:\n"
        f"Worktree: {wt2}\nWrite the file {good} containing ok.\n"
        f"Write the file {bad} containing x.\nThen say done."
    )
    # Operator user-level hooks stay out of the result.
    run = _claude([prompt, *WORKER_TOOLS, "Write", "--setting-sources", "project,local"], live_repo)
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


def test_coder_write_outside_its_worktree_is_refused_through_the_router(live_repo: Path) -> None:
    # 0044: the real hook process routes the coder's write to unit_writes, which refuses it.
    from lib.unit_binding import record_dispatch

    (wt,) = _train(live_repo, "u1")
    assert record_dispatch(live_repo, TRAIN, f"{TRAIN}-u1") is None
    session = str(uuid.uuid4())
    results = {}
    for target in (wt / "src" / "a.py", live_repo / "src" / "a.py"):
        payload = {
            "session_id": session,
            "hook_event_name": "PreToolUse",
            "cwd": str(live_repo),
            "agent_type": PROBE,
            "agent_id": "a-1",
            "tool_name": "Write",
            "tool_input": {"file_path": str(target), "content": "ok\n"},
        }
        results[target] = _jail_hook(payload)
    good, bad = results.values()
    assert good.returncode == 0, good.stderr
    assert bad.returncode == 2, bad.stderr
    assert bad.stderr.startswith("daedalus-jail[repo-coder]: unit_writes: "), bad.stderr
    log = live_repo / ".claude" / "daedalus" / "audit" / f"{session}.jsonl"
    recs = audit_records(log)
    for r in recs:
        print(json.dumps({k: r.get(k) for k in RECORD_KEYS}))
    assert [r["decision"] for r in recs] == ["allow", "block"], recs
    assert recs[0]["reason"] is None
    assert str(recs[1]["reason"]).startswith("unit_writes: "), recs[1]["reason"]
    _append_result(f"- session {session}: router refusal reason {recs[1]['reason']}")


def _saved_reply_run(repo: Path) -> tuple[LiveRun, list[dict[str, Any]], Path]:
    # spec 3.5 ASSUMED: the session saves the agent's reply with Write, as the runner asks.
    _train(repo)
    saved = repo / "docs" / ".tmp" / "daedalus" / TRAIN / "replies" / "probe-1.md"
    prompt = (
        f"Use the {PROBE} agent once with the prompt 'Reply now.'. When it returns, use the "
        f"Write tool to save its reply text exactly as returned, with nothing added, to {saved}. "
        "Then say done."
    )
    run = _claude([prompt, *WORKER_TOOLS, "Write"], repo)
    return run, _records(run), saved


def test_last_assistant_message_equals_the_agent_reply(live_repo: Path) -> None:
    from lib.audit import message_hmac, reply_key

    run, recs, saved = _saved_reply_run(live_repo)
    stops = [r for r in recs if r["event"] == "SubagentStop" and r["agent_type"] == PROBE]
    assert stops and saved.is_file(), "no probe stop record or no saved reply"
    mac = message_hmac(reply_key(str(live_repo), create=False), saved.read_bytes())
    equal = stops[-1]["last_message_hmac"] == mac
    _append_result(f"- session {run.session}: saved reply keyed digest equals the record: {equal}")
    assert equal


def test_subagent_stop_lands_before_the_next_tool_call(live_repo: Path) -> None:
    run, recs, _ = _saved_reply_run(live_repo)
    agent = next(
        i for i, r in enumerate(recs) if r["event"] == "PreToolUse" and r["tool_name"] == "Agent"
    )
    after = next(
        i
        for i, r in enumerate(recs)
        if i > agent and r["event"] == "PreToolUse" and r["agent_id"] is None
    )
    stop = [i for i, r in enumerate(recs) if r["event"] == "SubagentStop" and agent < i < after]
    _append_result(
        f"- session {run.session}: SubagentStop seq before next main PreToolUse: {bool(stop)}"
    )
    assert stop and recs[stop[0]]["seq"] < recs[after]["seq"]


def _span(recs: list[dict[str, Any]], agent_id: str) -> tuple[str, str]:
    mine = [r for r in recs if r["agent_id"] == agent_id]
    start = next(r["ts"] for r in mine if r["event"] == "SubagentStart")
    stop = next(r["ts"] for r in mine if r["event"] == "SubagentStop")
    return start, stop


def test_parallel_coders_stay_in_their_units(live_repo: Path) -> None:
    # issue 29, spec 4.1: two coders dispatched in one turn each write only their own unit.
    from lib.workspace import begin, create
    from verify_audit_chain import verify

    ledger = live_repo / "docs" / "decisions.md"
    ledger.parent.mkdir()
    shutil.copy(REPO_ROOT / "tests" / "fixtures" / "ledgers" / "table.md", ledger)
    git(live_repo, "add", "-A")
    git(live_repo, "commit", "-q", "-m", "init")
    seed = begin(live_repo)
    train = seed[0].split()[1]
    # 0011: lock creates the integration branch in a real train; this test has no contract.
    git(live_repo, "branch", f"daedalus/{train}")
    w1, w2 = (create(live_repo, f"{train}-{n}", f"daedalus/{train}") for n in ("u1", "u2"))
    own = {w1: w1 / "src" / "one.py", w2: w2 / "src" / "two.py"}
    stray = {w1: w2 / "src" / "stray1.py", w2: w1 / "src" / "stray2.py"}
    prompts = [
        f"Worktree: {w}\nWrite the file {own[w]} containing ok.\n"
        f"Write the file {stray[w]} containing x.\n"
        for w in (w1, w2)
    ]
    prompt = (
        f"In one single message, make two {PROBE} Agent tool calls at once, in parallel.\n"
        f"The first agent's prompt is exactly these three lines:\n{prompts[0]}"
        f"The second agent's prompt is exactly these three lines:\n{prompts[1]}"
        "When both return, say done."
    )
    # Operator user-level hooks stay out of the result.
    sources = ["--setting-sources", "project,local"]
    run = _claude([prompt, *WORKER_TOOLS, "Write", *sources], live_repo)
    recs = _records(run)
    ok, detail = verify(live_repo / ".claude" / "daedalus" / "audit" / f"{run.session}.jsonl")
    assert ok, detail
    pre = [r for r in recs if r["event"] == "PreToolUse" and r["agent_type"] == PROBE]
    writes = {
        (r.get("tool_input") or {}).get("file_path"): (r["decision"], r.get("reason"))
        for r in pre
        if r["tool_name"] == "Write"
    }
    for w in (w1, w2):
        assert writes.get(str(own[w]), ("missing",))[0] == "allow", writes
        decision, reason = writes.get(str(stray[w]), ("missing", None))
        assert decision == "block" and "issue 29" in str(reason), writes
        assert own[w].is_file() and not stray[w].exists()
    coders = sorted({r["agent_id"] for r in pre})
    assert len(coders) == 2, coders
    (s1, e1), (s2, e2) = (_span(recs, c) for c in coders)
    overlap = s1 < e2 and s2 < e1
    _append_result(
        f"- session {run.session}: parallel coders {coders} spans {s1}..{e1} and {s2}..{e2}, "
        f"overlap {overlap}; writes {writes}"
    )
