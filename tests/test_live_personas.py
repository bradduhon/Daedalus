# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import uuid
from pathlib import Path
from typing import Any

import pytest
from verify_audit_chain import verify

from tests.conftest import REPO_ROOT

LEDGER_FIXTURE = REPO_ROOT / "tests" / "fixtures" / "ledgers" / "table.md"
RECORD_KEYS = (
    "seq",
    "event",
    "agent_type",
    "agent_id",
    "tool_name",
    "tool_input.command",
    "decision",
    "reason",
)
LEDGER_SCRIPT = REPO_ROOT / "scripts" / "append_ledger.py"
# Charter-docs contract lines, as agents/charter-docs.md lists them.
CHARTER_STATUS = re.compile(
    r"^\[STATUS: (?:LEDGER_PROBED|LEDGER_APPENDED|LEDGER_MISMATCH|COMMITTED|BLOCKED)\]"
)
CONFIG = {
    "ledger": {
        "path": "docs/decisions.md",
        "format": "markdown-table-row",
        "id_scheme": "{seq:04d}-TST-{type}",
        "sequence_source": "last-row-id",
    },
    "standards_sources": [{"kind": "file", "path": "docs/STANDARDS.md"}],
}
STANDARDS = (
    "# Standards\n\n"
    "1. Every function carries type hints.\n"
    "2. Every function in src/ has a test in tests/.\n"
    "3. No print calls in src/.\n"
)
HELLO = 'def hello(name: str) -> str:\n    return f"hello {name}"\n'
HELLO_TEST = (
    "from src.hello import hello\n\n\n"
    "def test_hello() -> None:\n"
    '    assert hello("x") == "hello x"\n'
)
SPECIALIST_TASK = (
    "Phase 0 only: the frameworks cache directory named in this prompt is "
    "/nonexistent/frameworks. Verify the manifest and report."
)
pytestmark = pytest.mark.live


class LiveRun:
    def __init__(self, result: subprocess.CompletedProcess[str], session: str, repo: Path) -> None:
        self.result = result
        self.session = session
        self.repo = repo


def _field(rec: dict[str, Any], key: str) -> Any:
    value: Any = rec
    for part in key.split("."):
        value = value.get(part) if isinstance(value, dict) else None
    return value


def _fields(rec: dict[str, Any]) -> dict[str, Any]:
    return {k: _field(rec, k) for k in RECORD_KEYS}


def _last_line(text: str) -> str:
    lines = [line for line in text.splitlines() if line.strip()]
    return lines[-1].strip() if lines else ""


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True)


def _persona(name: str, task: str, tools: list[str], repo: Path) -> LiveRun:
    # 0010: the real daedalus namespace only; the probe flag stays unset.
    env = {k: v for k, v in os.environ.items() if k != "DAEDALUS_LIVE_TEST"}
    session = str(uuid.uuid4())
    result = subprocess.run(
        [
            "claude",
            "-p",
            "--plugin-dir",
            str(REPO_ROOT),
            # Operator user-level hooks stay out of the result.
            "--setting-sources",
            "project,local",
            "--agent",
            f"daedalus:{name}",
            "--session-id",
            session,
            "--allowedTools",
            ",".join(tools),
            "--output-format",
            "text",
            task,
        ],
        capture_output=True,
        text=True,
        env=env,
        cwd=repo,
        check=False,
        timeout=300,
    )
    print(f"persona={name} session={session} exit={result.returncode}")
    print(f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}")
    return LiveRun(result, session, repo)


def _records(run: LiveRun) -> list[dict[str, Any]]:
    logs = sorted(
        (run.repo / ".claude" / "daedalus" / "audit").glob("*.jsonl"),
        key=lambda p: p.stat().st_mtime,
    )
    assert logs, f"no audit log under {run.repo}/.claude/daedalus/audit"
    log = logs[-1]
    print(f"audit log: {log.name}")
    assert log.stem == run.session, f"newest audit log {log.name} is not session {run.session}"
    ok, detail = verify(log)
    print(f"chain: {detail}")
    assert ok, detail
    recs = [json.loads(line) for line in log.read_text().splitlines() if line.strip()]
    for r in recs:
        print(json.dumps(_fields(r)))
    return recs


def _check(
    run: LiveRun, name: str, markers: tuple[str, ...], *, block_ok: bool = False
) -> list[dict[str, Any]]:
    recs = _records(run)
    blocks = [
        r
        for r in recs
        if r.get("decision") == "block" and str(r.get("agent_type") or "").endswith(name)
    ]
    print(f"blocks for {name}: {len(blocks)}")
    if not block_ok:
        assert not blocks, [_fields(b) for b in blocks]
    out = run.result.stdout
    found = any(re.search(rf"^{re.escape(m)}", out, re.M) for m in markers)
    assert found, "\n".join(out.splitlines()[-10:])
    return recs


@pytest.fixture
def live_repo(tmp_path: Path) -> Path:
    if shutil.which("claude") is None:
        pytest.skip("claude CLI not on PATH")
    repo = tmp_path.resolve() / "repo"
    (repo / "docs" / ".tmp").mkdir(parents=True)
    (repo / "src").mkdir()
    (repo / "tests").mkdir()
    shutil.copy(LEDGER_FIXTURE, repo / "docs" / "decisions.md")
    (repo / "docs" / "STANDARDS.md").write_text(STANDARDS, encoding="utf-8")
    (repo / "docs" / ".tmp" / ".gitignore").write_text("*\n", encoding="utf-8")
    (repo / "src" / "__init__.py").write_text("", encoding="utf-8")
    (repo / "src" / "hello.py").write_text(HELLO, encoding="utf-8")
    (repo / "tests" / "test_hello.py").write_text(HELLO_TEST, encoding="utf-8")
    (repo / "README.md").write_text("# demo\n\nA demo repo.\n", encoding="utf-8")
    (repo / ".gitignore").write_text("__pycache__/\n*.pyc\n", encoding="utf-8")
    data = repo / ".claude" / "daedalus"
    data.mkdir(parents=True)
    (data / ".gitignore").write_text("*\n", encoding="utf-8")
    (data / "config.json").write_text(json.dumps(CONFIG, indent=2) + "\n", encoding="utf-8")
    subprocess.run(["git", "init", "-q", "-b", "main", str(repo)], check=True)
    _git(repo, "config", "user.email", "live@example.invalid")
    _git(repo, "config", "user.name", "Live Test")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "Initial commit")
    return repo


def test_contract_spec(live_repo: Path) -> None:
    task = (
        "Produce the Locked Contract Packet for a function add(a: int, b: int) -> int "
        "in src/hello.py. No files to read."
    )
    run = _persona("contract-spec", task, ["Read", "Glob", "Grep"], live_repo)
    _check(run, "contract-spec", ("## Locked Contract Packet",))


def test_charter_docs(live_repo: Path) -> None:
    task = (
        f"Run the ledger probe only: python3 {LEDGER_SCRIPT} --probe. "
        "Report its one line and end with your status."
    )
    run = _persona("charter-docs", task, ["Bash", "Read"], live_repo)
    _check(run, "charter-docs", ("[STATUS: LEDGER_PROBED]",))
    last = _last_line(run.result.stdout)
    assert CHARTER_STATUS.match(last), last
    # A probe writes nothing, so an append status is false.
    assert "[STATUS: LEDGER_APPENDED]" not in run.result.stdout, last


def test_repo_coder(live_repo: Path) -> None:
    from lib import train_state
    from lib.unit_binding import record_dispatch
    from lib.workspace import create, mark_train

    commit = ["-c", "user.name=t", "-c", "user.email=t@example.invalid", "-c"]
    _git(live_repo, *commit, "commit.gpgsign=false", "commit", "-q", "--allow-empty", "-m", "base")
    _git(live_repo, "branch", "daedalus/20261015-000000")
    # issue 29: coders write only inside a train, in the unit their dispatch named.
    train_state.save(live_repo, "20261015-000000", {"train_id": "20261015-000000"})
    mark_train(live_repo, "20261015-000000")
    worktree = create(live_repo, "20261015-000000-u1", "daedalus/20261015-000000")
    assert record_dispatch(live_repo, "20261015-000000", "20261015-000000-u1") is None
    task = (
        f"Worktree: {worktree}\n"
        "In that worktree add function add(a: int, b: int) -> int returning a + b to "
        "src/hello.py (create it if absent) with a test in tests/test_hello.py, run pytest "
        "there, commit there with message 'Add add', and end with your completion status."
    )
    tools = ["Read", "Edit", "Write", "Bash", "Glob", "Grep"]
    run = _persona("repo-coder", task, tools, live_repo)
    _check(run, "repo-coder", ("[STATUS: COMPLETE]",))


def test_web_researcher(live_repo: Path) -> None:
    task = (
        "Research question: what is the current stable Python 3 minor version? "
        "Answer under 50 words with one URL."
    )
    run = _persona("web-researcher", task, ["WebSearch", "WebFetch"], live_repo)
    _check(run, "web-researcher", ("[STATUS: RESEARCH]",))


@pytest.mark.parametrize("name", ["nist-specialist", "cis-specialist"])
def test_framework_specialist_without_cache(live_repo: Path, name: str) -> None:
    run = _persona(name, SPECIALIST_TASK, ["Read", "Grep", "Bash"], live_repo)
    _check(run, name, ("[STATUS: CACHE_INVALID]",))


def test_security_auditor(live_repo: Path) -> None:
    readme = live_repo / "README.md"
    readme.write_text(readme.read_text(encoding="utf-8") + "One more line.\n", encoding="utf-8")
    _git(live_repo, "commit", "-q", "-am", "Extend the README")
    task = (
        "Audit the diff between HEAD~1 and HEAD in this repo (a one-line README change) "
        "for the five concerns in your brief. Verdict first."
    )
    run = _persona("security-auditor", task, ["Read", "Bash", "Grep", "Glob"], live_repo)
    _check(run, "security-auditor", ("[VERDICT:",))
    first = next(line for line in run.result.stdout.splitlines() if line.strip())
    assert first.lstrip().startswith("[VERDICT:"), first


def test_pr_train_conductor(live_repo: Path) -> None:
    task = (
        "Preconditions only: this repo has no remote. "
        "Check your preconditions and end with your status line."
    )
    run = _persona("pr-train-conductor", task, ["Bash", "Read"], live_repo)
    _check(run, "pr-train-conductor", ("[STATUS: BLOCKED]",), block_ok=True)


def test_standards_rules_specialist(live_repo: Path) -> None:
    task = (
        "Read docs/STANDARDS.md and produce the Standards Packet for a task that adds "
        "one function to src/hello.py."
    )
    run = _persona("standards-rules-specialist", task, ["Read", "Glob", "Grep"], live_repo)
    _check(run, "standards-rules-specialist", ("## Standards Packet",))
