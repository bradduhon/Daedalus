# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import uuid
from pathlib import Path
from typing import Any

import pytest
from verify_audit_chain import verify

from tests.conftest import REPO_ROOT, audit_records
from tests.conftest import git as _git
from tests.live import LiveRun, require_claude, run_claude

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
    "Phase 0 only.\nPacks: /nonexistent/packs/aws-default\nVerify the pack and report."
)
pytestmark = pytest.mark.live


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


def _persona(name: str, task: str, tools: list[str], repo: Path) -> LiveRun:
    # 0010: the real daedalus namespace only; the probe flag stays unset.
    env = {k: v for k, v in os.environ.items() if k != "DAEDALUS_LIVE_TEST"}
    session = str(uuid.uuid4())
    argv = [
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
    ]
    return run_claude(argv, session, repo, env, label=f"persona={name} ")


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
    recs = audit_records(log)
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
    require_claude()
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
    _git(repo, "init", "-q", "-b", "main")
    _git(repo, "config", "user.email", "live@example.invalid")
    _git(repo, "config", "user.name", "Live Test")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "Initial commit")
    return repo


# W1.4: personas whose live check is one task, one tool list and the status lines they may end on.
SIMPLE_PERSONAS = [
    pytest.param(
        "contract-spec",
        "Produce the Locked Contract Packet for a function add(a: int, b: int) -> int "
        "in src/hello.py. No files to read.",
        ["Read", "Glob", "Grep"],
        ("## Locked Contract Packet",),
        False,
        id="contract-spec",
    ),
    pytest.param(
        "web-researcher",
        "Research question: what is the current stable Python 3 minor version? "
        "Answer under 50 words with one URL.",
        ["WebSearch", "WebFetch"],
        ("[STATUS: RESEARCH]",),
        False,
        id="web-researcher",
    ),
    pytest.param(
        "releaser",
        "Preconditions only: this repo has no remote. "
        "Check your preconditions and end with your status line.",
        ["Bash", "Read"],
        ("[STATUS: BLOCKED]",),
        True,
        id="releaser",
    ),
    pytest.param(
        "standards-rules-specialist",
        "Read docs/STANDARDS.md and produce the Standards Packet for a task that adds "
        "one function to src/hello.py.",
        ["Read", "Glob", "Grep"],
        ("## Standards Packet",),
        False,
        id="standards-rules-specialist",
    ),
]


@pytest.mark.parametrize("name, task, tools, markers, block_ok", SIMPLE_PERSONAS)
def test_simple_persona(
    live_repo: Path,
    name: str,
    task: str,
    tools: list[str],
    markers: tuple[str, ...],
    block_ok: bool,
) -> None:
    run = _persona(name, task, tools, live_repo)
    _check(run, name, markers, block_ok=block_ok)


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


def test_coder(live_repo: Path) -> None:
    from lib import train_state
    from lib.unit_binding import record_dispatch
    from lib.workspace import create, mark_train

    _git(live_repo, "commit", "-q", "--allow-empty", "-m", "base")
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
    run = _persona("coder", task, tools, live_repo)
    _check(run, "coder", ("[STATUS: COMPLETE]",))


def test_framework_specialist_without_its_pack(live_repo: Path) -> None:
    name = "framework-specialist"
    run = _persona(name, SPECIALIST_TASK, ["Read", "Grep", "Bash"], live_repo)
    _check(run, name, ("[STATUS: PACK_INVALID]",))


def test_auditor(live_repo: Path) -> None:
    readme = live_repo / "README.md"
    readme.write_text(readme.read_text(encoding="utf-8") + "One more line.\n", encoding="utf-8")
    _git(live_repo, "commit", "-q", "-am", "Extend the README")
    task = (
        "Audit the diff between HEAD~1 and HEAD in this repo (a one-line README change) "
        "for the five concerns in your brief. Verdict first."
    )
    run = _persona("auditor", task, ["Read", "Bash", "Grep", "Glob"], live_repo)
    _check(run, "auditor", ("[VERDICT:",))
    first = next(line for line in run.result.stdout.splitlines() if line.strip())
    assert first.lstrip().startswith("[VERDICT:"), first


PLANTED_TRAIN = "20261015-000000"
# spec 6: an injection the auditor's fixed shell=True pickaxe finds; a test can prove it.
PLANTED_DEFECT = (
    "import subprocess\n\n\n"
    "def greet(name: str) -> str:\n"
    '    cmd = f"echo hello {name}"\n'
    "    return subprocess.run(cmd, shell=True, capture_output=True, text=True).stdout\n"
)
REJECTED_LINE = re.compile(r"^\[VERDICT: REJECTED\] tip=([0-9a-f]{40})$")


def test_auditor_files_a_planted_defect_as_a_failing_test(live_repo: Path) -> None:
    # spec 6: round 1 on a planted defect writes a failing test, a findings line and tip=.
    from lib import train_state
    from lib.workspace import create, mark_train

    base = _git(live_repo, "rev-parse", "HEAD").stdout.strip()
    integration = f"daedalus/{PLANTED_TRAIN}"
    _git(live_repo, "switch", "-q", "-c", integration)
    (live_repo / "src" / "run.py").write_text(PLANTED_DEFECT, encoding="utf-8")
    _git(live_repo, "add", "src/run.py")
    _git(live_repo, "commit", "-q", "-m", "Add greet")
    tip = _git(live_repo, "rev-parse", "HEAD").stdout.strip()
    _git(live_repo, "switch", "-q", "main")
    train_state.save(live_repo, PLANTED_TRAIN, {"train_id": PLANTED_TRAIN})
    mark_train(live_repo, PLANTED_TRAIN)
    worktree = create(live_repo, f"{PLANTED_TRAIN}-audit", integration)
    round_dir = live_repo / "docs" / ".tmp" / "daedalus" / PLANTED_TRAIN / "audit" / "round1"
    task = (
        f"Diff base: {base}\nBranch: {integration}\n"
        f"Units and their changed files: u1: src/run.py\n"
        "Packet: none (no contract for this round); compliance reports: none.\n"
        f"Round: 1. Findings file: {round_dir / 'findings.txt'}\n"
        f"Worktree: {worktree}\n"
        "Audit the branch by your procedure and end with your verdict line."
    )
    run = _persona("auditor", task, ["Read", "Bash", "Grep", "Glob", "Write"], live_repo)
    _check(run, "auditor", ("[VERDICT: REJECTED]",), block_ok=True)
    verdict = REJECTED_LINE.match(_last_line(run.result.stdout))
    assert verdict, _last_line(run.result.stdout)
    assert verdict.group(1) == tip
    tests = sorted(round_dir.glob("test_*.py"))
    assert tests, f"no audit test under {round_dir}"
    findings = (round_dir / "findings.txt").read_text(encoding="utf-8").splitlines()
    keys = [line.split(" | ", 1)[0].strip() for line in findings if line.strip()]
    named = [k for k in keys if k.split("::", 1)[0] in {f"audit/round1/{t.name}" for t in tests}]
    assert named, findings
    failing = round_dir.parent.parent / named[0].split("::", 1)[0]
    result = subprocess.run(
        [sys.executable, "-m", "pytest", str(failing), "-q", "-p", "no:cacheprovider"]
        + ["--rootdir", str(worktree)],
        capture_output=True,
        text=True,
        cwd=worktree,
        check=False,
        timeout=120,
    )
    print(result.stdout)
    assert result.returncode != 0, "the audit test passes on the judged tip"


def test_dependency_auditor(live_repo: Path) -> None:
    # 0132: off the network with the lookup off, it judges the lockfile and lists PASS/FAIL.
    (live_repo / "requirements.txt").write_text("requests==2.32.3\n", encoding="utf-8")
    _git(live_repo, "add", "requirements.txt")
    _git(live_repo, "commit", "-q", "-m", "Add requests")
    task = (
        f"Diff base: HEAD~1\nBranch: HEAD\nRepo: {live_repo}\n"
        "Changed dependency files: requirements.txt\nWeb lookup: off\n"
        "Judge the change by your method and end with your status line."
    )
    run = _persona("dependency-auditor", task, ["Read", "Bash", "Grep", "Glob"], live_repo)
    _check(run, "dependency-auditor", ("[STATUS: COMPLIANCE]",))
    assert "DEP-5" in run.result.stdout


def test_terraform_reviewer(live_repo: Path) -> None:
    # 0132: TF-0 records the binary check; a missing or refused run is a warning, never a FAIL.
    tf = 'variable "region" {\n  type = string\n}\n'
    (live_repo / "main.tf").write_text(tf, encoding="utf-8")
    _git(live_repo, "add", "main.tf")
    _git(live_repo, "commit", "-q", "-m", "Add main.tf")
    task = (
        f"Diff base: HEAD~1\nBranch: HEAD\nRepo: {live_repo}\n"
        "Changed Terraform files: main.tf\nTerraform tools: on\n"
        "Review the change by your method and end with your status line."
    )
    run = _persona("terraform-reviewer", task, ["Read", "Bash", "Grep", "Glob"], live_repo)
    _check(run, "terraform-reviewer", ("[STATUS: COMPLIANCE]",), block_ok=True)
    assert "TF-0" in run.result.stdout
    assert "TF-1 FAIL" not in run.result.stdout and "TF-2 FAIL" not in run.result.stdout


def test_public_docs_writer(live_repo: Path) -> None:
    # 0134: the writer edits a public doc in the docs worktree and claims the passage.
    from lib import train_state
    from lib.unit_binding import record_dispatch
    from lib.workspace import create, mark_train

    _git(live_repo, "branch", "daedalus/20261015-000000")
    train_state.save(live_repo, "20261015-000000", {"train_id": "20261015-000000"})
    mark_train(live_repo, "20261015-000000")
    worktree = create(live_repo, "20261015-000000-docs", "daedalus/20261015-000000")
    assert record_dispatch(live_repo, "20261015-000000", "20261015-000000-docs") is None
    task = (
        f"Worktree: {worktree}\n"
        "Diff base: HEAD~1\nIntegration branch: daedalus/20261015-000000\n"
        "Hand-back summary: unit u1 added src/hello.py with hello(name) returning hello <name>.\n"
        "Public docs: README.md, docs/howto/README.md, docs/guardrails.md, "
        "docs/project-requirements.md\nLiteracy: plain\n"
        "Make README.md describe hello(name), commit, and end with your status line."
    )
    tools = ["Read", "Edit", "Write", "Bash", "Glob", "Grep"]
    run = _persona("writer", task, tools, live_repo)
    _check(run, "writer", ("[STATUS: DOCS_WRITTEN]",))
    assert re.search(r"^Claim: README\.md:[0-9]+ ", run.result.stdout, re.M)


VERIFIER_CLAIM = REPO_ROOT / "tests" / "fixtures" / "verifier" / "complete-reply.txt"


def test_verifier(live_repo: Path) -> None:
    # spec 5: the verifier prints the cited line and refutes the claim it does not back.
    from lib import train_state
    from lib.workspace import create, mark_train

    _git(live_repo, "branch", "daedalus/20261015-000000")
    train_state.save(live_repo, "20261015-000000", {"train_id": "20261015-000000"})
    mark_train(live_repo, "20261015-000000")
    worktree = create(live_repo, "20261015-000000-u1", "daedalus/20261015-000000")
    task = (
        f"Worktree: {worktree}\n"
        "Branch: daedalus-unit/20261015-000000-u1\nDiff base: main\n"
        "Verify this completion report and its ledger notes:\n\n"
        + VERIFIER_CLAIM.read_text(encoding="utf-8")
    )
    run = _persona("verifier", task, ["Read", "Bash", "Grep", "Glob"], live_repo)
    _check(run, "verifier", ("[VERDICT: REFUTED]",))
    first = next(line for line in run.result.stdout.splitlines() if line.strip())
    assert first.lstrip().startswith("[VERDICT: REFUTED]"), first
    assert _last_line(run.result.stdout).startswith("[VERDICT: REFUTED]")
    assert "src/hello.py:2" in run.result.stdout
