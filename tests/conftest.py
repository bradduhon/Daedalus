# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import json
import os
import subprocess
import sys
from collections.abc import Callable, Iterable, Iterator
from pathlib import Path
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS_DIR = REPO_ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS_DIR))

from lib.config import Config, LedgerDecl  # noqa: E402

# 0044: the fake repo the jail and hook-script cases share; it is not a real git repo.
CWD = "/work/repo"
CFG = Config(
    charter_root=Path("/work/Charter"),
    ledger=LedgerDecl(
        Path("/work/Charter/decision-log.md"), "markdown-table-row", "{seq:04d}", "last-row-id"
    ),
)
WT = f"{CWD}/.claude/worktrees/20261015-120000-u1"
FAKE_UNITS = frozenset({f"{CWD}/.claude/worktrees/u1", WT})
# issue 11: the integration branch of the train CWD stands in for.
TRAIN_BRANCH = "daedalus/20261015-120000"


@pytest.fixture
def jail_fakes(monkeypatch: pytest.MonkeyPatch) -> None:
    # 0022: CWD is not a real repo; register its fake unit worktrees, real repos query git.
    from lib import dispatch_binding, gh_policy, hook_io, jail

    real = getattr(jail, "_registered_worktrees", None)

    def fake(repo: str) -> frozenset[str]:
        if repo == CWD:
            return FAKE_UNITS
        return real(repo) if real is not None else frozenset()

    monkeypatch.setattr(jail, "_registered_worktrees", fake, raising=False)
    # issue 29: CWD has no train state; binding is proven in tests/test_unit_binding.py.
    real_binding = dispatch_binding._binding_reason

    def no_binding(hook_input: dict[str, object], cwd: str, units: set[str]) -> str | None:
        return None if cwd == CWD else real_binding(hook_input, cwd, units)

    monkeypatch.setattr(dispatch_binding, "_binding_reason", no_binding)
    # 0035: CWD stands for a repo a train runs in; real repos below resolve their own marker.
    real_scoped = jail._train_scoped

    def scoped(cwd: str, tool: str, tool_input: dict[str, object]) -> bool:
        return cwd.startswith(CWD) or real_scoped(cwd, tool, tool_input)

    monkeypatch.setattr(jail, "_train_scoped", scoped)
    # issue 11: CWD has no marker; real repos read the branch from their own marker.
    real_branch = jail._train_branch

    def branch(cwd: str) -> str | None:
        return TRAIN_BRANCH if cwd.startswith(CWD) else real_branch(cwd)

    monkeypatch.setattr(jail, "_train_branch", branch)
    # spec 4.2: CWD has no train state; the verdict gate is proven in tests/test_checks_git_push.py.
    real_verdict = gh_policy.verdict_reason

    def verdict(cwd: str, what: str) -> str | None:
        return None if cwd.startswith(CWD) else real_verdict(cwd, what)

    monkeypatch.setattr(gh_policy, "verdict_reason", verdict)
    # 0044: hook scripts read the project config through this one name.
    monkeypatch.setattr(hook_io, "hook_config", lambda cwd: CFG)


def fake_bin(
    tmp_path: Path, names: Iterable[str], exit_codes: dict[str, int] | None = None
) -> Path:
    # 0020: shared stub-tool directory for PATH; each stub exits with its mapped code or 0.
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    codes = exit_codes or {}
    for name in names:
        tool = bin_dir / name
        tool.write_text(f"#!/bin/sh\nexit {codes.get(name, 0)}\n")
        tool.chmod(0o755)
    return bin_dir


def write_train_marker(repo: Path, train: str = "20261017-120000") -> Path:
    # 0035: the audit log records only while this marker exists.
    marker = repo / ".claude" / "daedalus" / "train.active"
    marker.parent.mkdir(parents=True, exist_ok=True)
    marker.write_text(f"{train}\n", encoding="utf-8")
    return marker


# 0010: a throwaway identity so a test commit never reads the operator's git config.
GIT_IDENT = (
    "-c",
    "user.name=t",
    "-c",
    "user.email=t@example.invalid",
    "-c",
    "commit.gpgsign=false",
)


def git(repo: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    # W1.4: the one test git runner; check=False hands back a non-zero exit for the caller to read.
    from lib import git as git_lib

    done = git_lib.run([*GIT_IDENT, *args], repo)
    if check and done.returncode != 0:
        raise subprocess.CalledProcessError(done.returncode, done.args, done.stdout, done.stderr)
    return done


def audit_records(log: Path) -> list[dict[str, Any]]:
    # W1.4: every record of one audit log, in order.
    return [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines() if line]


def main_warning(stdout: str) -> str:
    # Main never prompted (amends 0105, 0106): no decision; one text in context and transcript.
    doc = json.loads(stdout)
    out = doc["hookSpecificOutput"]
    assert out["hookEventName"] == "PreToolUse" and "permissionDecision" not in out, doc
    assert out["additionalContext"] == doc["systemMessage"], doc
    return str(out["additionalContext"])


def append_handback(
    make_input: Callable[..., dict[str, Any]],
    message: str,
    agent_type: str = "daedalus:security-auditor",
    **extra: Any,
) -> None:
    # W1.4: one auditor SubagentHandback appended through the hook writer.
    from lib import audit

    audit.audit_append(
        make_input(
            hook_event_name="PostToolUse",
            tool_name="SubagentHandback",
            tool_input={"message": message},
            agent_type=agent_type,
            agent_id="a1",
            **extra,
        )
    )


def run_cli(
    script: str,
    *args: str,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    # W1.4: a script under scripts/ run as the operator runs it; a non-zero exit is returned.
    return subprocess.run(
        [sys.executable, str(SCRIPTS_DIR / script), *args],
        capture_output=True,
        text=True,
        check=False,
        cwd=cwd,
        env=env,
    )


def workspace_cli(*args: str, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    # issue 63: daedalus_workspace.py refuses a --repo that is not the project root of its cwd.
    return run_cli("daedalus_workspace.py", *args, cwd=cwd or Path(args[args.index("--repo") + 1]))


TRAIN_A_AUDITOR = REPO_ROOT / "tests" / "fixtures" / "audit" / "train-a-auditor.jsonl"


def replay_auditor(cwd: Path, session: str, handbacks: bool = True) -> list[dict[str, Any]]:
    # issue 57: Train A's three auditor rounds, appended through the hook writer.
    from lib import audit

    appended: list[dict[str, Any]] = []
    for raw in TRAIN_A_AUDITOR.read_text(encoding="utf-8").splitlines():
        rec = json.loads(raw)
        if rec["tool_name"] == "SubagentHandback" and not handbacks:
            continue
        payload: dict[str, Any] = {
            "session_id": session,
            "hook_event_name": rec["event"],
            "cwd": str(cwd),
            **{key: rec[key] for key in ("agent_id", "agent_type", "tool_name", "tool_use_id")},
            "tool_input": rec["tool_input"],
        }
        if rec["result_head"] is not None:
            payload["tool_response"] = json.loads(rec["result_head"])
        if rec["event"] == "SubagentStop":
            reply = f"{rec['last_message_head']}\n{rec['last_message_tail']}"
            payload["last_assistant_message"] = reply
        record = audit.audit_append(payload)
        assert record is not None
        appended.append(record)
    return appended


@pytest.fixture
def fake_claude(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    # issue 55: a versioned claude binary and the PATH link to it, as the installer lays them out.
    versions = tmp_path.resolve() / "share" / "versions"
    versions.mkdir(parents=True)
    binary = versions / "2.0.0"
    binary.write_text("#!/bin/sh\n")
    binary.chmod(0o755)
    bin_dir = tmp_path.resolve() / "bin"
    bin_dir.mkdir()
    (bin_dir / "claude").symlink_to(binary)
    monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}")
    return binary


@pytest.fixture
def cred_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    root = tmp_path.resolve() / "home"
    root.mkdir()
    monkeypatch.setenv("HOME", str(root))
    return root


@pytest.fixture
def train_cwd(tmp_path: Path) -> Path:
    root = tmp_path.resolve() / "trainrepo"
    (root / ".claude" / "daedalus").mkdir(parents=True)
    return root


@pytest.fixture
def plain_repo(tmp_path: Path) -> Path:
    root = tmp_path.resolve() / "repo"
    (root / "src").mkdir(parents=True)
    (root / ".github").mkdir()
    (root / "src" / "a.py").write_text("x\n")
    return root


@pytest.fixture
def marked_repo(tmp_path: Path) -> Path:
    # 0035: a real repo whose train marker is present.
    repo = tmp_path.resolve() / "marked"
    repo.mkdir()
    git(repo, "init", "-q", "-b", "main")
    write_train_marker(repo, "20261015-120000")
    return repo


@pytest.fixture
def other_repo(tmp_path: Path) -> Path:
    repo = tmp_path.resolve() / "other"
    repo.mkdir()
    git(repo, "init", "-q", "-b", "main")
    return repo


@pytest.fixture
def plugin_data(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    root = tmp_path / "plugin-data"
    root.mkdir()
    monkeypatch.setenv("CLAUDE_PLUGIN_DATA", str(root))
    return root


@pytest.fixture(autouse=True)
def _fresh_project_root() -> Iterator[None]:
    # 0010: root_info and the tracked-file check are cached per process; tests need them cold.
    from lib import audit

    audit.root_info.cache_clear()
    audit._TRACKED.clear()
    yield
    audit.root_info.cache_clear()
    audit._TRACKED.clear()


@pytest.fixture(autouse=True)
def _kernel_rules_off(monkeypatch: pytest.MonkeyPatch) -> None:
    # 0048: the confine check steps aside in-process; tests/test_confine.py restores the probe.
    import daedalus_confine

    off = daedalus_confine.Support(None, 0, False)
    monkeypatch.setattr(daedalus_confine, "kernel_support", lambda: off)


@pytest.fixture
def repo_cwd(tmp_path: Path) -> Path:
    root = tmp_path.resolve() / "repo"
    root.mkdir()
    git(root, "init", "-q", "-b", "main")
    return root


@pytest.fixture
def git_repo(tmp_path: Path) -> Path:
    # W1.4: a repo on main with one empty commit, built through git().
    root = tmp_path.resolve() / "repo"
    root.mkdir()
    git(root, "init", "-q", "-b", "main")
    git(root, "commit", "-q", "--allow-empty", "-m", "init")
    return root


@pytest.fixture
def project_data(repo_cwd: Path) -> Path:
    data = repo_cwd / ".claude" / "daedalus"
    data.mkdir(parents=True)
    return data


@pytest.fixture
def hook_input(repo_cwd: Path) -> Callable[..., dict[str, Any]]:
    def _make(**overrides: Any) -> dict[str, Any]:
        base: dict[str, Any] = {
            "session_id": "sess-test",
            "hook_event_name": "PreToolUse",
            "cwd": str(repo_cwd),
            "tool_name": "Bash",
            "tool_input": {"command": "ls"},
            "tool_use_id": "toolu_1",
        }
        base.update(overrides)
        return base

    return _make


@pytest.fixture
def run_script(
    plugin_data: Path,
) -> Callable[[str, dict[str, Any]], subprocess.CompletedProcess[str]]:
    def _run(script: str, payload: dict[str, Any]) -> subprocess.CompletedProcess[str]:
        env = dict(os.environ)
        env["CLAUDE_PLUGIN_DATA"] = str(plugin_data)
        return subprocess.run(
            [sys.executable, str(SCRIPTS_DIR / script)],
            input=json.dumps(payload),
            capture_output=True,
            text=True,
            env=env,
            check=False,
        )

    return _run
