# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import ast
import io
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import enforce_agent_jail
import pytest
from lib import jail

from tests.conftest import audit_records, main_warning, write_train_marker

_SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "enforce_agent_jail.py"


def _run_raw(text: str, script: Path = _SCRIPT) -> subprocess.CompletedProcess[str]:
    env = dict(os.environ)
    return subprocess.run(
        [sys.executable, str(script)],
        input=text,
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )


def _in_train(project_data: Path) -> None:
    # 0035: the main session meets config and audit failures only while a train runs.
    (project_data / "train.active").write_text("20261015-120000\n")


def test_allow_exits_zero_and_logs_allow(
    run_script: Any, project_data: Path, hook_input: Any
) -> None:
    _in_train(project_data)
    result = run_script("enforce_agent_jail.py", hook_input(tool_input={"command": "git status"}))
    assert result.returncode == 0, result.stderr
    rec = audit_records(project_data / "audit" / "sess-test.jsonl")[-1]
    assert rec["decision"] == "allow" and rec["reason"] is None


def test_main_write_in_a_train_exits_zero_with_context_and_logs_allow(
    run_script: Any, project_data: Path, repo_cwd: Path, hook_input: Any
) -> None:
    # Main never prompted (amends 0105): allowed, the warning in context, recorded as allow.
    _in_train(project_data)
    payload = hook_input(tool_name="Write", tool_input={"file_path": "README.md", "content": "x"})
    result = run_script("enforce_agent_jail.py", payload)
    assert result.returncode == 0 and result.stderr == "", result.stderr
    reason = main_warning(result.stdout)
    assert reason.startswith("Build Train 20261015-120000 is active in this repository")
    assert f"Writing {repo_cwd}/README.md here" in reason
    rec = audit_records(project_data / "audit" / "sess-test.jsonl")[-1]
    assert rec["decision"] == "allow" and rec["reason"] == f"jail: {reason}"
    # 0105, 6.1: the record names the deciding hook; the session's warning text does not.
    assert rec["reason"].startswith("jail: ") and not reason.startswith("jail: ")


def test_routed_agent_never_gets_ask(run_script: Any, project_data: Path, hook_input: Any) -> None:
    # Main never prompted (amends 0105): a denied agent write stays denied, with no warning.
    _in_train(project_data)
    write = {"file_path": "README.md", "content": "x"}
    payload = hook_input(agent_type="repo-coder", tool_name="Write", tool_input=write)
    result = run_script("enforce_agent_jail.py", payload)
    assert result.returncode == 2 and result.stdout == "", result.stdout
    rec = audit_records(project_data / "audit" / "sess-test.jsonl")[-1]
    assert rec["decision"] == "block", rec


def test_block_exits_two_with_message_and_logs_block(
    run_script: Any, project_data: Path, hook_input: Any
) -> None:
    _in_train(project_data)
    payload = hook_input(agent_type="repo-coder", tool_input={"command": "git push origin x"})
    result = run_script("enforce_agent_jail.py", payload)
    assert result.returncode == 2
    # 0044: the router prefixes the denying hook's name in stderr and in the record.
    want = "git_push: no remote git operations in the Build Train."
    assert result.stderr.startswith(f"daedalus-jail[repo-coder]: {want}")
    assert "Next:" in result.stderr
    rec = audit_records(project_data / "audit" / "sess-test.jsonl")[-1]
    assert rec["decision"] == "block" and rec["reason"].startswith(want)


def test_namespaced_block_label_uses_normalized_name(run_script: Any, hook_input: Any) -> None:
    # m2: the stderr label names the agent the jail judged, not the raw plugin:agent string.
    payload = hook_input(
        agent_type="daedalus:repo-coder", tool_input={"command": "git push origin x"}
    )
    result = run_script("enforce_agent_jail.py", payload)
    assert result.returncode == 2
    assert result.stderr.startswith("daedalus-jail[repo-coder]:")


def test_closed_stderr_still_exits_two(monkeypatch: pytest.MonkeyPatch) -> None:
    # m5: a print failure on a closed stderr must not escape as exit 1 (non-blocking).
    class Closed(io.StringIO):
        def write(self, _text: str) -> int:
            raise BrokenPipeError("closed")

    monkeypatch.setattr(sys, "stderr", Closed())
    assert enforce_agent_jail._block("repo-coder", "x. Next: y.") == 2


def test_unknown_agent_blocks_during_a_train(
    run_script: Any, project_data: Path, hook_input: Any
) -> None:
    (project_data / "train.active").write_text("20261015-120000\n")
    # 0100: a foreign agent reads during a train; its writes block.
    assert run_script("enforce_agent_jail.py", hook_input(agent_type="ghost")).returncode == 0
    payload = hook_input(agent_type="ghost", tool_input={"command": "touch x"})
    result = run_script("enforce_agent_jail.py", payload)
    assert result.returncode == 2 and "read-only while" in result.stderr


def test_unknown_agent_passes_without_a_train(
    run_script: Any, project_data: Path, hook_input: Any
) -> None:
    result = run_script("enforce_agent_jail.py", hook_input(agent_type="ghost"))
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize("agent", [None, "ghost"])
def test_unwritable_audit_dir_alerts_main_and_fails_closed_for_an_agent(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    project_data: Path,
    hook_input: Any,
    agent: str | None,
) -> None:
    # Main never prompted (amends 0106), AU-5: main is alerted and allowed; agents stay denied.
    _in_train(project_data)
    (project_data / "audit").write_text("not a directory")
    allowed = SimpleNamespace(allow=True, reason=None, warn=False, agent=agent or "main")
    monkeypatch.setattr(jail, "decide", lambda *_args: allowed)
    payload = hook_input(tool_input={"command": "ls"})
    if agent:
        payload.update(agent_type=agent, agent_id="g1")
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(payload)))
    code = enforce_agent_jail.main()
    out = capsys.readouterr()
    if agent:
        assert code == 2 and out.out == "" and "audit log unavailable" in out.err
    else:
        assert code == 0
        alert = main_warning(out.out)
        assert alert.startswith(enforce_agent_jail._AUDIT_WARN.format(tool="Bash")), alert
        assert alert.startswith("auditing is down") and alert in out.err


def test_unwritable_audit_dir_outside_a_train_lets_main_proceed(
    run_script: Any, project_data: Path, hook_input: Any
) -> None:
    # 0035: outside a train the hook records nothing, so a broken audit dir is never touched.
    (project_data / "audit").write_text("not a directory")
    result = run_script("enforce_agent_jail.py", hook_input(tool_input={"command": "ls"}))
    assert result.returncode == 0 and result.stderr == ""


@pytest.mark.parametrize("agent", [None, "ghost", "daedalus:security-auditor"])
def test_data_dir_without_a_train_marker_gets_no_record(
    run_script: Any, project_data: Path, hook_input: Any, agent: str | None
) -> None:
    # 0035: a repo that once ran a train is not logged again until a train marks it.
    for payload in (
        hook_input(agent_type=agent, tool_input={"command": "ls"}),
        hook_input(agent_type=agent, tool_name="Read", tool_input={"file_path": "/etc/hosts"}),
    ):
        result = run_script("enforce_agent_jail.py", payload)
        assert result.returncode == 0, result.stderr
    assert sorted(p.name for p in project_data.iterdir()) == []


AUDITOR = {"agent_type": "daedalus:security-auditor", "agent_id": "a1"}
CODER = {"agent_type": "daedalus:repo-coder", "agent_id": "c1"}


def _last_record(project_data: Path) -> dict[str, Any]:
    return dict(audit_records(project_data / "audit" / "sess-test.jsonl")[-1])


def test_malformed_config_blocks(run_script: Any, project_data: Path, hook_input: Any) -> None:
    # 0106: an agent's call stays blocked on a config failure.
    _in_train(project_data)
    (project_data / "config.json").write_text("{bad")
    payload = hook_input(tool_input={"command": "ls"}, **AUDITOR)
    result = run_script("enforce_agent_jail.py", payload)
    assert result.returncode == 2 and "config.json" in result.stderr


def test_oversized_int_config_blocks_and_records(
    run_script: Any, project_data: Path, hook_input: Any
) -> None:
    _in_train(project_data)
    (project_data / "config.json").write_text('{"x": ' + "1" * 5000 + "}")
    payload = hook_input(tool_input={"command": "ls"}, **AUDITOR)
    result = run_script("enforce_agent_jail.py", payload)
    assert result.returncode == 2
    assert result.stderr.startswith("daedalus-jail[daedalus:security-auditor]: ")
    assert "Next:" in result.stderr
    rec = _last_record(project_data)
    assert rec["decision"] == "block" and "not valid JSON" in rec["reason"]


def test_malformed_config_alerts_the_operator_and_records_allow(
    run_script: Any, project_data: Path, hook_input: Any
) -> None:
    # Main never prompted (amends 0106), SI-4: main is alerted with the exception text.
    _in_train(project_data)
    (project_data / "config.json").write_text("{bad")
    result = run_script("enforce_agent_jail.py", hook_input(tool_input={"command": "ls"}))
    assert result.returncode == 0, result.stderr
    reason = main_warning(result.stdout)
    assert reason.startswith(enforce_agent_jail._CONFIG_WARN.format(tool="Bash") + " (")
    assert "not valid JSON" in reason and "Next:" in reason and reason in result.stderr
    rec = _last_record(project_data)
    assert rec["decision"] == "allow" and rec["reason"] == f"config: {reason}"


def test_config_failure_with_no_audit_record_alerts_the_operator_unrecorded(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    project_data: Path,
    hook_input: Any,
) -> None:
    # Main never prompted (amends 0106), AU-5: the alert names the unrecorded call everywhere.
    _in_train(project_data)
    (project_data / "config.json").write_text("{bad")
    (project_data / "audit").write_text("not a directory")
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(hook_input())))
    assert enforce_agent_jail.main() == 0
    out = capsys.readouterr()
    reason = main_warning(out.out)
    assert (
        reason.startswith(enforce_agent_jail._AUDIT_WARN.format(tool="Bash")) and reason in out.err
    )
    assert enforce_agent_jail._CONFIG_WARN.format(tool="Bash") in reason
    assert "not valid JSON" in reason


def test_malformed_config_records_block(
    run_script: Any, project_data: Path, hook_input: Any
) -> None:
    _in_train(project_data)
    (project_data / "config.json").write_text("{bad")
    payload = hook_input(tool_input={"command": "ls"}, **AUDITOR)
    result = run_script("enforce_agent_jail.py", payload)
    assert result.returncode == 2
    rec = audit_records(project_data / "audit" / "sess-test.jsonl")[-1]
    assert rec["decision"] == "block"
    assert "config.json" in rec["reason"] and "not valid JSON" in rec["reason"]


def test_non_object_input_blocks(run_script: Any, project_data: Path) -> None:
    result = run_script("enforce_agent_jail.py", [1])
    assert result.returncode == 2
    assert result.stderr.startswith("daedalus-jail[?]: hook input is not a JSON object.")
    assert not (project_data / "audit").exists()


def test_oversized_int_input_blocks_without_audit(project_data: Path) -> None:
    result = _run_raw('{"x": ' + "1" * 5000 + "}")
    assert result.returncode == 2
    assert result.stderr.startswith("daedalus-jail[?]: hook input could not be parsed (")
    assert not (project_data / "audit").exists()


def test_unparseable_input_writes_no_record(project_data: Path) -> None:
    result = _run_raw("{bad")
    assert result.returncode == 2 and "Next:" in result.stderr
    assert not (project_data / "audit").exists()


@pytest.mark.parametrize("agent", ["main", "repo-coder"])
def test_string_tool_input_blocks_without_record(
    run_script: Any, project_data: Path, hook_input: Any, agent: str
) -> None:
    payload = hook_input(agent_type=agent, tool_input="git push origin x")
    result = run_script("enforce_agent_jail.py", payload)
    assert result.returncode == 2, result.stderr
    assert result.stderr.startswith(
        f"daedalus-jail[{agent}]: hook input tool_input is not an object. Next:"
    )
    assert not (project_data / "audit").exists()


@pytest.mark.parametrize("text", ["", "   \n\t"])
def test_empty_input_blocks_without_record(project_data: Path, text: str) -> None:
    result = _run_raw(text)
    assert result.returncode == 2
    assert result.stderr.startswith(
        "daedalus-jail[?]: hook input is empty. Next: report this hook failure to the operator."
    )
    assert not (project_data / "audit").exists()


@pytest.mark.parametrize("tool_name", [None, 7, ""])
def test_missing_tool_name_blocks_without_record(
    run_script: Any, project_data: Path, hook_input: Any, tool_name: Any
) -> None:
    payload = hook_input()
    if tool_name is None:
        del payload["tool_name"]
    else:
        payload["tool_name"] = tool_name
    result = run_script("enforce_agent_jail.py", payload)
    assert result.returncode == 2
    assert "hook input has no tool_name string. Next:" in result.stderr
    assert not (project_data / "audit").exists()


def _lone_script(tmp_path: Path, gate: bool = True) -> Path:
    # 0035: gate copies the stdlib marker finder beside the script; else no lib exists at all.
    lone = tmp_path / "lone"
    lone.mkdir()
    shutil.copy(_SCRIPT, lone / "enforce_agent_jail.py")
    if gate:
        (lone / "lib").mkdir()
        for name in ("__init__.py", "repo_root.py", "project_root.py"):
            shutil.copy(_SCRIPT.parent / "lib" / name, lone / "lib" / name)
    return lone / "enforce_agent_jail.py"


def test_missing_marker_finder_fails_open_outside_a_train(
    tmp_path: Path, repo_cwd: Path, hook_input: Any
) -> None:
    # 0035: the inline finder sees no marker, so a gutted install never blocks the call.
    result = _run_raw(json.dumps(hook_input()), _lone_script(tmp_path, gate=False))
    assert result.returncode == 0, result.stderr
    lines = result.stderr.splitlines()
    assert len(lines) == 1
    assert lines[0].startswith("daedalus-jail[?]: hook could not load its libraries (")
    assert "No module named 'lib'" in lines[0]
    assert "no train runs in this repository, so the call proceeds." in lines[0]
    assert not (repo_cwd / ".claude").exists()


@pytest.mark.parametrize("agent", [None, "daedalus:repo-coder"])
def test_missing_marker_finder_fails_closed_inside_a_train(
    tmp_path: Path, project_data: Path, hook_input: Any, agent: str | None
) -> None:
    # 0035, Main never prompted (amends 0106): an agent is blocked, main is alerted and allowed.
    _in_train(project_data)
    payload = hook_input(agent_type=agent, agent_id="a1") if agent else hook_input()
    result = _run_raw(json.dumps(payload), _lone_script(tmp_path, gate=False))
    if agent:
        assert result.returncode == 2
        assert result.stderr.startswith("daedalus-jail[?]: hook could not load its libraries (")
    else:
        assert result.returncode == 0, result.stderr
        alert = main_warning(result.stdout)
        assert alert.startswith(enforce_agent_jail._LOAD_WARN.format(tool="Bash"))
        assert alert in result.stderr


def test_inline_marker_finder_agrees_with_the_library(repo_cwd: Path) -> None:
    # 0035: the jail's fallback finder and lib.project_root resolve every path the same way.
    from lib import project_root, repo_root

    (repo_cwd / "README").write_text("r\n")
    _git_commit_all(repo_cwd)
    worktree = repo_cwd / ".claude" / "worktrees" / "u1"
    subprocess.run(["git", "-C", str(repo_cwd), "worktree", "add", "-q", str(worktree)], check=True)
    (worktree / "sub").mkdir()
    paths = [repo_cwd, repo_cwd / "missing" / "file", worktree, worktree / "sub"]
    for marked in (False, True):
        if marked:
            write_train_marker(repo_cwd)
        for path in paths:
            got = enforce_agent_jail._inline_project_root(path)
            assert got == project_root.project_root(path) == repo_cwd
            inline = enforce_agent_jail._inline_train_marked(str(path))
            assert inline == project_root.train_marked(str(path)) == marked
    assert enforce_agent_jail._TRAIN_MARKER == repo_root.TRAIN_MARKER
    assert enforce_agent_jail._MANIFEST == project_root.MANIFEST
    assert enforce_agent_jail._DATA_DIR == project_root.DATA_DIR


def test_inline_project_root_matches_lib(repo_cwd: Path, tmp_path: Path) -> None:
    # 0035, CM-5: the inline copy and the library give one answer over every fixture path.
    from lib import project_root, repo_root

    (repo_cwd / "service-manifest.json").write_text("{}")
    _git_commit_all(repo_cwd)
    linked = repo_cwd / ".claude" / "worktrees" / "u1"
    outside = tmp_path.resolve() / "outside-wt"
    for path in (linked, outside):
        subprocess.run(["git", "-C", str(repo_cwd), "worktree", "add", "-q", str(path)], check=True)
    nested = repo_cwd / "docs" / "private"
    nested.mkdir(parents=True)
    subprocess.run(["git", "init", "-q", str(nested)], check=True)
    inner = repo_cwd / "pkg"
    inner.mkdir()
    (inner / "service-manifest.json").write_text("{}")
    folder = tmp_path.resolve() / "folder"
    (folder / ".claude" / "daedalus").mkdir(parents=True)
    (folder / "x").mkdir()
    plain = tmp_path.resolve() / "plain"
    plain.mkdir()
    lone_git = tmp_path.resolve() / "lone"
    lone_git.mkdir()
    (lone_git / ".git").write_text("not a gitdir line\n")
    paths = [
        repo_cwd,
        repo_cwd / "missing" / "file",
        linked,
        outside / "sub",
        nested,
        nested / "deep",
        inner / "src",
        folder / "x",
        plain,
        plain / "missing",
        lone_git / "a",
        Path("/"),
    ]
    for path in paths:
        lib = project_root.project_root(path)
        assert enforce_agent_jail._inline_project_root(path) == lib, path
        assert enforce_agent_jail._inline_git_root(str(path)) == repo_root.git_root(str(path))


@pytest.mark.parametrize("agent", [None, "daedalus:repo-coder"])
def test_missing_libraries_fail_closed_during_a_train(
    tmp_path: Path, project_data: Path, hook_input: Any, agent: str | None
) -> None:
    # 0035, Main never prompted (amends 0106): an agent is blocked; main runs it with an alert.
    (project_data / "train.active").write_text("20261015-120000\n")
    payload = hook_input(agent_type=agent, agent_id="a1") if agent else hook_input()
    result = _run_raw(json.dumps(payload), _lone_script(tmp_path))
    next_line = "Next: run the plugin with Python 3.12 and an intact scripts/lib directory."
    if agent:
        assert result.returncode == 2
        assert result.stderr.startswith("daedalus-jail[?]: hook could not load its libraries (")
        assert next_line in result.stderr
    else:
        assert result.returncode == 0, result.stderr
        reason = main_warning(result.stdout)
        assert reason.startswith(enforce_agent_jail._LOAD_WARN.format(tool="Bash"))
        assert next_line in reason and reason in result.stderr


@pytest.mark.parametrize("tool", ["Bash", "Write", "Read"])
def test_missing_libraries_fail_open_outside_a_train(
    tmp_path: Path, repo_cwd: Path, hook_input: Any, tool: str
) -> None:
    # 0035: outside a train a broken install never blocks the session; one stderr line says so.
    result = _run_raw(json.dumps(hook_input(tool_name=tool)), _lone_script(tmp_path))
    assert result.returncode == 0
    lines = result.stderr.splitlines()
    assert len(lines) == 1
    assert lines[0].startswith("daedalus-jail[?]: hook could not load its libraries (")
    assert "no train runs in this repository, so the call proceeds." in lines[0]
    assert not (repo_cwd / ".claude").exists()


def test_missing_libraries_in_a_linked_worktree_of_a_train_fail_closed(
    tmp_path: Path, project_data: Path, repo_cwd: Path, hook_input: Any
) -> None:
    # 0035: a unit worktree resolves to the main working tree, where the marker lives.
    (project_data / "train.active").write_text("20261015-120000\n")
    _git_commit_all(repo_cwd)
    worktree = repo_cwd / ".claude" / "worktrees" / "u1"
    subprocess.run(["git", "-C", str(repo_cwd), "worktree", "add", "-q", str(worktree)], check=True)
    result = _run_raw(json.dumps(hook_input(cwd=str(worktree))), _lone_script(tmp_path))
    # Main never prompted (amends 0106): the alert names the train, so the marker was found.
    assert result.returncode == 0, result.stderr
    assert main_warning(result.stdout).startswith(enforce_agent_jail._LOAD_WARN.format(tool="Bash"))


def test_decide_exception_blocks_and_records(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    project_data: Path,
    hook_input: Any,
) -> None:
    def _boom(*_args: Any) -> Any:
        raise RuntimeError("decide exploded")

    # 0106: a foreign agent's call stays blocked when the judge raises.
    _in_train(project_data)
    monkeypatch.setattr(jail, "decide", _boom)
    payload = hook_input(agent_type="ghost", agent_id="g1")
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(payload)))
    assert enforce_agent_jail.main() == 2
    err = capsys.readouterr().err
    assert err.startswith("daedalus-jail[ghost]: jail: decide exploded Next:")
    rec = _last_record(project_data)
    assert rec["decision"] == "block" and rec["reason"].startswith("jail: decide exploded")


def test_routed_agent_judge_exception_blocks_and_records(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    project_data: Path,
    hook_input: Any,
) -> None:
    # 0106: a Daedalus agent's call stays blocked when the router raises.
    def _boom(*_args: Any) -> Any:
        raise RuntimeError("router exploded")

    from lib import router

    _in_train(project_data)
    monkeypatch.setattr(router, "route", _boom)
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(hook_input(**AUDITOR))))
    assert enforce_agent_jail.main() == 2
    err = capsys.readouterr().err
    assert err.startswith("daedalus-jail[daedalus:security-auditor]: jail: router exploded")
    assert _last_record(project_data)["decision"] == "block"


def test_judge_exception_alerts_the_operator_and_records_allow(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    project_data: Path,
    hook_input: Any,
) -> None:
    # Main never prompted (amends 0106), SI-4: main is alerted with the exception text.
    def _boom(*_args: Any) -> Any:
        raise RuntimeError("decide exploded")

    _in_train(project_data)
    monkeypatch.setattr(jail, "decide", _boom)
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(hook_input())))
    assert enforce_agent_jail.main() == 0
    out = capsys.readouterr()
    reason = main_warning(out.out)
    lead = enforce_agent_jail._JUDGE_WARN.format(tool="Bash")
    assert reason.startswith(f"{lead} (decide exploded).") and reason in out.err
    assert enforce_agent_jail._REPORT_NEXT.strip() in reason
    rec = _last_record(project_data)
    assert rec["decision"] == "allow" and rec["reason"] == f"jail: {reason}"


@pytest.mark.parametrize("cwd", [None, "relative"])
def test_missing_cwd_blocks_even_for_read(run_script: Any, hook_input: Any, cwd: Any) -> None:
    # 0010: the project data dir is located from cwd; without it there is no record, so no action.
    payload = hook_input(tool_name="Read", tool_input={"file_path": "/etc/hosts"}, cwd=cwd)
    result = run_script("enforce_agent_jail.py", payload)
    assert result.returncode == 2
    assert "absolute cwd" in result.stderr and "Next:" in result.stderr


def test_config_in_project_data_dir_is_loaded(
    run_script: Any, project_data: Path, hook_input: Any
) -> None:
    _in_train(project_data)
    (project_data / "config.json").write_text('{"ledger": {"path": "/x"}}')
    result = run_script("enforce_agent_jail.py", hook_input(tool_input={"command": "ls"}))
    assert result.returncode == 0, result.stderr
    assert "config.json is missing ledger.format" in main_warning(result.stdout)


def _git_commit_all(repo: Path) -> None:
    ident = ["-c", "user.name=t", "-c", "user.email=t@x.invalid", "-c", "commit.gpgsign=false"]
    subprocess.run(["git", "-C", str(repo), "add", "-A", "-f"], check=True)
    subprocess.run(["git", "-C", str(repo), *ident, "commit", "-q", "-m", "c"], check=True)


@pytest.mark.parametrize("case", ["tracked", "symlink", "marker"])
def test_untrusted_data_dir_blocks_the_hook(
    run_script: Any, repo_cwd: Path, tmp_path: Path, hook_input: Any, case: str
) -> None:
    # 0010: content arriving through git must not set jail policy or redirect writes.
    data = repo_cwd / ".claude" / "daedalus"
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    if case == "symlink":
        data.parent.mkdir()
        data.symlink_to(elsewhere)
    else:
        data.mkdir(parents=True)
        (data / ("config.json" if case == "tracked" else ".gitignore")).write_text("{}")
    _git_commit_all(repo_cwd)
    # 0035: a Daedalus agent meets the data dir checks with or without a train.
    payload = hook_input(agent_type="daedalus:security-auditor", tool_input={"command": "ls"})
    result = run_script("enforce_agent_jail.py", payload)
    assert result.returncode == 2, result.stderr
    assert "Next:" in result.stderr
    assert list(elsewhere.iterdir()) == []


def test_cwd_fallback_warns_on_stderr_and_allows(
    run_script: Any, hook_input: Any, tmp_path: Path
) -> None:
    plain = tmp_path / "plain"
    (plain / ".claude" / "daedalus").mkdir(parents=True)
    write_train_marker(plain)
    result = run_script("enforce_agent_jail.py", hook_input(cwd=str(plain)))
    assert result.returncode == 0, result.stderr
    assert result.stderr.startswith("daedalus-audit: project root fell back to cwd (")


def _run_home(payload: dict[str, Any], home: Path, plugin_data: Path) -> Any:
    # spec 8, 0023: HOME points at a temp dir so the credential deny never sees the real home.
    env = dict(os.environ, HOME=str(home), CLAUDE_PLUGIN_DATA=str(plugin_data))
    return subprocess.run(
        [sys.executable, str(_SCRIPT)],
        input=json.dumps(payload),
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )


@pytest.fixture
def temp_home(tmp_path: Path) -> Path:
    home = tmp_path / "home"
    (home / ".ssh").mkdir(parents=True)
    (home / ".ssh" / "id_ed25519").write_text("key\n")
    return home


def test_explore_read_of_a_normal_file_is_allowed_and_audited(
    temp_home: Path, plugin_data: Path, project_data: Path, repo_cwd: Path, hook_input: Any
) -> None:
    # spec 8, 0023: during a train an allowed Read through the jail still lands an audit record.
    _in_train(project_data)
    target = repo_cwd / "notes.txt"
    target.write_text("x\n")
    payload = hook_input(
        agent_type="Explore", tool_name="Read", tool_input={"file_path": str(target)}
    )
    result = _run_home(payload, temp_home, plugin_data)
    assert result.returncode == 0, result.stderr
    rec = audit_records(project_data / "audit" / "sess-test.jsonl")[-1]
    assert rec["decision"] == "allow" and rec["tool_name"] == "Read"


def test_explore_read_of_an_ssh_key_is_refused(
    temp_home: Path, plugin_data: Path, project_data: Path, hook_input: Any
) -> None:
    key = temp_home / ".ssh" / "id_ed25519"
    payload = hook_input(agent_type="Explore", tool_name="Read", tool_input={"file_path": str(key)})
    result = _run_home(payload, temp_home, plugin_data)
    assert result.returncode == 2
    assert result.stderr.startswith("daedalus-jail[Explore]:"), result.stderr


@pytest.mark.parametrize("agent", [None, "Explore"])
def test_main_grep_rooted_at_home_is_warned_and_an_agent_refused(
    temp_home: Path, plugin_data: Path, project_data: Path, hook_input: Any, agent: str | None
) -> None:
    # Main never prompted (amends 0106): the operator's own session is warned; an agent refused.
    payload = hook_input(tool_name="Grep", tool_input={"pattern": "x", "path": str(temp_home)})
    if agent:
        payload.update(agent_type=agent, agent_id="e1")
    result = _run_home(payload, temp_home, plugin_data)
    if agent:
        assert result.returncode == 2
        assert result.stderr.startswith(f"daedalus-jail[{agent}]:"), result.stderr
    else:
        assert result.returncode == 0, result.stderr
        assert main_warning(result.stdout).startswith(enforce_agent_jail._CREDENTIAL_WARN)


def test_main_glob_over_the_repo_is_allowed(
    temp_home: Path, plugin_data: Path, project_data: Path, repo_cwd: Path, hook_input: Any
) -> None:
    payload = hook_input(tool_name="Glob", tool_input={"pattern": "*", "path": str(repo_cwd)})
    result = _run_home(payload, temp_home, plugin_data)
    assert result.returncode == 0, result.stderr


def test_absent_data_dir_allows_main_bash_and_writes_nothing(
    run_script: Any, repo_cwd: Path, hook_input: Any
) -> None:
    # 0035: no train ever ran here, so the hook leaves the repository untouched.
    result = run_script("enforce_agent_jail.py", hook_input(tool_input={"command": "git status"}))
    assert result.returncode == 0, result.stderr
    assert not (repo_cwd / ".claude").exists()


def test_absent_config_allows_main_bash_and_writes_the_log(
    run_script: Any, project_data: Path, hook_input: Any
) -> None:
    # 0020: config.json is optional; absence is the empty config, never a block.
    _in_train(project_data)
    result = run_script("enforce_agent_jail.py", hook_input(tool_input={"command": "git status"}))
    assert result.returncode == 0, result.stderr
    assert not (project_data / "config.json").exists()
    assert list((project_data / "audit").glob("*.jsonl"))


def test_bash_naming_the_begin_command_creates_nothing(
    run_script: Any, repo_cwd: Path, hook_input: Any
) -> None:
    # 0035: only the begin command itself creates the data dir; a record naming it does not.
    command = f"grep -n 'daedalus_workspace.py begin --repo {repo_cwd}' README.md"
    result = run_script("enforce_agent_jail.py", hook_input(tool_input={"command": command}))
    assert result.returncode == 0, result.stderr
    assert not (repo_cwd / ".claude").exists()


def test_bad_config_still_allows_a_normal_read(
    temp_home: Path, plugin_data: Path, project_data: Path, repo_cwd: Path, hook_input: Any
) -> None:
    # 0023: a broken config.json leaves the credential deny as the only gate on reads.
    (project_data / "config.json").write_text("{bad")
    target = repo_cwd / "notes.txt"
    target.write_text("x\n")
    payload = hook_input(tool_name="Read", tool_input={"file_path": str(target)})
    result = _run_home(payload, temp_home, plugin_data)
    assert result.returncode == 0, result.stderr


def test_bad_config_still_refuses_an_ssh_key_read(
    temp_home: Path, plugin_data: Path, project_data: Path, hook_input: Any
) -> None:
    (project_data / "config.json").write_text("{bad")
    key = temp_home / ".ssh" / "id_ed25519"
    payload = hook_input(tool_name="Read", tool_input={"file_path": str(key)})
    result = _run_home(payload, temp_home, plugin_data)
    # Main never prompted (amends 0106): outside a train the operator's session is warned.
    assert result.returncode == 0, result.stderr
    assert "credential path" in main_warning(result.stdout)


def test_bad_config_still_blocks_bash(
    temp_home: Path, plugin_data: Path, project_data: Path, hook_input: Any
) -> None:
    _in_train(project_data)
    (project_data / "config.json").write_text("{bad")
    payload = hook_input(tool_input={"command": "ls"}, **AUDITOR)
    result = _run_home(payload, temp_home, plugin_data)
    assert result.returncode == 2 and "config.json" in result.stderr


def test_unwritable_audit_dir_still_allows_a_read(
    temp_home: Path, plugin_data: Path, project_data: Path, repo_cwd: Path, hook_input: Any
) -> None:
    # spec 8: an allowed read never waits on the audit record; the stderr line names the failure.
    _in_train(project_data)
    (project_data / "audit").write_text("not a directory")
    target = repo_cwd / "notes.txt"
    target.write_text("x\n")
    payload = hook_input(tool_name="Read", tool_input={"file_path": str(target)})
    result = _run_home(payload, temp_home, plugin_data)
    assert result.returncode == 0, result.stderr
    assert "audit log unavailable" in result.stderr


@pytest.mark.parametrize(
    ("tool", "tool_input"),
    [
        ("Write", {"file_path": "src/app.py", "content": "x"}),
        ("Edit", {"file_path": "tests/test_x.py", "old_string": "a", "new_string": "b"}),
        ("Write", {"file_path": ".claude/daedalus/config.json", "content": "{}"}),
        ("Bash", {"command": "git clean -fdx"}),
        ("Bash", {"command": "gh pr merge 1 --admin"}),
        ("Bash", {"command": "git push -f origin main"}),
        ("Bash", {"command": "echo $(date) > notes.txt"}),
        ("Bash", {"command": "cat ~/.ssh/id_ed25519"}),
    ],
)
def test_main_outside_a_train_meets_no_jail_rule(
    temp_home: Path,
    plugin_data: Path,
    repo_cwd: Path,
    hook_input: Any,
    tool: str,
    tool_input: dict[str, str],
) -> None:
    # 0035: outside a train only Read, Glob and Grep carry a check (the credential deny, 0023).
    payload = hook_input(tool_name=tool, tool_input=tool_input)
    result = _run_home(payload, temp_home, plugin_data)
    assert result.returncode == 0, result.stderr
    assert result.stderr == ""
    assert not (repo_cwd / ".claude").exists()


@pytest.mark.parametrize(
    ("tool", "tool_input", "reason"),
    # 0105: a main Write in a train is warned; see the context test above.
    [("Bash", {"command": "git clean -fdx"}, "git clean")],
)
def test_main_inside_a_train_meets_the_jail(
    temp_home: Path,
    plugin_data: Path,
    project_data: Path,
    hook_input: Any,
    tool: str,
    tool_input: dict[str, str],
    reason: str,
) -> None:
    # Main never prompted (amends 0106): main meets the jail as a warning and the finding.
    _in_train(project_data)
    payload = hook_input(tool_name=tool, tool_input=tool_input)
    result = _run_home(payload, temp_home, plugin_data)
    assert result.returncode == 0 and result.stderr == "", result.stderr
    assert reason in main_warning(result.stdout)


@pytest.mark.parametrize("agent", [None, "Explore"])
def test_credential_read_warns_main_and_refuses_an_agent_outside_a_train(
    temp_home: Path, plugin_data: Path, repo_cwd: Path, hook_input: Any, agent: str | None
) -> None:
    # 0023, Main never prompted (amends 0106): main is warned with the literal exposure text.
    key = temp_home / ".ssh" / "id_ed25519"
    payload = hook_input(tool_name="Read", tool_input={"file_path": str(key)})
    if agent:
        payload["agent_type"] = agent
    result = _run_home(payload, temp_home, plugin_data)
    if agent:
        assert result.returncode == 2 and result.stdout == ""
        assert "is a credential path" in result.stderr
    else:
        assert result.returncode == 0, result.stderr
        reason = main_warning(result.stdout)
        assert reason.startswith(
            "This path holds credentials; reading it puts the secret into the session "
            "transcript. The jail's finding: "
        )
        assert "is a credential path" in reason
    assert not (repo_cwd / ".claude").exists()


def test_daedalus_agent_outside_a_train_is_still_judged(
    run_script: Any, repo_cwd: Path, hook_input: Any
) -> None:
    payload = hook_input(agent_type="daedalus:repo-coder", tool_input={"command": "git push o x"})
    result = run_script("enforce_agent_jail.py", payload)
    assert result.returncode == 2
    assert not (repo_cwd / ".claude").exists()


def test_main_writing_into_another_repos_train_is_judged(
    run_script: Any, tmp_path: Path, repo_cwd: Path, hook_input: Any
) -> None:
    # issue 30: the fast path hands a call naming a marked repo to the full jail.
    marked = tmp_path.resolve() / "marked"
    subprocess.run(["git", "init", "-q", str(marked)], check=True)
    (marked / ".claude" / "daedalus").mkdir(parents=True)
    _in_train(marked / ".claude" / "daedalus")
    command = f"git -C {marked} clean -fdx"
    result = run_script("enforce_agent_jail.py", hook_input(tool_input={"command": command}))
    # Main never prompted (amends 0106): judged by the full jail, which warns main.
    assert result.returncode == 0
    assert "git clean" in main_warning(result.stdout)


def test_fast_path_imports_only_the_standard_library_modules(repo_cwd: Path) -> None:
    # 0035: outside a train a main-session call never loads the jail or the audit modules.
    payload = {
        "session_id": "s",
        "hook_event_name": "PreToolUse",
        "tool_name": "Read",
        "tool_input": {"file_path": str(repo_cwd / "x")},
        "cwd": str(repo_cwd),
    }
    result = subprocess.run(
        [sys.executable, "-X", "importtime", str(_SCRIPT)],
        input=json.dumps(payload),
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0
    loaded = {line.rsplit("|", 1)[-1].strip() for line in result.stderr.splitlines()}
    assert {"lib.credential_paths", "lib.train_scope"} <= loaded
    assert not loaded & {"lib.jail", "lib.audit", "lib.config", "subprocess"}


@pytest.mark.parametrize(
    "module", ["credential_paths.py", "train_scope.py", "repo_root.py", "project_root.py"]
)
def test_fast_path_modules_use_the_standard_library_only(module: str) -> None:
    # 0035: a fast-path module imports the standard library and other fast-path modules only.
    tree = ast.parse((_SCRIPT.parent / "lib" / module).read_text())
    names = [a.name for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names]
    names += [n.module or "" for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)]
    fast = {"lib.repo_root", "lib.project_root"} - {f"lib.{module.removesuffix('.py')}"}
    assert not [n for n in names if (n == "lib" or n.startswith("lib.")) and n not in fast]


_RETIRED_ASKS = [
    "repo write",
    "data folder write",
    "git write",
    "credential read",
    "force push",
    "recursive delete",
    "push during a train",
]


def _retired_ask(case: str, repo: Path, home: Path) -> tuple[str, dict[str, str], str]:
    # Main never prompted (amends 0105, 0106): each class that asked before, with its warning.
    dotgit = f"{repo}/.git/config"
    return {
        "repo write": ("Write", {"file_path": f"{repo}/src/a.py"}, "Build Train 20261015-120000"),
        "data folder write": (
            "Write",
            {"file_path": f"{repo}/.claude/daedalus/config.json"},
            jail.WARN_DATA_DIR,
        ),
        "git write": ("Write", {"file_path": dotgit}, jail.WARN_DOTGIT.format(path=dotgit)),
        "credential read": ("Read", {"file_path": f"{home}/.ssh/id_ed25519"}, jail.WARN_CREDENTIAL),
        "force push": ("Bash", {"command": "git push --force origin f/x"}, jail.WARN_FORCE_PUSH),
        "recursive delete": ("Bash", {"command": "rm -rf /"}, jail.WARN_DELETE),
        "push during a train": (
            "Bash",
            {"command": "git push -u origin f/x"},
            jail.WARN_TRAIN_PUSH,
        ),
    }[case]


@pytest.mark.parametrize("case", _RETIRED_ASKS)
def test_main_retired_ask_is_allowed_with_the_warning_in_context(
    temp_home: Path,
    plugin_data: Path,
    project_data: Path,
    repo_cwd: Path,
    hook_input: Any,
    case: str,
) -> None:
    # Main never prompted (amends 0105, 0106): allow, the warning in context, an allow record.
    _in_train(project_data)
    tool, tool_input, lead = _retired_ask(case, repo_cwd, temp_home)
    result = _run_home(hook_input(tool_name=tool, tool_input=tool_input), temp_home, plugin_data)
    assert result.returncode == 0 and result.stderr == "", result.stderr
    warning = main_warning(result.stdout)
    assert warning.startswith(lead) and "Approve" not in warning, warning
    rec = _last_record(project_data)
    assert rec["decision"] == "allow" and rec["reason"] == f"jail: {warning}", rec


@pytest.mark.parametrize("case", _RETIRED_ASKS)
def test_agent_stays_denied_where_main_is_warned(
    temp_home: Path,
    plugin_data: Path,
    project_data: Path,
    repo_cwd: Path,
    hook_input: Any,
    case: str,
) -> None:
    # Main never prompted (amends 0105, 0106): every agent decision stays allow or deny.
    _in_train(project_data)
    tool, tool_input, _ = _retired_ask(case, repo_cwd, temp_home)
    payload = hook_input(tool_name=tool, tool_input=tool_input, **CODER)
    result = _run_home(payload, temp_home, plugin_data)
    assert result.returncode == 2 and result.stdout == "", result.stdout
    assert _last_record(project_data)["decision"] == "block"


def test_main_path_outside_every_marked_repo_stays_unjudged(
    temp_home: Path, plugin_data: Path, project_data: Path, hook_input: Any
) -> None:
    # 0105, unchanged by Main never prompted: a path outside every train repo meets no warning.
    _in_train(project_data)
    for path in (temp_home / "notes" / "memory.md", Path("/tmp/daedalus-unjudged.md")):
        payload = hook_input(tool_name="Write", tool_input={"file_path": str(path)})
        result = _run_home(payload, temp_home, plugin_data)
        assert result.returncode == 0 and result.stdout == "", (path, result.stdout)
        rec = _last_record(project_data)
        assert rec["decision"] == "allow" and rec["reason"] is None, rec
