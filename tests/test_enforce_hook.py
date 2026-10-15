# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import io
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

import enforce_agent_jail
import pytest

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


def test_allow_exits_zero_and_logs_allow(
    run_script: Any, project_data: Path, hook_input: Any
) -> None:
    result = run_script("enforce_agent_jail.py", hook_input(tool_input={"command": "git status"}))
    assert result.returncode == 0, result.stderr
    rec = json.loads((project_data / "audit" / "sess-test.jsonl").read_text().splitlines()[-1])
    assert rec["decision"] == "allow" and rec["reason"] is None


def test_block_exits_two_with_message_and_logs_block(
    run_script: Any, project_data: Path, hook_input: Any
) -> None:
    payload = hook_input(agent_type="repo-coder", tool_input={"command": "git push origin x"})
    result = run_script("enforce_agent_jail.py", payload)
    assert result.returncode == 2
    assert result.stderr.startswith("daedalus-jail[repo-coder]: no remote git operations")
    assert "Next:" in result.stderr
    rec = json.loads((project_data / "audit" / "sess-test.jsonl").read_text().splitlines()[-1])
    assert rec["decision"] == "block" and rec["reason"].startswith("no remote git operations")


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
    result = run_script("enforce_agent_jail.py", hook_input(agent_type="ghost"))
    assert result.returncode == 2 and "fail closed" in result.stderr


def test_unknown_agent_passes_without_a_train(
    run_script: Any, project_data: Path, hook_input: Any
) -> None:
    result = run_script("enforce_agent_jail.py", hook_input(agent_type="ghost"))
    assert result.returncode == 0, result.stderr


def test_unwritable_audit_dir_fails_closed(
    run_script: Any, project_data: Path, hook_input: Any
) -> None:
    (project_data / "audit").write_text("not a directory")
    result = run_script("enforce_agent_jail.py", hook_input(tool_input={"command": "ls"}))
    assert result.returncode == 2
    assert "audit log unavailable" in result.stderr


def test_malformed_config_blocks(run_script: Any, project_data: Path, hook_input: Any) -> None:
    (project_data / "config.json").write_text("{bad")
    result = run_script("enforce_agent_jail.py", hook_input(tool_input={"command": "ls"}))
    assert result.returncode == 2 and "config.json" in result.stderr


def test_oversized_int_config_blocks_and_records(
    run_script: Any, project_data: Path, hook_input: Any
) -> None:
    (project_data / "config.json").write_text('{"x": ' + "1" * 5000 + "}")
    result = run_script("enforce_agent_jail.py", hook_input(tool_input={"command": "ls"}))
    assert result.returncode == 2
    assert result.stderr.startswith("daedalus-jail[main]: ")
    assert "Next:" in result.stderr
    rec = json.loads((project_data / "audit" / "sess-test.jsonl").read_text().splitlines()[-1])
    assert rec["decision"] == "block" and "not valid JSON" in rec["reason"]


def test_malformed_config_records_block(
    run_script: Any, project_data: Path, hook_input: Any
) -> None:
    (project_data / "config.json").write_text("{bad")
    result = run_script("enforce_agent_jail.py", hook_input(tool_input={"command": "ls"}))
    assert result.returncode == 2
    rec = json.loads((project_data / "audit" / "sess-test.jsonl").read_text().splitlines()[-1])
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


def test_missing_libraries_fail_closed(tmp_path: Path, project_data: Path, hook_input: Any) -> None:
    lone = tmp_path / "lone"
    lone.mkdir()
    shutil.copy(_SCRIPT, lone / "enforce_agent_jail.py")
    result = _run_raw(json.dumps(hook_input()), lone / "enforce_agent_jail.py")
    assert result.returncode == 2
    assert result.stderr.startswith("daedalus-jail[?]: hook could not load its libraries (")
    assert "Next: run the plugin with Python 3.12 and an intact scripts/lib directory." in (
        result.stderr
    )


def test_decide_exception_blocks_and_records(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    project_data: Path,
    hook_input: Any,
) -> None:
    def _boom(*_args: Any) -> Any:
        raise RuntimeError("decide exploded")

    monkeypatch.setattr(enforce_agent_jail, "decide", _boom)
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(hook_input())))
    assert enforce_agent_jail.main() == 2
    err = capsys.readouterr().err
    assert err.startswith("daedalus-jail[main]: decide exploded Next:")
    rec = json.loads((project_data / "audit" / "sess-test.jsonl").read_text().splitlines()[-1])
    assert rec["decision"] == "block" and rec["reason"].startswith("decide exploded")


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
    (project_data / "config.json").write_text('{"ledger": {"path": "/x"}}')
    result = run_script("enforce_agent_jail.py", hook_input(tool_input={"command": "ls"}))
    assert result.returncode == 2
    assert "config.json is missing ledger.format" in result.stderr


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
    result = run_script("enforce_agent_jail.py", hook_input(tool_input={"command": "ls"}))
    assert result.returncode == 2, result.stderr
    assert "Next:" in result.stderr
    assert list(elsewhere.iterdir()) == []


def test_cwd_fallback_warns_on_stderr_and_allows(
    run_script: Any, hook_input: Any, tmp_path: Path
) -> None:
    plain = tmp_path / "plain"
    plain.mkdir()
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
    # spec 8, 0023: an allowed Read through the jail still lands an audit record.
    target = repo_cwd / "notes.txt"
    target.write_text("x\n")
    payload = hook_input(
        agent_type="Explore", tool_name="Read", tool_input={"file_path": str(target)}
    )
    result = _run_home(payload, temp_home, plugin_data)
    assert result.returncode == 0, result.stderr
    rec = json.loads((project_data / "audit" / "sess-test.jsonl").read_text().splitlines()[-1])
    assert rec["decision"] == "allow" and rec["tool_name"] == "Read"


def test_explore_read_of_an_ssh_key_is_refused(
    temp_home: Path, plugin_data: Path, project_data: Path, hook_input: Any
) -> None:
    key = temp_home / ".ssh" / "id_ed25519"
    payload = hook_input(agent_type="Explore", tool_name="Read", tool_input={"file_path": str(key)})
    result = _run_home(payload, temp_home, plugin_data)
    assert result.returncode == 2
    assert result.stderr.startswith("daedalus-jail[Explore]:"), result.stderr


def test_main_grep_rooted_at_home_is_refused(
    temp_home: Path, plugin_data: Path, project_data: Path, hook_input: Any
) -> None:
    payload = hook_input(tool_name="Grep", tool_input={"pattern": "x", "path": str(temp_home)})
    result = _run_home(payload, temp_home, plugin_data)
    assert result.returncode == 2
    assert result.stderr.startswith("daedalus-jail[main]:"), result.stderr


def test_main_glob_over_the_repo_is_allowed(
    temp_home: Path, plugin_data: Path, project_data: Path, repo_cwd: Path, hook_input: Any
) -> None:
    payload = hook_input(tool_name="Glob", tool_input={"pattern": "*", "path": str(repo_cwd)})
    result = _run_home(payload, temp_home, plugin_data)
    assert result.returncode == 0, result.stderr


def test_absent_config_allows_main_bash_and_writes_the_log(
    run_script: Any, repo_cwd: Path, hook_input: Any
) -> None:
    # 0020: config.json is optional; absence is the empty config, never a block.
    result = run_script("enforce_agent_jail.py", hook_input(tool_input={"command": "git status"}))
    assert result.returncode == 0, result.stderr
    data = repo_cwd / ".claude" / "daedalus"
    assert not (data / "config.json").exists()
    assert list((data / "audit").glob("*.jsonl"))
