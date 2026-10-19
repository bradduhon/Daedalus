# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0044: each hook decides the same standalone (stdin, stdout) and imported (decide) by the router.
from __future__ import annotations

import json
from pathlib import Path

import pytest
from lib import hook_io

from tests.hook_chain import load, run_script

MALFORMED = "{}"


def _case(tool: str, cwd: Path, agent: str = "repo-coder", **fields: str) -> dict[str, object]:
    return {"tool_name": tool, "tool_input": dict(fields), "cwd": str(cwd), "agent_type": agent}


def _same(script: str, flags: list[str], hook_input: dict[str, object] | None) -> bool:
    # 0044: one decision through hook_io.run in a process, one through decide in this process.
    stdin = MALFORMED if hook_input is None else json.dumps(hook_input)
    standalone = run_script(script, stdin, *flags)
    imported = load(script).decide({} if hook_input is None else hook_input, list(flags))
    assert isinstance(imported, hook_io.HookDecision)
    want = {"decision": "allow" if imported.allow else "deny", "reason": imported.reason or ""}
    assert standalone == want, (script, hook_input, standalone, want)
    return imported.allow


def _check(script: str, allow: dict[str, object], deny: dict[str, object], *flags: str) -> None:
    assert _same(script, list(flags), allow) is True
    assert _same(script, list(flags), deny) is False
    assert _same(script, list(flags), None) is False
    reason = load(script).decide({}, list(flags)).reason
    assert reason == f"hook {script} failed closed (hook input has no tool_name)"


def test_credential_paths_standalone_matches_imported(tmp_path: Path) -> None:
    allow = _case("Read", tmp_path, file_path=str(tmp_path / "notes.md"))
    deny = _case("Read", tmp_path, file_path="~/.ssh/id_ed25519")
    _check("credential_paths", allow, deny)


def test_workspace_integrity_standalone_matches_imported(tmp_path: Path) -> None:
    allow = _case("Write", tmp_path, file_path=str(tmp_path / "notes.md"))
    deny = _case("Write", tmp_path, file_path=str(tmp_path / ".git" / "config"))
    _check("workspace_integrity", allow, deny)


def test_tool_bound_standalone_matches_imported(tmp_path: Path) -> None:
    allow = _case("Read", tmp_path, file_path=str(tmp_path / "notes.md"))
    deny = _case("WebFetch", tmp_path, url="https://example.com")
    _check("tool_bound", allow, deny)


def test_shell_tripwires_standalone_matches_imported(tmp_path: Path) -> None:
    allow = _case("Bash", tmp_path, command="ls")
    deny = _case("Bash", tmp_path, command="git push --force origin main")
    _check("shell_tripwires", allow, deny)


def test_network_tools_standalone_matches_imported(tmp_path: Path) -> None:
    allow = _case("Bash", tmp_path, command="ls")
    deny = _case("Bash", tmp_path, command="curl https://example.com")
    _check("network_tools", allow, deny)


def test_unit_writes_standalone_matches_imported(tmp_path: Path) -> None:
    allow = _case("Bash", tmp_path, command="pytest -q")
    deny = _case("Write", tmp_path, file_path=str(tmp_path / "src" / "a.py"))
    _check("unit_writes", allow, deny)


def test_root_writes_standalone_matches_imported(tmp_path: Path) -> None:
    allow = _case("Write", tmp_path, file_path=str(tmp_path / "docs" / "x.md"))
    deny = _case("Write", tmp_path, file_path=str(tmp_path / "src" / "a.py"))
    _check("root_writes", allow, deny, "--touch", "docs")


def test_read_only_bash_standalone_matches_imported(tmp_path: Path) -> None:
    allow = _case("Bash", tmp_path, "security-auditor", command="ls")
    deny = _case("Bash", tmp_path, "security-auditor", command="rm x")
    _check("read_only_bash", allow, deny, "--git", "read-only")


def test_git_grammar_standalone_matches_imported(tmp_path: Path) -> None:
    allow = _case("Bash", tmp_path, command="git status")
    deny = _case("Bash", tmp_path, command="git checkout main")
    _check("git_grammar", allow, deny, "--allow", "coder")


def test_git_push_standalone_matches_imported(tmp_path: Path) -> None:
    allow = _case("Bash", tmp_path, command="git status")
    deny = _case("Bash", tmp_path, command="git push origin x")
    _check("git_push", allow, deny)


def test_gh_classes_standalone_matches_imported(tmp_path: Path) -> None:
    allow = _case("Bash", tmp_path, command="ls")
    deny = _case("Bash", tmp_path, command="gh pr merge 3")
    _check("gh_classes", allow, deny)


def test_command_allowlist_standalone_matches_imported(tmp_path: Path) -> None:
    allow = _case("Bash", tmp_path, command="git status")
    deny = _case("Bash", tmp_path, command="ls")
    _check("command_allowlist", allow, deny, "--allow", "git")


@pytest.mark.parametrize(("allow", "reason"), [(True, None), (False, "refused. Next: stop.")])
def test_hook_decision_holds_its_invariant(allow: bool, reason: str | None) -> None:
    assert hook_io.HookDecision(allow, reason) == hook_io.HookDecision(allow, reason)


@pytest.mark.parametrize(("allow", "reason"), [(True, "x"), (False, None), (False, "")])
def test_hook_decision_refuses_a_mixed_state(allow: bool, reason: str | None) -> None:
    with pytest.raises(ValueError, match="HookDecision"):
        hook_io.HookDecision(allow, reason)
