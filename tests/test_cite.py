# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# RCP, 0128: cite.py prints <file>:<line> per matching line; the coder runs it by its real path.
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import cite
import pytest
from lib import shell

from tests.conftest import CFG, CWD, SCRIPTS_DIR, WT
from tests.hook_chain import decide, evaluate
from tests.jail_cases import _unit_repo
from tests.payloads import _b, _cwd

CITE = str(SCRIPTS_DIR / "cite.py")
HOOK = "shell_tripwires"


def _run(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, CITE, *args], capture_output=True, text=True, check=False
    )


def test_each_matching_line_is_cited(tmp_path: Path) -> None:
    path = tmp_path / "a.py"
    path.write_text("x = 1\ny = x\nprint(y)\nx\n", encoding="utf-8")
    got = _run(str(path), "x")
    assert (got.returncode, got.stdout, got.stderr) == (0, f"{path}:1\n{path}:2\n{path}:4\n", "")
    assert cite.citations(str(path), "print(") == [f"{path}:3"]


def test_the_pattern_is_a_fixed_string(tmp_path: Path) -> None:
    path = tmp_path / "a.txt"
    path.write_text("a.b\naxb\n[x]\nA.B\n", encoding="utf-8")
    assert cite.citations(str(path), "a.b") == [f"{path}:1"]
    assert cite.citations(str(path), "[x]") == [f"{path}:3"]


def test_the_path_is_printed_as_given(tmp_path: Path) -> None:
    (tmp_path / "scripts").mkdir()
    (tmp_path / "scripts" / "a.py").write_text("one\ntwo\n", encoding="utf-8")
    got = subprocess.run(
        [sys.executable, CITE, "scripts/a.py", "two"],
        capture_output=True,
        text=True,
        check=False,
        cwd=tmp_path,
    )
    assert got.stdout == "scripts/a.py:2\n"


def test_no_matching_line_exits_1_with_a_next_line(tmp_path: Path) -> None:
    path = tmp_path / "a.py"
    path.write_text("one\n", encoding="utf-8")
    got = _run(str(path), "two")
    assert (got.returncode, got.stdout) == (1, "")
    assert got.stderr.splitlines()[-1].startswith("Next: ")


@pytest.mark.parametrize("args", [(), ("a.py",), ("a.py", ""), ("a.py", "b", "c")])
def test_usage_errors_exit_2(args: tuple[str, ...]) -> None:
    got = _run(*args)
    assert (got.returncode, got.stdout) == (2, "")
    assert got.stderr == f"{cite.USAGE}\n{cite.USAGE_NEXT}\n"


def test_an_unreadable_file_exits_2(tmp_path: Path) -> None:
    got = _run(str(tmp_path / "missing.py"), "x")
    assert (got.returncode, got.stdout) == (2, "")
    assert got.stderr.splitlines()[-1].startswith("Next: ")


def test_a_pattern_that_looks_like_a_flag_is_a_pattern(tmp_path: Path) -> None:
    path = tmp_path / "a.sh"
    path.write_text("ls\nls -la\n", encoding="utf-8")
    assert _run(str(path), "-la").stdout == f"{path}:2\n"


@pytest.mark.usefixtures("jail_fakes")
class TestCoderAdmission:
    # RCP, requirement 4: the plugin's own cite.py, a file in the unit worktree, for repo-coders.
    def test_the_coder_runs_the_plugin_cite(self) -> None:
        for command in (
            f"python3 {CITE} {WT}/scripts/a.py check",
            f"python3 {CITE} {WT}/scripts/a.py 'def judge('",
            f"python3 {CITE} {WT}/a.md '${{CLAUDE_PLUGIN_ROOT}}'",
            f"python3 {CITE} {WT}/scripts/a.py x | head",
        ):
            assert decide(_b("repo-coder", command), CFG).allow, command

    def test_the_coder_cites_a_relative_file_after_cd(self, tmp_path: Path) -> None:
        repo, wt = _unit_repo(tmp_path / "repo")
        for command in (
            f"cd {wt} && python3 {CITE} scripts/a.py x",
            f"cd {wt}/scripts && python3 {CITE} a.py x",
        ):
            assert decide(_cwd(_b("repo-coder", command), repo), CFG).allow, command
        got = evaluate(HOOK, _cwd(_b("repo-coder", f"cd /tmp && python3 {CITE} a.py x"), repo))
        assert got == shell.R_INLINE

    @pytest.mark.parametrize(
        "command",
        [
            f"python3 {CITE} /etc/passwd root",
            f"python3 {CITE} {CWD}/scripts/a.py x",
            f"python3 {CITE} scripts/a.py x",
            f"python3 {CITE} {WT}/../a.py x",
            f"python3 {CITE} {CWD}/.claude/worktrees/u2/a.py x",
            f"python3 {CITE} {WT}/a.py x y",
            f"python3 {CITE} {WT}/a.py",
            f"python3 {SCRIPTS_DIR}/../scripts/cite.py {WT}/a.py x",
            f"python3 /tmp/cite.py {WT}/a.py x",
            f"python {CITE} {WT}/a.py x",
            f"python3 -I {CITE} {WT}/a.py x",
            f"python3 {SCRIPTS_DIR}/append_ledger.py {WT}/a.py x",
        ],
    )
    def test_other_forms_are_refused(self, command: str) -> None:
        assert evaluate(HOOK, _b("repo-coder", command)) == shell.R_INLINE, command

    def test_the_hygiene_check_still_judges_the_pattern(self) -> None:
        got = evaluate(HOOK, _b("repo-coder", f'python3 {CITE} {WT}/a.py "$HOME"'))
        assert got == shell.R_HYGIENE

    @pytest.mark.parametrize("agent", ["charter-docs", "pr-train-conductor"])
    def test_other_workers_are_refused(self, agent: str) -> None:
        got = evaluate(HOOK, _b(agent, f"python3 {CITE} {WT}/a.py x"))
        assert got == shell.R_INLINE
