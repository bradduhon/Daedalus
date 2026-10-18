# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0044: the README matrix is generated from the agent files, and a stale copy fails here.
from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

import catalog
import pytest

from tests.conftest import REPO_ROOT, SCRIPTS_DIR

AGENTS = REPO_ROOT / "agents"
START = "<!-- generated: catalog.py matrix -->\n"
END = "<!-- end generated -->"


def _readme_block() -> str:
    text = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    assert text.count(START) == 1 and text.count(END) == 1
    block = text.split(START, 1)[1].split(END, 1)[0]
    assert text.index(START) > text.index("## The agents")
    assert text.index(END) < text.index("## Files Daedalus creates")
    return block


def test_readme_matrix_is_current() -> None:
    assert _readme_block() == catalog.matrix(AGENTS)


def test_matrix_changes_when_an_agent_file_changes(tmp_path: Path) -> None:
    scratch = tmp_path / "agents"
    shutil.copytree(AGENTS, scratch)
    assert catalog.matrix(scratch) == _readme_block()
    coder = scratch / "repo-coder.md"
    text = coder.read_text(encoding="utf-8")
    assert "shell_tripwires.py --no-pipes" in text
    coder.write_text(text.replace("shell_tripwires.py --no-pipes", "shell_tripwires.py"))
    changed = catalog.matrix(scratch)
    assert changed != _readme_block()
    assert (
        "| repo-coder | producer | credential_paths, workspace_integrity, tool_bound, " in changed
    )
    assert ", shell_tripwires, network_tools," in changed


def test_matrix_shape() -> None:
    out = catalog.matrix(AGENTS)
    rows = out.splitlines()
    assert rows[:2] == ["| Agent | Shape | Hooks |", "|---|---|---|"]
    names = [row.split(" | ", 1)[0].removeprefix("| ") for row in rows[2:]]
    assert names == sorted(p.stem for p in AGENTS.glob("*.md"))
    assert out.endswith("|\n") and not out.endswith("\n\n")


def test_catalog_cli_prints_the_matrix() -> None:
    script = str(SCRIPTS_DIR / "catalog.py")
    done = subprocess.run(
        [sys.executable, script, "matrix"], capture_output=True, text=True, check=False
    )
    assert done.returncode == 0, done.stderr
    assert done.stdout == catalog.matrix(AGENTS)


@pytest.mark.parametrize("argv", [[], ["bogus"], ["matrix", "--bogus"]])
def test_catalog_cli_refuses_bad_arguments(argv: list[str]) -> None:
    script = str(SCRIPTS_DIR / "catalog.py")
    done = subprocess.run([sys.executable, script, *argv], capture_output=True, text=True)
    assert done.returncode == 2
    assert done.stdout == ""


def test_catalog_cli_reports_a_bad_agent_file(tmp_path: Path) -> None:
    (tmp_path / "bad.md").write_text("no frontmatter\n", encoding="utf-8")
    script = str(SCRIPTS_DIR / "catalog.py")
    argv = [sys.executable, script, "matrix", "--agents-dir", str(tmp_path)]
    done = subprocess.run(argv, capture_output=True, text=True, check=False)
    assert done.returncode == 1
    assert done.stdout == ""
    assert "Next: " in done.stderr
