# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0044: the README matrix is generated from the agent files, and a stale copy fails here.
# 0088: the agent table is generated too; README and the catalog skill carry it verbatim.
from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

import catalog
import pytest
from lib import agent_files
from lib.config import Config

from tests.conftest import REPO_ROOT, SCRIPTS_DIR

AGENTS = REPO_ROOT / "agents"
START = "<!-- generated: catalog.py matrix -->\n"
TABLE_START = "<!-- generated: catalog.py table -->\n"
END = "<!-- end generated -->"
CATALOG_SKILL = REPO_ROOT / "skills" / "catalog" / "SKILL.md"
# 0165, spec 3: the seven phase skills in run order.
PHASE_SKILLS = ("brainstorm", "plan", "build", "verify", "audit", "document", "release")
# 0176: each phase word on agent files maps to the phase skill that serves it.
WORD_MAP = {
    "context": "plan",
    "clarification": "plan",
    "plan": "plan",
    "implementation": "build",
    "audit": "audit",
    "commit": "release",
    "release": "release",
}


def _section_rows(head: str) -> list[list[str]]:
    text = CATALOG_SKILL.read_text(encoding="utf-8")
    section = text.split(f"\n{head}\n", 1)[1].split("\n## ", 1)[0]
    rows = [ln for ln in section.splitlines() if ln.startswith("| ")]
    return [row.removeprefix("| ").removesuffix(" |").split(" | ") for row in rows]


def test_catalog_tables_the_seven_phase_skills() -> None:
    # 0165, spec 3: one row per phase skill, each with what happens and the evidence that ends it.
    rows = _section_rows("## The seven phase skills")
    assert rows[0] == ["Phase skill", "What happens", "Evidence that ends it"]
    assert [row[0] for row in rows[1:]] == list(PHASE_SKILLS)
    for row in rows[1:]:
        assert len(row) == 3 and all(cell.strip() for cell in row), row
        assert (REPO_ROOT / "skills" / row[0] / "SKILL.md").is_file(), row[0]
    text = " ".join(CATALOG_SKILL.read_text(encoding="utf-8").split())
    assert "## The six phases" not in text and "| Commit and release |" not in text


def test_catalog_maps_each_phase_word_to_its_phase_skill() -> None:
    # 0176: the words stay on agent files; the catalog prints the word-to-skill map.
    rows = _section_rows("## The phase word map")
    assert rows[0] == ["Phase word", "Phase skill", "What the word covers there"]
    assert {row[0].strip("`"): row[1] for row in rows[1:]} == WORD_MAP
    assert [row[0].strip("`") for row in rows[1:]] == list(agent_files.PHASES)
    for path in AGENTS.glob("*.md"):
        assert set(agent_files.load(path).phases) <= set(WORD_MAP), path.stem


def _block(path: Path, start: str) -> str:
    text = path.read_text(encoding="utf-8")
    assert text.count(start) == 1
    return text.split(start, 1)[1].split(END, 1)[0]


def _readme_block(start: str = START) -> str:
    text = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    assert text.count(END) == 2
    assert text.index(start) > text.index("## The agents")
    assert text.rindex(END) < text.index("## Files Daedalus creates")
    return _block(REPO_ROOT / "README.md", start)


def test_readme_matrix_is_current() -> None:
    assert _readme_block() == catalog.matrix(AGENTS)


def test_table_equals_the_readme_table() -> None:
    # 9.1: the hand-written agent table is gone; README carries the generated one.
    text = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    assert _readme_block(TABLE_START) == catalog.table(AGENTS)
    assert text.index(TABLE_START) < text.index(START)
    assert "| Agent | Model | Tools | Job |" not in text


def test_table_shape() -> None:
    out = catalog.table(AGENTS)
    rows = out.splitlines()
    assert rows[:2] == [
        "| Agent | Shape | Model | Tools | Job | Reply lines | Phases |",
        "|---|---|---|---|---|---|---|",
    ]
    names = [row.split(" | ", 1)[0].removeprefix("| ") for row in rows[2:]]
    assert names == sorted(p.stem for p in AGENTS.glob("*.md"))
    loaded = agent_files.load_all(AGENTS)
    for row in rows[2:]:
        cells = row.removeprefix("| ").removesuffix(" |").split(" | ")
        assert len(cells) == 7, row
        agent = loaded[cells[0]]
        assert cells[1:4] == [agent.shape, agent.model, ", ".join(sorted(agent.tools))]
        assert agent.description.startswith(cells[4].removesuffix("."))
        assert cells[5] == "; ".join(f"`{line}`" for line in agent.status_lines)
        assert cells[6] == ", ".join(agent.phases)
    assert out.endswith("|\n") and not out.endswith("\n\n")


def test_table_job_is_the_first_sentence() -> None:
    assert catalog.job("Scoped worker. Writes code.") == "Scoped worker."
    assert catalog.job("One sentence only.") == "One sentence only."
    assert catalog.job("No period") == "No period"
    planner = next(r for r in catalog.table(AGENTS).splitlines() if r.startswith("| planner |"))
    assert "| shaper | opus | Glob, Grep, Read, Write |" in planner
    assert "`[STATUS: PLAN] path=<path> units=<n> critical_path=<k> width=<w>`" in planner
    assert planner.endswith("| clarification, plan |")


def test_catalog_skill_names_every_agent() -> None:
    # 9.2: the skill carries the generated table, so the session sees every agent it has.
    assert _block(CATALOG_SKILL, TABLE_START) == catalog.table(AGENTS)
    text = CATALOG_SKILL.read_text(encoding="utf-8")
    for path in AGENTS.glob("*.md"):
        assert f"| {path.stem} |" in text, path.stem


def test_catalog_skill_states_the_musts() -> None:
    # 0088, 0089, 0165: the musts and the seven phase skills with the evidence that ends each.
    text = " ".join(CATALOG_SKILL.read_text(encoding="utf-8").split())
    musts = text.split("## The musts", 1)[1].split(" ## ", 1)[0]
    for must in (
        "All work is audited and passes before it leaves a workspace, or the operator accepts the"
        " exception as a ruling with the findings it waives.",
        "No coder starts without a plan record and a worktree binding.",
        "Every ruling is captured in the ledger in the session it is made.",
        "Every choice is printed with its alternative and its cost before it is taken.",
        "These are musts, not suggestions.",
    ):
        assert must in musts, must
    # audit round 1, Main never prompted: four hook-checked exit conditions and the 0106 warning.
    assert "Hooks check four exit conditions today:" in text
    assert "no hook checks them" in text
    assert "warn the main session in context about its own (0106, Main never prompted)" in musts
    phases = text.split("## The seven phase skills", 1)[1].split(" ## ", 1)[0]
    for phase in PHASE_SKILLS:
        assert f"| {phase} |" in phases, phase
    words = text.split("## The phase word map", 1)[1].split(" ## ", 1)[0]
    for token in agent_files.PHASES:
        assert f"`{token}`" in words, token
    for pin in (
        "`python3 scripts/validate_plan.py <path> [--max-concurrent N]`",
        "`[STATUS: PLAN] path=<path> units=<n> critical_path=<k> width=<w>`",
        "`[STATUS: QUESTION] <what the task leaves open>`",
        "`python3 scripts/audit_report.py --repo <R> --session <S> --controls`",
    ):
        assert pin in text, pin
    rules = text.split("## Composition rules", 1)[1].split(" ## ", 1)[0]
    for rule in (
        "Phase 1 overlap (0082)",
        "Packets by hash (0083)",
        "Brief by file",
        "Warm dispatch (0086)",
        "Charter-docs reads (0084)",
        "Ledger entry files read-only",
    ):
        assert rule in rules, rule
    assert "`Dispatch: <agent>`" in rules and "`Prompt file: <path>`" in rules
    assert "`Expect: <reply lines>`" in rules


def _model_cells(out: str) -> dict[str, str]:
    rows = [row.removeprefix("| ").split(" | ") for row in out.splitlines()[2:]]
    return {cells[0]: cells[2] for cells in rows}


def test_table_without_a_config_is_unchanged_by_the_default_config() -> None:
    # pin C2 -> C1: no config prints the file models, which an empty config resolves to as well.
    assert catalog.table(AGENTS) == catalog.table(AGENTS, Config())


def test_table_with_a_config_prints_the_effective_model() -> None:
    # spec 4: agent_models replaces only the Model cell of the agents it names.
    config = Config(agent_models={"coder": "sonnet", "web-researcher": "fable"})
    plain, effective = catalog.table(AGENTS), catalog.table(AGENTS, config)
    files = _model_cells(plain)
    assert files["coder"] == "opus" and files["web-researcher"] == "haiku"
    assert _model_cells(effective) == files | config.agent_models
    changed = [a != b for a, b in zip(plain.splitlines(), effective.splitlines(), strict=True)]
    assert sum(changed) == 2


def test_catalog_cli_table_reads_the_repo_config(repo_cwd: Path, project_data: Path) -> None:
    doc = {"agent_models": {"planner": "haiku"}}
    (project_data / "config.json").write_text(json.dumps(doc), encoding="utf-8")
    script = str(SCRIPTS_DIR / "catalog.py")
    argv = [sys.executable, script, "table", "--repo", str(repo_cwd)]
    done = subprocess.run(argv, capture_output=True, text=True, check=False)
    assert done.returncode == 0, done.stderr
    assert done.stdout == catalog.table(AGENTS, Config(agent_models={"planner": "haiku"}))
    assert _model_cells(done.stdout)["planner"] == "haiku"


def test_catalog_cli_table_reports_a_bad_config(repo_cwd: Path, project_data: Path) -> None:
    (project_data / "config.json").write_text('{"agent_models": {"x": "opus"}}', encoding="utf-8")
    script = str(SCRIPTS_DIR / "catalog.py")
    argv = [sys.executable, script, "table", "--repo", str(repo_cwd)]
    done = subprocess.run(argv, capture_output=True, text=True, check=False)
    assert done.returncode == 1 and done.stdout == ""
    assert "agent_models" in done.stderr and "Next: " in done.stderr


def test_catalog_cli_prints_the_table() -> None:
    script = str(SCRIPTS_DIR / "catalog.py")
    done = subprocess.run(
        [sys.executable, script, "table"], capture_output=True, text=True, check=False
    )
    assert done.returncode == 0, done.stderr
    assert done.stdout == catalog.table(AGENTS)


def test_matrix_changes_when_an_agent_file_changes(tmp_path: Path) -> None:
    scratch = tmp_path / "agents"
    shutil.copytree(AGENTS, scratch)
    assert catalog.matrix(scratch) == _readme_block()
    coder = scratch / "coder.md"
    text = coder.read_text(encoding="utf-8")
    assert "git_grammar.py --allow coder" in text
    coder.write_text(text.replace("git_grammar.py --allow coder", "git_grammar.py --allow docs"))
    changed = catalog.matrix(scratch)
    assert changed != _readme_block()
    assert "| coder | producer | credential_paths, workspace_integrity, tool_bound, " in changed
    assert ", git_push, git_grammar --allow docs, unit_writes," in changed


def test_no_agent_file_passes_no_pipes() -> None:
    # B1: the pipe flag is deleted; the matrix shows shell_tripwires bare for every agent.
    out = catalog.matrix(AGENTS)
    assert "--no-pipes" not in out and "--no-pipes" not in _readme_block()
    for name in ("coder", "charter-docs", "releaser"):
        row = next(r for r in out.splitlines() if r.startswith(f"| {name} |"))
        assert ", shell_tripwires, network_tools" in row, name


def test_matrix_shape() -> None:
    out = catalog.matrix(AGENTS)
    rows = out.splitlines()
    assert rows[:2] == ["| Agent | Shape | Hooks |", "|---|---|---|"]
    names = [row.split(" | ", 1)[0].removeprefix("| ") for row in rows[2:]]
    # 0190: a writer kind gets its own row, labelled with the kind.
    labels = [
        f"{name} ({mode})" if mode else name
        for name, agent in sorted(agent_files.load_all(AGENTS).items())
        for mode in agent.chains()
    ]
    assert names == labels and "writer (derived)" in labels
    assert out.endswith("|\n") and not out.endswith("\n\n")


def test_catalog_cli_prints_the_matrix() -> None:
    script = str(SCRIPTS_DIR / "catalog.py")
    done = subprocess.run(
        [sys.executable, script, "matrix"], capture_output=True, text=True, check=False
    )
    assert done.returncode == 0, done.stderr
    assert done.stdout == catalog.matrix(AGENTS)


@pytest.mark.parametrize("argv", [[], ["bogus"], ["matrix", "--bogus"], ["table", "--bogus"]])
def test_catalog_cli_refuses_bad_arguments(argv: list[str]) -> None:
    script = str(SCRIPTS_DIR / "catalog.py")
    done = subprocess.run([sys.executable, script, *argv], capture_output=True, text=True)
    assert done.returncode == 2
    assert done.stdout == ""


@pytest.mark.parametrize("command", ["matrix", "table"])
def test_catalog_cli_reports_a_bad_agent_file(tmp_path: Path, command: str) -> None:
    (tmp_path / "bad.md").write_text("no frontmatter\n", encoding="utf-8")
    script = str(SCRIPTS_DIR / "catalog.py")
    argv = [sys.executable, script, command, "--agents-dir", str(tmp_path)]
    done = subprocess.run(argv, capture_output=True, text=True, check=False)
    assert done.returncode == 1
    assert done.stdout == ""
    assert "Next: " in done.stderr
