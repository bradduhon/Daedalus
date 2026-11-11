# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import re
from pathlib import Path

import pytest
from lib.human_text import MIN_WORDS

from tests.conftest import REPO_ROOT
from tests.skill_helpers import (
    _SCRIPT_REF,
    COPYRIGHT,
    HUMAN_TEXT_RULE,
    SKILLS,
    STANDARDS_SKILL,
    _forward_only,
    _operator_lines,
    _skill_lines,
    _split,
    _words,
)


def test_skills_exist() -> None:
    assert {p.parent.name for p in SKILLS} >= {
        "doctor",
        "audit-report",
        "brainstorm",
    }


@pytest.mark.parametrize("name", ["build-train", "push-train", "doc-train"])
def test_retired_train_commands_stay_gone(name: str) -> None:
    # 0241: no folder and no skill name forwards a retired train command.
    assert not (REPO_ROOT / "skills" / name).exists()
    assert all(_split(path)[0].get("name") != name for path in SKILLS)


@pytest.mark.parametrize("path", SKILLS, ids=lambda p: p.parent.name)
def test_frontmatter_names_the_directory(path: Path) -> None:
    fields, _ = _split(path)
    assert fields.get("name") == path.parent.name
    assert fields.get("description")


@pytest.mark.parametrize("path", SKILLS, ids=lambda p: p.parent.name)
def test_copyright_follows_frontmatter(path: Path) -> None:
    _, body = _split(path)
    assert body.splitlines()[0] == COPYRIGHT


@pytest.mark.parametrize("path", SKILLS, ids=lambda p: p.parent.name)
def test_no_em_or_en_dashes(path: Path) -> None:
    text = path.read_text(encoding="utf-8")
    assert "\u2013" not in text and "\u2014" not in text


@pytest.mark.parametrize("path", SKILLS, ids=lambda p: p.parent.name)
def test_named_scripts_exist(path: Path) -> None:
    for name in _SCRIPT_REF.findall(path.read_text(encoding="utf-8")):
        assert (REPO_ROOT / "scripts" / name).is_file(), f"{path}: {name}"


def test_script_ref_stops_at_py() -> None:
    # N2: a sentence-ending period after the script name is not part of the name.
    text = "run ${CLAUDE_PLUGIN_ROOT}/scripts/audit_report.py. Then"
    assert _SCRIPT_REF.findall(text) == ["audit_report.py"]


@pytest.mark.parametrize("path", SKILLS, ids=lambda p: p.parent.name)
def test_no_plan_or_task_numbers(path: Path) -> None:
    # R1-M3: operator text never names internal plan or task numbers.
    assert not re.search(r"(Task|Plan) [0-9]", path.read_text(encoding="utf-8"))


def test_standards_skill_keeps_the_method_and_its_receipt_forms() -> None:
    # 0186: nested, so out of the slash menu; the rule ids and reply forms of the agent survive.
    assert STANDARDS_SKILL not in SKILLS
    fields, body = _split(STANDARDS_SKILL)
    assert fields.get("name") == "standards" and fields.get("description")
    assert body.splitlines()[0] == COPYRIGHT
    assert "\u2013" not in body and "\u2014" not in body
    flat = " ".join(body.split())
    assert "Read this skill first and follow it yourself" in flat
    for rule_id in ("0005-DAE-PLT", "§6.6", "(0019)", "(0129, 0137)", "(0031)"):
        assert rule_id in flat, rule_id
    assert "under 300 words" in flat
    assert "An auditor brief ends with the rule list, nothing after it." in flat
    forms = body.split("\n## Receipt forms\n", 1)[1]
    assert forms.endswith(
        "- `## Standards Packet`\n"
        "- `[STANDARDS: CONTRADICTION] <spec ref> vs <source:line>`\n"
        "- `[STATUS: STANDARD] <answer>`\n"
    )


def test_operator_lines_are_not_bare_ids() -> None:
    bare = [
        f"{name}:{number} {kind}: {' '.join(text.split())}"
        for name, number, kind, text in _operator_lines()
        if text.strip() and not _forward_only(text) and len(_words(text)) < MIN_WORDS
    ]
    assert bare == []


@pytest.mark.parametrize("path", SKILLS, ids=lambda p: p.parent.name)
def test_operator_skills_carry_the_human_text_rule(path: Path) -> None:
    # 0031: every working skill speaks to the operator, so each carries the rule verbatim.
    assert HUMAN_TEXT_RULE in path.read_text(encoding="utf-8")


def test_operator_line_scanner_flags_bare_ids() -> None:
    # 0031: the scanner itself; a command or id alone is not a description.
    assert len(_words("run /daedalus:doctor.")) < MIN_WORDS
    assert len(_words("rerun `/daedalus:build-train` (0024)")) < MIN_WORDS
    assert len(_words("run the Daedalus health check (/daedalus:doctor).")) >= MIN_WORDS
    lines = _skill_lines(SKILLS[0])
    assert all(kind in {"next", "stop"} for _, kind, _ in lines)


ALL_SKILLS = sorted((REPO_ROOT / "skills").rglob("SKILL.md"))
RULE_START = "Self-Assessment mode (standing rule"
# 0252: the only two allowed-tools lines in the skills; neither names the findings script.
ALLOWED_TOOLS_LINES = {
    "doctor": "Bash(python3 ${CLAUDE_SKILL_DIR}/../../scripts/daedalus_doctor.py *)",
    "setup": (
        "Bash(python3 ${CLAUDE_SKILL_DIR}/../../scripts/daedalus_setup.py *), "
        "Bash(python3 ${CLAUDE_SKILL_DIR}/../../scripts/daedalus_train.py ask-check *), "
        "AskUserQuestion"
    ),
}


def _rule(path: Path) -> str:
    text = path.read_text(encoding="utf-8")
    found = [line for line in text.splitlines() if line.startswith(RULE_START)]
    assert len(found) == 1, path
    return found[0]


def test_all_skill_files_are_globbed() -> None:
    assert len(ALL_SKILLS) >= len(SKILLS)
    assert STANDARDS_SKILL in ALL_SKILLS


@pytest.mark.parametrize("path", ALL_SKILLS, ids=lambda p: p.parent.name)
def test_standing_rule_is_identical_in_every_skill(path: Path) -> None:
    assert _rule(path) == _rule(ALL_SKILLS[0])


@pytest.mark.parametrize("path", ALL_SKILLS, ids=lambda p: p.parent.name)
def test_standing_rule_sits_after_the_opening_paragraph(path: Path) -> None:
    lines = path.read_text(encoding="utf-8").splitlines()
    at = lines.index(_rule(path))
    assert lines[at - 1] == "" and lines[at + 1] == ""
    before = lines[at - 2]
    assert before.startswith("Human-facing text (0031)") or before.startswith("# ")


def test_standing_rule_calls_match_the_approval_rows(monkeypatch: pytest.MonkeyPatch) -> None:
    from lib import plugin_approvals

    monkeypatch.setenv("CLAUDE_PLUGIN_ROOT", str(REPO_ROOT))
    calls = [part for part in _rule(ALL_SKILLS[0]).split("`") if part.startswith("python3 ")]
    assert len(calls) == 3
    expected = ["findings-start", "findings-save", "findings-show"]
    for call, name in zip(calls, expected, strict=True):
        command = (
            call.replace("${CLAUDE_PLUGIN_ROOT}", str(REPO_ROOT))
            .replace("<path>", "/tmp/project")
            .replace("<stamp>", "20261111T000000Z")
        )
        payload = {"tool_name": "Bash", "tool_input": {"command": command}, "cwd": "/tmp/project"}
        assert plugin_approvals.approve(payload) == name, call


@pytest.mark.parametrize("path", ALL_SKILLS, ids=lambda p: p.parent.name)
def test_no_skill_pre_approves_the_findings_script(path: Path) -> None:
    fields, _ = _split(path)
    line = fields.get("allowed-tools")
    assert line == ALLOWED_TOOLS_LINES.get(path.parent.name)
    assert "daedalus_findings.py" not in (line or "")
