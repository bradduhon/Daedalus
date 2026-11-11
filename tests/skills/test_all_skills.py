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
