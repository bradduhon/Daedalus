# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import re

import pytest

from tests.skill_helpers import (
    _NEXT_ITEM,
    LOADED_SKILLS,
    NEXT_NAMES,
    PHASE_PARTS,
    PHASE_SKILLS,
    SKILLS,
    _drop_code_spans,
    _phase_skill,
    _split,
)


@pytest.mark.parametrize("name", LOADED_SKILLS)
def test_phase_skill_is_found_by_the_skill_loader(name: str) -> None:
    # Claude Code loads skills/<name>/SKILL.md by its folder; the frontmatter name matches it.
    path = _phase_skill(name)
    assert path in SKILLS
    fields, _ = _split(path)
    assert fields.get("name") == name and fields.get("description")


@pytest.mark.parametrize("name", PHASE_SKILLS)
def test_phase_skill_holds_the_four_parts_in_order(name: str) -> None:
    # spec 3: method, evidence, agents, then the suggested-next block, and no other part.
    _, body = _split(_phase_skill(name))
    heads = [line for line in body.splitlines() if line.startswith("## ")]
    assert heads == list(PHASE_PARTS)


@pytest.mark.parametrize("name", PHASE_SKILLS)
def test_phase_skill_suggests_only_phase_skills(name: str) -> None:
    # spec 3.2 to 3.4: each item names one phase skill and its trigger.
    _, body = _split(_phase_skill(name))
    block = body.split("\n## Suggested next\n", 1)[1]
    items = [line for line in block.splitlines() if line.strip()]
    assert items
    named = [m.group(1) for line in items if (m := _NEXT_ITEM.match(line))]
    assert len(named) == len(items), items
    assert set(named) <= NEXT_NAMES, named


@pytest.mark.parametrize("name", LOADED_SKILLS)
def test_phase_skill_says_run_not_train(name: str) -> None:
    # 0169: operator text says run; command, state file, script and hook names keep train.
    text = _drop_code_spans(_phase_skill(name).read_text(encoding="utf-8"))
    assert re.findall(r"\btrains?\b", text, re.IGNORECASE) == []


def test_run_not_train_scan_keeps_code_spans_and_catches_prose() -> None:
    # 0169: the scan above drops a command span but not a plain-word label span.
    kept = _drop_code_spans("run `/daedalus:build-train` on <train-id>, then `End the train`")
    assert re.findall(r"\btrains?\b", kept, re.IGNORECASE) == ["train"]


@pytest.mark.parametrize(
    ("name", "moved"),
    [
        (
            "plan",
            (
                "scripts/daedalus_map.py --repo <repo> --out "
                "<repo>/docs/.tmp/daedalus/<train-id>/map`",
                "scripts/daedalus_train.py contract --repo <repo>`",
                "scripts/daedalus_workspace.py lock --repo <repo> --no-contract`",
                "scripts/daedalus_workspace.py lock --repo <repo> --contract <contract path> "
                "--version <packet_version>`",
                "`Follow Plugin + amend global`",
                "`Contract: <contract path> sha256=<hex>`",
            ),
        ),
        (
            "build",
            (
                "scripts/daedalus_workspace.py create --repo <repo> --name <train-id>-<unit-slug> "
                "--base daedalus/<train-id>`",
                "scripts/daedalus_doctor.py --check-tools <names> --repo <repo>`",
                "`[STATUS: YIELD_CONTRACT] <mismatch>`",
                "`[STATUS: YIELD_COMPLIANCE] <question>`",
                "`git merge-base --is-ancestor <lock sha> <b>`",
                "scripts/daedalus_workspace.py finish --repo <repo>`",
            ),
        ),
        (
            "audit",
            (
                "scripts/daedalus_workspace.py create --repo <repo> --name <train-id>-audit "
                "--base daedalus/<train-id>`",
                "scripts/daedalus_workspace.py refresh --repo <repo> --name <train-id>-audit`",
                "`Hunt: can <attacker input> reach <protected thing> after <unit>?`",
                "scripts/daedalus_train.py verdict --repo <repo> --status rejected --round <n> "
                "--findings <findings path> --tip <judged tip>`",
                "scripts/daedalus_train.py ledger --repo <repo> --sha <sha> --ids <ids>`",
                "scripts/daedalus_train.py reaudit --repo <repo>`",
                "The orchestrator puts a `Size: small` line in the auditor's dispatch",
                "A later round on the same run, after a fix, uses the full procedure.",
                "A run in folder scope runs no audit",
            ),
        ),
        (
            "document",
            (
                "scripts/daedalus_workspace.py create --repo <repo> --name <train-id>-docstage "
                "--base daedalus/<train-id>`",
                "`<repo>/docs/.tmp/daedalus/<train-id>/briefs/docs.md`",
                "scripts/daedalus_train.py verdict --repo <repo> --gate docs --status verified "
                "--judged <sha>`",
                "scripts/freeze_sources.py --train <train-id> --output-dir <output folder>",
                "Runs only when the manifest declares a `baseline` role",
                "nothing derived is used anywhere until its rows read agreed",
            ),
        ),
        (
            "verify",
            (
                "`git -C <repo> diff -U0 <lock sha>...<b>`",
                "the line `Brief: <the unit's brief path from the build phase>`",
                "`[VERDICT: REFUTED] <rows>`",
                "`Claim: <output path>:<line> <claim>`",
            ),
        ),
    ],
)
def test_phase_skill_carries_the_method_it_moved(name: str, moved: tuple[str, ...]) -> None:
    # spec 3.1: the method moves from the orchestrator recipe into the phase skill.
    flat = " ".join(_phase_skill(name).read_text(encoding="utf-8").split())
    for item in moved:
        assert item in flat, item


def test_plan_and_document_skills_write_folder_outputs_into_the_run_output_folder() -> None:
    # issue 48: the hooks admit a folder run's output folder, so agents write there; no copy step.
    plan = " ".join(_phase_skill("plan").read_text(encoding="utf-8").split())
    assert "unit S1" not in plan
    assert "take `<repo>`, `<train-id>` and `<out>` from the State Block lines" in plan
    assert "In a folder run it is `<out>/plan-<YYYYMMDD>.md`" in plan
    assert "Next: run `/daedalus:run <spec>`, which opens a run in this folder" in plan
    assert "the run ends with the plan file at `<out>`, or goes on to a document phase" in plan
    doc = " ".join(_phase_skill("document").read_text(encoding="utf-8").split())
    assert "The output folder is `<out>`: freeze and the document outputs check admit it" in doc
    assert "In a folder run, the run entry's stop command ends the run in place of unmark." in doc
    for text in (plan, doc):
        assert "with Read and Write" not in text
