# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# B7: every key an operator file reader accepts appears in docs/project-requirements.md.
from __future__ import annotations

import json
import re
import subprocess
from pathlib import PurePosixPath

import standing_rules
from lib import train_definition
from lib.project_keys import manifest_keys
from lib.train_scope import policed_outside_train

from tests.conftest import REPO_ROOT

REQUIREMENTS = REPO_ROOT / "docs" / "project-requirements.md"
_HAND_ROW = re.compile(r"^\| `([^`]+)` \|", re.MULTILINE)
# 0069: entrypoints is a free map of area names, so the block itself is the key.
_OPAQUE = frozenset({"entrypoints"})


def _section(heading: str) -> str:
    text = REQUIREMENTS.read_text(encoding="utf-8")
    assert text.count(f"\n{heading}\n") == 1, heading
    body = text.split(f"\n{heading}\n", 1)[1]
    return re.split(r"\n#{2,3} ", body, maxsplit=1)[0]


def _leaves(value: object, prefix: str = "") -> set[str]:
    if not isinstance(value, dict) or prefix in _OPAQUE:
        return {prefix}
    out: set[str] = set()
    for key, inner in value.items():
        out |= _leaves(inner, f"{prefix}.{key}" if prefix else str(key))
    return out


def test_backfill_keys_and_areas_are_documented() -> None:
    section = _section("### Standing-rules backfill file")
    for key in sorted(standing_rules.BACKFILL_KEYS | standing_rules.RELATION_KEYS):
        assert f"`{key}`" in section, key
    for area in standing_rules.AREAS:
        assert f"`{area}`" in section, area


def test_train_definition_keys_are_documented() -> None:
    section = _section("### Project train definitions")
    keys = (
        train_definition.TOP_FIELDS
        + train_definition.STAGE_FIELDS
        + train_definition.OPTIONAL_STAGE_FIELDS
        + train_definition.SCOPE_FIELDS
        + train_definition.PROOF_FIELDS
        + train_definition.PATH_CLASSES
    )
    for key in keys:
        assert f"`{key}`" in section, key
    assert f'`"{train_definition.PER_UNIT}"`' in section


def _tree() -> str:
    text = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    section = text.split("\n## What is in this repo\n", 1)[1]
    return section.split("```\n", 1)[1].split("```", 1)[0]


def test_readme_tree_names_every_agent_skill_and_script() -> None:
    # B7: a file added under agents/, skills/ or scripts/ must appear in the README tree.
    names = set(re.findall(r"[├└]── (\S+)", _tree()))
    missing = []
    for top in ("agents", "skills", "scripts"):
        tracked = subprocess.run(
            ["git", "ls-files", top], cwd=REPO_ROOT, capture_output=True, check=True, text=True
        ).stdout.split()
        for line in tracked:
            rel = PurePosixPath(line).relative_to(top)
            # B7: skills are named by folder, and the controls fragments by their folder.
            if top == "skills":
                want = f"{rel.parts[0]}/SKILL.md"
            elif rel.parts[:2] == ("checks", "controls"):
                want = "checks/controls/"
            else:
                want = rel.as_posix()
            if want not in names:
                missing.append(f"{top}/{rel.as_posix()}")
    assert missing == []


def test_every_manifest_example_key_has_a_row() -> None:
    # B7: a key in the example is a reader key (README table) or a hand row here, never neither.
    section = _section("### service-manifest.json (repo root), optional **(checked)**")
    example = json.loads(section.split("```json\n", 1)[1].split("```", 1)[0])
    hand = set(_HAND_ROW.findall(section))
    readers = set(manifest_keys())
    assert sorted(_leaves(example) - readers - hand) == []
    assert sorted(hand & readers) == [], "a reader key belongs in the generated README table"


def test_readme_outside_train_claim_matches_the_jail() -> None:
    # B8: catalog agents keep their hooks outside a train; the main session is asked, not refused.
    assert policed_outside_train("daedalus:repo-coder")
    stale = (
        "Outside a train, the hooks refuse only reads and searches of credential files",
        "for every agent and the main session",
        "Every agent, and the main session, is refused reads",
        "and the main session while a train runs, are also refused",
    )
    for doc in (REPO_ROOT / "README.md", REPO_ROOT / "docs" / "project-requirements.md"):
        text = doc.read_text(encoding="utf-8")
        assert [claim for claim in stale if claim in text] == [], doc


def test_howto_merge_pick_names_the_push_train_verdict_stop() -> None:
    # B8: --approved has no exception path yet (issue 62), so a merge on an exception stops there.
    text = (REPO_ROOT / "docs" / "howto" / "README.md").read_text(encoding="utf-8")
    bullet = next(
        line for line in text.splitlines() if line.startswith("- Merge with each finding")
    )
    assert "Push Train" in bullet and "stops" in bullet, bullet
