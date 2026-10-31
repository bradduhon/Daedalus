# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0187: the coder tier of one unit dispatch, from its files and its refutation count.
from __future__ import annotations

import pytest
from lib import plan_record
from lib.coder_model import (
    CONTROL_PATH,
    DEFAULT,
    DEFAULT_CODER_MODELS,
    ESCALATED,
    REASON_DEFAULT,
    REASON_ESCALATED,
    TIERS,
    coder_tier,
)

CONTROL = plan_record.CONTROL_PATHS


def test_tiers_and_defaults_follow_the_ruling() -> None:
    assert TIERS == (DEFAULT, CONTROL_PATH, ESCALATED)
    assert DEFAULT_CODER_MODELS == {
        "default": "sonnet",
        "control_path": "opus",
        "escalated": "opus",
    }


def test_plain_files_take_the_default_tier() -> None:
    assert coder_tier(["src/app.py", "tests/test_app.py"], CONTROL, 0) == (DEFAULT, REASON_DEFAULT)
    assert coder_tier([], CONTROL, 1) == (DEFAULT, REASON_DEFAULT)


@pytest.mark.parametrize(
    "name",
    [
        "agents/coder.md",
        "skills/build/SKILL.md",
        "hooks/hooks.json",
        "scripts/checks/x.py",
        "scripts/lib/jail.py",
        "scripts/lib/shell.py",
        "scripts/enforce_agent_jail.py",
        "./hooks/hooks.json",
        "Agents/planner.md",
        "skills/",
    ],
)
def test_a_control_path_file_takes_the_control_path_tier(name: str) -> None:
    assert coder_tier(["src/a.py", name], CONTROL, 1) == (CONTROL_PATH, f"control path {name}")


def test_a_project_folder_named_like_a_control_path_counts() -> None:
    # 0183: the list applies in every repository, so another project's hooks/ folder is one.
    files = ["hooks/pre_commit.py", "README.md"]
    assert coder_tier(files, CONTROL, 0) == (CONTROL_PATH, "control path hooks/pre_commit.py")
    # 0183: the paths are project-root relative; a nested folder of the same name is not one.
    assert coder_tier(["src/hooks/pre_commit.py"], CONTROL, 0) == (DEFAULT, REASON_DEFAULT)


@pytest.mark.parametrize(
    ("name", "tier"),
    [("*.md", CONTROL_PATH), ("scripts/*.py", CONTROL_PATH), ("src/*.py", DEFAULT)],
)
def test_a_glob_that_could_reach_a_control_path_counts(name: str, tier: str) -> None:
    assert coder_tier([name], CONTROL, 0)[0] == tier


@pytest.mark.parametrize(
    "name", ["/etc/agents/x.py", "../other/a.py", "src/../../a.py", ".", "./", "", "src/.."]
)
def test_an_unsafe_path_fails_closed_to_the_control_path_tier(name: str) -> None:
    # 0187: an absolute, parent or whole-repository path never falls to the default tier.
    assert coder_tier(["src/a.py", name], CONTROL, 0) == (CONTROL_PATH, f"unsafe path {name}")


@pytest.mark.parametrize("files", [["src/a.py"], ["agents/coder.md"]])
def test_a_second_refutation_escalates_any_unit(files: list[str]) -> None:
    assert coder_tier(files, CONTROL, 2) == (ESCALATED, REASON_ESCALATED)
    assert coder_tier(files, CONTROL, 3) == (ESCALATED, REASON_ESCALATED)


def test_a_first_refutation_keeps_the_tier() -> None:
    # 0187: the first failing verdict goes back warm to the same coder on the same model.
    assert coder_tier(["src/a.py"], CONTROL, 1) == (DEFAULT, REASON_DEFAULT)
