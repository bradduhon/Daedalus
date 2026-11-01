# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# spec 4, pin C2 -> C3: the override, then config agent_models, then the agent file's model.
from __future__ import annotations

from pathlib import Path

import pytest
from lib import agent_files
from lib.agent_models import MODELS, AgentModelError, resolve
from lib.config import Config

from tests.conftest import REPO_ROOT

AGENTS = REPO_ROOT / "agents"


def test_models_are_the_four_pinned_values() -> None:
    assert MODELS == ("sonnet", "opus", "haiku", "fable")


def test_the_agent_file_model_applies_with_no_override_or_config() -> None:
    for path in sorted(AGENTS.glob("*.md")):
        assert resolve(path.stem, Config()) == agent_files.load(path).model, path.stem


def test_config_agent_models_wins_over_the_agent_file() -> None:
    config = Config(agent_models={"coder": "sonnet"})
    assert agent_files.load(AGENTS / "coder.md").model == "opus"
    assert resolve("coder", config) == "sonnet"
    assert resolve("planner", config) == "opus"


def test_the_override_wins_over_config_and_the_agent_file() -> None:
    config = Config(agent_models={"coder": "sonnet"})
    assert resolve("coder", config, "haiku") == "haiku"
    assert resolve("planner", Config(), override="fable") == "fable"


@pytest.mark.parametrize("name", ["mystery", "main", "daedalus:planner", "../agents/planner", ""])
def test_an_unknown_agent_is_refused_with_a_next_line(name: str) -> None:
    with pytest.raises(AgentModelError, match="Next: "):
        resolve(name, Config())


def test_an_override_outside_the_four_is_refused() -> None:
    with pytest.raises(AgentModelError, match="Next: "):
        resolve("planner", Config(), "gpt-4")


def test_agents_dir_reads_another_catalog(tmp_path: Path) -> None:
    (tmp_path / "solo.md").write_text("---\nname: solo\nmodel: haiku\n---\n", encoding="utf-8")
    assert resolve("solo", Config(), agents_dir=tmp_path) == "haiku"
    with pytest.raises(AgentModelError):
        resolve("planner", Config(), agents_dir=tmp_path)
