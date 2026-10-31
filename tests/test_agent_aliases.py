# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0190: old agent names in operator files read as their new names for one release, as 0174
# kept the old skill names; the doctor names each one, and no agent file keeps an old name.
from __future__ import annotations

import json
from pathlib import Path

import daedalus_doctor
import pytest
from lib import agent_aliases, agent_models, train_definition
from lib.config import Config, ConfigError, load_config
from lib.manifest import load as load_manifest

from tests.conftest import CWD, REPO_ROOT
from tests.hook_chain import evaluate, load
from tests.test_orchestrator import _start

AGENTS = REPO_ROOT / "agents"
DRIVERS = ["cost", "security", "ops", "trust"]
# 0190: old names come from the one table, so no other file spells them.
OLD = {
    new: sorted(o for o, n in agent_aliases.OLD_NAMES.items() if n == new)
    for new in agent_aliases.OLD_NAMES.values()
}
CODER, AUDITOR, RELEASER, COMPARER = (
    OLD[n][0] for n in ("coder", "auditor", "releaser", "comparer")
)
DERIVER, DOCS_WRITER = OLD["writer"]


def test_every_old_name_maps_to_a_shipped_agent_and_keeps_no_file() -> None:
    for old, new in agent_aliases.OLD_NAMES.items():
        assert (AGENTS / f"{new}.md").is_file(), new
        assert not (AGENTS / f"{old}.md").exists(), old
        assert agent_aliases.current(old) == new
    assert agent_aliases.current("verifier") == "verifier"


def _config(tmp_path: Path, models: dict[str, str]) -> Path:
    path = tmp_path / "config.json"
    path.write_text(json.dumps({"agent_models": models}), encoding="utf-8")
    return path


def test_config_agent_models_reads_an_old_name_as_its_new_name(tmp_path: Path) -> None:
    config = load_config(path=_config(tmp_path, {CODER: "sonnet", DERIVER: "haiku"}))
    assert config.agent_models == {"coder": "sonnet", "writer": "haiku"}
    assert agent_models.resolve("coder", config) == "sonnet"


def test_config_agent_models_refuses_two_models_for_one_new_name(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="two models under its old and new names"):
        load_config(path=_config(tmp_path, {DOCS_WRITER: "opus", DERIVER: "haiku"}))


def test_model_command_resolves_an_old_name() -> None:
    assert agent_models.resolve(RELEASER, Config()) == "opus"


def _manifest(repo: Path, agents: dict[str, object]) -> None:
    block = {"drivers": DRIVERS, "agents": agents}
    (repo / "service-manifest.json").write_text(json.dumps({"priorities": block}), "utf-8")


def test_manifest_priority_override_reads_an_old_name(tmp_path: Path) -> None:
    _manifest(tmp_path, {CODER: {"drivers": ["security", "cost", "ops", "trust"]}})
    manifest = load_manifest(tmp_path)
    assert manifest is not None and manifest.priorities is not None
    assert manifest.priorities.ranking("coder") == ("security", "cost", "ops", "trust")


def test_the_auditor_ranking_stays_closed_under_its_old_name(tmp_path: Path) -> None:
    _manifest(tmp_path, {AUDITOR: {"drivers": DRIVERS}})
    with pytest.raises(ValueError, match="whose ranking no project overrides"):
        load_manifest(tmp_path)


def test_a_train_definition_stage_reads_an_old_agent_name(tmp_path: Path) -> None:
    raw = json.loads((REPO_ROOT / "tests" / "fixtures" / "trains" / "valid.json").read_text())
    for stage in raw["stages"]:
        if stage["agent"] == "coder":
            stage["agent"] = CODER
    path = tmp_path / "train.json"
    path.write_text(json.dumps(raw), encoding="utf-8")
    agents = [stage["agent"] for stage in train_definition.load(path).stages]
    assert "coder" in agents and CODER not in agents


def test_the_doctor_names_each_old_name_with_its_new_name(tmp_path: Path) -> None:
    data = tmp_path / ".claude" / "daedalus"
    data.mkdir(parents=True)
    (data / "config.json").write_text(json.dumps({"agent_models": {COMPARER: "opus"}}))
    _manifest(tmp_path, {DOCS_WRITER: {"drivers": DRIVERS}})
    lines = [line for _, line in daedalus_doctor._old_agent_name_check(tmp_path)]
    assert lines == [
        agent_aliases.renamed_line(COMPARER, "config.json agent_models"),
        agent_aliases.renamed_line(DOCS_WRITER, "service-manifest.json priorities.agents"),
    ]
    assert lines[0].startswith(f"OPT  agent name {COMPARER} in config.json agent_models:")
    assert "renamed to comparer" in lines[0] and "Next: write comparer" in lines[0]


def test_the_doctor_names_an_old_name_in_a_project_train_definition(tmp_path: Path) -> None:
    # 0190: a definition under trains_dir aliases silently at load; the doctor names it.
    manifest = {"trains_dir": "trains"}
    (tmp_path / "service-manifest.json").write_text(json.dumps(manifest), "utf-8")
    raw = json.loads((REPO_ROOT / "tests" / "fixtures" / "trains" / "valid.json").read_text())
    for stage in raw["stages"]:
        if stage["agent"] == "coder":
            stage["agent"] = CODER
    raw["consults"] = {"code": [DERIVER, "verifier"]}
    (tmp_path / "trains").mkdir()
    (tmp_path / "trains" / "mine.json").write_text(json.dumps(raw), "utf-8")
    lines = [line for _, line in daedalus_doctor._old_agent_name_check(tmp_path)]
    where = "train definition trains/mine.json"
    assert lines == [
        agent_aliases.renamed_line(CODER, where),
        agent_aliases.renamed_line(DERIVER, where),
    ]


def test_the_orchestrator_is_told_the_new_name_of_an_old_agent() -> None:
    gate = load("dispatch_gate")
    reason = evaluate("dispatch_gate", _start(CWD, f"daedalus:{AUDITOR}"))
    assert reason == gate.R_OLD_NAME.format(old=AUDITOR, new="auditor")
