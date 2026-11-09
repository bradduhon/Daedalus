# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0217, 0213: the planner and the auditor prefer fable when the session can start it, and
# every source that cannot say so reads as not available, never a stop.
from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import catalog
import pytest
from lib import agent_files, audit, fable
from lib.agent_models import AgentModelError, resolve
from lib.config import Config, ConfigError, load_config

from tests.conftest import REPO_ROOT, write_train_marker
from tests.test_agent_files import BODY, HEAD, _write
from tests.test_doctor import _bins_with_git, _data, _git_repo, _run

AGENTS = REPO_ROOT / "agents"
PREFERRING = ("auditor", "planner")
FABLE_ID = "claude-fable-5"
NEXT = (
    "Next: set fable_available to true in .claude/daedalus/config.json when your plan offers Fable"
)
HookInput = Callable[..., dict[str, Any]]


def _session(repo: Path, hook_input: HookInput, model: object = FABLE_ID) -> Path:
    # 0217: a marked train, a SessionStart naming the model, then one later tool call.
    write_train_marker(repo)
    start = hook_input(
        hook_event_name="SessionStart", tool_name=None, tool_input=None, source="startup"
    )
    if model is not None:
        start["model"] = model
    record = audit.audit_append(start)
    assert record is not None
    assert audit.audit_append(hook_input()) is not None
    return audit.log_path("sess-test", str(repo))


def test_only_the_planner_and_the_auditor_prefer_fable_and_keep_opus() -> None:
    loaded = agent_files.load_all(AGENTS)
    assert sorted(name for name, a in loaded.items() if a.prefer is not None) == list(PREFERRING)
    for name in PREFERRING:
        assert (loaded[name].prefer, loaded[name].model) == ("fable", "opus")


@pytest.mark.parametrize("name", PREFERRING)
def test_prefer_is_honoured_when_config_says_fable_is_available(name: str) -> None:
    config = Config(fable_available=True)
    assert fable.availability(config, None) == fable.BY_CONFIG
    assert resolve(name, config) == "fable"


@pytest.mark.parametrize("name", PREFERRING)
def test_prefer_is_honoured_on_session_evidence(
    name: str, project_data: Path, repo_cwd: Path, hook_input: HookInput
) -> None:
    _session(repo_cwd, hook_input)
    assert fable.session_model(repo_cwd) == FABLE_ID
    assert fable.availability(Config(), repo_cwd) == fable.BY_SESSION
    assert resolve(name, Config(), repo=repo_cwd) == "fable"


@pytest.mark.parametrize("name", PREFERRING)
def test_prefer_is_not_honoured_with_no_config_and_no_session(name: str, repo_cwd: Path) -> None:
    assert fable.availability(Config(), repo_cwd) == fable.NOT_AVAILABLE
    assert resolve(name, Config(), repo=repo_cwd) == "opus"
    assert resolve(name, Config()) == "opus"


@pytest.mark.parametrize(
    "model", [None, "claude-opus-5-5", "fable", "x-claude-fable-5", "claude fable 5", {"id": 1}]
)
def test_a_session_on_another_model_or_none_leaves_opus(
    model: object, project_data: Path, repo_cwd: Path, hook_input: HookInput
) -> None:
    _session(repo_cwd, hook_input, model)
    assert fable.availability(Config(), repo_cwd) == fable.NOT_AVAILABLE
    assert resolve("planner", Config(), repo=repo_cwd) == "opus"


def test_config_false_beats_session_evidence(
    project_data: Path, repo_cwd: Path, hook_input: HookInput
) -> None:
    _session(repo_cwd, hook_input)
    config = Config(fable_available=False)
    assert fable.availability(config, repo_cwd) == fable.OFF_BY_CONFIG
    assert resolve("auditor", config, repo=repo_cwd) == "opus"


def test_a_log_without_a_train_marker_is_not_session_evidence(
    project_data: Path, repo_cwd: Path, hook_input: HookInput
) -> None:
    # 0217: only a marked train writes the log, so an unmarked repo's newest log is stale.
    marker = _session(repo_cwd, hook_input).parents[1] / "train.active"
    marker.unlink()
    assert fable.session_model(repo_cwd) is None
    assert resolve("planner", Config(), repo=repo_cwd) == "opus"


def test_a_broken_chain_fails_open_to_the_default(
    project_data: Path, repo_cwd: Path, hook_input: HookInput
) -> None:
    log = _session(repo_cwd, hook_input, "claude-opus-5-5")
    forged = {"event": "SessionStart", "model": FABLE_ID, "seq": 9, "hash": "0" * 64}
    with log.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(forged) + "\n")
    assert fable.session_model(repo_cwd) is None
    assert resolve("planner", Config(), repo=repo_cwd) == "opus"


def test_an_agent_without_prefer_is_untouched_when_fable_is_available() -> None:
    config = Config(fable_available=True)
    for name, agent in agent_files.load_all(AGENTS).items():
        if agent.prefer is None:
            assert resolve(name, config) == agent.model, name


def test_override_and_agent_models_still_come_before_the_preference() -> None:
    config = Config(fable_available=True, agent_models={"planner": "sonnet"})
    assert resolve("planner", config) == "sonnet"
    assert resolve("auditor", config, "haiku") == "haiku"
    assert resolve("auditor", config) == "fable"


@pytest.mark.parametrize("value", ["opus", "Fable", "fable, opus", "sonnet"])
def test_a_bad_prefer_value_fails_the_frontmatter_read_with_a_next_line(
    tmp_path: Path, value: str
) -> None:
    path = _write(tmp_path, [*HEAD, f"prefer: {value}", *BODY])
    with pytest.raises(agent_files.AgentFileError, match="Next: set prefer to fable"):
        agent_files.load(path)
    with pytest.raises(AgentModelError, match="Next: set prefer to fable"):
        resolve("probe", Config(fable_available=True), agents_dir=tmp_path)


def test_a_good_prefer_value_loads(tmp_path: Path) -> None:
    path = _write(tmp_path, [*HEAD, "prefer: fable", *BODY])
    assert agent_files.load(path).prefer == "fable"
    assert agent_files.load(_write(tmp_path, [*HEAD, *BODY])).prefer is None


@pytest.mark.parametrize("value", [True, False, None])
def test_fable_available_reads_true_false_or_null(project_data: Path, value: object) -> None:
    (project_data / "config.json").write_text(json.dumps({"fable_available": value}))
    assert load_config(str(project_data.parents[1])).fable_available is value
    (project_data / "config.json").write_text("{}")
    assert load_config(str(project_data.parents[1])).fable_available is None


@pytest.mark.parametrize("value", ["true", 1, 0, [], {}, "fable"])
def test_a_bad_fable_available_value_fails_config_loading(
    project_data: Path, value: object
) -> None:
    (project_data / "config.json").write_text(json.dumps({"fable_available": value}))
    with pytest.raises(ConfigError) as info:
        load_config(str(project_data.parents[1]))
    text = str(info.value)
    assert f"config.json fable_available must be true, false or null (got {value!r})" in text
    assert "Next: set fable_available to true when your plan offers Fable" in text


def test_session_start_record_keeps_a_model_id_and_nothing_else(hook_input: HookInput) -> None:
    start = hook_input(hook_event_name="SessionStart", tool_name=None, tool_input=None)
    for value, kept in [
        (FABLE_ID, FABLE_ID),
        ("claude-opus-5-5[1m]", "claude-opus-5-5[1m]"),
        ("claude fable", None),
        ("a" * 129, None),
        ("claude-fable-5\nforged", None),
        (["claude-fable-5"], None),
    ]:
        assert audit.build_record({**start, "model": value})["model"] == kept, value
    assert audit.build_record(start)["model"] is None
    assert "model" not in audit.build_record(hook_input(model=FABLE_ID))


def _model_cell(out: str, name: str) -> str:
    row = next(r for r in out.splitlines() if r.startswith(f"| {name} |"))
    return row.split(" | ")[2]


def test_catalog_cell_shows_the_preference_beside_the_model() -> None:
    plain = catalog.table(AGENTS)
    assert _model_cell(plain, "planner") == "opus, prefers fable"
    assert _model_cell(plain, "auditor") == "opus, prefers fable"
    assert _model_cell(plain, "coder") == "opus"
    assert _model_cell(catalog.table(AGENTS, Config()), "planner") == "opus, prefers fable"


def test_catalog_cell_drops_the_preference_once_taken_or_pinned() -> None:
    taken = catalog.table(AGENTS, Config(fable_available=True))
    assert _model_cell(taken, "planner") == "fable" and _model_cell(taken, "coder") == "opus"
    pinned = catalog.table(AGENTS, Config(fable_available=True, agent_models={"auditor": "opus"}))
    assert _model_cell(pinned, "auditor") == "opus"


def _doctor_fable(tmp_path: Path, repo: Path) -> list[str]:
    result = _run(None, repo, path_env=_bins_with_git(tmp_path), home=tmp_path / "home")
    return [line for line in result.stdout.splitlines() if line[5:].startswith("fable:")]


@pytest.mark.parametrize(
    ("doc", "want"),
    [
        (
            {"fable_available": True},
            "OK   fable: available by config, so auditor and planner run on fable",
        ),
        (
            {},
            "OPT  fable: not seen in this session, so auditor and planner run on opus. " + NEXT,
        ),
        (
            {"fable_available": False},
            "OPT  fable: off by config, so auditor and planner run on opus. " + NEXT,
        ),
        (
            {"fable_available": True, "agent_models": {"planner": "sonnet"}},
            "OK   fable: available by config, so auditor runs on fable, planner runs on sonnet",
        ),
    ],
)
def test_doctor_prints_one_fable_line_from_config(
    tmp_path: Path, doc: dict[str, object], want: str
) -> None:
    repo = tmp_path / "repo"
    _git_repo(repo)
    (_data(repo) / "config.json").write_text(json.dumps(doc))
    assert _doctor_fable(tmp_path, repo) == [want]


@pytest.mark.parametrize(
    ("model", "want"),
    [
        (FABLE_ID, "OK   fable: seen in this session, so auditor and planner run on fable"),
        (
            "claude-opus-5-5",
            "OPT  fable: not seen in this session, so auditor and planner run on opus. " + NEXT,
        ),
    ],
)
def test_doctor_prints_one_fable_line_from_the_session(
    tmp_path: Path, hook_input: HookInput, repo_cwd: Path, model: str, want: str
) -> None:
    _data(repo_cwd)
    _session(repo_cwd, hook_input, model)
    assert _doctor_fable(tmp_path, repo_cwd) == [want]
