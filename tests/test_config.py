# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
from lib.config import CONFIG_KEYS, Config, ConfigError, load_config

from tests.conftest import REPO_ROOT


def test_missing_file_gives_empty_config(project_data: Path) -> None:
    cfg = load_config(str(project_data.parents[1]))
    assert cfg == Config()
    assert cfg.charter_root is None and cfg.standards_sources == ()


def test_config_null_means_not_declared(project_data: Path) -> None:
    # 0076: null is the same as an absent key, so the setup starter loads as the defaults.
    nulls = {"local_docs_folder": None, "policy": None, "models": None, "limits": None}
    (project_data / "config.json").write_text(json.dumps(nulls))
    assert load_config(str(project_data.parents[1])) == Config()
    for key in ("local_docs_folder", "policy", "models", "limits"):
        (project_data / "config.json").write_text(json.dumps({key: ""}))
        with pytest.raises(ConfigError):
            load_config(str(project_data.parents[1]))


def test_full_config_parses(project_data: Path) -> None:
    (project_data / "config.json").write_text(
        json.dumps(
            {
                "local_docs_folder": "/work/Charter",
                "policy": {"engine": "conftest", "path": "/work/Charter/policy"},
                "coding_rules": [{"folder": "/work/me/.claude/rules"}, {"file": "/work/r.md"}],
            }
        )
    )
    cfg = load_config(str(project_data.parents[1]))
    assert cfg.charter_root == Path("/work/Charter")
    assert cfg.policy is not None and cfg.policy.engine == "conftest"
    assert [s.kind for s in cfg.standards_sources] == ["rules-dir", "file"]


@pytest.mark.parametrize(
    "old",
    [
        "charter_root",
        "standing_rules",
        "ledger",
        "excluded_roots",
        "standards_sources",
        "operator_signing_keys",
        "max_concurrent_builders",
        "audit_retention_days",
        "wrapper_read_roots",
        "unit_token_budget",
        "coder_models",
        "fable_available",
        "agent_models",
        "operator",
    ],
)
def test_an_old_top_level_key_is_refused_with_the_valid_names(project_data: Path, old: str) -> None:
    # 0245, 0241: no alias; the ordinary unknown-key refusal lists every valid name.
    (project_data / "config.json").write_text(json.dumps({old: None}))
    with pytest.raises(ConfigError) as info:
        load_config(str(project_data.parents[1]))
    text = str(info.value)
    assert f"unknown keys ['{old}']" in text and all(key in text for key in CONFIG_KEYS)
    assert "Next:" in text


@pytest.mark.parametrize(
    ("group", "old"),
    [("models", "default"), ("models", "control_path"), ("limits", "max_concurrent_builders")],
)
def test_an_old_key_inside_a_group_is_refused_with_the_valid_names(
    project_data: Path, group: str, old: str
) -> None:
    (project_data / "config.json").write_text(json.dumps({group: {old: 1}}))
    with pytest.raises(ConfigError) as info:
        load_config(str(project_data.parents[1]))
    assert f"{group} has unknown keys ['{old}']" in str(info.value)
    assert "known:" in str(info.value)


@pytest.mark.parametrize(
    "entry",
    [
        {"kind": "path", "path": "/x", "pattern": "*"},
        {"kind": "gitignore", "glob": "x"},
    ],
)
def test_an_unknown_key_in_an_excluded_folder_entry_is_refused(
    project_data: Path, entry: dict[str, object]
) -> None:
    (project_data / "config.json").write_text(json.dumps({"git_excluded_folders": [entry]}))
    with pytest.raises(ConfigError, match=r"git_excluded_folders\[\] has unknown keys"):
        load_config(str(project_data.parents[1]))


def test_an_unknown_policy_key_is_refused(project_data: Path) -> None:
    doc = {"policy": {"engine": "conftest", "path": "/p", "mode": "strict"}}
    (project_data / "config.json").write_text(json.dumps(doc))
    with pytest.raises(ConfigError, match="policy has unknown keys"):
        load_config(str(project_data.parents[1]))


def test_unknown_policy_engine_raises(project_data: Path) -> None:
    (project_data / "config.json").write_text(
        json.dumps({"policy": {"engine": "magic", "path": "/p"}})
    )
    with pytest.raises(ConfigError) as info:
        load_config(str(project_data.parents[1]))
    assert "cfn-guard" in str(info.value) and "conftest" in str(info.value)


def test_invalid_json_raises(project_data: Path) -> None:
    (project_data / "config.json").write_text("{nope")
    with pytest.raises(ConfigError):
        load_config(str(project_data.parents[1]))


@pytest.mark.parametrize(
    "doc",
    [
        {"local_docs_folder": 5},
        {"local_docs_folder": ""},
        {"local_docs_folder": False},
        {"local_docs_folder": "docs/private"},
        {"policy": {"engine": 3, "path": "/p"}},
        {"policy": {"engine": "conftest", "path": []}},
        {"coding_rules": [{"folder": 1}]},
        {"coding_rules": [{"file": ""}]},
        {"coding_rules": [{"folder": "/a", "file": "/b"}]},
        {"coding_rules": [{}]},
        {"coding_rules": [{"kind": "rules-dir", "path": "/a"}]},
        {"coding_rules": "/a"},
    ],
)
def test_wrong_typed_values_raise_config_error(project_data: Path, doc: dict[str, object]) -> None:
    (project_data / "config.json").write_text(json.dumps(doc))
    with pytest.raises(ConfigError) as info:
        load_config(str(project_data.parents[1]))
    assert "Next:" in str(info.value)


def test_local_docs_folder_refuses_a_symlink_and_keeps_a_folder_inside_the_project(
    project_data: Path, tmp_path: Path
) -> None:
    # 0245: a link is refused; a git-ignored clone inside the project is kept, as before.
    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "link"
    link.symlink_to(real)
    (project_data / "config.json").write_text(json.dumps({"local_docs_folder": str(link)}))
    with pytest.raises(ConfigError, match="is a symlink"):
        load_config(str(project_data.parents[1]))
    inside = project_data.parents[1] / "docs" / "private"
    (project_data / "config.json").write_text(json.dumps({"local_docs_folder": str(inside)}))
    assert load_config(str(project_data.parents[1])).charter_root == inside


def test_directory_at_config_path_raises(project_data: Path) -> None:
    (project_data / "config.json").mkdir()
    with pytest.raises(ConfigError) as info:
        load_config(str(project_data.parents[1]))
    assert "Next:" in str(info.value)


def test_non_utf8_bytes_raise(project_data: Path) -> None:
    (project_data / "config.json").write_bytes(b"\xff\xfe")
    with pytest.raises(ConfigError) as info:
        load_config(str(project_data.parents[1]))
    assert "Next:" in str(info.value)


def test_oversized_int_raises_config_error(project_data: Path) -> None:
    (project_data / "config.json").write_text('{"x": ' + "1" * 5000 + "}")
    with pytest.raises(ConfigError) as info:
        load_config(str(project_data.parents[1]))
    assert "not valid JSON" in str(info.value) and "Next:" in str(info.value)


def _load(project_data: Path, doc: dict[str, object]) -> Config:
    (project_data / "config.json").write_text(json.dumps(doc))
    return load_config(str(project_data.parents[1]))


def test_parallel_coders_defaults_to_five(project_data: Path) -> None:
    # 0072: absent key and absent file both run five coders at once.
    assert Config().max_concurrent_builders == 5
    assert _load(project_data, {}).max_concurrent_builders == 5


def test_parallel_coders_reads_a_whole_number(project_data: Path) -> None:
    assert _load(project_data, {"limits": {"parallel_coders": 2}}).max_concurrent_builders == 2


@pytest.mark.parametrize("value", [0, -1, "3", 2.5, True, None, [3]])
def test_parallel_coders_refuses_anything_but_one_or_more(
    project_data: Path, value: object
) -> None:
    with pytest.raises(ConfigError) as info:
        _load(project_data, {"limits": {"parallel_coders": value}})
    text = str(info.value)
    assert "limits.parallel_coders must be a whole number of at least 1" in text
    assert "Next: set limits.parallel_coders to 1 or more" in text


def test_log_retention_defaults_to_keeping_every_log(project_data: Path) -> None:
    # issue 50, AU-11: absent and null both keep every audit log.
    assert Config().audit_retention_days is None
    assert (
        _load(project_data, {"limits": {"log_retention_days": None}}).audit_retention_days is None
    )


@pytest.mark.parametrize("value", [90, 365])
def test_log_retention_reads_a_number_at_the_floor_or_above(project_data: Path, value: int) -> None:
    assert (
        _load(project_data, {"limits": {"log_retention_days": value}}).audit_retention_days == value
    )


@pytest.mark.parametrize("value", [89, 1, 0, -5, "90", 90.0, True, [90]])
def test_log_retention_refuses_below_the_floor_or_off_type(
    project_data: Path, value: object
) -> None:
    # AU-11, AU-6: a declared retention keeps at least 90 days for review look-back.
    with pytest.raises(ConfigError) as info:
        _load(project_data, {"limits": {"log_retention_days": value}})
    text = str(info.value)
    assert "limits.log_retention_days must be a whole number of at least 90" in text
    assert "Next: set it to 90 or more, or to null to keep every audit log." in text


def test_model_agents_absent_or_null_is_empty(project_data: Path) -> None:
    # spec 4: with no map, every agent runs on its agent file's model.
    assert Config().agent_models == {}
    assert _load(project_data, {}).agent_models == {}
    assert _load(project_data, {"models": {"agents": None}}).agent_models == {}


def test_model_agents_reads_a_valid_map(project_data: Path) -> None:
    agents = {"coder": "sonnet", "planner": "fable", "web-researcher": "haiku"}
    assert _load(project_data, {"models": {"agents": agents}}).agent_models == agents


@pytest.mark.parametrize("name", ["mystery", "main", "daedalus:planner", ""])
def test_model_agents_refuses_an_unknown_agent(project_data: Path, name: str) -> None:
    with pytest.raises(ConfigError) as info:
        _load(project_data, {"models": {"agents": {name: "opus"}}})
    text = str(info.value)
    assert f"models.agents names {name!r}, which is not a catalog agent" in text
    assert "Next: key models.agents by an agent name the catalog lists, one of " in text
    assert "coder" in text


@pytest.mark.parametrize("model", ["gpt-4", "Opus", "inherit", "", None, 1])
def test_model_agents_refuses_an_unknown_model(project_data: Path, model: object) -> None:
    with pytest.raises(ConfigError) as info:
        _load(project_data, {"models": {"agents": {"coder": model}}})
    want = "Next: set models.agents.coder to one of sonnet, opus, haiku, fable."
    assert want in str(info.value)


@pytest.mark.parametrize("value", [["coder"], "opus", 3])
def test_model_agents_refuses_anything_but_an_object(project_data: Path, value: object) -> None:
    with pytest.raises(ConfigError, match="models.agents must be an object. Next: "):
        _load(project_data, {"models": {"agents": value}})


RETIRED = ("coder", "plugin_file_coder", "coder_after_rejection")


def test_a_schema_1_file_holding_the_retired_coder_keys_still_loads(project_data: Path) -> None:
    # 332: the schema map drops the three keys when an older file is read, so no run stops.
    models = {key: "opus" for key in RETIRED} | {"fable_available": True}
    cfg = _load(project_data, {"schema": 1, "models": models})
    assert cfg.fable_available is True


@pytest.mark.parametrize("key", RETIRED)
def test_a_current_schema_file_refuses_a_retired_coder_key(project_data: Path, key: str) -> None:
    # 332: no alias; at schema 2 the key is unknown, and the refusal lists the valid names.
    with pytest.raises(ConfigError) as info:
        _load(project_data, {"schema": 2, "models": {key: "opus"}})
    assert f"unknown keys ['{key}']" in str(info.value) and "fable_available" in str(info.value)


def test_missing_data_dir_gives_empty_config(repo_cwd: Path) -> None:
    # 0020: no .claude/daedalus at all is still the empty config.
    assert load_config(str(repo_cwd)) == Config()


PACK_LINE = re.compile(r"^- D[BC]-[0-9]+: ")
CONTROL = r"[A-Z]{2}-[0-9]+(\([0-9]+\))?"
MAPS = re.compile(rf" Maps: NIST {CONTROL}(, {CONTROL})*(; ASVS V[0-9.]+[0-9](, V[0-9.]+[0-9])*)?$")


def test_builtin_rules_resolve_under_the_plugin(project_data: Path) -> None:
    doc = {"coding_rules": [{"builtin": "baseline"}]}
    (project_data / "config.json").write_text(json.dumps(doc))
    (source,) = load_config(str(project_data.parents[1])).standards_sources
    assert source.kind == "pack" and source.name == "baseline"
    assert source.path == REPO_ROOT / "packs" / "baseline"
    assert (source.path / "rules.md").is_file()


@pytest.mark.parametrize("name", ["nope", "../packs/baseline", "", 3])
def test_unknown_builtin_name_refused(project_data: Path, name: object) -> None:
    (project_data / "config.json").write_text(json.dumps({"coding_rules": [{"builtin": name}]}))
    with pytest.raises(ConfigError) as info:
        load_config(str(project_data.parents[1]))
    assert str(info.value).endswith('Next: name the shipped baseline rules, "baseline".')


def test_pack_rules_are_one_line_with_ids() -> None:
    lines = (REPO_ROOT / "packs" / "baseline" / "rules.md").read_text(encoding="utf-8").splitlines()
    assert lines[0].startswith("<!-- Copyright")
    baseline = lines.index("## Baseline")
    cloud = lines.index("## Cloud security standards")
    assert 0 < baseline < cloud
    rules = [(n, line) for n, line in enumerate(lines) if line.startswith("- ")]
    assert all(PACK_LINE.match(line) for _, line in rules), rules
    ids = [line.split(":", 1)[0][2:] for _, line in rules]
    assert ids[:5] == [f"DB-{n}" for n in range(1, 6)]
    assert ids[5:] == [f"DC-{n}" for n in range(1, len(ids) - 4)]
    assert len(ids) >= 11
    for n, line in rules:
        assert n > (cloud if line.startswith("- DC-") else baseline), line
        assert "CIS" not in line, line
        if " Maps: " in line:
            assert MAPS.search(line), line
