# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
from lib.config import Config, ConfigError, load_config, standing_rules_path

from tests.conftest import REPO_ROOT


def test_missing_file_gives_empty_config(project_data: Path) -> None:
    cfg = load_config(str(project_data.parents[1]))
    assert cfg == Config()
    assert cfg.ledger is None and cfg.standards_sources == ()


def test_config_null_means_not_declared(project_data: Path) -> None:
    # 0076: null is the same as an absent key, so the setup starter loads as the defaults.
    nulls = {"charter_root": None, "standing_rules": None, "ledger": None, "policy": None}
    (project_data / "config.json").write_text(json.dumps(nulls))
    assert load_config(str(project_data.parents[1])) == Config()
    for key in nulls:
        (project_data / "config.json").write_text(json.dumps({key: ""}))
        with pytest.raises(ConfigError):
            load_config(str(project_data.parents[1]))


def test_full_config_parses(project_data: Path) -> None:
    (project_data / "config.json").write_text(
        json.dumps(
            {
                "charter_root": "/work/Charter",
                "ledger": {
                    "path": "/work/Charter/decision-log.md",
                    "format": "markdown-table-row",
                    "id_scheme": "{seq:04d}-{repo}-{type}",
                    "sequence_source": "last-row-id",
                },
                "policy": {"engine": "conftest", "path": "/work/Charter/policy"},
                "standards_sources": [{"kind": "rules-dir", "path": "/work/me/.claude/rules"}],
                "operator_signing_keys": ["ABCD1234"],
            }
        )
    )
    cfg = load_config(str(project_data.parents[1]))
    assert cfg.charter_root == Path("/work/Charter")
    assert cfg.ledger is not None and cfg.ledger.id_scheme == "{seq:04d}-{repo}-{type}"
    assert cfg.policy is not None and cfg.policy.engine == "conftest"
    assert cfg.standards_sources[0].kind == "rules-dir"
    assert cfg.operator_signing_keys == ("ABCD1234",)


def test_bad_ledger_shape_raises_with_next(project_data: Path) -> None:
    (project_data / "config.json").write_text(json.dumps({"ledger": {"path": "/x"}}))
    with pytest.raises(ConfigError) as info:
        load_config(str(project_data.parents[1]))
    assert "ledger.format" in str(info.value)
    assert "Next:" in str(info.value)


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


_LEDGER = {
    "path": "/l.md",
    "format": "markdown-table-row",
    "id_scheme": "{seq:04d}",
    "sequence_source": "last-row-id",
}


@pytest.mark.parametrize(
    "doc",
    [
        {"charter_root": 5},
        {"charter_root": ""},
        {"charter_root": False},
        {"charter_root": 0},
        {"standing_rules": 5},
        {"standing_rules": ""},
        {"ledger": {**_LEDGER, "path": 1}},
        {"ledger": {**_LEDGER, "format": ["markdown-table-row"]}},
        {"ledger": {**_LEDGER, "id_scheme": 7}},
        {"ledger": {**_LEDGER, "sequence_source": None}},
        {"policy": {"engine": 3, "path": "/p"}},
        {"policy": {"engine": "conftest", "path": []}},
        {"standards_sources": [{"kind": 1, "path": []}]},
        {"standards_sources": [{"kind": "rules-dir", "path": 2}]},
        {"operator_signing_keys": 5},
        {"operator_signing_keys": "ABCD"},
        {"operator_signing_keys": ["ABCD", 1]},
        {"operator_signing_keys": [""]},
    ],
)
def test_wrong_typed_values_raise_config_error(project_data: Path, doc: dict[str, object]) -> None:
    (project_data / "config.json").write_text(json.dumps(doc))
    with pytest.raises(ConfigError) as info:
        load_config(str(project_data.parents[1]))
    assert "Next:" in str(info.value)


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


def test_signing_keys_list_parses(project_data: Path) -> None:
    (project_data / "config.json").write_text(
        json.dumps({"operator_signing_keys": ["ABCD", "EF01"]})
    )
    assert load_config(str(project_data.parents[1])).operator_signing_keys == ("ABCD", "EF01")


def test_oversized_int_raises_config_error(project_data: Path) -> None:
    (project_data / "config.json").write_text('{"x": ' + "1" * 5000 + "}")
    with pytest.raises(ConfigError) as info:
        load_config(str(project_data.parents[1]))
    assert "not valid JSON" in str(info.value) and "Next:" in str(info.value)


def test_max_concurrent_builders_defaults_to_five(project_data: Path) -> None:
    # 0072: absent key and absent file both run five coders at once.
    assert Config().max_concurrent_builders == 5
    (project_data / "config.json").write_text("{}")
    assert load_config(str(project_data.parents[1])).max_concurrent_builders == 5


def test_max_concurrent_builders_reads_a_whole_number(project_data: Path) -> None:
    (project_data / "config.json").write_text(json.dumps({"max_concurrent_builders": 2}))
    assert load_config(str(project_data.parents[1])).max_concurrent_builders == 2


@pytest.mark.parametrize("value", [0, -1, "3", 2.5, True, None, [3]])
def test_max_concurrent_builders_refuses_anything_but_one_or_more(
    project_data: Path, value: object
) -> None:
    (project_data / "config.json").write_text(json.dumps({"max_concurrent_builders": value}))
    with pytest.raises(ConfigError) as info:
        load_config(str(project_data.parents[1]))
    text = str(info.value)
    assert "max_concurrent_builders must be a whole number of at least 1" in text
    assert "Next: set max_concurrent_builders to 1 or more" in text


def test_audit_retention_defaults_to_keeping_every_log(project_data: Path) -> None:
    # issue 50, AU-11: absent and null both keep every audit log.
    assert Config().audit_retention_days is None
    (project_data / "config.json").write_text(json.dumps({"audit_retention_days": None}))
    assert load_config(str(project_data.parents[1])).audit_retention_days is None


@pytest.mark.parametrize("value", [90, 365])
def test_audit_retention_reads_a_number_at_the_floor_or_above(
    project_data: Path, value: int
) -> None:
    (project_data / "config.json").write_text(json.dumps({"audit_retention_days": value}))
    assert load_config(str(project_data.parents[1])).audit_retention_days == value


@pytest.mark.parametrize("value", [89, 1, 0, -5, "90", 90.0, True, [90]])
def test_audit_retention_refuses_below_the_floor_or_off_type(
    project_data: Path, value: object
) -> None:
    # AU-11, AU-6: a declared retention keeps at least 90 days for review look-back.
    (project_data / "config.json").write_text(json.dumps({"audit_retention_days": value}))
    with pytest.raises(ConfigError) as info:
        load_config(str(project_data.parents[1]))
    text = str(info.value)
    assert "audit_retention_days must be a whole number of at least 90" in text
    assert "Next: set it to 90 or more, or to null to keep every audit log." in text


def _load(project_data: Path, doc: dict[str, object]) -> Config:
    (project_data / "config.json").write_text(json.dumps(doc))
    return load_config(str(project_data.parents[1]))


def test_retired_audit_round_budget_is_refused(project_data: Path) -> None:
    # 0133: the key is gone; tests/test_operator_gates.py covers its refusal text.
    with pytest.raises(ConfigError):
        _load(project_data, {"audit_round_budget": 5})


def test_agent_models_absent_or_null_is_empty(project_data: Path) -> None:
    # spec 4: with no map, every agent runs on its agent file's model.
    assert Config().agent_models == {}
    assert _load(project_data, {}).agent_models == {}
    assert _load(project_data, {"agent_models": None}).agent_models == {}


def test_agent_models_reads_a_valid_map(project_data: Path) -> None:
    doc = {"agent_models": {"coder": "sonnet", "planner": "fable", "web-researcher": "haiku"}}
    assert _load(project_data, doc).agent_models == doc["agent_models"]


@pytest.mark.parametrize("name", ["mystery", "main", "daedalus:planner", ""])
def test_agent_models_refuses_an_unknown_agent(project_data: Path, name: str) -> None:
    with pytest.raises(ConfigError) as info:
        _load(project_data, {"agent_models": {name: "opus"}})
    text = str(info.value)
    assert f"agent_models names {name!r}, which is not a catalog agent" in text
    assert "Next: key agent_models by an agent name the catalog lists, one of " in text
    assert "coder" in text


@pytest.mark.parametrize("model", ["gpt-4", "Opus", "inherit", "", None, 1])
def test_agent_models_refuses_an_unknown_model(project_data: Path, model: object) -> None:
    with pytest.raises(ConfigError) as info:
        _load(project_data, {"agent_models": {"coder": model}})
    assert "Next: set agent_models.coder to one of sonnet, opus, haiku, fable." in str(info.value)


@pytest.mark.parametrize("value", [["coder"], "opus", 3])
def test_agent_models_refuses_anything_but_an_object(project_data: Path, value: object) -> None:
    with pytest.raises(ConfigError, match="agent_models must be an object. Next: "):
        _load(project_data, {"agent_models": value})


def test_coder_models_default_and_partial(project_data: Path) -> None:
    # 0187: absent or null is the default map; a tier left out keeps its default.
    want = {"default": "sonnet", "control_path": "opus", "escalated": "opus"}
    assert Config().coder_models == want
    assert _load(project_data, {"coder_models": None}).coder_models == want
    doc: dict[str, object] = {"coder_models": {"default": "opus", "escalated": "fable"}}
    got = _load(project_data, doc).coder_models
    assert got == {"default": "opus", "control_path": "opus", "escalated": "fable"}


def test_coder_models_refuses_an_unknown_tier(project_data: Path) -> None:
    with pytest.raises(ConfigError) as info:
        _load(project_data, {"coder_models": {"fast": "haiku"}})
    text = str(info.value)
    assert "coder_models names 'fast', which is not a coder tier" in text
    assert "Next: name only the coder tiers in coder_models, which are default, " in text


@pytest.mark.parametrize("model", ["gpt-4", "Opus", "claude-opus-4-8", "", None, 1])
def test_coder_models_refuses_an_unknown_model(project_data: Path, model: object) -> None:
    # 0187: the dispatch gate admits only the four model words, so a full id is refused here.
    with pytest.raises(ConfigError) as info:
        _load(project_data, {"coder_models": {"default": model}})
    assert "Next: set coder_models.default to one of sonnet, opus, haiku, fable." in str(info.value)


@pytest.mark.parametrize("value", [["opus"], "opus", 3])
def test_coder_models_refuses_anything_but_an_object(project_data: Path, value: object) -> None:
    with pytest.raises(ConfigError, match="coder_models must be an object. Next: "):
        _load(project_data, {"coder_models": value})


def test_missing_data_dir_gives_empty_config(repo_cwd: Path) -> None:
    # 0020: no .claude/daedalus at all is still the empty config.
    assert load_config(str(repo_cwd)) == Config()


PACK_LINE = re.compile(r"^- D[BC]-[0-9]+: ")
CONTROL = r"[A-Z]{2}-[0-9]+(\([0-9]+\))?"
MAPS = re.compile(rf" Maps: NIST {CONTROL}(, {CONTROL})*(; ASVS V[0-9.]+[0-9](, V[0-9.]+[0-9])*)?$")


def test_pack_source_resolves_under_the_plugin(project_data: Path) -> None:
    doc = {"standards_sources": [{"kind": "pack", "name": "baseline"}]}
    (project_data / "config.json").write_text(json.dumps(doc))
    (source,) = load_config(str(project_data.parents[1])).standards_sources
    assert source.kind == "pack" and source.name == "baseline"
    assert source.path == REPO_ROOT / "packs" / "baseline"
    assert (source.path / "rules.md").is_file()


@pytest.mark.parametrize(
    "entry",
    [
        {"kind": "pack", "name": "nope"},
        {"kind": "pack", "name": "../packs/baseline"},
        {"kind": "pack", "name": ""},
        {"kind": "pack", "name": 3},
        {"kind": "pack", "path": "/work/packs/baseline"},
    ],
)
def test_unknown_pack_name_refused(project_data: Path, entry: dict[str, object]) -> None:
    (project_data / "config.json").write_text(json.dumps({"standards_sources": [entry]}))
    with pytest.raises(ConfigError) as info:
        load_config(str(project_data.parents[1]))
    assert str(info.value).endswith('Next: name the shipped baseline pack, "baseline".')


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


@pytest.mark.parametrize(
    ("doc", "expected"),
    [
        ({}, None),
        ({"standing_rules": "standing-rules.md"}, "repo/standing-rules.md"),
        ({"charter_root": "/work/Charter", "standing_rules": "rules.md"}, "/work/Charter/rules.md"),
        ({"charter_root": "docs/private", "standing_rules": "s.md"}, "repo/docs/private/s.md"),
        ({"charter_root": "/work/Charter", "standing_rules": "/abs/s.md"}, "/abs/s.md"),
    ],
)
def test_standing_rules_key_resolves(
    project_data: Path, tmp_path: Path, doc: dict[str, object], expected: str | None
) -> None:
    # 0090: relative to charter_root when declared, else to the project root; absent is none.
    (project_data / "config.json").write_text(json.dumps(doc))
    cfg = load_config(str(project_data.parents[1]))
    assert cfg.standing_rules == doc.get("standing_rules")
    found = standing_rules_path(cfg, tmp_path / "repo")
    if expected is None:
        assert found is None
    else:
        want = Path(expected) if expected.startswith("/") else tmp_path / expected
        assert found == want
