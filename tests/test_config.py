# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import json
from pathlib import Path

import pytest
from lib.config import Config, ConfigError, load_config


def test_missing_file_gives_empty_config(project_data: Path) -> None:
    cfg = load_config(str(project_data.parents[1]))
    assert cfg == Config()
    assert cfg.ledger is None and cfg.standards_sources == ()


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


def test_missing_data_dir_gives_empty_config(repo_cwd: Path) -> None:
    # 0020: no .claude/daedalus at all is still the empty config.
    assert load_config(str(repo_cwd)) == Config()
