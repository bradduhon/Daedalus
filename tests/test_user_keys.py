# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0260: a key that starts with an underscore is the user's own; the three readers skip it, the
# wizard keeps it, and every other unknown key is still refused.
from __future__ import annotations

import copy
import json
from collections.abc import Callable
from pathlib import Path

import pytest
from lib.config import ConfigError, parse_config
from lib.manifest import ManifestError, PrioritiesError, parse
from lib.operator_file import OperatorError, validate
from lib.project_keys import KEY_ROWS, starter_config, starter_manifest, starter_operator
from lib.settings_maps import Convert, Drop, Kind, Move, SchemaError, Set, Step, upgrade
from lib.user_keys import is_user_key

from tests.conftest import REPO_ROOT
from tests.test_settings_replace import _moves, _replace
from tests.test_setup_wizard import SCAN, _manifest, _run, _set

RULE = {
    "between": ["security", "cost"],
    "reasons": ["incident"],
    "outcome": "security",
    "note": "keys first",
}
VALUES: list[object] = ["a copyright line", {"a": [1, 2]}, [1, "x"], 7, None, True]


def _manifest_doc() -> dict[str, object]:
    doc = starter_manifest()
    doc["run_output_priority"] = {
        "order": ["security", "trust", "operations", "cost"],
        "rules": [dict(RULE)],
    }
    return doc


def _config_doc() -> dict[str, object]:
    doc = starter_config()
    doc["policy"] = {"engine": "conftest", "path": "p"}
    doc["git_excluded_folders"] = [{"kind": "path", "path": "/x"}]
    doc["coding_rules"] = [{"builtin": "baseline"}]
    doc["models"] = {"agents": {"coder": "opus"}}
    return doc


def _operator_doc() -> dict[str, object]:
    return starter_operator()


def _parse_manifest(doc: object) -> object:
    return parse(doc, Path("service-manifest.json"))


def _parse_config(doc: object) -> object:
    return parse_config(doc, Path("config.json"))


def _parse_operator(doc: object) -> object:
    return validate(doc, "operator.json")


def _personal(doc: dict[str, object]) -> object:
    return _parse_config({**_config_doc(), "personal_overrides": doc})


# (name, builder, parser, error, dotted path of the object that gets the key)
CASES: list[tuple[str, Callable[[], dict[str, object]], Callable[[object], object], type, str]] = [
    ("manifest", _manifest_doc, _parse_manifest, ManifestError, ""),
    ("manifest", _manifest_doc, _parse_manifest, ManifestError, "commands"),
    ("manifest", _manifest_doc, _parse_manifest, PrioritiesError, "run_output_priority"),
    ("manifest", _manifest_doc, _parse_manifest, PrioritiesError, "run_output_priority.rules.0"),
    ("config", _config_doc, _parse_config, ConfigError, ""),
    ("config", _config_doc, _parse_config, ConfigError, "limits"),
    ("config", _config_doc, _parse_config, ConfigError, "models"),
    ("config", _config_doc, _parse_config, ConfigError, "policy"),
    ("config", _config_doc, _parse_config, ConfigError, "git_excluded_folders.0"),
    ("config", _config_doc, _parse_config, ConfigError, "personal_overrides"),
    ("operator", _operator_doc, _parse_operator, OperatorError, ""),
]


def _at(doc: dict[str, object], where: str) -> dict[str, object]:
    node: object = doc
    for part in filter(None, where.split(".")):
        if isinstance(node, list):
            node = node[int(part)]
        else:
            assert isinstance(node, dict)
            if node.get(part) is None:
                node[part] = {}
            node = node[part]
    assert isinstance(node, dict)
    return node


def _walk(value: object) -> list[str]:
    names: list[str] = []
    if isinstance(value, dict):
        for key, item in value.items():
            names.append(str(key))
            names += _walk(item)
    elif isinstance(value, list):
        for item in value:
            names += _walk(item)
    return names


@pytest.mark.parametrize(("kind", "build", "parser", "error", "where"), CASES)
def test_a_user_key_is_accepted_and_absent_from_the_result(
    kind: str,
    build: Callable[[], dict[str, object]],
    parser: Callable[[object], object],
    error: type,
    where: str,
) -> None:
    base = parser(build())
    for name in ("_note", "_", "___"):
        doc = build()
        _at(doc, where)[name] = "a copyright line"
        parsed = parser(doc)
        assert parsed == base, (kind, where, name)
        assert "a copyright line" not in repr(parsed)


@pytest.mark.parametrize(("kind", "build", "parser", "error", "where"), CASES)
def test_a_user_key_takes_any_json_value(
    kind: str,
    build: Callable[[], dict[str, object]],
    parser: Callable[[object], object],
    error: type,
    where: str,
) -> None:
    base = parser(build())
    for value in VALUES:
        doc = build()
        _at(doc, where)["_x"] = value
        assert parser(doc) == base


@pytest.mark.parametrize(("kind", "build", "parser", "error", "where"), CASES)
def test_a_misspelled_setting_is_still_refused_and_the_text_names_user_keys(
    kind: str,
    build: Callable[[], dict[str, object]],
    parser: Callable[[object], object],
    error: type,
    where: str,
) -> None:
    doc = build()
    target = _at(doc, where)
    target["_fine"] = 1
    target["typoo"] = 1
    with pytest.raises(error) as caught:
        parser(doc)
    text = str(caught.value)
    assert "typoo" in text and "_fine" not in text.split("(known")[0]
    assert "starts with an underscore is your own and is ignored" in text
    assert "Next:" in text


def test_a_user_key_in_a_coding_rules_entry_and_agent_map_is_skipped() -> None:
    doc = _config_doc()
    doc["coding_rules"] = [{"builtin": "baseline", "_why": "copyright"}]
    doc["models"] = {"agents": {"coder": "opus", "_n": 3}}
    assert _parse_config(doc) == _parse_config(_config_doc())
    doc["coding_rules"] = [{"_why": "x"}]
    with pytest.raises(ConfigError):
        _parse_config(doc)


def test_a_user_key_in_the_manifest_free_name_maps_is_skipped() -> None:
    doc = _manifest_doc()
    doc["code_areas"] = {"api": "src/api", "_note": 3}
    prio = doc["run_output_priority"]
    assert isinstance(prio, dict)
    prio["agent_order"] = {"_note": 3}
    assert _parse_manifest(doc) == _parse_manifest(_manifest_doc())


def test_a_user_key_is_not_a_setting_name() -> None:
    assert is_user_key("_") and is_user_key("___") and is_user_key("_commands")
    assert not is_user_key("commands") and not is_user_key(3) and not is_user_key("")
    names = {part for _, key in KEY_ROWS for part in key.split(".")}
    assert not [name for name in names if name.startswith("_")]


@pytest.mark.parametrize("name", ["", "__", "x_"])
def test_only_a_leading_underscore_makes_a_user_key(name: str) -> None:
    assert not is_user_key(name) or name == "__"


def test_the_map_module_refuses_a_row_naming_a_user_key() -> None:
    for build in (
        lambda: Move(("a",), ("_b",)),
        lambda: Move(("_a", "b"), ("c",)),
        lambda: Drop(("g", "_x"), "gone"),
        lambda: Set(("_x",), 1),
        lambda: Convert(("g", "_x"), "f"),
    ):
        with pytest.raises(SchemaError):
            build()
    assert Move(("a",), ("b",)).new == ("b",)


def test_an_upgrade_carries_user_keys_unchanged() -> None:
    kinds = {"manifest": Kind(2, (Step(1, 2, (Set(("new",), 1), Move(("old",), ("moved",)))),))}
    doc: dict[str, object] = {"schema": 1, "_top": {"a": 1}, "old": 5, "g": {"_in": [1]}}
    result = upgrade(copy.deepcopy(doc), "manifest", lambda _d: True, kinds)
    assert result.doc["_top"] == {"a": 1} and result.doc["g"] == {"_in": [1]}
    assert result.doc["moved"] == 5 and result.doc["schema"] == 2
    assert all("_" not in a.text.replace("->", "") for a in result.actions)


def _with_user_keys(wizard: Path) -> str:
    doc = json.loads(_manifest(wizard).read_text(encoding="utf-8"))
    doc["_top"] = "copyright line"
    doc["checks"]["_note"] = {"a": [1]}
    doc["commands"]["_n"] = None
    text = json.dumps(doc, indent=2) + "\n"
    _manifest(wizard).write_text(text, encoding="utf-8")
    return text


@pytest.fixture
def home(tmp_path: Path) -> Path:
    path = tmp_path / "home"
    path.mkdir()
    return path


@pytest.fixture
def wizard(repo_cwd: Path, home: Path) -> Path:
    assert _run(["--repo", str(repo_cwd)], home).returncode == 0
    return repo_cwd


def test_set_leaves_every_user_key_where_it_was(wizard: Path, home: Path) -> None:
    before = _with_user_keys(wizard)
    result = _set(wizard, home, "manifest", SCAN, "true")
    assert result.returncode == 0, result.stdout
    after = _manifest(wizard).read_text(encoding="utf-8")
    assert after == before.replace('"secret_scan": false', '"secret_scan": true')
    assert '"_note"' in after and '"_top"' in after and '"_n"' in after


def test_describe_does_not_list_a_user_key(wizard: Path, home: Path) -> None:
    _with_user_keys(wizard)
    done = _run(["--describe", "--repo", str(wizard)], home)
    assert done.returncode == 0, done.stdout
    assert not [n for n in _walk(json.loads(done.stdout)["keys"]) if n.startswith("_")]
    assert '"key": "_' not in done.stdout


def test_replace_carries_user_keys_and_never_lists_them_as_dropped(
    wizard: Path, home: Path
) -> None:
    old = {
        "stack": {"language": "python"},
        "_top": "copyright line",
        "commands": {"unit_test": "pytest -q", "_n": [1], "build": "make"},
        "checks": {"_c": {"k": 1}},
    }
    _manifest(wizard).write_text(json.dumps(old), encoding="utf-8")
    code, out = _replace(wizard, home, "manifest", "--write")
    assert code == 0, out
    carried, dropped = _moves(out)
    assert not [p for p in carried | set(dropped) if "_" in p.replace("unit_test", "")]
    assert "stack" in dropped and "commands.build" in dropped
    doc = json.loads(_manifest(wizard).read_text(encoding="utf-8"))
    assert doc["_top"] == "copyright line"
    assert doc["commands"]["_n"] == [1] and doc["commands"]["unit_test"] == "pytest -q"
    assert doc["checks"]["_c"] == {"k": 1}


@pytest.mark.parametrize(
    "name",
    [
        "service-manifest.example.json",
        "service-manifest.all-overrides.example.json",
        "config.example.json",
        "config.all-overrides.example.json",
        "operator.example.json",
    ],
)
def test_the_example_files_still_load(name: str) -> None:
    doc = json.loads((REPO_ROOT / "docs" / "examples" / name).read_text(encoding="utf-8"))
    if name.startswith("service-manifest"):
        _parse_manifest(doc)
    elif name.startswith("config"):
        _parse_config(doc)
    else:
        _parse_operator(doc)
