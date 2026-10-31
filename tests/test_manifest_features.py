# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import ast
import json
from pathlib import Path

import pytest
from lib import manifest
from lib.config import load_config
from lib.manifest import (
    FEATURE_KEYS,
    FRAMEWORKS_KEYS,
    Features,
    Frameworks,
    Manifest,
    ManifestError,
    load,
)
from lib.project_keys import KEY_ROWS, MANIFEST_FILE, manifest_keys, starter_manifest

from tests.conftest import SCRIPTS_DIR

NARROWING = {"forbidden_paths": ["infra/"], "forbidden_extensions": [".pem"]}


def _write(repo: Path, payload: object) -> None:
    (repo / "service-manifest.json").write_text(json.dumps(payload), encoding="utf-8")


def _ends_with_next(message: str) -> bool:
    head, sep, tail = message.rpartition(". Next: ")
    return bool(head and sep and tail.endswith(".")) and message.count("Next:") == 1


def _refused(repo: Path, payload: object) -> str:
    _write(repo, payload)
    with pytest.raises(ManifestError) as caught:
        load(repo)
    message = str(caught.value)
    assert _ends_with_next(message), message
    return message


def test_feature_keys_are_the_features_fields() -> None:
    # 0132, 0172: the persona switches follow ledger; github was dropped.
    assert FEATURE_KEYS == (
        "scope",
        "secrets_scan",
        "scrub_file",
        "ledger",
        "dependency_web_lookup",
        "terraform_tools",
        "terraform_validate",
    )


def test_absent_manifest_gives_every_feature_its_default(tmp_path: Path) -> None:
    # 0069: no manifest is no feature; load stays None and the dataclass default is all off.
    assert load(tmp_path) is None
    assert manifest.features(tmp_path) == Features(None, False, None, None)


def test_absent_features_object_gives_every_feature_its_default(tmp_path: Path) -> None:
    _write(tmp_path, {"manifest_version": 1})
    loaded = load(tmp_path)
    assert loaded is not None
    assert loaded.features == Features(scope=None, secrets_scan=False, scrub_file=None)
    assert loaded.features.ledger is None
    assert manifest.features(tmp_path) == loaded.features


@pytest.mark.parametrize(
    ("block", "want"),
    [
        ({"scope": "repository"}, Features(scope="repository")),
        ({"scope": "folder"}, Features(scope="folder")),
        ({"scope": None}, Features()),
        ({"secrets_scan": True}, Features(secrets_scan=True)),
        ({"secrets_scan": False}, Features()),
        ({"scrub_file": "docs/terms.txt"}, Features(scrub_file="docs/terms.txt")),
        ({"scrub_file": None}, Features()),
        ({"ledger": True}, Features(ledger=True)),
        ({"ledger": False}, Features(ledger=False)),
        ({"ledger": None}, Features()),
        (
            {
                "scope": "folder",
                "secrets_scan": True,
                "scrub_file": "t.txt",
                "ledger": False,
            },
            Features("folder", True, "t.txt", False),
        ),
    ],
)
def test_each_feature_key_reads_its_values(
    tmp_path: Path, block: dict[str, object], want: Features
) -> None:
    _write(tmp_path, {"features": block})
    loaded = load(tmp_path)
    assert loaded is not None and loaded.features == want


@pytest.mark.parametrize("value", [True, False, None, "yes", 1, {}])
def test_retired_github_key_loads_and_is_ignored(tmp_path: Path, value: object) -> None:
    # 0172: a manifest still carrying github loads with any value; the key changes nothing.
    _write(tmp_path, {"features": {"secrets_scan": True, "github": value}})
    loaded = load(tmp_path)
    assert loaded is not None and loaded.features == Features(secrets_scan=True)
    assert manifest.retired_features(tmp_path) == ("github",)


def test_unknown_feature_key_is_refused(tmp_path: Path) -> None:
    message = _refused(tmp_path, {"features": {"scope": "folder", "gitleaks": True}})
    assert "gitleaks" in message


@pytest.mark.parametrize(
    "block",
    [
        {"scope": "repo"},
        {"scope": ""},
        {"scope": True},
        {"secrets_scan": "yes"},
        {"secrets_scan": None},
        {"secrets_scan": 1},
        {"ledger": "on"},
        {"ledger": 0},
        {"scrub_file": 3},
        {"scrub_file": ["a"]},
    ],
)
def test_bad_scope_value_is_refused(tmp_path: Path, block: dict[str, object]) -> None:
    # 0073: a value outside the field's type is refused, as jail_narrowing refuses one.
    _refused(tmp_path, {"features": block})


@pytest.mark.parametrize("payload", [{"features": []}, {"features": "on"}, {"features": 1}])
def test_features_that_is_not_an_object_is_refused(tmp_path: Path, payload: object) -> None:
    _refused(tmp_path, payload)


@pytest.mark.parametrize(
    "scrub", ["/etc/terms.txt", "../terms.txt", "a/../../b", "a\\b", "*.txt", "", "./t.txt"]
)
def test_scrub_file_outside_the_project_is_refused(tmp_path: Path, scrub: str) -> None:
    _refused(tmp_path, {"features": {"scrub_file": scrub}})


def test_jail_narrowing_unchanged_beside_features(tmp_path: Path) -> None:
    _write(tmp_path, {"jail_narrowing": NARROWING})
    alone = load(tmp_path)
    _write(tmp_path, {"jail_narrowing": NARROWING, "features": {"secrets_scan": True}})
    beside = load(tmp_path)
    assert alone is not None and beside is not None
    assert (beside.forbidden_paths, beside.forbidden_extensions) == (("infra/",), (".pem",))
    assert (alone.forbidden_paths, alone.forbidden_extensions) == (
        beside.forbidden_paths,
        beside.forbidden_extensions,
    )
    assert beside.features == Features(secrets_scan=True)


def test_trains_dir_is_read_from_the_manifest(tmp_path: Path) -> None:
    _write(tmp_path, {"trains_dir": "ops/trains"})
    loaded = load(tmp_path)
    assert loaded is not None and loaded.trains_dir == "ops/trains"
    _write(tmp_path, {})
    assert load(tmp_path) == Manifest()


@pytest.mark.parametrize("value", ["/abs/trains", "../trains", "", 7, ["trains"]])
def test_trains_dir_outside_the_project_is_refused(tmp_path: Path, value: object) -> None:
    _refused(tmp_path, {"trains_dir": value})


def test_unit_test_cmd_is_read_from_the_manifest_stack(tmp_path: Path) -> None:
    _write(tmp_path, {"stack": {"language": "python", "unit_test_cmd": "pytest -q"}})
    loaded = load(tmp_path)
    assert loaded is not None and loaded.unit_test_cmd == "pytest -q"
    _write(tmp_path, {"stack": {"unit_test_cmd": None}})
    assert load(tmp_path) == Manifest()


@pytest.mark.parametrize("payload", [{"stack": []}, {"stack": {"unit_test_cmd": 5}}])
def test_bad_stack_is_refused(tmp_path: Path, payload: object) -> None:
    _refused(tmp_path, payload)


# 0070: a project file found through the plugin root or the home folder is the wrong copy.
_PROJECT_FILES = ("service-manifest.json", "config.json")
_ELSEWHERE = frozenset({"HOME", "CLAUDE_PLUGIN_ROOT"})


def _reads_elsewhere(scope: ast.AST) -> bool:
    for node in ast.walk(scope):
        if isinstance(node, ast.Constant) and node.value in _ELSEWHERE:
            return True
        if isinstance(node, ast.Attribute) and node.attr in {"home", "expanduser"}:
            return True
    return False


def _names_project_file(scope: ast.AST) -> bool:
    for node in ast.walk(scope):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            if any(name in node.value for name in _PROJECT_FILES):
                return True
        if isinstance(node, ast.Name) and node.id == "MANIFEST_NAME":
            return True
    return False


def _scopes(tree: ast.Module) -> list[ast.AST]:
    funcs = [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef | ast.AsyncFunctionDef)]
    top = [n for n in tree.body if not isinstance(n, ast.FunctionDef | ast.ClassDef)]
    return [*funcs, *top]


def test_project_files_resolve_from_the_project_root_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    offenders = []
    for path in sorted(SCRIPTS_DIR.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for scope in _scopes(tree):
            if _reads_elsewhere(scope) and _names_project_file(scope):
                offenders.append(f"{path.relative_to(SCRIPTS_DIR)}:{getattr(scope, 'lineno', 0)}")
    assert offenders == []
    project, home, plugin = (tmp_path / name for name in ("project", "home", "plugin"))
    for root, scope in ((project, "folder"), (home, "repository"), (plugin, "repository")):
        (root / ".claude" / "daedalus").mkdir(parents=True)
        _write(root, {"features": {"scope": scope}, "trains_dir": f"{root.name}-trains"})
        config = {"charter_root": str(root / "Charter")}
        (root / ".claude" / "daedalus" / "config.json").write_text(json.dumps(config))
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("CLAUDE_PLUGIN_ROOT", str(plugin))
    loaded = load(project)
    assert loaded is not None
    assert (loaded.features.scope, loaded.trains_dir) == ("folder", "project-trains")
    assert load_config(cwd=str(project)).charter_root == project / "Charter"


# 0157: the frameworks block names the project's pack folder.


def test_absent_frameworks_block_reads_the_shipped_packs(tmp_path: Path) -> None:
    _write(tmp_path, {})
    loaded = load(tmp_path)
    assert loaded is not None and loaded.frameworks == Frameworks(None, True)
    assert FRAMEWORKS_KEYS == ("pack_dir", "default_packs", "packs")


@pytest.mark.parametrize(
    ("block", "want"),
    [
        ({}, Frameworks()),
        ({"pack_dir": "compliance/packs"}, Frameworks("compliance/packs", True)),
        ({"pack_dir": None, "default_packs": False}, Frameworks(None, False)),
        ({"pack_dir": "packs/", "default_packs": True}, Frameworks("packs/", True)),
        ({"packs": ["cost-tier"]}, Frameworks(None, True, ("cost-tier",))),
        ({"packs": []}, Frameworks()),
    ],
)
def test_each_frameworks_key_reads_its_values(
    tmp_path: Path, block: dict[str, object], want: Frameworks
) -> None:
    _write(tmp_path, {"frameworks": block})
    loaded = load(tmp_path)
    assert loaded is not None and loaded.frameworks == want


def test_unknown_frameworks_key_is_refused(tmp_path: Path) -> None:
    message = _refused(tmp_path, {"frameworks": {"pack_dir": "p", "cache": "x"}})
    assert "frameworks has unknown keys ['cache'] (known: pack_dir, default_packs, packs)" in message


@pytest.mark.parametrize(
    "payload",
    [
        {"frameworks": []},
        {"frameworks": "packs"},
        {"frameworks": {"pack_dir": "/etc/packs"}},
        {"frameworks": {"pack_dir": "../packs"}},
        {"frameworks": {"pack_dir": "packs/*"}},
        {"frameworks": {"pack_dir": 3}},
        {"frameworks": {"default_packs": None}},
        {"frameworks": {"default_packs": "yes"}},
        {"frameworks": {"default_packs": 0}},
        {"frameworks": {"packs": "cost-tier"}},
        {"frameworks": {"packs": ["Cost_Tier"]}},
        {"frameworks": {"packs": ["cost-tier", "cost-tier"]}},
        {"frameworks": {"packs": [3]}},
    ],
)
def test_bad_frameworks_value_is_refused(tmp_path: Path, payload: object) -> None:
    assert "frameworks" in _refused(tmp_path, payload)


def test_frameworks_keys_have_rows_and_setup_writes_no_block() -> None:
    keys = manifest_keys()
    want = ("frameworks.pack_dir", "frameworks.default_packs", "frameworks.packs")
    assert want == tuple(key for key in keys if key.startswith("frameworks."))
    for key in want:
        assert (MANIFEST_FILE, key) in KEY_ROWS, key
    assert "frameworks" not in starter_manifest()


# 0158: features.terraform_validate is an opt-in switch beside terraform_tools.


def test_terraform_validate_reads_false_when_absent(tmp_path: Path) -> None:
    # 0158: validate is opt-in; no key, no features object and no manifest all read false.
    assert Features().terraform_validate is False
    assert manifest.features(tmp_path).terraform_validate is False
    for payload in ({}, {"features": {}}, {"features": {"terraform_tools": True}}):
        _write(tmp_path, payload)
        loaded = load(tmp_path)
        assert loaded is not None and loaded.features.terraform_validate is False, payload


@pytest.mark.parametrize("value", [True, False])
def test_terraform_validate_reads_its_boolean(tmp_path: Path, value: bool) -> None:
    _write(tmp_path, {"features": {"terraform_validate": value}})
    loaded = load(tmp_path)
    assert loaded is not None and loaded.features == Features(terraform_validate=value)


@pytest.mark.parametrize("value", [None, "true", "on", 1, 0, [], {}])
def test_terraform_validate_refuses_a_non_boolean(tmp_path: Path, value: object) -> None:
    # 0158: true or false only; null is refused, unlike the true-false-null persona switches.
    message = _refused(tmp_path, {"features": {"terraform_validate": value}})
    assert "features.terraform_validate" in message and "must be true or false" in message


def test_terraform_validate_has_a_row_and_setup_writes_no_value() -> None:
    assert "features.terraform_validate" in manifest_keys()
    row = KEY_ROWS[(MANIFEST_FILE, "features.terraform_validate")]
    assert row.kind == "boolean" and row.default.startswith("`false`")
    features = starter_manifest()["features"]
    assert isinstance(features, dict) and "terraform_validate" not in features
