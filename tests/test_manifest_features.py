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
    CHECK_KEYS,
    COMPLIANCE_KEYS,
    FEATURE_KEYS,
    Features,
    Frameworks,
    Manifest,
    ManifestError,
    load,
)
from lib.project_keys import KEY_ROWS, MANIFEST_FILE, manifest_keys, starter_manifest

from tests.conftest import SCRIPTS_DIR
from tests.helpers import ends_with_next, write_manifest

PROHIBITED = {"paths": ["infra/"], "file_types": [".pem"]}


def _refused(repo: Path, payload: object) -> str:
    write_manifest(repo, payload)
    with pytest.raises(ManifestError) as caught:
        load(repo)
    message = str(caught.value)
    assert ends_with_next(message), message
    return message


def test_the_checks_group_names_its_switches() -> None:
    # 0245: the file names say what each switch checks; the internal fields stay.
    assert tuple(CHECK_KEYS) == (
        "secret_scan",
        "online_advisory_lookup",
        "terraform_format",
        "terraform_validate",
        "release_banned_terms",
    )
    assert set(CHECK_KEYS.values()) <= set(FEATURE_KEYS)


def test_absent_manifest_gives_every_check_its_default(tmp_path: Path) -> None:
    # 0069: no manifest is no feature; load stays None and the dataclass default is all off.
    assert load(tmp_path) is None
    assert manifest.features(tmp_path) == Features()


def test_absent_checks_group_gives_every_check_its_default(tmp_path: Path) -> None:
    write_manifest(tmp_path, {})
    loaded = load(tmp_path)
    assert loaded is not None and loaded.features == Features()
    assert loaded.features.ledger is False and loaded.features.scope is None
    write_manifest(tmp_path, {"checks": None})
    assert load(tmp_path) == loaded


@pytest.mark.parametrize(
    ("block", "want"),
    [
        ({"secret_scan": True}, Features(secrets_scan=True)),
        ({"secret_scan": False}, Features()),
        ({"release_banned_terms": "docs/terms.txt"}, Features(scrub_file="docs/terms.txt")),
        ({"release_banned_terms": None}, Features()),
        ({"online_advisory_lookup": False}, Features(dependency_web_lookup=False)),
        ({"terraform_format": True}, Features(terraform_tools=True)),
        ({"terraform_validate": True}, Features(terraform_validate=True)),
    ],
)
def test_each_check_reads_its_values(
    tmp_path: Path, block: dict[str, object], want: Features
) -> None:
    write_manifest(tmp_path, {"checks": block})
    loaded = load(tmp_path)
    assert loaded is not None and loaded.features == want


@pytest.mark.parametrize(("filename", "on"), [("decisions.md", True), (None, False)])
def test_the_ledger_switch_follows_the_decisions_filename(
    tmp_path: Path, filename: str | None, on: bool
) -> None:
    # 0247: decisions are recorded exactly when a decisions file is named.
    write_manifest(tmp_path, {"docs": {"decisions_filename": filename}})
    loaded = load(tmp_path)
    assert loaded is not None and loaded.features.ledger is on


@pytest.mark.parametrize("old", ["secrets_scan", "scope", "ledger", "github", "terraform_tools"])
def test_an_old_check_name_is_refused_with_the_valid_names(tmp_path: Path, old: str) -> None:
    # 0245: no alias; the refusal lists every valid name in the group.
    message = _refused(tmp_path, {"checks": {old: True}})
    assert f"checks has unknown keys ['{old}']" in message
    assert "(known: " + ", ".join(CHECK_KEYS) + ")" in message


@pytest.mark.parametrize(
    "block",
    [
        {"secret_scan": "yes"},
        {"secret_scan": None},
        {"secret_scan": 1},
        {"online_advisory_lookup": "on"},
        {"terraform_format": 0},
        {"release_banned_terms": 3},
        {"release_banned_terms": ["a"]},
    ],
)
def test_a_bad_check_value_is_refused(tmp_path: Path, block: dict[str, object]) -> None:
    # 0073: a value outside the field's type is refused, as prohibited_writes refuses one.
    _refused(tmp_path, {"checks": block})


@pytest.mark.parametrize("payload", [{"checks": []}, {"checks": "on"}, {"checks": 1}])
def test_checks_that_is_not_an_object_is_refused(tmp_path: Path, payload: object) -> None:
    _refused(tmp_path, payload)


@pytest.mark.parametrize(
    "scrub", ["/etc/terms.txt", "../terms.txt", "a/../../b", "a\\b", "*.txt", "", "./t.txt"]
)
def test_banned_terms_file_outside_the_project_is_refused(tmp_path: Path, scrub: str) -> None:
    _refused(tmp_path, {"checks": {"release_banned_terms": scrub}})


def test_prohibited_writes_unchanged_beside_checks(tmp_path: Path) -> None:
    write_manifest(tmp_path, {"prohibited_writes": PROHIBITED})
    alone = load(tmp_path)
    write_manifest(tmp_path, {"prohibited_writes": PROHIBITED, "checks": {"secret_scan": True}})
    beside = load(tmp_path)
    assert alone is not None and beside is not None
    assert (beside.forbidden_paths, beside.forbidden_extensions) == (("infra/",), (".pem",))
    assert (alone.forbidden_paths, alone.forbidden_extensions) == (
        beside.forbidden_paths,
        beside.forbidden_extensions,
    )
    assert beside.features.secrets_scan is True


def test_run_definitions_folder_is_read_from_the_manifest(tmp_path: Path) -> None:
    write_manifest(tmp_path, {"run_definitions_folder": "ops/trains"})
    loaded = load(tmp_path)
    assert loaded is not None and loaded.trains_dir == "ops/trains"
    write_manifest(tmp_path, {})
    assert load(tmp_path) == Manifest()


@pytest.mark.parametrize("value", ["/abs/trains", "../trains", "", 7, ["trains"]])
def test_run_definitions_folder_outside_the_project_is_refused(
    tmp_path: Path, value: object
) -> None:
    _refused(tmp_path, {"run_definitions_folder": value})


def test_unit_test_command_is_read_from_the_commands_group(tmp_path: Path) -> None:
    write_manifest(tmp_path, {"commands": {"unit_test": "pytest -q"}})
    loaded = load(tmp_path)
    assert loaded is not None and loaded.unit_test_cmd == ("pytest -q",)
    write_manifest(tmp_path, {"commands": {"unit_test": None}})
    assert load(tmp_path) == Manifest()


@pytest.mark.parametrize("payload", [{"commands": []}, {"commands": {"unit_test": 5}}])
def test_bad_commands_group_is_refused(tmp_path: Path, payload: object) -> None:
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
    for root, scan in ((project, True), (home, False), (plugin, False)):
        (root / ".claude" / "daedalus").mkdir(parents=True)
        body = {"checks": {"secret_scan": scan}}
        write_manifest(root, body | {"run_definitions_folder": f"{root.name}-trains"})
        config = {"local_docs_folder": str(root / "Charter")}
        (root / ".claude" / "daedalus" / "config.json").write_text(json.dumps(config))
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("CLAUDE_PLUGIN_ROOT", str(plugin))
    loaded = load(project)
    assert loaded is not None
    assert (loaded.features.secrets_scan, loaded.trains_dir) == (True, "project-trains")
    assert load_config(cwd=str(project)).charter_root == project / "Charter"


# 0157, 0245: compliance_rules names the project's rulebook folder.


def test_absent_compliance_rules_reads_the_builtin_rulebooks(tmp_path: Path) -> None:
    write_manifest(tmp_path, {})
    loaded = load(tmp_path)
    assert loaded is not None and loaded.frameworks == Frameworks(None, True)
    assert COMPLIANCE_KEYS == ("folder", "use_builtin", "extra_builtin")


@pytest.mark.parametrize(
    ("block", "want"),
    [
        ({}, Frameworks()),
        ({"folder": "compliance/packs"}, Frameworks("compliance/packs", True)),
        ({"folder": None, "use_builtin": False}, Frameworks(None, False)),
        ({"folder": "packs/", "use_builtin": True}, Frameworks("packs/", True)),
        ({"extra_builtin": ["cost-tier"]}, Frameworks(None, True, ("cost-tier",))),
        ({"extra_builtin": []}, Frameworks()),
    ],
)
def test_each_compliance_rules_key_reads_its_values(
    tmp_path: Path, block: dict[str, object], want: Frameworks
) -> None:
    write_manifest(tmp_path, {"compliance_rules": block})
    loaded = load(tmp_path)
    assert loaded is not None and loaded.frameworks == want


@pytest.mark.parametrize("old", ["pack_dir", "default_packs", "packs"])
def test_an_old_compliance_rules_key_is_refused(tmp_path: Path, old: str) -> None:
    message = _refused(tmp_path, {"compliance_rules": {old: None}})
    known = "(known: folder, use_builtin, extra_builtin)"
    assert f"compliance_rules has unknown keys ['{old}'] {known}" in message


@pytest.mark.parametrize(
    "payload",
    [
        {"compliance_rules": []},
        {"compliance_rules": "packs"},
        {"compliance_rules": {"folder": "/etc/packs"}},
        {"compliance_rules": {"folder": "../packs"}},
        {"compliance_rules": {"folder": "packs/*"}},
        {"compliance_rules": {"folder": 3}},
        {"compliance_rules": {"use_builtin": None}},
        {"compliance_rules": {"use_builtin": "yes"}},
        {"compliance_rules": {"use_builtin": 0}},
        {"compliance_rules": {"extra_builtin": "cost-tier"}},
        {"compliance_rules": {"extra_builtin": ["Cost_Tier"]}},
        {"compliance_rules": {"extra_builtin": ["cost-tier", "cost-tier"]}},
        {"compliance_rules": {"extra_builtin": [3]}},
    ],
)
def test_bad_compliance_rules_value_is_refused(tmp_path: Path, payload: object) -> None:
    assert "compliance_rules" in _refused(tmp_path, payload)


def test_compliance_rules_keys_have_rows_and_are_overrides() -> None:
    keys = manifest_keys()
    want = tuple(f"compliance_rules.{name}" for name in COMPLIANCE_KEYS)
    assert want == tuple(key for key in keys if key.startswith("compliance_rules."))
    for key in want:
        assert KEY_ROWS[(MANIFEST_FILE, key)].override, key
    assert "compliance_rules" not in starter_manifest()


# 0158: checks.terraform_validate is an opt-in switch beside terraform_format.


def test_terraform_validate_reads_false_when_absent(tmp_path: Path) -> None:
    assert Features().terraform_validate is False
    assert manifest.features(tmp_path).terraform_validate is False
    for payload in ({}, {"checks": {}}, {"checks": {"terraform_format": True}}):
        write_manifest(tmp_path, payload)
        loaded = load(tmp_path)
        assert loaded is not None and loaded.features.terraform_validate is False, payload


@pytest.mark.parametrize("value", [None, "true", "on", 1, 0, [], {}])
def test_terraform_validate_refuses_a_non_boolean(tmp_path: Path, value: object) -> None:
    # 0158: true or false only; null is refused, unlike the true-false-null switches.
    message = _refused(tmp_path, {"checks": {"terraform_validate": value}})
    assert "checks.terraform_validate" in message and "must be true or false" in message


def test_terraform_validate_has_a_row() -> None:
    assert "checks.terraform_validate" in manifest_keys()
    row = KEY_ROWS[(MANIFEST_FILE, "checks.terraform_validate")]
    assert row.kind == "boolean" and row.default.startswith("`false`")
