# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import ast
import json
from pathlib import Path

import pytest
from lib import manifest
from lib.config import load_config
from lib.manifest import FEATURE_KEYS, Features, Manifest, ManifestError, load

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
    assert FEATURE_KEYS == ("scope", "secrets_scan", "scrub_file", "ledger", "github")


def test_absent_manifest_gives_every_feature_its_default(tmp_path: Path) -> None:
    # 0069: no manifest is no feature; load stays None and the dataclass default is all off.
    assert load(tmp_path) is None
    assert manifest.features(tmp_path) == Features(None, False, None, None, False)


def test_absent_features_object_gives_every_feature_its_default(tmp_path: Path) -> None:
    _write(tmp_path, {"manifest_version": 1})
    loaded = load(tmp_path)
    assert loaded is not None
    assert loaded.features == Features(scope=None, secrets_scan=False, scrub_file=None)
    assert loaded.features.ledger is None
    # issue 48: an absent github key reads false, never null.
    assert loaded.features.github is False
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
        ({"github": True}, Features(github=True)),
        ({"github": False}, Features()),
        ({"github": None}, Features(github=None)),
        (
            {
                "scope": "folder",
                "secrets_scan": True,
                "scrub_file": "t.txt",
                "ledger": False,
                "github": True,
            },
            Features("folder", True, "t.txt", False, True),
        ),
    ],
)
def test_each_feature_key_reads_its_values(
    tmp_path: Path, block: dict[str, object], want: Features
) -> None:
    _write(tmp_path, {"features": block})
    loaded = load(tmp_path)
    assert loaded is not None and loaded.features == want


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
        {"github": "true"},
        {"github": 1},
        {"github": {}},
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
