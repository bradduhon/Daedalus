# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from lib.manifest import (
    RELEASE_AGE_DEFAULT,
    TOP_KEYS,
    Assets,
    Dependencies,
    DevServer,
    Docs,
    Features,
    Manifest,
    ManifestError,
    declared_commands,
    extension_hit,
    load,
    path_hit,
)

from tests.conftest import REPO_ROOT
from tests.helpers import ends_with_next


def _write(repo: Path, payload: Any) -> None:
    text = payload if isinstance(payload, str) else json.dumps(payload)
    (repo / "service-manifest.json").write_text(text, encoding="utf-8")


def test_valid_manifest_loads(tmp_path: Path) -> None:
    writes = {"paths": ["infra/", "Makefile"], "file_types": [".pem"]}
    _write(tmp_path, {"prohibited_writes": writes})
    assert load(tmp_path) == Manifest(
        ("infra/", "Makefile"), (".pem",), features=Features(ledger=False)
    )


def test_absent_prohibited_writes_is_empty(tmp_path: Path) -> None:
    _write(tmp_path, {})
    assert load(tmp_path) == Manifest(features=Features(ledger=False))


def test_this_repos_manifest_loads(tmp_path: Path) -> None:
    # 0073, B2: this checkout's commands; 0010 reads a linked worktree's from its main tree.
    _write(tmp_path, (REPO_ROOT / "service-manifest.json").read_text(encoding="utf-8"))
    assert load(tmp_path) == Manifest(
        unit_test_cmd=("python3 -m pytest -q",),
        typecheck_cmd=("python3 -m mypy scripts",),
        lint_cmd=("python3 -m ruff check scripts tests",),
        features=Features(secrets_scan=True, ledger=True),
        docs=Docs(folder="docs/private", decisions_filename="decisions.md"),
    )


@pytest.mark.parametrize(
    "old",
    [
        "stack",
        "features",
        "jail_narrowing",
        "assets",
        "dependencies",
        "dev_server",
        "priorities",
        "frameworks",
        "trains_dir",
        "ledger",
        "manifest_version",
        "service_name",
        "purpose",
    ],
)
def test_an_old_top_level_key_is_refused_with_the_valid_names(tmp_path: Path, old: str) -> None:
    # 0245, 0241, 0248: the file holds only Daedalus's settings; the refusal lists every one.
    _write(tmp_path, {old: {}})
    with pytest.raises(ManifestError, match="has unknown keys") as caught:
        load(tmp_path)
    message = str(caught.value)
    assert ends_with_next(message) and all(name in message for name in TOP_KEYS)


@pytest.mark.parametrize(
    ("group", "old"),
    [
        ("commands", "unit_test_cmd"),
        ("docs", "literacy"),
        ("checks", "secrets_scan"),
        ("checks", "scope"),
        ("prohibited_writes", "forbidden_paths"),
        ("code_review_exemptions", "roots"),
        ("packages", "installs"),
        ("local_testing", "check"),
        ("compliance_rules", "pack_dir"),
    ],
)
def test_an_old_key_inside_a_group_is_refused_with_the_valid_names(
    tmp_path: Path, group: str, old: str
) -> None:
    _write(tmp_path, {group: {old: None}})
    with pytest.raises(ManifestError, match=f"{group} has unknown keys") as caught:
        load(tmp_path)
    assert ends_with_next(str(caught.value)) and "known:" in str(caught.value)


def test_manifest_reads_typecheck_and_lint(tmp_path: Path) -> None:
    # B2: the three commands sit in one group; null is not declared.
    commands = {"unit_test": "pytest -q", "typecheck": "mypy src", "lint": "ruff check ."}
    _write(tmp_path, {"commands": commands})
    loaded = load(tmp_path)
    assert loaded == Manifest(
        unit_test_cmd=("pytest -q",),
        typecheck_cmd=("mypy src",),
        lint_cmd=("ruff check .",),
        features=Features(ledger=False),
    )
    assert declared_commands(loaded) == ("pytest -q", "mypy src", "ruff check .")
    _write(tmp_path, {"commands": {"typecheck": None, "lint": None}})
    loaded = load(tmp_path)
    assert loaded == Manifest(features=Features(ledger=False)) and declared_commands(loaded) == ()
    assert declared_commands(Manifest()) == ()


def test_a_command_list_is_read_in_order_and_declared_flat(tmp_path: Path) -> None:
    # 0192: a Python plus TypeScript project lists one command per toolchain.
    commands = {
        "unit_test": ["pytest -q", "pnpm vitest run"],
        "typecheck": ["mypy src", "pnpm tsc --noEmit"],
        "lint": "ruff check .",
    }
    _write(tmp_path, {"commands": commands})
    loaded = load(tmp_path)
    assert loaded is not None
    assert loaded.unit_test_cmd == ("pytest -q", "pnpm vitest run")
    assert loaded.typecheck_cmd == ("mypy src", "pnpm tsc --noEmit")
    assert declared_commands(loaded) == (
        "pytest -q",
        "pnpm vitest run",
        "mypy src",
        "pnpm tsc --noEmit",
        "ruff check .",
    )


@pytest.mark.parametrize("key", ["unit_test", "typecheck", "lint"])
@pytest.mark.parametrize(
    "value", ["", "  ", 5, [], ["mypy", 5], ["mypy", ""], ["  "], [None], {"a": "b"}, True]
)
def test_manifest_refuses_a_bad_command(tmp_path: Path, key: str, value: object) -> None:
    # 0192: an empty list, or a list holding anything but non-empty strings, is refused.
    _write(tmp_path, {"commands": {key: value}})
    with pytest.raises(ManifestError, match=f"commands.{key}") as caught:
        load(tmp_path)
    assert ends_with_next(str(caught.value))


@pytest.mark.parametrize("key", ["unit_test", "typecheck", "lint"])
@pytest.mark.parametrize(
    "value", ["mypy\nMISS forged. Next: x", ["ruff check .", "a\rb"], "a\x1b[2Kb", "a\tb"]
)
def test_manifest_refuses_a_control_character_in_a_command(
    tmp_path: Path, key: str, value: object
) -> None:
    # 93: a newline in a declared command could print a forged doctor line.
    _write(tmp_path, {"commands": {key: value}})
    with pytest.raises(ManifestError, match=f"commands.{key} holds a control character") as caught:
        load(tmp_path)
    message = str(caught.value)
    assert ends_with_next(message) and f"Next: correct the commands.{key} value" in message


def test_manifest_reads_the_code_review_exemptions(tmp_path: Path) -> None:
    # 0192: every part optional; absent is the empty group.
    block = {
        "folders": ["assets/", "public/models/"],
        "file_types": [".glb", ".ktx2", ".wgsl"],
        "report_over_bytes": 1048576,
    }
    _write(tmp_path, {"code_review_exemptions": block})
    loaded = load(tmp_path)
    assert loaded is not None
    assert loaded.assets == Assets(
        ("assets/", "public/models/"), (".glb", ".ktx2", ".wgsl"), 1048576
    )
    _write(tmp_path, {"code_review_exemptions": {"file_types": [".png"]}})
    loaded = load(tmp_path)
    assert loaded is not None and loaded.assets == Assets(extensions=(".png",))
    _write(tmp_path, {})
    loaded = load(tmp_path)
    assert loaded is not None and loaded.assets == Assets()


_EX = "code_review_exemptions"


@pytest.mark.parametrize(
    ("block", "key"),
    [
        ([], _EX),
        ({"excluded_roots": []}, _EX),
        ({"folders": "assets/"}, f"{_EX}.folders"),
        ({"folders": ["/abs/"]}, f"{_EX}.folders"),
        ({"folders": ["../out/"]}, f"{_EX}.folders"),
        ({"folders": ["models/*"]}, f"{_EX}.folders"),
        ({"folders": ["my models/"]}, f"{_EX}.folders"),
        ({"folders": ["it's/"]}, f"{_EX}.folders"),
        ({"folders": [5]}, f"{_EX}.folders"),
        ({"file_types": ["glb"]}, f"{_EX}.file_types"),
        ({"file_types": [".g lb"]}, f"{_EX}.file_types"),
        ({"file_types": ["*.glb"]}, f"{_EX}.file_types"),
        ({"file_types": [".a/b"]}, f"{_EX}.file_types"),
        # M1, 0128: a source ending is never an asset ending, whatever its case.
        ({"file_types": [".glb", ".py"]}, f"{_EX}.file_types"),
        ({"file_types": [".TS"]}, f"{_EX}.file_types"),
        ({"file_types": [".env"]}, f"{_EX}.file_types"),
        ({"file_types": [".sh"]}, f"{_EX}.file_types"),
        ({"file_types": [".json"]}, f"{_EX}.file_types"),
        ({"report_over_bytes": 0}, f"{_EX}.report_over_bytes"),
        ({"report_over_bytes": -1}, f"{_EX}.report_over_bytes"),
        ({"report_over_bytes": True}, f"{_EX}.report_over_bytes"),
        ({"report_over_bytes": "1MB"}, f"{_EX}.report_over_bytes"),
        ({"report_over_bytes": 1.5}, f"{_EX}.report_over_bytes"),
    ],
)
def test_manifest_refuses_bad_code_review_exemptions(
    tmp_path: Path, block: object, key: str
) -> None:
    _write(tmp_path, {_EX: block})
    with pytest.raises(ManifestError, match=f"{key} ") as caught:
        load(tmp_path)
    assert ends_with_next(str(caught.value))


@pytest.mark.parametrize(
    "url",
    [
        "http://localhost:5173",
        "https://localhost:5173/play",
        "http://127.0.0.1:8080/",
        "http://localhost",
        "http://LOCALHOST:3000",
    ],
)
def test_manifest_reads_a_local_testing_site(tmp_path: Path, url: str) -> None:
    # 0164: the operator hosts the site on this machine.
    check = "the scene loads and the player can move"
    _write(tmp_path, {"local_testing": {"url": url, "instructions": check}})
    loaded = load(tmp_path)
    assert loaded is not None and loaded.dev_server == DevServer(url, check)
    _write(tmp_path, {"local_testing": None})
    loaded = load(tmp_path)
    assert loaded is not None and loaded.dev_server is None


_LT = "local_testing"


@pytest.mark.parametrize(
    ("block", "key"),
    [
        ("http://localhost:5173", _LT),
        ({"url": "http://localhost:5173"}, _LT),
        ({"url": "http://localhost:5173", "instructions": "x", "port": 1}, _LT),
        ({"url": "http://example.com", "instructions": "x"}, f"{_LT}.url"),
        ({"url": "http://localhost.example.com", "instructions": "x"}, f"{_LT}.url"),
        ({"url": "http://127.0.0.1@example.com", "instructions": "x"}, f"{_LT}.url"),
        ({"url": "http://user:pw@localhost:5173", "instructions": "x"}, f"{_LT}.url"),
        ({"url": "http://10.0.0.5:5173", "instructions": "x"}, f"{_LT}.url"),
        ({"url": "ftp://localhost", "instructions": "x"}, f"{_LT}.url"),
        ({"url": "file:///tmp/index.html", "instructions": "x"}, f"{_LT}.url"),
        ({"url": "http://localhost:99999", "instructions": "x"}, f"{_LT}.url"),
        ({"url": "http://localhost:0", "instructions": "x"}, f"{_LT}.url"),
        ({"url": "http://127.0.0.1:0/", "instructions": "x"}, f"{_LT}.url"),
        ({"url": "http://localhost:5173/a b", "instructions": "x"}, f"{_LT}.url"),
        ({"url": 5173, "instructions": "x"}, f"{_LT}.url"),
        ({"url": "http://localhost:5173", "instructions": ""}, f"{_LT}.instructions"),
        ({"url": "http://localhost:5173", "instructions": "a\nb"}, f"{_LT}.instructions"),
        ({"url": "http://localhost:5173", "instructions": 1}, f"{_LT}.instructions"),
        ({"url": "http://localhost:5173", "instructions": "run `pnpm dev`"}, f"{_LT}.instructions"),
    ],
)
def test_manifest_refuses_a_bad_local_testing_site(tmp_path: Path, block: object, key: str) -> None:
    # 0164: a url off this machine is refused; the plugin never reaches beyond localhost.
    _write(tmp_path, {_LT: block})
    with pytest.raises(ManifestError, match=f"{key} ") as caught:
        load(tmp_path)
    assert ends_with_next(str(caught.value))


def test_missing_manifest_is_none(tmp_path: Path) -> None:
    assert load(tmp_path) is None


def test_malformed_json_raises(tmp_path: Path) -> None:
    _write(tmp_path, "{ not json")
    with pytest.raises(ManifestError, match="could not be read as JSON") as caught:
        load(tmp_path)
    assert ends_with_next(str(caught.value))


@pytest.mark.parametrize(
    "payload",
    [
        [],
        "3",
        {"prohibited_writes": []},
        {"prohibited_writes": {"path": []}},
        {"prohibited_writes": {"paths": "infra/"}},
        {"prohibited_writes": {"paths": [1]}},
        {"prohibited_writes": {"file_types": ".pem"}},
        {"prohibited_writes": {"paths": ["/etc/x"]}},
        {"prohibited_writes": {"paths": ["a/../b"]}},
        {"prohibited_writes": {"paths": [".."]}},
        {"prohibited_writes": {"paths": ["a\\b"]}},
        {"prohibited_writes": {"paths": ["*.tf"]}},
        {"prohibited_writes": {"paths": ["infra/[ab]"]}},
        {"prohibited_writes": {"paths": ["a//b"]}},
        {"prohibited_writes": {"paths": ["./a"]}},
        {"prohibited_writes": {"paths": [""]}},
        {"prohibited_writes": {"file_types": ["pem"]}},
        {"prohibited_writes": {"file_types": ["."]}},
        {"prohibited_writes": {"file_types": [".a/b"]}},
        {"prohibited_writes": {"file_types": [".p*"]}},
    ],
)
def test_wrong_shape_raises_with_next(tmp_path: Path, payload: Any) -> None:
    _write(tmp_path, payload)
    with pytest.raises(ManifestError) as caught:
        load(tmp_path)
    assert ends_with_next(str(caught.value)), str(caught.value)


@pytest.mark.parametrize(
    ("rel", "hit"),
    [
        ("infra/main.tf", True),
        ("infra/deep/x.tf", True),
        ("infra", True),
        ("INFRA/main.tf", True),
        ("infra2/main.tf", False),
        ("src/infra/x", False),
        ("Makefile", True),
        ("Makefile/x", False),
        ("docs", True),
        ("docs/decisions.md", True),
        ("docs/other.md", False),
    ],
)
def test_folder_prefix_and_exact_match(rel: str, hit: bool) -> None:
    # 0054: a trailing slash is a folder prefix; an ancestor of an entry is a hit too.
    manifest = Manifest(("infra/", "Makefile", "docs/decisions.md"))
    assert path_hit(manifest, rel) is hit


@pytest.mark.parametrize(
    ("rel", "hit"),
    [("server.pem", True), ("keys/a.PEM", True), ("pem.py", False), ("a.tar.gz", True)],
)
def test_extension_match(rel: str, hit: bool) -> None:
    assert extension_hit(Manifest((), (".pem", ".tar.gz")), rel) is hit


def test_the_package_age_defaults_to_seven_days(tmp_path: Path) -> None:
    # 0197: absent group or key reads the default, and no reason is needed at or above it.
    _write(tmp_path, {})
    loaded = load(tmp_path)
    assert loaded is not None and loaded.dependencies == Dependencies((), RELEASE_AGE_DEFAULT, None)
    assert RELEASE_AGE_DEFAULT == 7
    _write(tmp_path, {"packages": {"minimum_age_days": 30}})
    loaded = load(tmp_path)
    assert loaded is not None and loaded.dependencies.minimum_release_age_days == 30


@pytest.mark.parametrize(
    ("block", "ok"),
    [
        ({"minimum_age_days": 7}, True),
        ({"minimum_age_days": 0, "minimum_age_reason": "a" * 20}, True),
        ({"minimum_age_days": 6}, False),
        ({"minimum_age_days": 6, "minimum_age_reason": "a" * 19}, False),
        ({"minimum_age_days": 6, "minimum_age_reason": " " * 25}, False),
        ({"minimum_age_days": -1, "minimum_age_reason": "a" * 20}, False),
        ({"minimum_age_days": True}, False),
        ({"minimum_age_days": "7"}, False),
        ({"minimum_age_days": 8, "minimum_age_reason": 5}, False),
        ({"minimum_age_days": 8, "minimum_age_reason": "two\nlines"}, False),
    ],
)
def test_a_package_age_below_the_default_needs_a_reason(
    tmp_path: Path, block: dict[str, object], ok: bool
) -> None:
    # 0197: the floor is 0; below 7 needs a reason of 20 characters; the refusal names 0197.
    _write(tmp_path, {"packages": block})
    if ok:
        assert load(tmp_path) is not None
        return
    with pytest.raises(ManifestError, match="packages.minimum_age") as caught:
        load(tmp_path)
    if block.get("minimum_age_days") == 6:
        assert "(0197)" in str(caught.value)


@pytest.mark.parametrize(
    ("docs", "ok"),
    [
        ({"folder": "docs", "decisions_filename": "decisions.md"}, True),
        ({"folder": None}, True),
        ({"folder": "/abs"}, False),
        ({"folder": "../out"}, False),
        ({"decisions_filename": "sub/decisions.md"}, False),
        ({"decisions_filename": ".."}, False),
        ({"decisions_filename": ""}, False),
        ({"decisions_filename": 5}, False),
        ({"git_branch": "main"}, True),
        ({"git_branch": "two words"}, False),
    ],
)
def test_the_docs_group_is_checked(tmp_path: Path, docs: dict[str, object], ok: bool) -> None:
    # 0245, 0247: a project-relative docs folder and a plain decisions file name.
    _write(tmp_path, {"docs": docs})
    if ok:
        loaded = load(tmp_path)
        assert loaded is not None and loaded.docs.folder == "docs"
        assert loaded.features.ledger is (docs.get("decisions_filename") is not None)
        return
    with pytest.raises(ManifestError, match="docs.") as caught:
        load(tmp_path)
    assert ends_with_next(str(caught.value))
