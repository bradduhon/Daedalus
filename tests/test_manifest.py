# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from lib.manifest import Manifest, ManifestError, extension_hit, load, path_hit

from tests.conftest import REPO_ROOT


def _write(repo: Path, payload: Any) -> None:
    text = payload if isinstance(payload, str) else json.dumps(payload)
    (repo / "service-manifest.json").write_text(text, encoding="utf-8")


def _ends_with_next(message: str) -> bool:
    head, sep, tail = message.rpartition(". Next: ")
    return bool(head and sep and tail.endswith(".")) and message.count("Next:") == 1


def test_valid_manifest_loads(tmp_path: Path) -> None:
    narrowing = {"forbidden_paths": ["infra/", "Makefile"], "forbidden_extensions": [".pem"]}
    _write(tmp_path, {"manifest_version": 1, "jail_narrowing": narrowing})
    assert load(tmp_path) == Manifest(("infra/", "Makefile"), (".pem",))


def test_absent_jail_narrowing_is_empty(tmp_path: Path) -> None:
    _write(tmp_path, {"manifest_version": 1})
    assert load(tmp_path) == Manifest()


def test_this_repos_manifest_loads() -> None:
    # 0073: this repo's stack.unit_test_cmd is read now; every feature stays at its default.
    assert load(REPO_ROOT) == Manifest(unit_test_cmd=".venv/bin/pytest -q")


def test_missing_manifest_is_none(tmp_path: Path) -> None:
    assert load(tmp_path) is None


def test_malformed_json_raises(tmp_path: Path) -> None:
    _write(tmp_path, "{ not json")
    with pytest.raises(ManifestError, match="could not be read as JSON") as caught:
        load(tmp_path)
    assert _ends_with_next(str(caught.value))


@pytest.mark.parametrize(
    "payload",
    [
        [],
        "3",
        {"jail_narrowing": []},
        {"jail_narrowing": {"forbidden_path": []}},
        {"jail_narrowing": {"forbidden_paths": "infra/"}},
        {"jail_narrowing": {"forbidden_paths": [1]}},
        {"jail_narrowing": {"forbidden_extensions": ".pem"}},
        {"jail_narrowing": {"forbidden_paths": ["/etc/x"]}},
        {"jail_narrowing": {"forbidden_paths": ["a/../b"]}},
        {"jail_narrowing": {"forbidden_paths": [".."]}},
        {"jail_narrowing": {"forbidden_paths": ["a\\b"]}},
        {"jail_narrowing": {"forbidden_paths": ["*.tf"]}},
        {"jail_narrowing": {"forbidden_paths": ["infra/[ab]"]}},
        {"jail_narrowing": {"forbidden_paths": ["a//b"]}},
        {"jail_narrowing": {"forbidden_paths": ["./a"]}},
        {"jail_narrowing": {"forbidden_paths": [""]}},
        {"jail_narrowing": {"forbidden_extensions": ["pem"]}},
        {"jail_narrowing": {"forbidden_extensions": ["."]}},
        {"jail_narrowing": {"forbidden_extensions": [".a/b"]}},
        {"jail_narrowing": {"forbidden_extensions": [".p*"]}},
    ],
)
def test_wrong_shape_raises_with_next(tmp_path: Path, payload: Any) -> None:
    _write(tmp_path, payload)
    with pytest.raises(ManifestError) as caught:
        load(tmp_path)
    assert _ends_with_next(str(caught.value)), str(caught.value)


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
