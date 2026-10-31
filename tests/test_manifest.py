# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from lib.manifest import (
    Assets,
    DevServer,
    Features,
    Manifest,
    ManifestError,
    declared_commands,
    extension_hit,
    load,
    path_hit,
)

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
    # 0073, B2: this repo's stack commands are read and the secret scan is on.
    assert load(REPO_ROOT) == Manifest(
        unit_test_cmd=(".venv/bin/pytest -q",),
        typecheck_cmd=("python3 -m mypy scripts",),
        lint_cmd=(".venv/bin/ruff check scripts tests",),
        features=Features(secrets_scan=True),
    )


def test_manifest_reads_typecheck_and_lint_cmd(tmp_path: Path) -> None:
    # B2: the two keys sit beside unit_test_cmd; null is not declared.
    stack = {"unit_test_cmd": "pytest -q", "typecheck_cmd": "mypy src", "lint_cmd": "ruff check ."}
    _write(tmp_path, {"stack": stack})
    loaded = load(tmp_path)
    assert loaded == Manifest(
        unit_test_cmd=("pytest -q",), typecheck_cmd=("mypy src",), lint_cmd=("ruff check .",)
    )
    assert declared_commands(loaded) == ("pytest -q", "mypy src", "ruff check .")
    _write(tmp_path, {"stack": {"typecheck_cmd": None, "lint_cmd": None}})
    loaded = load(tmp_path)
    assert loaded == Manifest() and declared_commands(loaded) == ()
    assert declared_commands(Manifest()) == ()


def test_a_stack_command_list_is_read_in_order_and_declared_flat(tmp_path: Path) -> None:
    # 0192: a Python plus TypeScript stack lists one command per toolchain.
    stack = {
        "unit_test_cmd": ["pytest -q", "pnpm vitest run"],
        "typecheck_cmd": ["mypy src", "pnpm tsc --noEmit"],
        "lint_cmd": "ruff check .",
        "package_manager": "pnpm",
    }
    _write(tmp_path, {"stack": stack})
    loaded = load(tmp_path)
    assert loaded is not None
    assert loaded.unit_test_cmd == ("pytest -q", "pnpm vitest run")
    assert loaded.typecheck_cmd == ("mypy src", "pnpm tsc --noEmit")
    assert loaded.package_manager == "pnpm"
    assert declared_commands(loaded) == (
        "pytest -q",
        "pnpm vitest run",
        "mypy src",
        "pnpm tsc --noEmit",
        "ruff check .",
    )


@pytest.mark.parametrize("key", ["unit_test_cmd", "typecheck_cmd", "lint_cmd"])
@pytest.mark.parametrize(
    "value", ["", "  ", 5, [], ["mypy", 5], ["mypy", ""], ["  "], [None], {"a": "b"}, True]
)
def test_manifest_refuses_a_bad_stack_command(tmp_path: Path, key: str, value: object) -> None:
    # 0192: an empty list, or a list holding anything but non-empty strings, is refused.
    _write(tmp_path, {"stack": {key: value}})
    with pytest.raises(ManifestError, match=f"stack.{key}") as caught:
        load(tmp_path)
    assert _ends_with_next(str(caught.value))


@pytest.mark.parametrize("name", ["pnpm", "npm", "yarn", "pip", "uv", None])
def test_manifest_reads_a_known_package_manager(tmp_path: Path, name: str | None) -> None:
    _write(tmp_path, {"stack": {"package_manager": name}})
    loaded = load(tmp_path)
    assert loaded is not None and loaded.package_manager == name


@pytest.mark.parametrize("name", ["bun", "PNPM", "", 5, ["pnpm"], True])
def test_manifest_refuses_an_unknown_package_manager(tmp_path: Path, name: object) -> None:
    # 0192: one of the five names or null; the refusal names the key and ends with Next.
    _write(tmp_path, {"stack": {"package_manager": name}})
    with pytest.raises(ManifestError, match="stack.package_manager") as caught:
        load(tmp_path)
    assert _ends_with_next(str(caught.value))


def test_manifest_reads_the_assets_block(tmp_path: Path) -> None:
    # 0192: every part optional; absent is the empty block.
    block = {
        "roots": ["assets/", "public/models/"],
        "extensions": [".glb", ".ktx2", ".wgsl"],
        "max_bytes": 1048576,
    }
    _write(tmp_path, {"assets": block})
    loaded = load(tmp_path)
    assert loaded is not None
    assert loaded.assets == Assets(
        ("assets/", "public/models/"), (".glb", ".ktx2", ".wgsl"), 1048576
    )
    _write(tmp_path, {"assets": {"extensions": [".png"]}})
    loaded = load(tmp_path)
    assert loaded is not None and loaded.assets == Assets(extensions=(".png",))
    _write(tmp_path, {})
    loaded = load(tmp_path)
    assert loaded is not None and loaded.assets == Assets()


@pytest.mark.parametrize(
    ("block", "key"),
    [
        ([], "assets"),
        ({"excluded_roots": []}, "assets"),
        ({"roots": "assets/"}, "assets.roots"),
        ({"roots": ["/abs/"]}, "assets.roots"),
        ({"roots": ["../out/"]}, "assets.roots"),
        ({"roots": ["models/*"]}, "assets.roots"),
        ({"roots": ["my models/"]}, "assets.roots"),
        ({"roots": ["it's/"]}, "assets.roots"),
        ({"roots": [5]}, "assets.roots"),
        ({"extensions": ["glb"]}, "assets.extensions"),
        ({"extensions": [".g lb"]}, "assets.extensions"),
        ({"extensions": ["*.glb"]}, "assets.extensions"),
        ({"extensions": [".a/b"]}, "assets.extensions"),
        ({"max_bytes": 0}, "assets.max_bytes"),
        ({"max_bytes": -1}, "assets.max_bytes"),
        ({"max_bytes": True}, "assets.max_bytes"),
        ({"max_bytes": "1MB"}, "assets.max_bytes"),
        ({"max_bytes": 1.5}, "assets.max_bytes"),
    ],
)
def test_manifest_refuses_a_bad_assets_block(tmp_path: Path, block: object, key: str) -> None:
    _write(tmp_path, {"assets": block})
    with pytest.raises(ManifestError, match=f"{key} ") as caught:
        load(tmp_path)
    assert _ends_with_next(str(caught.value))


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
def test_manifest_reads_a_local_dev_server(tmp_path: Path, url: str) -> None:
    # 0164: the operator hosts the site on this machine.
    check = "the scene loads and the player can move"
    _write(tmp_path, {"dev_server": {"url": url, "check": check}})
    loaded = load(tmp_path)
    assert loaded is not None and loaded.dev_server == DevServer(url, check)
    _write(tmp_path, {"dev_server": None})
    loaded = load(tmp_path)
    assert loaded is not None and loaded.dev_server is None


@pytest.mark.parametrize(
    ("block", "key"),
    [
        ("http://localhost:5173", "dev_server"),
        ({"url": "http://localhost:5173"}, "dev_server"),
        ({"url": "http://localhost:5173", "check": "x", "port": 1}, "dev_server"),
        ({"url": "http://example.com", "check": "x"}, "dev_server.url"),
        ({"url": "http://localhost.example.com", "check": "x"}, "dev_server.url"),
        ({"url": "http://127.0.0.1@example.com", "check": "x"}, "dev_server.url"),
        ({"url": "http://user:pw@localhost:5173", "check": "x"}, "dev_server.url"),
        ({"url": "http://10.0.0.5:5173", "check": "x"}, "dev_server.url"),
        ({"url": "ftp://localhost", "check": "x"}, "dev_server.url"),
        ({"url": "file:///tmp/index.html", "check": "x"}, "dev_server.url"),
        ({"url": "http://localhost:99999", "check": "x"}, "dev_server.url"),
        ({"url": "http://localhost:5173/a b", "check": "x"}, "dev_server.url"),
        ({"url": 5173, "check": "x"}, "dev_server.url"),
        ({"url": "http://localhost:5173", "check": ""}, "dev_server.check"),
        ({"url": "http://localhost:5173", "check": "a\nb"}, "dev_server.check"),
        ({"url": "http://localhost:5173", "check": 1}, "dev_server.check"),
    ],
)
def test_manifest_refuses_a_bad_dev_server(tmp_path: Path, block: object, key: str) -> None:
    # 0164: a url off this machine is refused; the plugin never reaches beyond localhost.
    _write(tmp_path, {"dev_server": block})
    with pytest.raises(ManifestError, match=f"{key} ") as caught:
        load(tmp_path)
    assert _ends_with_next(str(caught.value))


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
