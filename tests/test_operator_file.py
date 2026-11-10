# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import json
import os
import re
from pathlib import Path

import pytest
from lib import operator_file
from lib.config import ConfigError, load_config
from lib.operator_file import (
    MAIN_REFUSAL_CLASSES,
    Operator,
    OperatorError,
    load,
    load_user,
    operator_path,
)

from tests.conftest import REPO_ROOT


@pytest.fixture
def home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    # 0235: every test reads a temp HOME, never the real operator file.
    folder = tmp_path / "home"
    (folder / ".claude" / "daedalus").mkdir(parents=True)
    monkeypatch.setenv("HOME", str(folder))
    return folder


def _write(home: Path, body: object) -> Path:
    path = home / ".claude" / "daedalus" / "operator.json"
    path.write_text(body if isinstance(body, str) else json.dumps(body), encoding="utf-8")
    return path


def test_path_resolves_under_home_at_call_time(home: Path) -> None:
    assert operator_path() == home / ".claude" / "daedalus" / "operator.json"


def test_absent_file_gives_defaults(home: Path) -> None:
    assert load_user() == Operator()


def test_valid_full_file(home: Path) -> None:
    _write(
        home,
        {
            "main_refusals": ["commit_on_main", "credential_read"],
            "profile": {"literacy": "plain", "dash_ban": True},
        },
    )
    assert load_user() == Operator(("commit_on_main", "credential_read"), "plain", True)


def test_profile_literacy_path_value_accepted(home: Path) -> None:
    _write(home, {"profile": {"literacy": "profile:docs/voice.md"}})
    assert load_user().literacy == "profile:docs/voice.md"


def test_symlink_refused(home: Path, tmp_path: Path) -> None:
    target = tmp_path / "real.json"
    target.write_text("{}")
    (home / ".claude" / "daedalus" / "operator.json").symlink_to(target)
    with pytest.raises(OperatorError, match="symlink"):
        load_user()


def test_dangling_symlink_refused(home: Path, tmp_path: Path) -> None:
    (home / ".claude" / "daedalus" / "operator.json").symlink_to(tmp_path / "gone.json")
    with pytest.raises(OperatorError, match="symlink"):
        load_user()


def test_fifo_refused_without_blocking(home: Path) -> None:
    # 0235: O_NONBLOCK lets the open return, so fstat refuses the FIFO instead of hanging.
    os.mkfifo(home / ".claude" / "daedalus" / "operator.json")
    with pytest.raises(OperatorError, match="regular file"):
        load_user()


def test_folder_refused(home: Path) -> None:
    (home / ".claude" / "daedalus" / "operator.json").mkdir()
    with pytest.raises(OperatorError, match="regular file"):
        load_user()


def test_oversize_refused(home: Path) -> None:
    _write(home, '{"main_refusals": [], "pad": "' + "x" * 70000 + '"}')
    with pytest.raises(OperatorError, match="larger than 64 KiB"):
        load_user()


def test_bad_utf8_refused(home: Path) -> None:
    (home / ".claude" / "daedalus" / "operator.json").write_bytes(b'{"a": "\xff"}')
    with pytest.raises(OperatorError, match="UTF-8"):
        load_user()


def test_invalid_json_refused(home: Path) -> None:
    _write(home, "{nope")
    with pytest.raises(OperatorError, match="operator.json"):
        load_user()


@pytest.mark.parametrize("body", [[], "text", 3, None])
def test_not_an_object_refused(home: Path, body: object) -> None:
    _write(home, json.dumps(body))
    with pytest.raises(OperatorError, match="JSON object"):
        load_user()


@pytest.mark.parametrize(
    ("body", "key"),
    [
        ({"nope": 1}, "nope"),
        ({"profile": {"nope": 1}}, "nope"),
        ({"main_refusals": ["rm_everything"]}, "rm_everything"),
        ({"main_refusals": ["commit_on_main", "commit_on_main"]}, "twice"),
        ({"main_refusals": "commit_on_main"}, "main_refusals"),
        ({"main_refusals": True}, "main_refusals"),
        ({"main_refusals": [True]}, "main_refusals"),
        ({"profile": True}, "profile"),
        ({"profile": {"literacy": True}}, "profile.literacy"),
        ({"profile": {"literacy": None}}, "profile.literacy"),
        ({"profile": {"literacy": "loud"}}, "profile.literacy"),
        ({"profile": {"literacy": "profile:../x"}}, "profile.literacy"),
        ({"profile": {"dash_ban": "yes"}}, "profile.dash_ban"),
        ({"profile": {"dash_ban": 1}}, "profile.dash_ban"),
    ],
)
def test_each_refusal_names_the_file_and_key(home: Path, body: object, key: str) -> None:
    path = _write(home, body)
    with pytest.raises(OperatorError) as err:
        load_user()
    assert str(path) in str(err.value) and key in str(err.value)


def test_every_class_is_accepted(home: Path) -> None:
    _write(home, {"main_refusals": list(MAIN_REFUSAL_CLASSES)})
    assert load_user().main_refusals == MAIN_REFUSAL_CLASSES


def test_literacy_value_set_is_the_manifest_one() -> None:
    # 0235: no second copy of the value set; the validator imports the manifest's.
    source = (REPO_ROOT / "scripts" / "lib" / "operator_file.py").read_text(encoding="utf-8")
    assert "from lib.manifest import" in source and '"plain"' not in source


def _repo(tmp_path: Path, override: object | None) -> Path:
    repo = tmp_path / "repo"
    (repo / ".claude" / "daedalus").mkdir(parents=True)
    (repo / ".git").mkdir()
    if override is not None:
        (repo / ".claude" / "daedalus" / "config.json").write_text(
            json.dumps({"operator": override})
        )
    return repo


def test_load_inherits_when_repo_sets_nothing(home: Path, tmp_path: Path) -> None:
    _write(home, {"main_refusals": ["commit_on_main"], "profile": {"literacy": "plain"}})
    assert load(_repo(tmp_path, None)) == Operator(("commit_on_main",), "plain", None)


def test_load_replaces_per_key_and_lists_replace(home: Path, tmp_path: Path) -> None:
    _write(
        home,
        {"main_refusals": ["commit_on_main", "credential_read"], "profile": {"dash_ban": True}},
    )
    repo = _repo(
        tmp_path, {"main_refusals": ["redirect_to_file"], "profile": {"literacy": "expert"}}
    )
    assert load(repo) == Operator(("redirect_to_file",), "expert", True)


def test_load_override_error_names_config_json_and_key(home: Path, tmp_path: Path) -> None:
    repo = _repo(tmp_path, {"profile": {"dash_ban": "yes"}})
    with pytest.raises(ConfigError, match=r"config\.json operator\.profile\.dash_ban"):
        load(repo)


@pytest.mark.parametrize(
    ("override", "key"),
    [
        ("text", "operator"),
        ({"x": 1}, "operator"),
        ({"main_refusals": ["bogus"]}, "operator.main_refusals"),
        ({"profile": {"literacy": 5}}, "operator.profile.literacy"),
    ],
)
def test_bad_config_operator_block_raises_config_error(
    tmp_path: Path, override: object, key: str
) -> None:
    repo = _repo(tmp_path, override)
    with pytest.raises(ConfigError, match=re.escape(key)):
        load_config(path=repo / ".claude" / "daedalus" / "config.json")


def test_config_carries_the_validated_override(tmp_path: Path) -> None:
    repo = _repo(tmp_path, {"main_refusals": ["commit_on_main"], "profile": {"dash_ban": False}})
    cfg = load_config(path=repo / ".claude" / "daedalus" / "config.json")
    assert cfg.operator == {"main_refusals": ("commit_on_main",), "dash_ban": False}


def test_only_the_named_modules_mention_operator_file() -> None:
    # 0235: nothing reads the operator file yet beyond config, doctor, key rows and itself.
    allowed = {"config.py", "daedalus_doctor.py", "project_keys.py", "operator_file.py"}
    # 0242: setup creates the file and checks a changed one with its validator; it acts on no value.
    allowed.add("daedalus_setup.py")
    found = {
        path.name
        for path in (REPO_ROOT / "scripts").rglob("*.py")
        if "operator_file" in path.read_text(encoding="utf-8")
    }
    assert found == allowed - {"operator_file.py"}
    assert operator_file.OPERATOR_FILE.name == "operator.json"
