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
    TOP_KEYS,
    Operator,
    OperatorError,
    load,
    load_user,
    operator_path,
)
from lib.project_keys import starter_operator

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
            "hard_stops": ["commit_on_main", "credential_read"],
            "reading_level": "plain",
            "no_long_dashes": True,
            "guidance_source": "daedalus",
            "script_language": "python",
        },
    )
    want = Operator(("commit_on_main", "credential_read"), "plain", True, "daedalus", "python")
    assert load_user() == want


def test_the_starter_file_reads_as_the_defaults(home: Path) -> None:
    # 0245: null is the same as absent for every choice.
    _write(home, json.dumps(starter_operator()))
    assert load_user() == Operator()


def test_reading_level_path_value_accepted(home: Path) -> None:
    _write(home, {"reading_level": "profile:docs/voice.md"})
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
    _write(home, '{"hard_stops": [], "pad": "' + "x" * 70000 + '"}')
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
        ({"hard_stops": ["rm_everything"]}, "rm_everything"),
        ({"hard_stops": ["commit_on_main", "commit_on_main"]}, "twice"),
        ({"hard_stops": "commit_on_main"}, "hard_stops"),
        ({"hard_stops": True}, "hard_stops"),
        ({"hard_stops": [True]}, "hard_stops"),
        ({"reading_level": True}, "reading_level"),
        ({"reading_level": "loud"}, "reading_level"),
        ({"reading_level": "profile:../x"}, "reading_level"),
        ({"no_long_dashes": "yes"}, "no_long_dashes"),
        ({"no_long_dashes": 1}, "no_long_dashes"),
        ({"guidance_source": "mine"}, "guidance_source"),
        ({"script_language": "Python 3"}, "script_language"),
        ({"self_assessment": "yes"}, "self_assessment"),
        ({"self_assessment": 1}, "self_assessment"),
        ({"self_assessment": None}, "self_assessment"),
        ({"developer_profile": "yes"}, "developer_profile"),
        ({"developer_profile": None}, "developer_profile"),
    ],
)
def test_each_refusal_names_the_file_and_key(home: Path, body: object, key: str) -> None:
    path = _write(home, body)
    with pytest.raises(OperatorError) as err:
        load_user()
    assert str(path) in str(err.value) and key in str(err.value)


@pytest.mark.parametrize(
    "body",
    [
        {"main_refusals": []},
        {"profile": {"literacy": "plain"}},
        {"profile": {"dash_ban": True}},
        {"operator_profile": {}},
    ],
)
def test_an_old_key_is_refused_with_the_valid_names(home: Path, body: object) -> None:
    # 0245: no alias; the refusal lists every valid top-level name.
    _write(home, body)
    with pytest.raises(OperatorError) as err:
        load_user()
    assert f"has unknown keys [{next(iter(body))!r}]" in str(err.value)
    assert "(known: " + ", ".join(TOP_KEYS) + ")" in str(err.value)


def test_every_class_is_accepted(home: Path) -> None:
    _write(home, {"hard_stops": list(MAIN_REFUSAL_CLASSES)})
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
            json.dumps({"personal_overrides": override})
        )
    return repo


def test_load_inherits_when_repo_sets_nothing(home: Path, tmp_path: Path) -> None:
    _write(home, {"hard_stops": ["commit_on_main"], "reading_level": "plain"})
    assert load(_repo(tmp_path, None)) == Operator(("commit_on_main",), "plain", None)


def test_load_replaces_per_key_and_lists_replace(home: Path, tmp_path: Path) -> None:
    _write(home, {"hard_stops": ["commit_on_main", "credential_read"], "no_long_dashes": True})
    repo = _repo(tmp_path, {"hard_stops": ["redirect_to_file"], "reading_level": "expert"})
    assert load(repo) == Operator(("redirect_to_file",), "expert", True)


def test_self_assessment_defaults_false_and_a_project_override_replaces_it(
    home: Path, tmp_path: Path
) -> None:
    # A1: the personal value is replaced for one project through personal_overrides.
    assert Operator().self_assessment is False
    _write(home, {"self_assessment": True})
    assert load(_repo(tmp_path / "a", None)).self_assessment is True
    assert load(_repo(tmp_path / "b", {"self_assessment": False})).self_assessment is False


def test_developer_profile_defaults_false_and_a_project_override_replaces_it(
    home: Path, tmp_path: Path
) -> None:
    # 0252: same shape as self_assessment.
    assert Operator().developer_profile is False
    _write(home, {"developer_profile": True})
    assert load(_repo(tmp_path / "a", None)).developer_profile is True
    assert load(_repo(tmp_path / "b", {"developer_profile": False})).developer_profile is False


def test_load_override_error_names_config_json_and_key(home: Path, tmp_path: Path) -> None:
    repo = _repo(tmp_path, {"no_long_dashes": "yes"})
    with pytest.raises(ConfigError, match=r"config\.json personal_overrides\.no_long_dashes"):
        load(repo)


@pytest.mark.parametrize(
    ("override", "key"),
    [
        ("text", "personal_overrides"),
        ({"x": 1}, "personal_overrides"),
        ({"hard_stops": ["bogus"]}, "personal_overrides.hard_stops"),
        ({"reading_level": 5}, "personal_overrides.reading_level"),
        ({"profile": {"literacy": "plain"}}, "personal_overrides"),
    ],
)
def test_bad_config_operator_block_raises_config_error(
    tmp_path: Path, override: object, key: str
) -> None:
    repo = _repo(tmp_path, override)
    with pytest.raises(ConfigError, match=re.escape(key)):
        load_config(path=repo / ".claude" / "daedalus" / "config.json")


def test_config_carries_the_validated_override(tmp_path: Path) -> None:
    repo = _repo(tmp_path, {"hard_stops": ["commit_on_main"], "no_long_dashes": False})
    cfg = load_config(path=repo / ".claude" / "daedalus" / "config.json")
    assert cfg.operator == {"main_refusals": ("commit_on_main",), "dash_ban": False}


def test_only_the_named_modules_mention_operator_file() -> None:
    # 0235: nothing reads the operator file yet beyond config, doctor, key rows and itself.
    allowed = {"config.py", "daedalus_doctor.py", "project_keys.py", "operator_file.py"}
    # 0242: setup creates the file and checks a changed one with its validator; it acts on no value.
    allowed.add("daedalus_setup.py")
    # A1: the flag reader loads the file through load().
    allowed.add("self_assessment.py")
    allowed.add("developer_profile.py")
    # 0270: the class lookup takes an Operator, typed only; no caller acts on it yet.
    allowed.add("work_classes.py")
    # 0280: the plan validator loads the work classes; the plan record takes them, typed only.
    allowed.update({"validate_plan.py", "plan_record.py"})
    found = {
        path.name
        for path in (REPO_ROOT / "scripts").rglob("*.py")
        if "operator_file" in path.read_text(encoding="utf-8")
    }
    assert found == allowed - {"operator_file.py"}
    assert operator_file.OPERATOR_FILE.name == "operator.json"
