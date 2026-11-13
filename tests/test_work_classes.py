# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0267, 0270, 0280: the two class settings, their defaults, their checks and the one lookup.
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from lib import agent_models, work_classes
from lib.config import ConfigError, load_config
from lib.operator_file import Operator, OperatorError, load, load_user, validate
from lib.project_keys import KEY_ROWS, OPERATOR_FILE_NAME, starter_operator
from lib.work_classes import (
    DEFAULT_CLASSES,
    DEFAULT_MODELS,
    MECHANICAL,
    MIDDLE_MODEL,
    PLUMBING,
    SMALLEST_MODEL,
    TOP_MODEL,
    model_for,
)

from tests.conftest import SCRIPTS_DIR

SETUP = SCRIPTS_DIR / "daedalus_setup.py"
# 0245, 0260: the operator file as written before this unit, with neither class key.
BEFORE = {
    "schema": 1,
    "hard_stops": [],
    "reading_level": None,
    "no_long_dashes": None,
    "guidance_source": "claude",
    "script_language": None,
    "self_assessment": False,
    "developer_profile": False,
}


@pytest.fixture
def home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    folder = tmp_path / "home"
    (folder / ".claude" / "daedalus").mkdir(parents=True)
    monkeypatch.setenv("HOME", str(folder))
    return folder


def _write(home: Path, body: object) -> None:
    path = home / ".claude" / "daedalus" / "operator.json"
    path.write_text(json.dumps(body), encoding="utf-8")


def _repo(tmp_path: Path, override: object) -> Path:
    # A plain clone: .git is a folder.
    repo = tmp_path / "repo"
    (repo / ".claude" / "daedalus").mkdir(parents=True)
    (repo / ".git").mkdir()
    (repo / ".claude" / "daedalus" / "config.json").write_text(
        json.dumps({"personal_overrides": override}), encoding="utf-8"
    )
    return repo


NEW_CLASSES = ("Injection sinks", "Isolation and confinement", "Supply chain", "Redaction")


def test_the_shipped_defaults_hold_twenty_classes_on_three_models() -> None:
    names = [name for name, _ in DEFAULT_CLASSES]
    # 0267, 0275: the operator's own class names, in spec section 4 order.
    assert names == [
        "AuthN",
        "AuthZ",
        "Identity",
        "Access grants and escalation",
        "Cryptography",
        "Encryption",
        "Secrets",
        "Tokens",
        "API keys",
        "Credentials",
        "Untrusted input",
        "Network exposure",
        "Audit trail",
        "Policy as code",
        "Injection sinks",
        "Isolation and confinement",
        "Supply chain",
        "Redaction",
        PLUMBING,
        MECHANICAL,
    ]
    assert (PLUMBING, MECHANICAL) == ("Plumbing", "Mechanical")
    models = dict(DEFAULT_MODELS)
    assert list(models) == names
    assert [n for n in names if models[n] == TOP_MODEL] == names[:18]
    assert all(models[n] == TOP_MODEL for n in NEW_CLASSES)
    assert models[PLUMBING] == MIDDLE_MODEL and models[MECHANICAL] == SMALLEST_MODEL
    assert (TOP_MODEL, MIDDLE_MODEL, SMALLEST_MODEL) == ("opus", "sonnet", "haiku")


def test_the_model_set_is_the_one_agents_accept() -> None:
    assert work_classes.MODELS is agent_models.MODELS


def test_lookup_with_no_classes_key_uses_the_shipped_defaults(home: Path) -> None:
    _write(home, BEFORE)
    operator = load_user()
    assert operator == Operator()
    assert model_for("AuthN", operator) == TOP_MODEL
    assert model_for(PLUMBING, operator) == MIDDLE_MODEL
    assert model_for(MECHANICAL, operator) == SMALLEST_MODEL
    assert model_for("Not a class", operator) == MIDDLE_MODEL


def test_lookup_with_an_empty_list_is_the_middle_model(home: Path) -> None:
    _write(home, {"work_classes": []})
    operator = load_user()
    assert operator.work_classes == ()
    for name, _ in DEFAULT_CLASSES:
        assert model_for(name, operator) == MIDDLE_MODEL


def test_lookup_of_a_class_with_no_mapping_is_the_middle_model(home: Path) -> None:
    rows = [{"name": "Legal review", "definition": "The work drafts a contract clause."}]
    _write(home, {"work_classes": rows, "class_models": {}})
    assert model_for("Legal review", load_user()) == MIDDLE_MODEL


def test_a_project_that_removes_a_class_the_personal_file_maps(home: Path, tmp_path: Path) -> None:
    _write(home, starter_operator())
    kept = [{"name": n, "definition": d} for n, d in DEFAULT_CLASSES if n != "Tokens"]
    operator = load(_repo(tmp_path, {"work_classes": kept}))
    assert dict(operator.class_models)["Tokens"] == TOP_MODEL
    assert model_for("Tokens", operator) == MIDDLE_MODEL
    assert model_for("AuthN", operator) == TOP_MODEL


def test_a_project_that_lowers_one_class_and_raises_another(home: Path, tmp_path: Path) -> None:
    _write(home, starter_operator())
    mapping = {**dict(DEFAULT_MODELS), "AuthN": "sonnet", PLUMBING: "opus"}
    operator = load(_repo(tmp_path, {"class_models": mapping}))
    assert model_for("AuthN", operator) == MIDDLE_MODEL
    assert model_for(PLUMBING, operator) == TOP_MODEL
    assert model_for("AuthZ", operator) == TOP_MODEL
    assert load_user().class_models == DEFAULT_MODELS


def test_a_project_that_adds_a_class_with_its_model(home: Path, tmp_path: Path) -> None:
    _write(home, BEFORE)
    rows = [*work_classes.classes_json(), {"name": "Privacy", "definition": "Personal data."}]
    mapping = {**dict(DEFAULT_MODELS), "Privacy": "fable"}
    operator = load(_repo(tmp_path, {"work_classes": rows, "class_models": mapping}))
    assert model_for("Privacy", operator) == "fable"


def test_a_pre_unit_file_passes_the_check_unchanged(home: Path) -> None:
    assert validate(dict(BEFORE), "operator.json") == {
        "main_refusals": (),
        "guidance_source": "claude",
        "self_assessment": False,
        "developer_profile": False,
    }
    _write(home, BEFORE)
    assert load_user() == Operator()


def test_null_reads_as_absent(home: Path) -> None:
    _write(home, {"work_classes": None, "class_models": None})
    assert load_user() == Operator()


def test_the_starter_file_reads_as_the_defaults(home: Path) -> None:
    _write(home, starter_operator())
    assert load_user() == Operator()


@pytest.mark.parametrize(
    ("body", "words"),
    [
        ({"class_models": {"Bogus": "opus"}}, "class_models maps ['Bogus']"),
        (
            {
                "work_classes": [{"name": "A", "definition": "a."}],
                "class_models": {"AuthN": "opus"},
            },
            "class_models maps ['AuthN']",
        ),
        ({"class_models": {"AuthN": "gpt"}}, "not one of sonnet, opus, haiku, fable"),
        ({"class_models": {"AuthN": None}}, "not one of"),
        ({"class_models": []}, "class_models must be an object"),
        ({"work_classes": {}}, "work_classes must be a list"),
        ({"work_classes": ["AuthN"]}, "entry 0 must be an object"),
        ({"work_classes": [{"name": "A"}]}, "entry 0 definition"),
        ({"work_classes": [{"name": "", "definition": "a."}]}, "entry 0 name"),
        ({"work_classes": [{"name": "_A", "definition": "a."}]}, "entry 0 name"),
        ({"work_classes": [{"name": " A", "definition": "a."}]}, "entry 0 name"),
        ({"work_classes": [{"name": "A", "definition": "a.\nb."}]}, "entry 0 definition"),
        ({"work_classes": [{"name": "A", "definition": "x" * 301}]}, "entry 0 definition"),
        ({"work_classes": [{"name": "A" * 41, "definition": "a."}]}, "entry 0 name"),
        (
            {"work_classes": [{"name": "A", "definition": "a.", "model": "opus"}]},
            "unknown keys ['model']",
        ),
        (
            {
                "work_classes": [
                    {"name": "Tokens", "definition": "a."},
                    {"name": "tokens", "definition": "b."},
                ]
            },
            "names the class 'tokens' twice",
        ),
        (
            {"work_classes": [{"name": f"C{i}", "definition": "a."} for i in range(65)]},
            "at most 64",
        ),
    ],
)
def test_the_check_refuses_with_a_next_line(body: dict[str, object], words: str) -> None:
    with pytest.raises(OperatorError) as err:
        validate(body, "operator.json")
    assert words in str(err.value) and "Next:" in str(err.value)


def test_user_keys_inside_the_class_settings_are_kept_out(home: Path) -> None:
    # 0260: a key starting with an underscore is the user's own at any level.
    rows = [{"name": "A", "definition": "a.", "_why": 1}]
    _write(home, {"work_classes": rows, "class_models": {"A": "haiku", "_note": "x"}})
    operator = load_user()
    assert operator.work_classes == (("A", "a."),)
    assert operator.class_models == (("A", "haiku"),)


def test_a_project_mapping_is_checked_against_the_list_it_inherits(
    home: Path, tmp_path: Path
) -> None:
    rows = [{"name": "Legal review", "definition": "The work drafts a contract clause."}]
    _write(home, {"work_classes": rows})
    repo = _repo(tmp_path / "a", {"class_models": {"Legal review": "opus"}})
    assert model_for("Legal review", load(repo)) == TOP_MODEL
    repo = _repo(tmp_path / "b", {"class_models": {"AuthN": "opus"}})
    with pytest.raises(OperatorError, match="personal_overrides.class_models maps.*Next:"):
        load(repo)


def test_a_project_list_and_mapping_are_checked_together(tmp_path: Path) -> None:
    override = {"work_classes": [], "class_models": {"AuthN": "opus"}}
    with pytest.raises(ConfigError, match="personal_overrides.class_models maps"):
        load_config(path=_repo(tmp_path, override) / ".claude" / "daedalus" / "config.json")


def test_both_keys_have_rows_that_name_the_project_winner() -> None:
    for key in ("work_classes", "class_models"):
        row = KEY_ROWS[(OPERATOR_FILE_NAME, key)]
        assert "`personal_overrides`" in row.governs and "wins for that project" in row.governs
        # 0267: the model command reads both, so both are active.
        assert "scripts/lib/train_runner.py" in row.readers and not row.override


def _setup(args: list[str], home: Path) -> subprocess.CompletedProcess[str]:
    env = {k: v for k, v in os.environ.items() if k not in ("CLAUDE_PLUGIN_DATA", "HOME")}
    env["HOME"] = str(home)
    return subprocess.run(
        [sys.executable, str(SETUP), *args], capture_output=True, text=True, env=env, check=False
    )


def test_the_wizard_describes_creates_and_refuses_a_bad_set(tmp_path: Path) -> None:
    home = tmp_path / "home"
    home.mkdir()
    repo = tmp_path / "repo"
    (repo / ".git").mkdir(parents=True)
    described = _setup(["--describe", "--repo", str(repo)], home)
    assert described.returncode == 0, described.stderr
    keys = {(k["file"], k["key"]): k for k in json.loads(described.stdout)["keys"]}
    for key in ("work_classes", "class_models"):
        entry = keys[("operator", key)]
        assert entry["affects"] == KEY_ROWS[(OPERATOR_FILE_NAME, key)].affects
        assert entry["group"] == "personal" and entry["active"] is True
    assert _setup(["--create-operator", "--repo", str(repo)], home).returncode == 0
    path = home / ".claude" / "daedalus" / "operator.json"
    assert json.loads(path.read_text(encoding="utf-8")) == starter_operator()
    bad = _setup(
        ["--set", "operator", "class_models", "--value", '{"Bogus": "opus"}', "--repo", str(repo)],
        home,
    )
    assert bad.returncode != 0 and "Next:" in bad.stdout + bad.stderr
    good = _setup(
        [
            "--set",
            "operator",
            "class_models",
            "--value",
            '{"AuthN": "sonnet"}',
            "--repo",
            str(repo),
        ],
        home,
    )
    assert good.returncode == 0, good.stdout + good.stderr
    assert json.loads(path.read_text(encoding="utf-8"))["class_models"] == {"AuthN": "sonnet"}


def test_the_wizard_refuses_a_project_mapping_the_next_load_refuses(tmp_path: Path) -> None:
    # 0280: the set form runs load's own cross-file check before it writes the config.
    home = tmp_path / "home"
    (home / ".claude" / "daedalus").mkdir(parents=True)
    rows = [{"name": "Legal review", "definition": "The work drafts a contract clause."}]
    _write(home, {"work_classes": rows})
    repo = tmp_path / "repo"
    (repo / ".git").mkdir(parents=True)
    created = _setup(["--repo", str(repo)], home)
    assert created.returncode == 0, created.stdout + created.stderr
    config = repo / ".claude" / "daedalus" / "config.json"
    before = config.read_bytes()
    value = '{"class_models": {"AuthN": "opus"}}'
    bad = _setup(
        ["--set", "config", "personal_overrides", "--value", value, "--repo", str(repo)], home
    )
    out = bad.stdout + bad.stderr
    assert bad.returncode != 0
    assert "personal_overrides.class_models maps ['AuthN']" in out
    assert "Next: add each to work_classes, or remove it from class_models." in out
    assert config.read_bytes() == before
    value = '{"class_models": {"Legal review": "opus"}}'
    good = _setup(
        ["--set", "config", "personal_overrides", "--value", value, "--repo", str(repo)], home
    )
    assert good.returncode == 0, good.stdout + good.stderr
    assert json.loads(config.read_text(encoding="utf-8"))["personal_overrides"] == {
        "class_models": {"Legal review": "opus"}
    }
