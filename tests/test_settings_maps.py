# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0264: a settings file carries a schema number, and a layout change ships a map from every
# earlier layout. The guard tests fail when the key table changes without a number and a step.
from __future__ import annotations

import dataclasses
import json
from collections.abc import Callable
from pathlib import Path

import pytest
from lib import settings_maps
from lib.config import ConfigError, parse_config
from lib.manifest import ManifestError
from lib.manifest import parse as parse_manifest
from lib.operator_file import OperatorError
from lib.operator_file import validate as validate_operator
from lib.project_keys import (
    CONFIG_FILE,
    KEY_ROWS,
    MANIFEST_FILE,
    OPERATOR_FILE_NAME,
    UNSETTABLE,
    fingerprint,
    reference_keys,
    starter_config,
    starter_manifest,
    starter_operator,
)
from lib.settings_maps import (
    Convert,
    Drop,
    Kind,
    Move,
    SchemaError,
    Set,
    Step,
    upgrade,
)

from tests.conftest import REPO_ROOT
from tests.test_setup_wizard import _manifest, _operator, _refused, _run, _set

EXAMPLES = {
    "manifest": "docs/examples/service-manifest.example.json",
    "config": "docs/examples/config.example.json",
    "operator": "docs/examples/operator.example.json",
}
OLD_EXAMPLES = REPO_ROOT / "tests" / "data" / "schema_examples"


def _reader(form: str) -> Callable[[object], bool]:
    def accepts(doc: object) -> bool:
        try:
            if form == "manifest":
                parse_manifest(doc, Path("service-manifest.json"))
            elif form == "config":
                parse_config(doc, Path("config.json"))
            else:
                validate_operator(doc, "operator.json")
        except ValueError:
            return False
        return True

    return accepts


# 0264: the fake kind has two schemas and one row of each kind; its reader wants the new names.
def _double(value: object) -> object:
    if not isinstance(value, int):
        raise TypeError("not a number")
    return value * 2


FAKE_CONVERTERS: dict[str, Callable[[object], object]] = {"double": _double}
FAKE_STEP = Step(
    1,
    2,
    (
        Move(("old", "name"), ("new", "name")),
        Drop(("gone",), "nothing reads it"),
        Set(("fresh",), "dflt"),
        Convert(("count",), "double"),
    ),
)
FAKE = {"fake": Kind(2, (FAKE_STEP,))}


def _fake_accepts(doc: object) -> bool:
    return isinstance(doc, dict) and "gone" not in doc and "old" not in doc


def _fake_upgrade(doc: dict[str, object]) -> settings_maps.Upgrade:
    return upgrade(doc, "fake", _fake_accepts, FAKE, FAKE_CONVERTERS)


def test_each_row_kind_does_its_one_job() -> None:
    old = {"schema": 1, "old": {"name": "x"}, "gone": True, "count": 4, "keep": 1}
    result = _fake_upgrade(old)
    assert result.doc == {
        "schema": 2,
        "new": {"name": "x"},
        "fresh": "dflt",
        "count": 8,
        "keep": 1,
    }
    assert [(a.verb, a.start, a.end) for a in result.actions] == [
        ("move", 1, 2),
        ("drop", 1, 2),
        ("set", 1, 2),
        ("convert", 1, 2),
    ]
    assert "old.name -> new.name" in result.actions[0].text
    assert "nothing reads it" in result.actions[1].text
    assert old["schema"] == 1 and "old" in old


def test_a_set_row_never_overwrites_and_an_absent_source_is_skipped() -> None:
    result = _fake_upgrade({"schema": 1, "fresh": "mine"})
    assert result.doc == {"schema": 2, "fresh": "mine"}
    assert result.actions == []


def test_a_file_two_schemas_behind_upgrades_in_one_pass() -> None:
    step_two = Step(2, 3, (Move(("new", "name"), ("renamed",)), Set(("later",), 7)))
    kinds = {"fake": Kind(3, (FAKE_STEP, step_two))}
    result = upgrade(
        {"schema": 1, "old": {"name": "x"}, "count": 1},
        "fake",
        lambda d: True,
        kinds,
        FAKE_CONVERTERS,
    )
    assert result.doc == {"schema": 3, "renamed": "x", "count": 2, "fresh": "dflt", "later": 7}
    assert [(a.start, a.end) for a in result.actions] == [(1, 2), (1, 2), (1, 2), (2, 3), (2, 3)]
    middle = upgrade(
        {"schema": 2, "new": {"name": "y"}}, "fake", lambda d: True, kinds, FAKE_CONVERTERS
    )
    assert [a.start for a in middle.actions] == [2, 2] and middle.doc["schema"] == 3


def test_a_missing_step_in_the_chain_is_refused() -> None:
    kinds = {"fake": Kind(3, (Step(2, 3, ()),))}
    with pytest.raises(SchemaError, match=r"no map from schema 1 to schema 2.*Next:"):
        upgrade({"schema": 1}, "fake", lambda d: True, kinds)


def test_a_step_that_skips_a_number_is_refused() -> None:
    kinds = {"fake": Kind(3, (Step(1, 3, ()),))}
    with pytest.raises(SchemaError, match="no map from schema 1 to schema 2"):
        upgrade({"schema": 1}, "fake", lambda d: True, kinds)


def test_a_move_onto_an_existing_key_is_refused() -> None:
    with pytest.raises(SchemaError, match=r"moves old.name to new.name.*already in.*Next:"):
        _fake_upgrade({"schema": 1, "old": {"name": "x"}, "new": {"name": "y"}})


def test_a_result_the_reader_refuses_is_refused() -> None:
    with pytest.raises(SchemaError, match=r"failed its own check.*Next:"):
        upgrade({"schema": 1, "old": {"name": 1}}, "fake", lambda d: False, FAKE, FAKE_CONVERTERS)


def test_a_converter_that_cannot_read_the_value_is_refused() -> None:
    with pytest.raises(SchemaError, match=r"count cannot be converted.*Next:"):
        _fake_upgrade({"schema": 1, "count": "four"})
    unnamed = {"fake": Kind(2, (Step(1, 2, (Convert(("count",), "nope"),)),))}
    with pytest.raises(SchemaError, match="converter 'nope'"):
        upgrade({"schema": 1, "count": 1}, "fake", lambda d: True, unnamed)


def test_the_chain_refuses_a_file_with_no_number_and_a_current_file_is_unchanged() -> None:
    with pytest.raises(SchemaError, match="holds no schema number"):
        _fake_upgrade({"gone": 1})
    same = _fake_upgrade({"schema": 2, "x": 1})
    assert same.doc == {"schema": 2, "x": 1} and same.actions == []


@pytest.mark.parametrize("form", ["manifest", "operator"])
def test_a_real_kind_without_a_change_stays_at_schema_one_with_no_steps(form: str) -> None:
    assert settings_maps.KINDS[form] == Kind(1, ())


def test_the_config_kind_is_at_schema_two_with_one_step_that_drops_three_keys() -> None:
    kind = settings_maps.KINDS["config"]
    (step,) = kind.steps
    assert kind.current == 2 and (step.start, step.end) == (1, 2)
    assert sorted(row.path for row in step.rows if isinstance(row, settings_maps.Drop)) == [
        ("models", "coder"),
        ("models", "coder_after_rejection"),
        ("models", "plugin_file_coder"),
    ]


READERS: dict[str, Callable[[dict[str, object]], object]] = {
    "manifest": lambda d: parse_manifest(d, Path("service-manifest.json")),
    "config": lambda d: parse_config(d, Path("config.json")),
    "operator": lambda d: validate_operator(d, "operator.json"),
}
ERRORS = {"manifest": ManifestError, "config": ConfigError, "operator": OperatorError}


@pytest.mark.parametrize("form", ["manifest", "config", "operator"])
@pytest.mark.parametrize(
    ("value", "words"),
    [
        ("one", "schema must be a whole number, and it is 'one'"),
        (1.5, "schema must be a whole number"),
        (True, "schema must be a whole number"),
        (None, "schema must be a whole number"),
        (0, "schema is 0, and the lowest schema number is 1"),
        (-3, "schema is -3, and the lowest schema number is 1"),
        (3, "schema is 3, but this version of Daedalus reads schema"),
    ],
)
def test_the_three_readers_refuse_a_bad_schema_number(form: str, value: object, words: str) -> None:
    with pytest.raises(ERRORS[form]) as err:
        READERS[form]({"schema": value})
    text = str(err.value)
    assert words in text and text.rstrip().endswith(".") and "Next:" in text
    if value == 3:
        assert "newer version wrote this file" in text and "update the Daedalus plugin" in text


@pytest.mark.parametrize("form", ["manifest", "config", "operator"])
def test_a_file_with_no_number_and_a_file_with_the_current_number_are_read(form: str) -> None:
    READERS[form]({})
    READERS[form]({"schema": settings_maps.current(form)})


def test_the_number_is_not_a_personal_override() -> None:
    with pytest.raises(ConfigError, match="unknown keys"):
        parse_config({"personal_overrides": {"schema": 1}}, Path("config.json"))


def test_the_starter_shapes_hold_the_number_first() -> None:
    for form, starter in (
        ("manifest", starter_manifest()),
        ("config", starter_config()),
        ("operator", starter_operator()),
    ):
        assert next(iter(starter)) == "schema" and starter["schema"] == settings_maps.current(form)


def test_create_and_replace_write_the_number(repo_cwd: Path, tmp_path: Path) -> None:
    home = tmp_path / "home"
    home.mkdir()
    assert _run(["--repo", str(repo_cwd)], home).returncode == 0
    assert json.loads(_manifest(repo_cwd).read_text(encoding="utf-8"))["schema"] == 1
    assert _run(["--create-operator", "--repo", str(repo_cwd)], home).returncode == 0
    assert json.loads(_operator(home).read_text(encoding="utf-8"))["schema"] == 1
    _manifest(repo_cwd).write_text('{"service_name": "old"}', encoding="utf-8")
    done = _run(["--replace", "manifest", "--write", "--repo", str(repo_cwd)], home)
    assert done.returncode == 0, done.stdout + done.stderr
    assert json.loads(_manifest(repo_cwd).read_text(encoding="utf-8"))["schema"] == 1


def test_the_set_form_refuses_the_number(repo_cwd: Path, tmp_path: Path) -> None:
    home = tmp_path / "home"
    home.mkdir()
    assert _run(["--repo", str(repo_cwd)], home).returncode == 0
    out = _refused(_set(repo_cwd, home, "manifest", "schema", "1"))
    assert "schema of the manifest file is not set by this wizard" in out
    assert {(u.file, u.key) for u in UNSETTABLE} >= {
        (MANIFEST_FILE, "schema"),
        (CONFIG_FILE, "schema"),
        (OPERATOR_FILE_NAME, "schema"),
    }


def test_every_form_has_a_schema_key_row() -> None:
    for file in (MANIFEST_FILE, CONFIG_FILE, OPERATOR_FILE_NAME):
        assert (file, "schema") in KEY_ROWS and (file, "schema") in set(reference_keys())


def test_the_wizard_plans_then_writes_the_chain(
    repo_cwd: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture
) -> None:
    import daedalus_setup

    home = tmp_path / "home"
    path = home / ".claude" / "daedalus" / "operator.json"
    path.parent.mkdir(parents=True)
    old = {"schema": 1, "guidance_source": "claude", "developer_profile": True, "hard_stops": []}
    path.write_text(json.dumps(old), encoding="utf-8")
    monkeypatch.setenv("HOME", str(home))
    rows = (
        Convert(("guidance_source",), "to_daedalus"),
        Drop(("developer_profile",), "the profile moved elsewhere"),
        Set(("script_language",), "python"),
    )
    monkeypatch.setitem(settings_maps.KINDS, "operator", Kind(2, (Step(1, 2, rows),)))
    monkeypatch.setitem(settings_maps.CONVERTERS, "to_daedalus", lambda v: "daedalus")
    assert daedalus_setup.replace("operator", repo_cwd, False) == 0
    plan = capsys.readouterr().out
    assert "schema 1 to 2:" in plan and "  drop: developer_profile (the profile moved" in plan
    assert plan.index("convert:") < plan.index("drop:") < plan.index("set:")
    assert json.loads(path.read_text(encoding="utf-8")) == old
    assert daedalus_setup.replace("operator", repo_cwd, True) == 0
    done = capsys.readouterr().out
    assert "upgraded:" in done and "from schema 1 to schema 2" in done
    now = json.loads(path.read_text(encoding="utf-8"))
    assert now == {
        "schema": 2,
        "guidance_source": "daedalus",
        "hard_stops": [],
        "script_language": "python",
    }
    with pytest.raises(daedalus_setup.SetupStop, match="already passes"):
        daedalus_setup.replace("operator", repo_cwd, False)


def test_a_file_with_no_number_keeps_the_carry_plan(repo_cwd: Path, tmp_path: Path) -> None:
    home = tmp_path / "home"
    home.mkdir()
    assert _run(["--repo", str(repo_cwd)], home).returncode == 0
    _manifest(repo_cwd).write_text('{"service_name": "old"}', encoding="utf-8")
    done = _run(["--replace", "manifest", "--repo", str(repo_cwd)], home)
    assert done.returncode == 0
    assert "plan: replace" in done.stdout and "schema 1 to" not in done.stdout


# 0264: the guard. The key table is the layout; a change to it needs a new number and a step.
def guard_problem(
    form: str, kinds: dict[str, Kind], recorded: dict[int, str], now: str
) -> str | None:
    top = kinds[form].current
    if recorded.get(top) == now:
        return None
    return (
        f"The {form} settings key table changed, but schema {top} records a different hash. "
        f"Raise the {form} schema number to {top + 1} in settings_maps.KINDS, add a map step "
        f"from schema {top} (Step({top}, {top + 1}, rows) in that kind), and record this hash "
        f"for schema {top + 1} in settings_maps.FINGERPRINTS: {now}"
    )


def chain_problems(
    form: str,
    kinds: dict[str, Kind],
    recorded: dict[int, str],
    example: Callable[[str, int], dict[str, object] | None],
    accepts: Callable[[object], bool],
    converters: dict[str, Callable[[object], object]],
) -> list[str]:
    top = kinds[form].current
    problems: list[str] = []
    if sorted(recorded) != list(range(1, top + 1)):
        problems.append(f"{form}: recorded schema numbers {sorted(recorded)} are not 1 to {top}")
    for number in sorted(recorded):
        doc = example(form, number)
        if doc is None:
            problems.append(f"{form}: no example file for schema {number}")
            continue
        if number < top and not any(
            s.start == number and s.end == number + 1 for s in kinds[form].steps
        ):
            problems.append(f"{form}: no map step from schema {number}")
            continue
        try:
            result = upgrade(doc, form, accepts, kinds, converters).doc if number < top else doc
        except SchemaError as exc:
            problems.append(f"{form}: schema {number} example did not upgrade: {exc}")
            continue
        if not accepts(result):
            problems.append(
                f"{form}: schema {number} example ends in a document the reader refuses"
            )
    return problems


def _real_example(form: str, number: int) -> dict[str, object] | None:
    top = settings_maps.KINDS[form].current
    path = REPO_ROOT / EXAMPLES[form] if number == top else OLD_EXAMPLES / f"{form}-{number}.json"
    if not path.is_file():
        return None
    doc = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(doc, dict)
    return doc


@pytest.mark.parametrize("form", ["manifest", "config", "operator"])
def test_the_key_table_matches_the_hash_recorded_for_its_schema_number(form: str) -> None:
    problem = guard_problem(
        form, settings_maps.KINDS, settings_maps.FINGERPRINTS[form], fingerprint(form)
    )
    assert problem is None, problem


def test_the_guard_message_says_what_to_do_in_plain_words() -> None:
    message = guard_problem("manifest", settings_maps.KINDS, {1: "old"}, "newhash")
    assert message is not None
    assert message.startswith("The manifest settings key table changed, but schema 1 records")
    assert "Raise the manifest schema number to 2" in message
    assert "add a map step from schema 1" in message
    assert "record this hash for schema 2" in message and message.endswith("newhash")


def test_a_changed_key_table_changes_the_hash(monkeypatch: pytest.MonkeyPatch) -> None:
    before = fingerprint("operator")
    row = KEY_ROWS[(OPERATOR_FILE_NAME, "hard_stops")]
    monkeypatch.setitem(
        KEY_ROWS, (OPERATOR_FILE_NAME, "hard_stops"), dataclasses.replace(row, kind="other kind")
    )
    assert fingerprint("operator") != before


@pytest.mark.parametrize("form", ["manifest", "config", "operator"])
def test_every_recorded_schema_has_a_step_and_an_example_the_reader_accepts(form: str) -> None:
    problems = chain_problems(
        form,
        settings_maps.KINDS,
        settings_maps.FINGERPRINTS[form],
        _real_example,
        _reader(form),
        settings_maps.CONVERTERS,
    )
    assert problems == []


def test_the_chain_check_covers_schema_two_the_day_one_exists() -> None:
    old = {"schema": 1, "old": {"name": "x"}, "gone": 1, "count": 2}
    new = {"schema": 2, "new": {"name": "x"}, "fresh": "d", "count": 4}

    def example(form: str, number: int) -> dict[str, object] | None:
        return {1: old, 2: new}.get(number)

    recorded = {1: "h1", 2: "h2"}
    args = ("fake", FAKE, recorded, example, _fake_accepts, FAKE_CONVERTERS)
    assert chain_problems(*args) == []
    assert guard_problem("fake", FAKE, recorded, "h2") is None
    assert guard_problem("fake", FAKE, recorded, "h3") is not None
    no_step = {"fake": Kind(2, ())}
    found = chain_problems("fake", no_step, recorded, example, _fake_accepts, FAKE_CONVERTERS)
    assert found == ["fake: no map step from schema 1"]
    assert chain_problems("fake", FAKE, {2: "h2"}, example, _fake_accepts, FAKE_CONVERTERS) != []
    refused = chain_problems("fake", FAKE, recorded, example, lambda d: False, FAKE_CONVERTERS)
    assert any("reader refuses" in p or "did not upgrade" in p for p in refused)
