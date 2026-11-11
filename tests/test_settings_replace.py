# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0257: the setup wizard replaces a settings file the current reader refuses, carrying forward
# each value it still accepts at the same place, and sets every key the file accepts.
from __future__ import annotations

import json
import os
import re
from pathlib import Path

import pytest
from lib import settings_replace
from lib.config import load_config
from lib.manifest import load as load_manifest
from lib.operator_file import validate as validate_operator
from lib.project_keys import (
    MANIFEST_FILE,
    OPERATOR_FILE_NAME,
    SETTINGS_FILES,
    UNSETTABLE,
    reference_keys,
    starter_config,
    starter_manifest,
    starter_operator,
)

from tests.test_setup_wizard import (
    _config,
    _keys,
    _manifest,
    _operator,
    _refused,
    _run,
    _set,
    _value_file,
)


@pytest.fixture
def home(tmp_path: Path) -> Path:
    path = tmp_path / "home"
    path.mkdir()
    return path


@pytest.fixture
def wizard(repo_cwd: Path, home: Path) -> Path:
    # The starter files the create step writes, as the wizard tests start from.
    assert _run(["--repo", str(repo_cwd)], home).returncode == 0
    return repo_cwd


# 0257: the manifest as the plugin's own repository held it before the key names changed.
OLD_SHAPE = {
    "manifest_version": 1,
    "service_name": "daedalus",
    "stack": {"language": "python", "unit_test_cmd": "python3 -m pytest -q", "build_cmd": None},
    "features": {"secrets_scan": True},
    "entrypoints": {"scripts": "scripts/"},
    "jail_narrowing": {"forbidden_extensions": [], "forbidden_paths": []},
    "upstream_dependencies": [],
}
GOOD_RULE = {
    "between": ["security", "cost"],
    "reasons": ["incident"],
    "outcome": "security",
    "note": "keys first",
}
REASON = "the mirror delays every release by days"
MIXED = {
    "stack": {"unit_test_cmd": "pytest"},
    "commands": {"unit_test": "python3 -m pytest -q", "build": "make"},
    "checks": {"secret_scan": "yes", "terraform_format": False},
    "prohibited_writes": {"paths": ["src/gen/", "/abs"], "file_types": [".pem"]},
    "packages": {"minimum_age_days": 3, "minimum_age_reason": REASON, "registry": "x"},
    "run_output_priority": {
        "order": ["security", "trust", "operations", "cost"],
        "rules": [GOOD_RULE, {**GOOD_RULE, "outcome": "nobody"}],
    },
    "code_areas": {"api": "src/api", "bad": 3},
    "docs": {"folder": "documentation", "literacy": "plain"},
    "local_testing": {"url": "http://localhost:3000", "instructions": "bad `tick`"},
}
MIXED_CARRIED = {
    "commands.unit_test",
    "checks.terraform_format",
    "prohibited_writes.paths[0]",
    "prohibited_writes.file_types",
    "packages.minimum_age_days",
    "packages.minimum_age_reason",
    "run_output_priority.order",
    "run_output_priority.rules[0]",
    "code_areas.api",
    "docs.folder",
}
MIXED_DROPPED = {
    "stack": "no longer a setting",
    "commands.build": "no longer a setting",
    "checks.secret_scan": "this version refuses its value",
    "prohibited_writes.paths[1]": "this version refuses its value",
    "packages.registry": "no longer a setting",
    "run_output_priority.rules[1]": "this version refuses its value",
    "code_areas.bad": "this version refuses its value",
    "docs.literacy": "no longer a setting",
    "local_testing.url": "this version refuses its value",
    "local_testing.instructions": "this version refuses its value",
}
_LINE = re.compile(
    r"^(carry|drop): (\S+) = (.*?)(?: \((no longer a setting|this version refuses its value)\))?$"
)


def _replace(repo: Path, home: Path, form: str, *extra: str) -> tuple[int, str]:
    done = _run(["--replace", form, *extra, "--repo", str(repo)], home)
    return done.returncode, done.stdout + done.stderr


def _moves(out: str) -> tuple[set[str], dict[str, str]]:
    carried: set[str] = set()
    dropped: dict[str, str] = {}
    for line in out.splitlines():
        found = _LINE.match(line)
        if found is None:
            continue
        if found[1] == "carry":
            carried.add(found[2])
        else:
            dropped[found[2]] = str(found[4])
    return carried, dropped


def _backup(out: str) -> Path:
    found = re.search(r"^backup: (\S+) \(", out, re.MULTILINE)
    assert found is not None, out
    return Path(found[1])


def _old(path: Path, doc: object, tail: str = "") -> bytes:
    # 0257: odd spacing and a tail make the backup's byte-for-byte check bite.
    text = json.dumps(doc, indent="\t") + tail
    path.write_text(text, encoding="utf-8")
    return path.read_bytes()


def test_plan_writes_nothing_and_names_the_backup(wizard: Path, home: Path) -> None:
    path = _manifest(wizard)
    before = _old(path, {**OLD_SHAPE, "service_name": str(wizard)})
    stamp = path.stat().st_mtime_ns
    code, out = _replace(wizard, home, "manifest")
    assert code == 0, out
    assert path.read_bytes() == before and path.stat().st_mtime_ns == stamp
    assert not _backup(out).exists()
    assert out.splitlines()[0].startswith(f"plan: replace {path}, a settings file from an older")
    assert out.splitlines()[-1] == (
        "nothing was written. Next: run the same command with --write to replace the file."
    )


def test_old_shape_manifest_drops_every_entry_and_writes_the_starter(
    wizard: Path, home: Path
) -> None:
    path = _manifest(wizard)
    before = _old(path, {**OLD_SHAPE, "service_name": str(wizard)}, "\n\n")
    code, out = _replace(wizard, home, "manifest", "--write")
    assert code == 0, out
    carried, dropped = _moves(out)
    assert carried == set()
    assert set(dropped) == set(OLD_SHAPE) and set(dropped.values()) == {"no longer a setting"}
    assert json.loads(path.read_text(encoding="utf-8")) == starter_manifest()
    assert _backup(out).read_bytes() == before
    assert out.splitlines()[-1] == f"replaced: {path}, 0 value(s) carried, 7 entry(ies) dropped"
    assert load_manifest(wizard) is not None


def test_mixed_manifest_carries_top_values_groups_and_rows(wizard: Path, home: Path) -> None:
    path = _manifest(wizard)
    before = _old(path, MIXED)
    plan_code, plan = _replace(wizard, home, "manifest")
    code, out = _replace(wizard, home, "manifest", "--write")
    assert plan_code == 0 and code == 0, out
    # 0257: the write shows the plan's own carry and drop lines.
    assert _moves(plan) == _moves(out)
    carried, dropped = _moves(out)
    assert carried == MIXED_CARRIED and dropped == MIXED_DROPPED
    doc = json.loads(path.read_text(encoding="utf-8"))
    want = starter_manifest()
    want["commands"]["unit_test"] = "python3 -m pytest -q"  # type: ignore[index]
    want["checks"]["terraform_format"] = False  # type: ignore[index]
    want["prohibited_writes"] = {"paths": ["src/gen/"], "file_types": [".pem"]}
    want["packages"] = {
        "allowed_installers": [],
        "minimum_age_days": 3,
        "minimum_age_reason": REASON,
    }
    want["run_output_priority"] = {
        "order": MIXED["run_output_priority"]["order"],
        "rules": [GOOD_RULE],
    }  # type: ignore[index]
    want["code_areas"] = {"api": "src/api"}
    want["docs"]["folder"] = "documentation"  # type: ignore[index]
    assert doc == want
    loaded = load_manifest(wizard)
    assert loaded is not None and loaded.dependencies.minimum_release_age_days == 3
    assert _backup(out).read_bytes() == before
    for name in ("stack", "build", "registry", "literacy", "bad", "nobody"):
        assert name not in path.read_text(encoding="utf-8"), name


def test_config_carries_rows_and_group_members(wizard: Path, home: Path) -> None:
    path = _config(wizard)
    old = {
        "charter_root": "/work/docs",
        "coding_rules": [{"builtin": "baseline"}, {"builtin": "nope"}],
        "models": {"coder": "gpt", "fable_available": True},
        "limits": {"parallel_coders": 2},
    }
    _old(path, old)
    code, out = _replace(wizard, home, "config", "--write")
    assert code == 0, out
    carried, dropped = _moves(out)
    assert carried == {"coding_rules[0]", "models.fable_available", "limits"}
    assert dropped == {
        "charter_root": "no longer a setting",
        "coding_rules[1]": "this version refuses its value",
        "models.coder": "this version refuses its value",
    }
    config = load_config(path=path)
    assert [s.name for s in config.standards_sources] == ["baseline"]
    assert config.fable_available is True and config.max_concurrent_builders == 2
    assert set(json.loads(path.read_text(encoding="utf-8"))) >= set(starter_config())
    assert oct(path.stat().st_mode & 0o777) == oct(0o600)


def test_personal_file_carries_rows_after_a_yes(wizard: Path, home: Path) -> None:
    path = _operator(home)
    path.parent.mkdir(parents=True)
    _old(path, {"profile": {"literacy": "plain"}, "hard_stops": ["commit_on_main", "bogus"]})
    code, out = _replace(wizard, home, "operator", "--write")
    assert code == 0, out
    carried, dropped = _moves(out)
    assert carried == {"hard_stops[0]"}
    assert dropped == {
        "profile": "no longer a setting",
        "hard_stops[1]": "this version refuses its value",
    }
    doc = json.loads(path.read_text(encoding="utf-8"))
    assert doc == {**starter_operator(), "hard_stops": ["commit_on_main"]}
    assert validate_operator(doc, str(path))["main_refusals"] == ("commit_on_main",)


def test_a_value_that_looks_like_a_secret_is_never_printed(wizard: Path, home: Path) -> None:
    token = "ghp_" + "a1" * 18
    _old(_manifest(wizard), {"api_token": token, "stack": {"auth": f"Bearer {token}"}})
    code, out = _replace(wizard, home, "manifest")
    assert code == 0 and token not in out, out
    assert "drop: api_token = <value withheld> (no longer a setting)" in out
    assert "note: 2 value(s) look like secrets and are not shown" in out


@pytest.mark.parametrize(
    ("text", "said"),
    [
        ("{ nope", "is not valid JSON"),
        ("[1, 2]", "is not one JSON object"),
        ('{"commands": {}, "commands": {}}', "holds the key 'commands' twice"),
    ],
)
def test_a_file_that_is_not_one_json_object_is_refused_and_offers_a_starter(
    wizard: Path, home: Path, text: str, said: str
) -> None:
    path = _manifest(wizard)
    path.write_text(text, encoding="utf-8")
    for extra in ((), ("--write",)):
        out = _refused(_run(["--replace", "manifest", *extra, "--repo", str(wizard)], home))
        assert said in out and "nothing was written" in out
        assert "writes a new starter manifest file with nothing carried" in out
        assert path.read_text(encoding="utf-8") == text


def test_a_linked_manifest_is_refused(wizard: Path, home: Path, tmp_path: Path) -> None:
    target = tmp_path / "elsewhere.json"
    target.write_text(json.dumps(OLD_SHAPE), encoding="utf-8")
    _manifest(wizard).unlink()
    _manifest(wizard).symlink_to(target)
    out = _refused(_run(["--replace", "manifest", "--write", "--repo", str(wizard)], home))
    assert "is a symlink" in out
    assert json.loads(target.read_text(encoding="utf-8")) == OLD_SHAPE


def test_a_linked_config_is_refused_by_the_data_folder_check(
    wizard: Path, home: Path, tmp_path: Path
) -> None:
    target = tmp_path / "config.json"
    target.write_text('{"charter_root": "/x"}', encoding="utf-8")
    _config(wizard).unlink()
    _config(wizard).symlink_to(target)
    out = _refused(_run(["--replace", "config", "--write", "--repo", str(wizard)], home))
    assert "the project data folder failed a check" in out
    assert target.read_text(encoding="utf-8") == '{"charter_root": "/x"}'


def test_a_personal_file_reached_outside_home_is_refused(
    wizard: Path, home: Path, tmp_path: Path
) -> None:
    outside = tmp_path / "outside" / ".claude"
    (outside / "daedalus").mkdir(parents=True)
    (outside / "daedalus" / "operator.json").write_text('{"profile": 1}', encoding="utf-8")
    (home / ".claude").symlink_to(outside)
    out = _refused(_run(["--replace", "operator", "--write", "--repo", str(wizard)], home))
    assert "resolves outside" in out and "setup never writes there" in out
    assert (outside / "daedalus" / "operator.json").read_text(encoding="utf-8") == '{"profile": 1}'


def test_replace_refuses_an_accepted_or_missing_file_and_a_bad_form(
    wizard: Path, home: Path
) -> None:
    before = _manifest(wizard).read_bytes()
    assert "already passes its own check" in _refused(
        _run(["--replace", "manifest", "--write", "--repo", str(wizard)], home)
    )
    assert _manifest(wizard).read_bytes() == before
    assert "does not exist" in _refused(
        _run(["--replace", "operator", "--repo", str(wizard)], home)
    )
    assert "is not one of the settings files" in _refused(
        _run(["--replace", "nope", "--repo", str(wizard)], home)
    )
    assert "--write goes only with --replace" in _refused(
        _run(["--write", "--repo", str(wizard)], home)
    )


def test_a_linked_backup_folder_stops_the_write_before_any_change(
    wizard: Path,
    home: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    # 0257, self-hunt: the backup never lands through a link, and no backup means no replace.
    import daedalus_setup
    from lib import storage

    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (tmp_path / "tmproot").symlink_to(elsewhere)
    monkeypatch.setattr(storage, "TMP_ROOT", tmp_path / "tmproot")
    monkeypatch.setenv("HOME", str(home))
    path = _manifest(wizard)
    before = _old(path, OLD_SHAPE)
    assert daedalus_setup.main(["--replace", "manifest", "--write", "--repo", str(wizard)]) == 1
    out = capsys.readouterr().out
    assert "the backup of the old file could not be written" in out and "is a symlink" in out
    assert path.read_bytes() == before and list(elsewhere.iterdir()) == []


def test_a_second_replace_of_the_result_finds_nothing_to_replace(wizard: Path, home: Path) -> None:
    _old(_manifest(wizard), MIXED)
    assert _replace(wizard, home, "manifest", "--write")[0] == 0
    assert "already passes its own check" in _refused(
        _run(["--replace", "manifest", "--write", "--repo", str(wizard)], home)
    )


# 0257, self-hunt: no old value is lost unlisted, and no carried value is one the reader refuses.
def _leaves(doc: object, path: tuple[str, ...] = ()) -> list[tuple[str, ...]]:
    if isinstance(doc, dict) and doc:
        return [leaf for k, v in doc.items() for leaf in _leaves(v, (*path, k))]
    if isinstance(doc, list) and doc:
        return [(*path, f"[{i}]") for i in range(len(doc))]
    return [path]


def _covered(leaf: tuple[str, ...], moved: list[settings_replace.Moved]) -> bool:
    return any(leaf[: len(m.path)] == m.path for m in moved)


@pytest.mark.parametrize(
    ("old", "starter", "name"),
    [
        (MIXED, starter_manifest(), MANIFEST_FILE),
        (OLD_SHAPE, starter_manifest(), MANIFEST_FILE),
        (
            {"hard_stops": ["x", "credential_read"], "z": {"y": [1]}},
            starter_operator(),
            OPERATOR_FILE_NAME,
        ),
    ],
)
def test_every_old_leaf_is_carried_or_listed_once(
    old: dict[str, object], starter: dict[str, object], name: str, tmp_path: Path
) -> None:
    import daedalus_setup

    form = next(f.form for f in SETTINGS_FILES if f.name == name)
    keys = tuple(k for f, k in reference_keys() if f == name)
    accepts = daedalus_setup._accepts(form, tmp_path / "file.json")
    outcome = settings_replace.carry(old, starter, keys, accepts)
    for leaf in _leaves(old):
        carried = _covered(leaf, outcome.carried)
        dropped = _covered(leaf, outcome.dropped)
        assert carried != dropped, leaf
    assert accepts(outcome.doc)


def test_a_known_name_is_matched_by_the_key_table_only() -> None:
    keys = ("coding_rules[].folder", "run_output_priority.agent_order.<name>", "models.agents")
    assert settings_replace.known(("coding_rules",), keys)
    assert not settings_replace.known(("coding_rules", "folder"), keys)
    assert settings_replace.known(("run_output_priority", "agent_order", "planner"), keys)
    assert settings_replace.known(("models", "agents", "planner"), keys)
    assert not settings_replace.known(("models", "coder"), keys)
    assert not settings_replace.known(("stack",), keys)


def test_a_name_with_a_line_break_prints_on_one_line() -> None:
    shown = settings_replace.shown_path(("docs", "a\nfake: line"))
    assert "\n" not in shown and shown == 'docs."a\\nfake: line"'


# 0257: the set form admits every key the file accepts.
def test_every_key_is_settable_or_has_a_not_settable_row() -> None:
    import daedalus_setup

    by_name = {f.name: f for f in SETTINGS_FILES}
    for name, key in reference_keys():
        if daedalus_setup.unsettable(name, key) is not None:
            continue
        target = daedalus_setup.set_as(key)
        assert daedalus_setup._key_refusal(by_name[name], target) is None, (name, key, target)
    for row in UNSETTABLE:
        assert (row.file, row.key) in set(reference_keys()) and row.why.strip()


def test_describe_names_the_whole_list_to_set(wizard: Path, home: Path) -> None:
    done = _run(["--describe", "--repo", str(wizard)], home)
    keys = _keys(json.loads(done.stdout))
    assert keys[("config", "coding_rules[].folder")]["set_as"] == "coding_rules"
    assert keys[("config", "coding_rules[].folder")]["value"] == []
    agent = keys[("manifest", "run_output_priority.agent_order.<name>")]
    assert agent["set_as"] == "run_output_priority.agent_order" and agent["settable"] is True
    assert keys[("manifest", SCAN_KEY)]["set_as"] == SCAN_KEY


SCAN_KEY = "checks.secret_scan"


@pytest.mark.parametrize(
    ("form", "key", "value"),
    [
        ("config", "coding_rules", [{"builtin": "baseline"}, {"folder": "/work/rules"}]),
        ("config", "models.agents", {"planner": "sonnet"}),
        ("manifest", "run_output_priority.order", ["security", "trust", "operations", "cost"]),
    ],
)
def test_a_list_or_named_entry_key_sets_whole(
    wizard: Path, home: Path, tmp_path: Path, form: str, key: str, value: object
) -> None:
    path = _manifest(wizard) if form == "manifest" else _config(wizard)
    done = _run(
        [
            "--set",
            form,
            key,
            "--value-file",
            str(_value_file(tmp_path, value)),
            "--repo",
            str(wizard),
        ],
        home,
    )
    assert done.returncode == 0, done.stdout
    assert done.stdout.startswith(f"changed: {path} {key}:")


def test_priority_rows_set_after_the_order_and_are_checked_by_the_reader(
    wizard: Path, home: Path, tmp_path: Path
) -> None:
    base = ["--repo", str(wizard)]
    rules = str(_value_file(tmp_path, [GOOD_RULE], "rules.json"))
    out = _refused(
        _run(["--set", "manifest", "run_output_priority.rules", "--value-file", rules, *base], home)
    )
    assert "the file's own check refused the new value" in out
    order = ["security", "trust", "operations", "cost"]
    assert (
        _set(wizard, home, "manifest", "run_output_priority.order", json.dumps(order)).returncode
        == 0
    )
    assert (
        _run(
            ["--set", "manifest", "run_output_priority.rules", "--value-file", rules, *base], home
        ).returncode
        == 0
    )
    bad = str(_value_file(tmp_path, {"auditor": order}, "bad.json"))
    out = _refused(
        _run(
            ["--set", "manifest", "run_output_priority.agent_order", "--value-file", bad, *base],
            home,
        )
    )
    assert "auditor" in out
    loaded = load_manifest(wizard)
    assert loaded is not None and loaded.priorities is not None
    assert len(loaded.priorities.rules) == 1


def test_coding_rules_is_settable_where_it_was_refused(wizard: Path, home: Path) -> None:
    done = _set(wizard, home, "config", "coding_rules", '[{"builtin": "baseline"}]')
    assert done.returncode == 0, done.stdout
    assert 'coding_rules: [] -> [{"builtin": "baseline"}]' in done.stdout
    out = _refused(_set(wizard, home, "config", "coding_rules", '[{"builtin": "nope"}]'))
    assert "is not a rule set Daedalus ships" in out
    assert os.path.isfile(_config(wizard))


def test_skill_offers_the_replace_once_and_closes_on_the_uncommitted_file() -> None:
    text = (Path(__file__).resolve().parents[1] / "skills" / "setup" / "SKILL.md").read_text(
        encoding="utf-8"
    )
    describe = text.split("1. **Describe.**", 1)[1].split("2. **Create.**", 1)[0]
    assert "--replace <file>" in describe and "with `--write` added" in describe
    assert "I lean to replace it." in describe and "not as a choice block" in describe
    close = text.split("5. **Close.**", 1)[1]
    assert "pull request will not carry it unless you commit it yourself" in close
    more = text.split("4. **More.**", 1)[1].split("5. **Close.**", 1)[0]
    assert "`set_as`" in more and "changed by hand" not in more
