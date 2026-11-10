# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0242: the settings wizard's tables, overlaps, script forms, examples and skill.
from __future__ import annotations

import json
import os
import re
import shlex
import stat
import subprocess
import sys
from collections import Counter
from pathlib import Path

import pytest
from lib import settings_edit
from lib.operator_file import Operator, load_user
from lib.project_keys import (
    GROUPS,
    KEY_ROWS,
    OVERLAPS,
    SETTINGS_FILES,
    reference_keys,
    starter_operator,
)

from tests.conftest import REPO_ROOT, SCRIPTS_DIR

SETUP = SCRIPTS_DIR / "daedalus_setup.py"


def _run(args: list[str], home: Path | str | None) -> subprocess.CompletedProcess[str]:
    env = {k: v for k, v in os.environ.items() if k not in ("CLAUDE_PLUGIN_DATA", "HOME")}
    if home is not None:
        env["HOME"] = str(home)
    return subprocess.run(
        [sys.executable, str(SETUP), *args], capture_output=True, text=True, env=env, check=False
    )


@pytest.fixture
def home(tmp_path: Path) -> Path:
    path = tmp_path / "home"
    path.mkdir()
    return path


@pytest.fixture
def wizard(repo_cwd: Path, home: Path) -> Path:
    assert _run(["--repo", str(repo_cwd)], home).returncode == 0
    return repo_cwd


def _manifest(repo: Path) -> Path:
    return repo / "service-manifest.json"


def _config(repo: Path) -> Path:
    return repo / ".claude" / "daedalus" / "config.json"


def _operator(home: Path) -> Path:
    return home / ".claude" / "daedalus" / "operator.json"


def _set(repo: Path, home: Path | str | None, *args: str) -> subprocess.CompletedProcess[str]:
    form, key, value = args
    return _run(["--set", form, key, "--value", value, "--repo", str(repo)], home)


def _refused(result: subprocess.CompletedProcess[str]) -> str:
    assert result.returncode == 1, result.stdout + result.stderr
    assert "Next:" in result.stdout, result.stdout
    return result.stdout


def _describe(repo: Path, home: Path) -> dict[str, object]:
    result = _run(["--describe", "--repo", str(repo)], home)
    assert result.returncode == 0, result.stdout + result.stderr
    doc = json.loads(result.stdout)
    assert isinstance(doc, dict)
    return doc


def _keys(doc: dict[str, object]) -> dict[tuple[str, str], dict[str, object]]:
    entries = doc["keys"]
    assert isinstance(entries, list)
    return {(e["file"], e["key"]): e for e in entries}


def _files(doc: dict[str, object]) -> dict[str, dict[str, object]]:
    entries = doc["files"]
    assert isinstance(entries, list)
    return {e["file"]: e for e in entries}


def test_describe_lists_every_key_once_with_its_text_and_state(wizard: Path, home: Path) -> None:
    doc = _describe(wizard, home)
    names = {f.form: f.name for f in SETTINGS_FILES}
    entries = doc["keys"]
    assert isinstance(entries, list)
    pairs = [(names[e["file"]], e["key"]) for e in entries]
    assert len(pairs) == len(set(pairs)) and set(pairs) == set(reference_keys())
    files = _files(doc)
    assert list(files) == ["manifest", "config", "operator"]
    assert files["manifest"]["exists"] and files["config"]["exists"]
    assert not files["operator"]["exists"] and files["operator"]["malformed"] is None
    for entry in files.values():
        for field in ("path", "where", "whose", "shared", "holds", "groups"):
            assert entry[field], field
    assert doc["overlaps"] == [{"id": o.id, "text": o.text} for o in OVERLAPS]
    keys = _keys(doc)
    scan = keys[("manifest", "features.secrets_scan")]
    row = KEY_ROWS[("service-manifest.json", "features.secrets_scan")]
    assert scan["affects"] == row.affects and scan["governs"] == row.governs
    assert scan["state"] == "default" and scan["value"] is False and scan["day_one"]
    assert keys[("operator", "profile.literacy")]["state"] == "absent"
    assert keys[("operator", "profile.literacy")]["active"] is False
    assert keys[("manifest", "priorities.rules[].note")]["settable"] is False


def test_describe_still_describes_two_files_when_one_is_malformed(wizard: Path, home: Path) -> None:
    _config(wizard).write_text('{"max_concurrent_builders": 3,}\n', encoding="utf-8")
    doc = _describe(wizard, home)
    files = _files(doc)
    assert "not valid JSON" in str(files["config"]["malformed"])
    assert files["manifest"]["malformed"] is None and files["operator"]["malformed"] is None
    keys = _keys(doc)
    assert keys[("config", "max_concurrent_builders")]["state"] == "unknown"
    assert keys[("manifest", "features.ledger")]["state"] == "default"


def test_describe_proposes_stack_commands_from_marker_files_only(wizard: Path, home: Path) -> None:
    (wizard / "pyproject.toml").write_text(
        "[tool.pytest.ini_options]\naddopts = '-q'\n[tool.ruff]\n", encoding="utf-8"
    )
    (wizard / "package.json").write_text('{"scripts": {"test": "vitest"}}', encoding="utf-8")
    (wizard / "pnpm-lock.yaml").write_text("lockfileVersion: 9\n", encoding="utf-8")
    detected = _describe(wizard, home)["detected"]
    assert detected == {
        "stack.unit_test_cmd": {
            "value": ["python3 -m pytest -q", "pnpm test"],
            "from": ["pyproject.toml tool pytest ini_options", "package.json scripts test"],
        },
        "stack.lint_cmd": {
            "value": "python3 -m ruff check .",
            "from": ["pyproject.toml tool ruff"],
        },
        "stack.package_manager": {"value": "pnpm", "from": ["pnpm-lock.yaml"]},
    }


def test_describe_skips_the_terraform_questions_only_without_terraform_files(
    wizard: Path, home: Path
) -> None:
    moot = _describe(wizard, home)["moot"]
    assert isinstance(moot, dict) and "features.terraform_tools" in moot
    (wizard / "infra").mkdir()
    (wizard / "infra" / "main.tf").write_text("", encoding="utf-8")
    assert _describe(wizard, home)["moot"] == {}


def test_create_operator_creates_keeps_and_refuses(
    home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _operator(home)
    first = _run(["--create-operator"], home)
    assert first.returncode == 0 and first.stdout == f"written: {path}\n"
    assert json.loads(path.read_text(encoding="utf-8")) == starter_operator()
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700
    monkeypatch.setenv("HOME", str(home))
    assert load_user() == Operator()
    second = _run(["--create-operator"], home)
    assert second.returncode == 0 and second.stdout == f"kept: {path} (it already exists)\n"
    path.unlink()
    path.symlink_to(tmp_path / "elsewhere.json")
    assert "symlink" in _refused(_run(["--create-operator"], home))
    assert not (tmp_path / "elsewhere.json").exists()


def test_create_operator_refuses_a_linked_folder(home: Path, tmp_path: Path) -> None:
    (home / ".claude").mkdir()
    (tmp_path / "other").mkdir()
    (home / ".claude" / "daedalus").symlink_to(tmp_path / "other")
    assert "symlink" in _refused(_run(["--create-operator"], home))
    assert list((tmp_path / "other").iterdir()) == []


@pytest.mark.parametrize("value", [None, "relative/home"])
def test_operator_forms_refuse_an_unset_or_relative_home(
    repo_cwd: Path, tmp_path: Path, value: str | None, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    assert "HOME" in _refused(_run(["--create-operator"], value))
    assert "HOME" in _refused(_set(repo_cwd, value, "operator", "profile.dash_ban", "true"))
    assert not (tmp_path / "relative").exists()


def test_set_changes_one_key_and_keeps_every_other_byte(wizard: Path, home: Path) -> None:
    path = _manifest(wizard)
    before = path.read_text(encoding="utf-8")
    mode = stat.S_IMODE(path.stat().st_mode)
    result = _set(wizard, home, "manifest", "features.secrets_scan", "true")
    assert result.returncode == 0, result.stdout
    assert result.stdout == f"changed: {path} features.secrets_scan: false -> true\n"
    assert path.read_text(encoding="utf-8") == before.replace(
        '"secrets_scan": false', '"secrets_scan": true'
    )
    assert stat.S_IMODE(path.stat().st_mode) == mode
    again = _set(wizard, home, "manifest", "features.secrets_scan", "true")
    assert (
        again.returncode == 0
        and again.stdout == f"kept: {path} features.secrets_scan already true\n"
    )


def test_set_keeps_the_config_mode_and_inserts_a_missing_key_at_its_indent(
    wizard: Path, home: Path
) -> None:
    config, manifest = _config(wizard), _manifest(wizard)
    assert _set(wizard, home, "config", "max_concurrent_builders", "3").returncode == 0
    assert stat.S_IMODE(config.stat().st_mode) == 0o600
    before = manifest.read_text(encoding="utf-8")
    assert _set(wizard, home, "manifest", "features.terraform_validate", "true").returncode == 0
    after = manifest.read_text(encoding="utf-8")
    assert '"terraform_tools": false,\n    "terraform_validate": true\n  }' in after
    assert after.replace(',\n    "terraform_validate": true', "") == before


def test_set_writes_the_personal_file_through_its_reader(home: Path, repo_cwd: Path) -> None:
    assert "create the file first" in _refused(
        _set(repo_cwd, home, "operator", "profile.literacy", '"plain"')
    )
    assert _run(["--create-operator"], home).returncode == 0
    result = _set(repo_cwd, home, "operator", "profile.literacy", '"plain"')
    assert result.returncode == 0, result.stdout
    assert 'profile.literacy: absent -> "plain"' in result.stdout
    doc = json.loads(_operator(home).read_text(encoding="utf-8"))
    assert doc == {"main_refusals": [], "profile": {"literacy": "plain"}}
    assert stat.S_IMODE(_operator(home).stat().st_mode) == 0o600


def test_set_refuses_a_key_of_another_file(wizard: Path, home: Path) -> None:
    before = _config(wizard).read_bytes()
    out = _refused(_set(wizard, home, "config", "features.ledger", "true"))
    assert "a setting of the manifest file, not the config file" in out
    assert _config(wizard).read_bytes() == before


@pytest.mark.parametrize("key", ["stack", "features", "dependencies.minimum_release_age"])
def test_set_refuses_a_prefix_of_a_real_key(wizard: Path, home: Path, key: str) -> None:
    before = _manifest(wizard).read_bytes()
    _refused(_set(wizard, home, "manifest", key, "1"))
    assert _manifest(wizard).read_bytes() == before


def test_set_refuses_a_key_inside_a_list_entry(wizard: Path, home: Path) -> None:
    out = _refused(_set(wizard, home, "manifest", "priorities.rules[].note", '"x"'))
    assert "cannot be set alone" in out


def test_set_refuses_a_value_that_breaks_another_key(wizard: Path, home: Path) -> None:
    path = _manifest(wizard)
    doc = json.loads(path.read_text(encoding="utf-8"))
    doc["dependencies"]["minimum_release_age_days"] = 3
    doc["dependencies"]["minimum_release_age_reason"] = "an internal mirror holds new versions"
    path.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    before = path.read_bytes()
    out = _refused(
        _set(wizard, home, "manifest", "dependencies.minimum_release_age_reason", "null")
    )
    assert "dependencies.minimum_release_age_days is below 7 days" in out
    assert path.read_bytes() == before


def test_set_refuses_valid_json_of_the_wrong_type(wizard: Path, home: Path) -> None:
    before = _manifest(wizard).read_bytes()
    out = _refused(_set(wizard, home, "manifest", "features.secrets_scan", '"yes"'))
    assert "features.secrets_scan must be true or false" in out
    assert _manifest(wizard).read_bytes() == before
    assert "is not JSON" in _refused(_set(wizard, home, "manifest", "features.ledger", "yes"))


@pytest.mark.parametrize(
    ("text", "why"),
    [
        ('{"features": {"ledger": false,}}\n', "not valid JSON"),
        ('{"features": {}, "features": {}}\n', "holds the key 'features' twice"),
    ],
)
def test_set_refuses_a_malformed_file(wizard: Path, home: Path, text: str, why: str) -> None:
    _manifest(wizard).write_text(text, encoding="utf-8")
    assert why in _refused(_set(wizard, home, "manifest", "features.ledger", "true"))
    assert _manifest(wizard).read_text(encoding="utf-8") == text


def test_set_refuses_a_symlinked_file(wizard: Path, home: Path, tmp_path: Path) -> None:
    real = tmp_path / "real.json"
    real.write_text('{"features": {"ledger": false}}\n', encoding="utf-8")
    _manifest(wizard).unlink()
    _manifest(wizard).symlink_to(real)
    assert "symlink" in _refused(_set(wizard, home, "manifest", "features.ledger", "true"))
    assert real.read_text(encoding="utf-8") == '{"features": {"ledger": false}}\n'


@pytest.mark.skipif(os.geteuid() == 0, reason="root writes into a read-only folder")
def test_set_refuses_a_read_only_folder(wizard: Path, home: Path) -> None:
    before = _manifest(wizard).read_bytes()
    wizard.chmod(0o500)
    try:
        out = _refused(_set(wizard, home, "manifest", "features.ledger", "true"))
    finally:
        wizard.chmod(0o755)
    assert "could not be written" in out and _manifest(wizard).read_bytes() == before


def test_a_second_set_that_lands_first_is_never_overwritten(
    wizard: Path, home: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # 0242: the rename is atomic, so a reader sees the old file or the new one, never part of
    # one; a set whose file changed after it read it is refused, so the other change stands.
    import daedalus_setup

    monkeypatch.setenv("HOME", str(home))
    real = settings_edit.splice

    def racing(text: str, path: tuple[str, ...], value: object) -> str:
        assert _set(wizard, home, "manifest", "features.ledger", "true").returncode == 0
        return real(text, path, value)

    monkeypatch.setattr(daedalus_setup.settings_edit, "splice", racing)
    args = ["--set", "manifest", "features.secrets_scan", "--value", "true", "--repo", str(wizard)]
    assert daedalus_setup.main(args) == 1
    assert "changed while this command ran" in capsys.readouterr().out
    doc = json.loads(_manifest(wizard).read_text(encoding="utf-8"))
    assert doc["features"]["ledger"] is True and doc["features"]["secrets_scan"] is False


def test_a_changed_manifest_still_loads_in_the_doctor(wizard: Path, home: Path) -> None:
    import daedalus_doctor

    for key, value in (("stack.unit_test_cmd", '["pytest -q"]'), ("docs.literacy", '"plain"')):
        assert _set(wizard, home, "manifest", key, value).returncode == 0
    ok, line = daedalus_doctor._manifest_check(wizard)
    assert ok and line.startswith("OK   service-manifest.json: "), line


@pytest.mark.parametrize(
    "args",
    [
        ["--value", "true"],
        ["--set", "manifest", "features.ledger"],
        ["--set", "settings", "features.ledger", "--value", "true"],
    ],
)
def test_malformed_set_commands_are_refused(wizard: Path, home: Path, args: list[str]) -> None:
    _refused(_run([*args, "--repo", str(wizard)], home))


@pytest.mark.parametrize(
    ("text", "path", "value", "want"),
    [
        ('{"a": {"b": 1}}', ("a", "b"), 2, '{"a": {"b": 2}}'),
        ('{"a": {}}', ("a", "b"), [1], '{"a": {"b": [1]}}'),
        ('{"a": null}', ("a", "b"), True, '{"a": {"b": true}}'),
        ('{"a": 1}', ("c", "d"), "x", '{"a": 1, "c": {"d": "x"}}'),
        ('{\n  "a": 1\n}\n', ("b",), None, '{\n  "a": 1,\n  "b": null\n}\n'),
    ],
)
def test_splice_replaces_or_inserts_only_the_one_value(
    text: str, path: tuple[str, ...], value: object, want: str
) -> None:
    assert settings_edit.splice(text, path, value) == want


def test_each_overlap_answer_rests_on_the_line_it_cites() -> None:
    # 0242: a moved or changed line fails here, so the answer is reread before it ships.
    assert [o.id for o in OVERLAPS] == ["ledger", "literacy", "operator"]
    for overlap in OVERLAPS:
        for path, line, words in overlap.sources:
            text = (REPO_ROOT / path).read_text(encoding="utf-8").splitlines()[line - 1]
            assert words in text, (overlap.id, path, line)


def test_overlaps_with_no_deciding_code_say_so_in_future_tense() -> None:
    literacy = next(o for o in OVERLAPS if o.id == "literacy")
    assert "nothing reads it yet" in literacy.text and "will apply" in literacy.text


def test_every_key_sits_in_exactly_one_group_of_its_file() -> None:
    placed = Counter((group.file, key) for group in GROUPS for key in group.keys)
    assert sorted(k for k, n in placed.items() if n > 1) == []
    assert sorted(set(reference_keys()) - set(placed)) == []
    assert sorted(set(placed) - set(reference_keys())) == []


def test_groups_have_unique_ids_orders_and_plain_titles() -> None:
    assert len({g.id for g in GROUPS}) == len(GROUPS)
    assert sorted(g.order for g in GROUPS) == list(range(1, len(GROUPS) + 1))
    for group in GROUPS:
        assert group.title and "\n" not in group.title and not set(group.title) & set("`_/"), group


def test_day_one_keys_are_group_keys_with_readers() -> None:
    for group in GROUPS:
        assert set(group.day_one) <= set(group.keys), group.id
        for key in group.day_one:
            assert KEY_ROWS[(group.file, key)].readers, (group.id, key)
    day_one = [key for group in GROUPS for key in group.day_one]
    assert day_one == [
        "stack.unit_test_cmd",
        "stack.typecheck_cmd",
        "stack.lint_cmd",
        "stack.package_manager",
        "features.secrets_scan",
        "features.ledger",
        "features.terraform_tools",
        "docs.literacy",
    ]


EXAMPLES = REPO_ROOT / "docs" / "examples"
EXAMPLE_NAMES = {
    "manifest": "service-manifest.example.json",
    "config": "config.example.json",
    "operator": "operator.example.json",
}


def _example(form: str) -> object:
    return json.loads((EXAMPLES / EXAMPLE_NAMES[form]).read_text(encoding="utf-8"))


def _holds(doc: object, key: str) -> bool:
    # 0242: a [] segment looks in any list entry and a <name> segment in any named entry.
    head, _, rest = key.partition(".")
    if head.startswith("<"):
        return isinstance(doc, dict) and any(_holds(v, rest) for v in doc.values())
    name = head.removesuffix("[]")
    if not isinstance(doc, dict) or name not in doc:
        return False
    child = doc[name]
    if head.endswith("[]"):
        return isinstance(child, list) and any(_holds(item, rest) for item in child)
    return not rest or _holds(child, rest)


def test_each_example_loads_through_its_own_reader(tmp_path: Path) -> None:
    from lib.config import Config, load_config
    from lib.ledger import resolve_ledger
    from lib.manifest import load as load_manifest
    from lib.operator_file import validate

    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "service-manifest.json").write_bytes(
        (EXAMPLES / EXAMPLE_NAMES["manifest"]).read_bytes()
    )
    loaded = load_manifest(repo)
    assert loaded is not None and loaded.docs.literacy == "plain"
    found = resolve_ledger(str(repo), Config())
    assert found is not None and found.origin == "manifest"
    config = load_config(path=EXAMPLES / EXAMPLE_NAMES["config"])
    assert config.max_concurrent_builders == 3 and config.policy is not None
    assert validate(_example("operator"), "operator.example.json")["dash_ban"] is True


def test_each_example_sets_every_key_of_its_file() -> None:
    for info in SETTINGS_FILES:
        doc = _example(info.form)
        missing = [k for f, k in KEY_ROWS if f == info.name and not _holds(doc, k)]
        assert missing == [], info.form


def _readme_section() -> str:
    text = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    return text.split("\n### The three settings files\n", 1)[1].split("\n### ", 1)[0]


def test_readme_section_carries_the_file_table_and_the_overlaps() -> None:
    section = _readme_section()
    for info in SETTINGS_FILES:
        row = f"| `{info.name}` | {info.where} | {info.whose} | {info.shared} | {info.holds} |"
        assert row in section, info.form
    for overlap in OVERLAPS:
        assert f"- {overlap.text}\n" in section, overlap.id
    assert "type `/daedalus:setup` again" in section and "docs/examples/" in section


SKILL = REPO_ROOT / "skills" / "setup" / "SKILL.md"
_COMMAND = re.compile(
    r"`(python3 \$\{CLAUDE_SKILL_DIR\}/\.\./\.\./scripts/daedalus_setup\.py[^`]*)`"
)
_FILL = {'"<path>"': ".", "<file>": "manifest", "<key>": "features.ledger", "'<json>'": "true"}


def test_skill_command_lines_parse_with_the_script_parser() -> None:
    # 0242: each command line the skill gives, placeholders filled, is one the parser accepts.
    import daedalus_setup

    lines = _COMMAND.findall(SKILL.read_text(encoding="utf-8"))
    forms = set()
    for line in lines:
        for placeholder, value in _FILL.items():
            line = line.replace(placeholder, value)
        args = daedalus_setup.build_parser().parse_args(shlex.split(line)[2:])
        forms.add(
            "describe"
            if args.describe
            else "create"
            if args.create_operator
            else "set"
            if args.set
            else "starter"
        )
        assert args.set is None or (args.set[0] in daedalus_setup.FORMS and args.value == "true")
    assert forms == {"describe", "create", "set", "starter"}


def test_skill_states_the_question_rules_and_never_asks_a_not_active_setting() -> None:
    text = SKILL.read_text(encoding="utf-8")
    fields = text.split("\n---\n", 1)[0]
    assert "AskUserQuestion" in fields and "daedalus_setup.py *" in fields
    assert "No key name, file path, ruling id or JSON goes in a question" in text
    assert "Never ask it." in text and "not active" in text
    heads = re.findall(r"^\d+\. \*\*(\w[\w ]*)\.\*\*", text, re.MULTILINE)
    assert heads == ["Describe", "Create", "Day one", "More", "Close"]


def test_examples_name_no_home_or_machine_path() -> None:
    for name in EXAMPLE_NAMES.values():
        text = (EXAMPLES / name).read_text(encoding="utf-8")
        assert not re.search(r"/(?:hom[e]|User[s])/|[A-Z]:\\", text), name
