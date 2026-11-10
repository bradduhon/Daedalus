# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0242, 0245: the settings wizard's tables, overlaps, script forms, examples and skill.
from __future__ import annotations

import argparse
import copy
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
    BLOCKS,
    CONFIG_FILE,
    GROUPS,
    KEY_ROWS,
    MANIFEST_FILE,
    OVERLAPS,
    SETTINGS_FILES,
    Block,
    SettingsFile,
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


SCAN = "checks.secret_scan_on_push"


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
    assert doc["overlaps"] == [{"id": o.id, "text": o.text, "wins": o.wins} for o in OVERLAPS]
    keys = _keys(doc)
    scan = keys[("manifest", SCAN)]
    row = KEY_ROWS[(MANIFEST_FILE, SCAN)]
    assert scan["affects"] == row.affects and scan["governs"] == row.governs
    assert scan["state"] == "default" and scan["value"] is False and scan["day_one"]
    assert scan["override"] is False
    # 0245: an override is flagged so the skill offers it only in the more step.
    assert keys[("config", "limits.parallel_coders")]["override"] is True
    assert keys[("operator", "reading_level")]["state"] == "absent"
    assert keys[("operator", "reading_level")]["active"] is False
    assert keys[("manifest", "run_output_priority.rules[].note")]["settable"] is False


def test_describe_still_describes_two_files_when_one_is_malformed(wizard: Path, home: Path) -> None:
    _config(wizard).write_text('{"limits": {"parallel_coders": 3},}\n', encoding="utf-8")
    doc = _describe(wizard, home)
    files = _files(doc)
    assert "not valid JSON" in str(files["config"]["malformed"])
    assert files["manifest"]["malformed"] is None and files["operator"]["malformed"] is None
    keys = _keys(doc)
    assert keys[("config", "limits.parallel_coders")]["state"] == "unknown"
    assert keys[("manifest", "docs.decisions_filename")]["state"] == "default"


def test_describe_proposes_commands_from_marker_files_only(wizard: Path, home: Path) -> None:
    (wizard / "pyproject.toml").write_text(
        "[tool.pytest.ini_options]\naddopts = '-q'\n[tool.ruff]\n", encoding="utf-8"
    )
    (wizard / "package.json").write_text('{"scripts": {"test": "vitest"}}', encoding="utf-8")
    (wizard / "pnpm-lock.yaml").write_text("lockfileVersion: 9\n", encoding="utf-8")
    detected = _describe(wizard, home)["detected"]
    assert detected == {
        "commands.unit_test": {
            "value": ["python3 -m pytest -q", "pnpm test"],
            "from": ["pyproject.toml tool pytest ini_options", "package.json scripts test"],
        },
        "commands.lint": {
            "value": "python3 -m ruff check .",
            "from": ["pyproject.toml tool ruff"],
        },
    }


def test_describe_skips_the_terraform_questions_only_without_terraform_files(
    wizard: Path, home: Path
) -> None:
    moot = _describe(wizard, home)["moot"]
    assert isinstance(moot, dict) and "checks.terraform_format" in moot
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
    assert "HOME" in _refused(_set(repo_cwd, value, "operator", "no_long_dashes", "true"))
    assert not (tmp_path / "relative").exists()


def test_set_changes_one_key_and_keeps_every_other_byte(wizard: Path, home: Path) -> None:
    path = _manifest(wizard)
    before = path.read_text(encoding="utf-8")
    mode = stat.S_IMODE(path.stat().st_mode)
    result = _set(wizard, home, "manifest", SCAN, "true")
    assert result.returncode == 0, result.stdout
    assert result.stdout == f"changed: {path} {SCAN}: false -> true\n"
    assert path.read_text(encoding="utf-8") == before.replace(
        '"secret_scan_on_push": false', '"secret_scan_on_push": true'
    )
    assert stat.S_IMODE(path.stat().st_mode) == mode
    again = _set(wizard, home, "manifest", SCAN, "true")
    assert again.returncode == 0 and again.stdout == f"kept: {path} {SCAN} already true\n"


def test_set_names_the_decisions_file_and_keeps_every_other_byte(wizard: Path, home: Path) -> None:
    # 0247: naming the file is the switch; the reader resolves it in the docs folder.
    from lib.config import Config
    from lib.ledger import resolve_ledger

    path = _manifest(wizard)
    before = path.read_text(encoding="utf-8")
    assert resolve_ledger(str(wizard), Config()) is None
    result = _set(wizard, home, "manifest", "docs.decisions_filename", '"decisions.md"')
    assert result.returncode == 0, result.stdout
    assert path.read_text(encoding="utf-8") == before.replace(
        '"decisions_filename": null', '"decisions_filename": "decisions.md"'
    )
    found = resolve_ledger(str(wizard), Config())
    assert found is not None and found.path == wizard / "docs" / "decisions.md"
    out = _refused(_set(wizard, home, "manifest", "docs.decisions_filename", '"docs/d.md"'))
    assert "docs.decisions_filename must be null or a plain file name" in out


def test_set_inserts_a_missing_key_at_its_indent_in_an_existing_group(
    wizard: Path, home: Path
) -> None:
    manifest = _manifest(wizard)
    before = manifest.read_text(encoding="utf-8")
    key, value = "checks.release_banned_terms_file", '"docs/terms.txt"'
    assert _set(wizard, home, "manifest", key, value).returncode == 0
    after = manifest.read_text(encoding="utf-8")
    added = ',\n    "release_banned_terms_file": "docs/terms.txt"'
    assert '"terraform_validate": false' + added + "\n  }" in after
    assert after.replace(added, "") == before


def test_set_on_a_grouped_key_creates_the_absent_group_and_keeps_sibling_bytes(
    wizard: Path, home: Path
) -> None:
    # 0245: an override group is absent from the starter; setting one key creates the group.
    from lib.config import load_config

    config = _config(wizard)
    before = config.read_text(encoding="utf-8")
    result = _set(wizard, home, "config", "limits.parallel_coders", "3")
    assert result.returncode == 0, result.stdout
    after = config.read_text(encoding="utf-8")
    assert after.startswith(before.rstrip().removesuffix("}").rstrip())
    doc, was = json.loads(after), json.loads(before)
    assert doc.pop("limits") == {"parallel_coders": 3} and doc == was
    assert stat.S_IMODE(config.stat().st_mode) == 0o600
    assert load_config(path=config).max_concurrent_builders == 3


def test_set_writes_the_personal_file_through_its_reader(home: Path, repo_cwd: Path) -> None:
    assert "create the file first" in _refused(
        _set(repo_cwd, home, "operator", "reading_level", '"plain"')
    )
    assert _run(["--create-operator"], home).returncode == 0
    result = _set(repo_cwd, home, "operator", "reading_level", '"plain"')
    assert result.returncode == 0, result.stdout
    assert 'reading_level: null -> "plain"' in result.stdout
    doc = json.loads(_operator(home).read_text(encoding="utf-8"))
    assert doc == {**starter_operator(), "reading_level": "plain"}
    assert stat.S_IMODE(_operator(home).stat().st_mode) == 0o600


def test_set_refuses_a_key_of_another_file(wizard: Path, home: Path) -> None:
    before = _config(wizard).read_bytes()
    out = _refused(_set(wizard, home, "config", SCAN, "true"))
    assert "a setting of the manifest file, not the config file" in out
    assert _config(wizard).read_bytes() == before


@pytest.mark.parametrize("key", ["commands", "checks", "packages.minimum_age"])
def test_set_refuses_a_prefix_of_a_real_key(wizard: Path, home: Path, key: str) -> None:
    before = _manifest(wizard).read_bytes()
    _refused(_set(wizard, home, "manifest", key, "1"))
    assert _manifest(wizard).read_bytes() == before


@pytest.mark.parametrize(
    ("form", "key"),
    [
        ("manifest", "features.secrets_scan"),
        ("manifest", "stack.unit_test_cmd"),
        ("manifest", "ledger"),
        ("config", "max_concurrent_builders"),
        ("config", "charter_root"),
        ("operator", "main_refusals"),
        ("operator", "profile.literacy"),
    ],
)
def test_set_refuses_an_old_key_name(wizard: Path, home: Path, form: str, key: str) -> None:
    # 0245: no alias; the old name is not a setting of any file.
    out = _refused(_set(wizard, home, form, key, "true"))
    assert "is not a setting" in out


def test_set_refuses_a_key_inside_a_list_entry(wizard: Path, home: Path) -> None:
    out = _refused(_set(wizard, home, "manifest", "run_output_priority.rules[].note", '"x"'))
    assert "cannot be set alone" in out


def test_set_refuses_a_value_that_breaks_another_key(wizard: Path, home: Path) -> None:
    path = _manifest(wizard)
    doc = json.loads(path.read_text(encoding="utf-8"))
    doc["packages"]["minimum_age_days"] = 3
    doc["packages"]["minimum_age_reason"] = "an internal mirror holds new versions"
    path.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    before = path.read_bytes()
    out = _refused(_set(wizard, home, "manifest", "packages.minimum_age_reason", "null"))
    assert "packages.minimum_age_days is below 7 days" in out
    assert path.read_bytes() == before


def test_set_refuses_valid_json_of_the_wrong_type(wizard: Path, home: Path) -> None:
    before = _manifest(wizard).read_bytes()
    out = _refused(_set(wizard, home, "manifest", SCAN, '"yes"'))
    assert f"{SCAN} must be true or false" in out
    assert _manifest(wizard).read_bytes() == before
    assert "is not JSON" in _refused(_set(wizard, home, "manifest", SCAN, "yes"))


@pytest.mark.parametrize(
    ("text", "why"),
    [
        ('{"checks": {"secret_scan_on_push": false,}}\n', "not valid JSON"),
        ('{"checks": {}, "checks": {}}\n', "holds the key 'checks' twice"),
    ],
)
def test_set_refuses_a_malformed_file(wizard: Path, home: Path, text: str, why: str) -> None:
    _manifest(wizard).write_text(text, encoding="utf-8")
    assert why in _refused(_set(wizard, home, "manifest", SCAN, "true"))
    assert _manifest(wizard).read_text(encoding="utf-8") == text


def test_set_refuses_a_symlinked_file(wizard: Path, home: Path, tmp_path: Path) -> None:
    real = tmp_path / "real.json"
    real.write_text('{"checks": {"secret_scan_on_push": false}}\n', encoding="utf-8")
    _manifest(wizard).unlink()
    _manifest(wizard).symlink_to(real)
    assert "symlink" in _refused(_set(wizard, home, "manifest", SCAN, "true"))
    assert real.read_text(encoding="utf-8") == '{"checks": {"secret_scan_on_push": false}}\n'


@pytest.mark.skipif(os.geteuid() == 0, reason="root writes into a read-only folder")
def test_set_refuses_a_read_only_folder(wizard: Path, home: Path) -> None:
    before = _manifest(wizard).read_bytes()
    wizard.chmod(0o500)
    try:
        out = _refused(_set(wizard, home, "manifest", SCAN, "true"))
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
        name = '"decisions.md"'
        assert _set(wizard, home, "manifest", "docs.decisions_filename", name).returncode == 0
        return real(text, path, value)

    monkeypatch.setattr(daedalus_setup.settings_edit, "splice", racing)
    args = ["--set", "manifest", SCAN, "--value", "true", "--repo", str(wizard)]
    assert daedalus_setup.main(args) == 1
    assert "changed while this command ran" in capsys.readouterr().out
    doc = json.loads(_manifest(wizard).read_text(encoding="utf-8"))
    assert doc["docs"]["decisions_filename"] == "decisions.md"
    assert doc["checks"]["secret_scan_on_push"] is False


def test_a_changed_manifest_still_loads_in_the_doctor(wizard: Path, home: Path) -> None:
    import daedalus_doctor

    for key, value in (("commands.unit_test", '["pytest -q"]'), ("docs.reading_level", '"plain"')):
        assert _set(wizard, home, "manifest", key, value).returncode == 0
    ok, line = daedalus_doctor._manifest_check(wizard)
    assert ok and line.startswith("OK   service-manifest.json: "), line


@pytest.mark.parametrize(
    "args",
    [
        ["--value", "true"],
        ["--set", "manifest", SCAN],
        ["--set", "settings", SCAN, "--value", "true"],
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
    assert [o.id for o in OVERLAPS] == ["docs", "literacy", "operator"]
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


def test_day_one_keys_are_starter_group_keys_with_readers() -> None:
    # 0245: the first walk asks starter keys only; every override waits for the more step.
    for group in GROUPS:
        assert set(group.day_one) <= set(group.keys), group.id
        for key in group.day_one:
            row = KEY_ROWS[(group.file, key)]
            assert row.readers and not row.override, (group.id, key)
    day_one = [key for group in GROUPS for key in group.day_one]
    assert day_one == [
        "commands.unit_test",
        "commands.typecheck",
        "commands.lint",
        "docs.reading_level",
        "docs.decisions_filename",
        "checks.secret_scan_on_push",
        "checks.terraform_format",
    ]


EXAMPLES = REPO_ROOT / "docs" / "examples"
EXAMPLE_NAMES = {
    "manifest": "service-manifest.example.json",
    "config": "config.example.json",
    "operator": "operator.example.json",
}
# 0245: one example with every override set, as a manifest and a config.
FULL_NAMES = {
    "manifest": "service-manifest.all-overrides.example.json",
    "config": "config.all-overrides.example.json",
    "operator": "operator.example.json",
}


def _example(form: str, names: dict[str, str] = EXAMPLE_NAMES) -> object:
    return json.loads((EXAMPLES / names[form]).read_text(encoding="utf-8"))


def _holds(doc: object, key: str) -> bool:
    # 0242: a [] segment looks in any list entry and a <name> segment in any named entry.
    head, _, rest = key.partition(".")
    if head.startswith("<"):
        values = doc.values() if isinstance(doc, dict) else ()
        return any(not rest or _holds(v, rest) for v in values)
    name = head.removesuffix("[]")
    if not isinstance(doc, dict) or name not in doc:
        return False
    child = doc[name]
    if head.endswith("[]"):
        return isinstance(child, list) and any(_holds(item, rest) for item in child)
    return not rest or _holds(child, rest)


def _present(doc: object, key: str) -> bool:
    # 0076: a key under a list or null parent is present when its parent is.
    head, _, rest = key.partition(".")
    name = head.removesuffix("[]")
    if not isinstance(doc, dict) or name not in doc:
        return False
    child = doc[name]
    return not rest or not isinstance(child, dict) or _present(child, rest)


def test_each_example_loads_through_its_own_reader(tmp_path: Path) -> None:
    from lib.config import Config, load_config
    from lib.ledger import resolve_ledger
    from lib.manifest import load as load_manifest
    from lib.operator_file import validate

    repo = tmp_path / "repo"
    repo.mkdir()
    target = repo / "service-manifest.json"
    target.write_bytes((EXAMPLES / EXAMPLE_NAMES["manifest"]).read_bytes())
    loaded = load_manifest(repo)
    assert loaded is not None and loaded.docs.literacy == "standard"
    assert resolve_ledger(str(repo), Config()) is None
    target.write_bytes((EXAMPLES / FULL_NAMES["manifest"]).read_bytes())
    loaded = load_manifest(repo)
    assert loaded is not None and loaded.trains_dir == "runs"
    found = resolve_ledger(str(repo), Config())
    assert found is not None and found.path == repo / "docs" / "decisions.md"
    assert found.branch == "main"
    assert len(load_config(path=EXAMPLES / EXAMPLE_NAMES["config"]).standards_sources) == 2
    config = load_config(path=EXAMPLES / FULL_NAMES["config"])
    assert config.max_concurrent_builders == 3 and config.policy is not None
    assert validate(_example("operator"), "operator.example.json") == {
        "main_refusals": (),
        "guidance_source": "claude",
    }


@pytest.mark.parametrize("info", SETTINGS_FILES, ids=lambda f: f.form)
def test_the_starter_examples_hold_every_starter_key_and_no_override(info: SettingsFile) -> None:
    # 0245: spec section 3; an override stays out of the files a new project gets.
    doc = _example(info.form)
    rows = [(k, row) for (f, k), row in KEY_ROWS.items() if f == info.name]
    assert [k for k, row in rows if not row.override and not _present(doc, k)] == []
    assert [k for k, row in rows if row.override and _holds(doc, k)] == []


@pytest.mark.parametrize("form", ["manifest", "config"])
def test_the_all_overrides_example_sets_every_key_of_its_file(form: str) -> None:
    doc = _example(form, FULL_NAMES)
    name = MANIFEST_FILE if form == "manifest" else CONFIG_FILE
    assert [k for f, k in KEY_ROWS if f == name and not _holds(doc, k)] == []


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


_FORM_OF = {f.name: f.form for f in SETTINGS_FILES}


@pytest.mark.parametrize("block", BLOCKS, ids=lambda b: f"{_FORM_OF[b.file]}-{b.key}")
def test_each_block_reader_refuses_exactly_its_missing_required_members(
    block: Block, tmp_path: Path
) -> None:
    # 0242: the block table is checked against the readers here, never found by trial in code.
    import daedalus_setup

    form = _FORM_OF[block.file]
    members = [k for f, k in KEY_ROWS if f == block.file and k.startswith(block.key + ".")]
    assert list(block.members) == members and set(block.required) <= set(members)
    path = tmp_path / ".claude" / "daedalus" / "x.json"
    doc = _example(form, FULL_NAMES)
    assert isinstance(doc, dict)
    daedalus_setup._check(form, doc, path)
    for member in block.members:
        trimmed = copy.deepcopy(doc)
        del trimmed[block.key][member.rsplit(".", 1)[1]]
        if member in block.required:
            with pytest.raises(ValueError):
                daedalus_setup._check(form, trimmed, path)
        else:
            daedalus_setup._check(form, trimmed, path)
    daedalus_setup._check(form, {**doc, block.key: None}, path)


@pytest.mark.parametrize("info", SETTINGS_FILES, ids=lambda f: f.form)
def test_no_other_object_block_refuses_a_lone_member(info: SettingsFile, tmp_path: Path) -> None:
    import daedalus_setup

    doc = _example(info.form, FULL_NAMES)
    assert isinstance(doc, dict)
    blocks = {b.key for b in BLOCKS if b.file == info.name}
    parents: dict[str, list[str]] = {}
    for file, key in KEY_ROWS:
        head, _, leaf = key.partition(".")
        if file == info.name and leaf and "[]" not in key and "<" not in key:
            parents.setdefault(head, []).append(leaf.split(".")[0])
    for parent, leaves in parents.items():
        if parent in blocks:
            continue
        for leaf in leaves:
            lone = {**doc, parent: {leaf: doc[parent][leaf]}}
            daedalus_setup._check(info.form, lone, tmp_path / "x.json")


SITE = {"url": "http://localhost:5173", "instructions": "The page loads."}


def _value_file(tmp_path: Path, value: object, name: str = "value.json") -> Path:
    path = tmp_path / name
    path.write_text(json.dumps(value), encoding="utf-8")
    return path


def test_describe_marks_each_block_with_its_members_in_asking_order(
    wizard: Path, home: Path
) -> None:
    doc = _describe(wizard, home)
    blocks = doc["blocks"]
    assert isinstance(blocks, list)
    assert [(b["file"], b["key"]) for b in blocks] == [
        ("manifest", "local_testing"),
        ("config", "policy"),
    ]
    site = blocks[0]
    assert site["members"] == ["local_testing.url", "local_testing.instructions"]
    assert site["required"] == site["members"] and site["state"] == "absent"
    keys = _keys(doc)
    assert keys[("config", "policy.engine")]["block"] == "policy"
    assert keys[("manifest", SCAN)]["block"] is None


def test_a_block_set_passes_and_keeps_every_other_byte(
    wizard: Path, home: Path, tmp_path: Path
) -> None:
    from lib.manifest import load as load_manifest

    path = _manifest(wizard)
    before = path.read_text(encoding="utf-8")
    value = _value_file(tmp_path, SITE)
    args = ["--set", "manifest", "local_testing", "--value-file", str(value)]
    result = _run([*args, "--repo", str(wizard)], home)
    assert result.returncode == 0, result.stdout
    assert result.stdout.startswith(f"changed: {path} local_testing: null -> {{")
    assert path.read_text(encoding="utf-8") == before.replace(
        '"local_testing": null', '"local_testing": ' + json.dumps(SITE)
    )
    loaded = load_manifest(wizard)
    assert loaded is not None and loaded.dev_server is not None
    assert loaded.dev_server.check == "The page loads."


def test_a_block_missing_a_required_member_is_refused_by_its_reader(
    wizard: Path, home: Path
) -> None:
    before = _manifest(wizard).read_bytes()
    site = '{"url": "http://localhost:5173"}'
    out = _refused(_set(wizard, home, "manifest", "local_testing", site))
    assert "local_testing lacks instructions" in out
    out = _refused(_set(wizard, home, "config", "policy", '{"engine": "conftest"}'))
    assert "config.json policy needs engine and path" in out
    # 0242: a lone member of a null block is refused the same way, by its reader.
    out = _refused(_set(wizard, home, "manifest", "local_testing.url", '"http://localhost:5173"'))
    assert "local_testing lacks instructions" in out
    assert _manifest(wizard).read_bytes() == before


def test_a_block_member_the_table_does_not_list_is_refused_by_name(
    wizard: Path, home: Path
) -> None:
    before = _config(wizard).read_bytes()
    value = '{"engine": "conftest", "path": "/work/policy", "shape": 1}'
    assert "has no setting named shape" in _refused(_set(wizard, home, "config", "policy", value))
    assert "takes an object" in _refused(_set(wizard, home, "manifest", "local_testing", "3"))
    assert _config(wizard).read_bytes() == before


def test_set_never_writes_an_unknown_top_level_config_key(wizard: Path, home: Path) -> None:
    # 0242, 0241: the key table refuses the key, and the config reader refuses a file holding one.
    path = _config(wizard)
    assert "is not a setting" in _refused(_set(wizard, home, "config", "mystery", "1"))
    doc = json.loads(path.read_text(encoding="utf-8"))
    path.write_text(json.dumps({**doc, "mystery": 1}, indent=2) + "\n", encoding="utf-8")
    before = path.read_bytes()
    out = _refused(_set(wizard, home, "config", "limits.parallel_coders", "3"))
    assert "has unknown keys ['mystery']" in out
    assert path.read_bytes() == before


def test_null_clears_a_block(wizard: Path, home: Path) -> None:
    path = _manifest(wizard)
    before = path.read_text(encoding="utf-8")
    assert _set(wizard, home, "manifest", "local_testing", json.dumps(SITE)).returncode == 0
    doc = json.loads(path.read_text(encoding="utf-8"))
    assert doc["local_testing"]["instructions"] == "The page loads."
    cleared = _set(wizard, home, "manifest", "local_testing", "null")
    assert cleared.returncode == 0 and "local_testing: {" in cleared.stdout
    assert path.read_text(encoding="utf-8") == before


def test_value_file_carries_text_a_command_line_would_need_to_escape(
    wizard: Path, home: Path, tmp_path: Path
) -> None:
    command = "ruff check . > /dev/null && echo '$HOME'"
    value = _value_file(tmp_path, command)
    args = ["--set", "manifest", "commands.lint", "--value-file", str(value)]
    result = _run([*args, "--repo", str(wizard)], home)
    assert result.returncode == 0, result.stdout
    doc = json.loads(_manifest(wizard).read_text(encoding="utf-8"))
    assert doc["commands"]["lint"] == command


def test_value_file_refusals(wizard: Path, home: Path, tmp_path: Path) -> None:
    before = _manifest(wizard).read_bytes()
    good = _value_file(tmp_path, True)
    base = ["--set", "manifest", SCAN, "--repo", str(wizard)]
    both = _refused(_run([*base, "--value", "true", "--value-file", str(good)], home))
    assert "exactly one of --value and --value-file" in both
    assert "exactly one" in _refused(_run(base, home))
    alone = _refused(_run(["--value-file", str(good), "--repo", str(wizard)], home))
    assert "go only with --set" in alone
    link = tmp_path / "link.json"
    link.symlink_to(good)
    assert "is a symlink" in _refused(_run([*base, "--value-file", str(link)], home))
    big = tmp_path / "big.json"
    big.write_text('"' + "x" * settings_edit.MAX_BYTES + '"', encoding="utf-8")
    assert "is larger than" in _refused(_run([*base, "--value-file", str(big)], home))
    bad = tmp_path / "bad.json"
    bad.write_text("yes please", encoding="utf-8")
    assert "is not JSON" in _refused(_run([*base, "--value-file", str(bad)], home))
    missing = str(tmp_path / "missing.json")
    assert "could not be opened" in _refused(_run([*base, "--value-file", missing], home))
    assert _manifest(wizard).read_bytes() == before


SKILL = REPO_ROOT / "skills" / "setup" / "SKILL.md"
_COMMAND = re.compile(
    r"`(python3 \$\{CLAUDE_SKILL_DIR\}/\.\./\.\./scripts/daedalus_setup\.py[^`]*)`"
)
_FILL = {
    '"<path>"': ".",
    "<file>": "manifest",
    "<key>": SCAN,
    "<block>": "local_testing",
    "'<json>'": "true",
    '"<value file>"': "value-1.json",
}


def _form(args: argparse.Namespace) -> str:
    if args.describe:
        return "describe"
    if args.create_operator:
        return "create"
    if args.set is None:
        return "starter"
    kind = "block" if args.set[1] == "local_testing" else "key"
    return f"set {kind} by {'file' if args.value_file else 'value'}"


def test_skill_command_lines_parse_with_the_script_parser() -> None:
    # 0242: each command line the skill gives, placeholders filled, is one the parser accepts.
    import daedalus_setup

    lines = _COMMAND.findall(SKILL.read_text(encoding="utf-8"))
    forms = set()
    for line in lines:
        for placeholder, value in _FILL.items():
            line = line.replace(placeholder, value)
        args = daedalus_setup.build_parser().parse_args(shlex.split(line)[2:])
        forms.add(_form(args))
        if args.set is not None:
            assert args.set[0] in daedalus_setup.FORMS
            assert (args.value, args.value_file) in (("true", None), (None, "value-1.json"))
            if args.set[1] == "local_testing":
                assert daedalus_setup.block_of(MANIFEST_FILE, "local_testing") is not None
    assert forms == {
        "describe",
        "create",
        "starter",
        "set key by value",
        "set key by file",
        "set block by file",
    }


def test_skill_states_the_question_rules_and_never_asks_a_not_active_setting() -> None:
    text = SKILL.read_text(encoding="utf-8")
    fields = text.split("\n---\n", 1)[0]
    assert "AskUserQuestion" in fields and "daedalus_setup.py *" in fields
    assert "No key name, file path, ruling id or JSON goes in a question" in text
    assert "Never ask it." in text and "not active" in text
    heads = re.findall(r"^\d+\. \*\*(\w[\w ]*)\.\*\*", text, re.MULTILINE)
    assert heads == ["Describe", "Create", "Day one", "More", "Close"]


def test_skill_offers_overrides_only_in_the_more_step_and_asks_for_decisions() -> None:
    # 0245, 0247: the day-one step skips every override; decisions are asked with a not-now answer.
    text = SKILL.read_text(encoding="utf-8")
    day_one = text.split("**Day one.**", 1)[1].split("**More.**", 1)[0]
    more = text.split("**More.**", 1)[1].split("**Close.**", 1)[0]
    assert "its `override` value is true: skip it" in day_one
    assert "a key whose `override` value is true" in more
    assert "Do you want decisions recorded" in day_one and "Not now" in day_one


def test_examples_name_no_home_or_machine_path() -> None:
    for name in {*EXAMPLE_NAMES.values(), *FULL_NAMES.values()}:
        text = (EXAMPLES / name).read_text(encoding="utf-8")
        assert not re.search(r"/(?:hom[e]|User[s])/|[A-Z]:\\", text), name
