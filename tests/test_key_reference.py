# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import json
import re
from pathlib import Path

from lib.project_keys import (
    CONFIG_FILE,
    KEY_ROWS,
    MANIFEST_FILE,
    NOT_ACTIVE,
    OPERATOR_FILE_NAME,
    REFERENCE_HEADER,
    config_keys,
    manifest_keys,
    operator_keys,
    reference_table,
)

from tests.conftest import REPO_ROOT

BEGIN = "<!-- key reference -->"
END = "<!-- end key reference -->"
_ROW = re.compile(r"^\| `([^`]+)` \| `([^`]+)` \|(.*)\|\s*$")
# 0065: a row never carries a version literal; VERSION and the manifests own it.
_VERSION = re.compile(r"\bv?\d+\.\d+\.\d+\b")


def _block() -> str:
    text = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    assert text.count(BEGIN) == 1 and text.count(END) == 1
    return text.split(BEGIN, 1)[1].split(END, 1)[0]


def _rows() -> list[tuple[str, str, list[str]]]:
    rows = []
    for line in _block().splitlines():
        match = _ROW.match(line)
        if match:
            cells = [cell.strip() for cell in match.group(3).split(" | ")]
            rows.append((match.group(1), match.group(2), cells))
    return rows


def _reader_pairs() -> set[tuple[str, str]]:
    return (
        {(MANIFEST_FILE, k) for k in manifest_keys()}
        | {(CONFIG_FILE, k) for k in config_keys()}
        | {(OPERATOR_FILE_NAME, k) for k in operator_keys()}
    )


def test_readme_key_reference_is_the_generated_table() -> None:
    # B7: the README carries reference_table() verbatim between its markers.
    assert _block().strip("\n") == reference_table().strip("\n")


def test_every_reader_key_has_a_generator_row() -> None:
    # B7: a key a reader accepts with no KEY_ROWS entry fails here, before the README test.
    assert sorted(_reader_pairs() - set(KEY_ROWS)) == []
    assert sorted(set(KEY_ROWS) - _reader_pairs()) == []


def test_every_reader_key_has_a_reference_row() -> None:
    documented = {(file, key) for key, file, _ in _rows()}
    assert sorted(_reader_pairs() - documented) == []


def test_every_reference_row_names_a_reader_key() -> None:
    rows = [(file, key) for key, file, _ in _rows()]
    assert len(rows) == len(set(rows)), "a key has two rows"
    assert sorted(set(rows) - _reader_pairs()) == []


def test_reference_rows_name_their_file() -> None:
    rows = _rows()
    assert rows, "no key reference rows between the markers"
    for key, file, cells in rows:
        assert file in (MANIFEST_FILE, CONFIG_FILE, OPERATOR_FILE_NAME), key
        # 0031, B7: what it governs, its type, values, default and an example, each in words.
        assert len(cells) == len(REFERENCE_HEADER) - 2 and all(cells), key
        assert not _VERSION.search(" ".join(cells)), key


def test_models_agents_row_names_the_catalog_models() -> None:
    # 0110, 0245: the per-agent model map is an override inside the models group.
    keys = [key for key, file, _ in _rows() if file == CONFIG_FILE]
    assert "audit_round_budget" not in keys and "agent_models" not in keys
    models = KEY_ROWS[(CONFIG_FILE, "models.agents")]
    assert models.kind == "object" and models.default.startswith("`{}`") and models.override
    assert '`"sonnet"`, `"opus"`, `"haiku"` or `"fable"`' in models.values
    # 0187: inside a run models.coder sets the coder, so the example names another agent.
    assert models.example == '`{"planner": "sonnet"}`'


def test_no_row_keeps_a_cut_or_renamed_key() -> None:
    # 0172, 0245, 0247: no old name has a row; the switches live in the checks group.
    keys = {key for key, _, _ in _rows()}
    assert not {k for k in keys if k.startswith(("features.", "stack.", "priorities."))}
    for old in OLD_TOP_NAMES:
        assert old not in keys and not any(k.startswith(old + ".") for k in keys), old


def test_reader_keys_follow_the_reader_tables() -> None:
    # 0245: the readers' name tables are the one source of every key name.
    from lib.config import CONFIG_KEYS, LIMIT_KEYS, MODEL_KEYS, RULE_SOURCE_KEYS
    from lib.manifest import (
        CHECK_KEYS,
        COMMAND_KEYS,
        COMPLIANCE_KEYS,
        DOCS_KEYS,
        EXEMPTION_KEYS,
        LOCAL_TESTING_KEYS,
        PACKAGE_KEYS,
        PRIORITY_ROWS,
        PROHIBITED_KEYS,
        TOP_KEYS,
    )
    from lib.operator_file import TOP_KEYS as OPERATOR_TOP_KEYS

    def tops(keys: tuple[str, ...]) -> set[str]:
        return {key.split(".", 1)[0].removesuffix("[]") for key in keys}

    assert tops(manifest_keys()) == set(TOP_KEYS)
    assert tops(config_keys()) == set(CONFIG_KEYS)
    assert set(operator_keys()) == set(OPERATOR_TOP_KEYS)
    groups = {
        "commands": COMMAND_KEYS,
        "docs": DOCS_KEYS,
        "checks": CHECK_KEYS,
        "prohibited_writes": PROHIBITED_KEYS,
        "code_review_exemptions": EXEMPTION_KEYS,
        "packages": PACKAGE_KEYS,
        "local_testing": LOCAL_TESTING_KEYS,
        "compliance_rules": COMPLIANCE_KEYS,
        "run_output_priority": PRIORITY_ROWS,
    }
    for group, names in groups.items():
        want = {f"{group}.{name}" for name in names}
        assert want == {k for k in manifest_keys() if k.startswith(group + ".")}, group
    assert {f"models.{k}" for k in MODEL_KEYS} <= set(config_keys())
    assert {f"limits.{k}" for k in LIMIT_KEYS} <= set(config_keys())
    assert {f"coding_rules[].{k}" for k in RULE_SOURCE_KEYS} <= set(config_keys())


def test_every_named_reader_exists_and_names_the_key() -> None:
    # 0242: a reader is a real file whose text names the key's last segment.
    bad = []
    for (file, key), row in KEY_ROWS.items():
        leaf = key.rsplit(".", 1)[-1].removesuffix("[]")
        for reader in row.readers:
            path = REPO_ROOT / reader
            if not path.is_file() or leaf not in path.read_text(encoding="utf-8"):
                bad.append(f"{file} {key}: {reader}")
    assert bad == []


def test_every_affects_is_one_plain_sentence() -> None:
    # 0242: the wizard puts affects into a question, so it holds no key name, path or id.
    for (file, key), row in KEY_ROWS.items():
        text = row.affects
        assert text and text.endswith(".") and text[0].isupper(), (file, key)
        assert not set(text) & set("`_/<>"), (file, key, text)
        assert text.count(". ") == 0, (file, key, text)


def test_a_key_without_readers_says_it_is_not_active() -> None:
    # 0242: readers=() and the not-active opening go together, both ways.
    for (file, key), row in KEY_ROWS.items():
        assert (row.readers == ()) == row.affects.startswith(NOT_ACTIVE), (file, key)


# 0245: spec section 1; plugin vocabulary never names a key.
BANNED_WORDS = frozenset(
    {"train", "jail", "wrapper", "unit", "ledger", "charter", "standing", "pack", "driver"}
)
# 0245: spec section 4 names these as written, so the rule test lists them by name.
NAMED_BY_THE_SPEC = {
    "checks.secret_scan_on_push": "four words, named in spec section 4",
    "checks.release_banned_terms_file": "four words, named in spec section 4",
    "models.coder_on_plugin_files": "four words, named in spec section 4",
    "commands.unit_test": "the word unit, named in spec section 4",
    "run_output_priority.principles[].priority": "repeats its group word, spec section 4",
}
OLD_TOP_NAMES = (
    "features",
    "stack",
    "jail_narrowing",
    "assets",
    "dev_server",
    "dependencies",
    "frameworks",
    "priorities",
    "trains_dir",
    "ledger",
    "charter_root",
    "standing_rules",
    "excluded_roots",
    "standards_sources",
    "operator_signing_keys",
    "max_concurrent_builders",
    "audit_retention_days",
    "wrapper_read_roots",
    "unit_token_budget",
    "coder_models",
    "fable_available",
    "agent_models",
    "operator",
    "main_refusals",
    "profile",
    "manifest_version",
    "service_name",
    "purpose",
)


def _words(segment: str) -> list[str]:
    return segment.removesuffix("[]").strip("<>").split("_")


def test_every_key_name_follows_the_naming_rule() -> None:
    # 0245: lowercase words of plain English, at most three per name, no plugin vocabulary.
    bad = []
    for file, key in KEY_ROWS:
        if key in NAMED_BY_THE_SPEC:
            continue
        segments = key.split(".")
        group = segments[0]
        for segment in segments:
            words = _words(segment)
            if not re.fullmatch(r"<?[a-z][a-z_]*(\[\])?>?", segment) or len(words) > 3:
                bad.append((file, key, segment))
            if BANNED_WORDS & set(words):
                bad.append((file, key, segment))
            if segment != group and set(_words(group)) & set(words):
                bad.append((file, key, segment))
    assert bad == []
    assert set(NAMED_BY_THE_SPEC) <= {key for _, key in KEY_ROWS}


def _settings_files() -> list[tuple[str, str]]:
    # 0245: every tracked settings file in the repository, with the reader form it takes.
    import subprocess

    listed = subprocess.run(
        ["git", "-C", str(REPO_ROOT), "ls-files", "*.json"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.split()
    out = []
    for path in listed:
        name = path.rsplit("/", 1)[-1]
        if name == "service-manifest.json" or name.startswith("service-manifest."):
            out.append((path, "manifest"))
        elif path.startswith("evals/fixtures/") and name == "manifest.json":
            out.append((path, "manifest"))
        elif name == "daedalus-config.json" or (
            path.startswith("docs/examples/") and name.startswith("config.")
        ):
            out.append((path, "config"))
        elif path.startswith("docs/examples/") and name.startswith("operator."):
            out.append((path, "operator"))
    return out


def test_every_tracked_settings_file_loads_through_its_reader(tmp_path: Path) -> None:
    # 0245: each reader refuses an unknown key at every level, so no old name survives.
    from lib.config import load_config
    from lib.manifest import load as load_manifest
    from lib.operator_file import validate

    files = _settings_files()
    assert len(files) >= 16, files
    for path, form in files:
        source = REPO_ROOT / path
        if form == "manifest":
            (tmp_path / "service-manifest.json").write_bytes(source.read_bytes())
            assert load_manifest(tmp_path) is not None, path
        elif form == "config":
            load_config(path=source)
        else:
            validate(json.loads(source.read_text(encoding="utf-8")), path)


OLD_DOTTED = re.compile(
    r"features\.[a-z_]+|stack\.[a-z_]+_cmd|stack\.package_manager|docs\.literacy"
    r"|jail_narrowing|dependencies\.installs|dependencies\.minimum_release_age\w*|dev_server\."
    r"|trains_dir|wrapper_read_roots|unit_token_budget|coder_models|audit_retention_days"
    r"|standards_sources|operator_signing_keys|profile\.(?:literacy|dash_ban)"
    r"|priorities\.(?:drivers|rules|principles|agents)|max_concurrent_builders"
    r"|frameworks\.(?:pack_dir|default_packs|packs)|assets\.(?:roots|extensions|max_bytes)"
)
PROSE = ("README.md", "docs/howto/README.md", "docs/project-requirements.md")


def test_no_doc_skill_or_agent_names_an_old_key() -> None:
    # 0245: the README, the guides, every skill and agent file and the judge books use new names.
    paths = [REPO_ROOT / p for p in PROSE]
    for folder in ("skills", "agents", "packs"):
        paths += sorted((REPO_ROOT / folder).rglob("*.md"))
    found = []
    for path in paths:
        for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            found += [f"{path.relative_to(REPO_ROOT)}:{n}: {m}" for m in OLD_DOTTED.findall(line)]
    assert found == []
