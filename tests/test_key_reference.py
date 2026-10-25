# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import re

from lib.project_keys import (
    CONFIG_FILE,
    KEY_ROWS,
    MANIFEST_FILE,
    REFERENCE_HEADER,
    config_keys,
    manifest_keys,
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
    return {(MANIFEST_FILE, k) for k in manifest_keys()} | {(CONFIG_FILE, k) for k in config_keys()}


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
        assert file in (MANIFEST_FILE, CONFIG_FILE), key
        # 0031, B7: what it governs, its type, values, default and an example, each in words.
        assert len(cells) == len(REFERENCE_HEADER) - 2 and all(cells), key
        assert not _VERSION.search(" ".join(cells)), key


def test_audit_round_budget_and_agent_models_rows() -> None:
    # 0109, 0110, spec 4: both keys are generated rows in the config section, in that order.
    keys = [key for key, file, _ in _rows() if file == CONFIG_FILE]
    assert keys[-2:] == ["audit_round_budget", "agent_models"]
    budget = KEY_ROWS[(CONFIG_FILE, "audit_round_budget")]
    assert budget.kind == "integer" and budget.default == "`5`"
    assert "from 1 to 10" in budget.values and "refused" in budget.values
    models = KEY_ROWS[(CONFIG_FILE, "agent_models")]
    assert models.kind == "object" and models.default.startswith("`{}`")
    assert '`"sonnet"`, `"opus"`, `"haiku"` or `"fable"`' in models.values
    assert models.example == '`{"repo-coder": "sonnet"}`'


def test_github_feature_row() -> None:
    # issue 48: the row sits after features.ledger and names both doctor outcomes.
    keys = [key for key, file, _ in _rows() if file == MANIFEST_FILE]
    assert keys[keys.index("features.ledger") + 1] == "features.github"
    row = KEY_ROWS[(MANIFEST_FILE, "features.github")]
    assert row.kind == "boolean or null" and row.default.startswith("`false`")
    assert "`MISS`" in row.governs and "`OPT`" in row.governs
    assert "`null` reads as `false`" in row.values


def test_reader_keys_follow_the_reader_dataclasses() -> None:
    # 0076: a field added to a reader adds a key, so the reference test sees it.
    from dataclasses import fields

    from lib.config import Config
    from lib.manifest import FEATURE_KEYS, Manifest

    tops = {key.split(".", 1)[0].removesuffix("[]") for key in config_keys()}
    assert tops == {f.name for f in fields(Config)}
    assert {f"features.{k}" for k in FEATURE_KEYS} <= set(manifest_keys())
    leaves = {key.rsplit(".", 1)[-1] for key in manifest_keys()}
    assert {f.name for f in fields(Manifest)} - {"features"} <= leaves
