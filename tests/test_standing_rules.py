# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import json
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path

import pytest
import standing_rules

from tests.conftest import REPO_ROOT, SCRIPTS_DIR

FIX = REPO_ROOT / "tests" / "fixtures" / "standing-rules"
LEDGER = FIX / "decisions.md"
BACKFILL = FIX / "backfill.json"
EXPECTED = FIX / "expected.md"

Backfill = dict[str, object]


def _args(ledger: Path, backfill: Path, out: Path, *extra: str) -> list[str]:
    return ["--ledger", str(ledger), "--backfill", str(backfill), "--out", str(out), *extra]


def test_fixture_ledger_generates_the_expected_file(tmp_path: Path) -> None:
    out = tmp_path / "standing-rules.md"
    assert standing_rules.main(_args(LEDGER, BACKFILL, out)) == 0
    assert out.read_text(encoding="utf-8") == EXPECTED.read_text(encoding="utf-8")


def test_check_passes_on_the_committed_expected_file() -> None:
    # 0090: the script holds the file equal to its own output.
    out = subprocess.run(
        [sys.executable, str(SCRIPTS_DIR / "standing_rules.py"), *_args(LEDGER, BACKFILL, EXPECTED)]
        + ["--check"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert out.returncode == 0, out.stderr


@pytest.mark.parametrize("drift", ["edited", "missing"])
def test_check_exits_1_on_drift_and_writes_nothing(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], drift: str
) -> None:
    out = tmp_path / "standing-rules.md"
    if drift == "edited":
        out.write_text(EXPECTED.read_text(encoding="utf-8") + "A hand-written line.\n", "utf-8")
    before = out.read_bytes() if out.exists() else None
    assert standing_rules.main(_args(LEDGER, BACKFILL, out, "--check")) == 1
    assert "differs from" in capsys.readouterr().err
    assert (out.read_bytes() if out.exists() else None) == before


def _drop_area(data: Backfill) -> None:
    areas = data["areas"]
    assert isinstance(areas, dict)
    del areas["0007-TST-PLT"]


def _bad_area(data: Backfill) -> None:
    areas = data["areas"]
    assert isinstance(areas, dict)
    areas["0007-TST-PLT"] = "miscellany"


def _stale_area(data: Backfill) -> None:
    areas = data["areas"]
    assert isinstance(areas, dict)
    areas["0099-TST-PLT"] = "operator interaction"


def _drop_relations(data: Backfill) -> None:
    relations = data["relations"]
    assert isinstance(relations, dict)
    del relations["0002-TST-PLT"]


def _late_relations(data: Backfill) -> None:
    relations = data["relations"]
    assert isinstance(relations, dict)
    relations["0006-TST-PLT"] = {"supersedes": [], "amends": []}


def _bad_relations(data: Backfill) -> None:
    relations = data["relations"]
    assert isinstance(relations, dict)
    relations["0002-TST-PLT"] = {"supersedes": "0001-TST-PLT", "amends": []}


def _unknown_cutoff(data: Backfill) -> None:
    data["relations_from"] = "0099-TST-PLT"


def _extra_key(data: Backfill) -> None:
    data["notes"] = "free text"


@pytest.mark.parametrize(
    ("edit", "needle"),
    [
        (_drop_area, "row 0007-TST-PLT is in force but has no area (0090). Next:"),
        (_bad_area, "gives 0007-TST-PLT the area 'miscellany' (0090). Next:"),
        (_stale_area, "backfill areas name ids not in the ledger: 0099-TST-PLT. Next:"),
        (_drop_relations, "row 0002-TST-PLT is before 0005-TST-PLT and has no backfill"),
        (_late_relations, "carries relations for 0006-TST-PLT, which reads its own"),
        (_bad_relations, "must be a list of ids. Next:"),
        (_unknown_cutoff, "relations_from 0099-TST-PLT is not a row of the ledger. Next:"),
        (_extra_key, "is not an object with exactly"),
    ],
)
def test_malformed_backfill_refused(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    edit: Callable[[Backfill], None],
    needle: str,
) -> None:
    data = json.loads(BACKFILL.read_text(encoding="utf-8"))
    edit(data)
    backfill = tmp_path / "backfill.json"
    backfill.write_text(json.dumps(data), encoding="utf-8")
    out = tmp_path / "standing-rules.md"
    assert standing_rules.main(_args(LEDGER, backfill, out)) == 1
    assert needle in capsys.readouterr().err
    assert not out.exists()


@pytest.mark.parametrize(
    ("old", "new", "needle"),
    [
        ("| None. | None |", "| Supersedes: 0099-TST-PLT. | None |", "amends 0099-TST-PLT, which"),
        ("| Amends: 0002-TST-PLT. |", "| Amends: 0007-TST-PLT. |", "amends 0007-TST-PLT, which"),
        ("| 0008-TST-PLT |", "| 0007-TST-PLT |", "ledger id 0007-TST-PLT appears more than once"),
        ("| Supersedes | Follow-ups |", "| Replaces | Follow-ups |", "header lacks supersedes"),
        ("| Pipe escape kept.", "| Pipe | escape kept.", "has 6 cells, the header 5"),
    ],
)
def test_malformed_ledger_refused(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], old: str, new: str, needle: str
) -> None:
    text = LEDGER.read_text(encoding="utf-8")
    assert old in text
    ledger = tmp_path / "decisions.md"
    ledger.write_text(text.replace(old, new), encoding="utf-8")
    out = tmp_path / "standing-rules.md"
    assert standing_rules.main(_args(ledger, BACKFILL, out)) == 1
    err = capsys.readouterr().err
    assert needle in err and "Next:" in err
    assert not out.exists()


def test_first_clause_skips_parens_and_code() -> None:
    clause = standing_rules._first_clause("Keep `a, b` and (c, d) whole, then stop.")
    assert clause == "Keep `a, b` and (c, d) whole"
    assert standing_rules._first_clause("Python 3.12 only.") == "Python 3.12 only"
