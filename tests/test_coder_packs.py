# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 227: the coder method packs keep the baseline line shape, eight rows at most and no source names.
from __future__ import annotations

import re

import pytest

from tests.conftest import REPO_ROOT

CODER_PACKS = REPO_ROOT / "packs" / "coder"
PACK_PREFIX = {
    "secure-architecture": "SA",
    "adversarial-coding": "AC",
    "shell-semantics": "SS",
}
COPYRIGHT = (REPO_ROOT / "packs" / "baseline" / "rules.md").read_text().splitlines()[0]
MAX_ROWS = 8
FORBIDDEN = (
    "O'Reilly",
    "Adkins",
    "Beyer",
    "Blankinship",
    "Lewandowski",
    "Oprea",
    "Stubblefield",
    "Building Secure",
    "Fitzpatrick",
    "Mom Test",
    "Kaner",
    "chapter",
    "ch.",
    "p.",
    "ISBN",
)
_RULE = re.compile(r"- ([A-Z]+)-(\d+): \S.*")


def _forbidden_hits(text: str) -> list[str]:
    # A token starting with a letter matches only at a word start, so "p." never hits "step.".
    return [
        token
        for token in FORBIDDEN
        if re.search(rf"(?<![A-Za-z]){re.escape(token)}", text, re.IGNORECASE)
    ]


def _problems(text: str, prefix: str) -> list[str]:
    lines = text.splitlines()
    problems: list[str] = []
    if not lines or lines[0] != COPYRIGHT:
        problems.append("first line is not the copyright comment")
    if "## Rules" not in lines:
        return [*problems, "no ## Rules section"]
    body = [line for line in lines[lines.index("## Rules") + 1 :] if line.strip()]
    if len(body) % 3:
        problems.append(f"{len(body)} lines is not whole rule rows of three")
    rows = [body[i : i + 3] for i in range(0, len(body), 3)]
    for n, row in enumerate(rows, 1):
        rule = _RULE.fullmatch(row[0])
        if rule is None or rule.group(1) != prefix or int(rule.group(2)) != n:
            problems.append(f"row {n}: {row[0]!r} is not `- {prefix}-{n}: <rule>`")
        if len(row) < 2 or not row[1].startswith("  Check: "):
            problems.append(f"row {n}: no indented Check: line")
        if len(row) < 3 or not row[2].startswith("  Why: "):
            problems.append(f"row {n}: no indented Why: line")
    if len(rows) > MAX_ROWS:
        problems.append(f"{len(rows)} rows is more than {MAX_ROWS}")
    problems.extend(f"forbidden token {token!r}" for token in _forbidden_hits(text))
    return problems


def test_the_coder_packs_are_the_kept_named_files() -> None:
    found = sorted(p.relative_to(CODER_PACKS).as_posix() for p in CODER_PACKS.rglob("*.md"))
    assert found == sorted(f"{name}/rules.md" for name in PACK_PREFIX)


@pytest.mark.parametrize(("name", "prefix"), sorted(PACK_PREFIX.items()))
def test_each_pack_keeps_the_rule_shape_and_holds_no_source_name(name: str, prefix: str) -> None:
    assert _problems((CODER_PACKS / name / "rules.md").read_text(), prefix) == []


def _rows(prefix: str, count: int) -> str:
    rows = [
        f"- {prefix}-{n}: Do it.\n  Check: it is done.\n  Why: it matters.\n"
        for n in range(1, count + 1)
    ]
    return f"{COPYRIGHT}\n# pack\n\nIntro.\n\n## Rules\n\n{''.join(rows)}"


def test_a_row_without_its_why_line_is_refused() -> None:
    text = _rows("SA", 2).replace("  Why: it matters.\n", "", 1)
    assert any("Why:" in p for p in _problems(text, "SA"))


def test_a_row_without_its_check_line_is_refused() -> None:
    text = _rows("SA", 2).replace("  Check: it is done.\n", "", 1)
    assert any("Check:" in p for p in _problems(text, "SA"))


def test_nine_rows_are_refused_and_eight_admitted() -> None:
    assert _problems(_rows("AC", 8), "AC") == []
    assert _problems(_rows("AC", 9), "AC") == ["9 rows is more than 8"]


def test_ids_out_of_order_or_another_prefix_are_refused() -> None:
    assert _problems(_rows("SA", 3).replace("SA-2:", "SA-3:", 1), "SA")
    assert _problems(_rows("SA", 3).replace("SA-2:", "AC-2:", 1), "SA")


@pytest.mark.parametrize("token", FORBIDDEN)
def test_a_forbidden_token_in_another_case_is_refused(token: str) -> None:
    variant = token.swapcase()
    text = _rows("SA", 1).replace("Do it.", f"Do it, see {variant} 4.")
    assert _problems(text, "SA") == [f"forbidden token {token!r}"]


@pytest.mark.parametrize("word", ["step.", "each.", "help."])
def test_a_word_ending_in_a_short_token_is_not_a_hit(word: str) -> None:
    assert _forbidden_hits(f"Run the {word}") == []
