# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 109: every judge agent file and judge rulebook carries a method section and a rubric section.
from __future__ import annotations

import re
from pathlib import Path

import pytest
from lib.agent_files import frontmatter

from tests.conftest import REPO_ROOT

# 109: the heading names the judge files use today for each section.
METHOD_HEADINGS = frozenset({"Method", "Procedure"})
RUBRIC_HEADINGS = frozenset({"Rubric", "Severity"})

# 109: judge files that lack a section today; reason names the file and the gap.
KNOWN_GAPS = {
    ("agents/verifier.md", "rubric"): "agents/verifier.md has no Rubric or Severity section",
}

_HEADING = re.compile(r"^##\s+(.+?)\s*$")


def _judge_files() -> list[str]:
    agents = [
        str(p.relative_to(REPO_ROOT))
        for p in sorted((REPO_ROOT / "agents").glob("*.md"))
        if frontmatter(p).get("shape") == "judge"
    ]
    packs = [
        str(p.relative_to(REPO_ROOT)) for p in sorted((REPO_ROOT / "packs/judges").glob("*.md"))
    ]
    return agents + packs


def _headings(path: Path) -> set[str]:
    found = (_HEADING.match(line) for line in path.read_text(encoding="utf-8").splitlines())
    return {m.group(1) for m in found if m}


def _params() -> list[object]:
    out: list[object] = []
    for rel in _judge_files():
        for kind in ("method", "rubric"):
            gap = KNOWN_GAPS.get((rel, kind))
            marks = [pytest.mark.xfail(reason=gap, strict=True)] if gap else []
            out.append(pytest.param(rel, kind, id=f"{rel}-{kind}", marks=marks))
    return out


def test_judge_files_are_found() -> None:
    files = _judge_files()
    assert "agents/auditor.md" in files
    assert "agents/verifier.md" in files
    assert any(f.startswith("packs/judges/") for f in files)


@pytest.mark.parametrize(("rel", "kind"), _params())
def test_judge_file_has_method_and_rubric(rel: str, kind: str) -> None:
    accepted = METHOD_HEADINGS if kind == "method" else RUBRIC_HEADINGS
    assert _headings(REPO_ROOT / rel) & accepted, (
        f"{rel} has no {kind} heading from {sorted(accepted)}"
    )
