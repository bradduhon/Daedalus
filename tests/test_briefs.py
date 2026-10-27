# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0153, 0157 (12.5): decision briefs are checked at the manifest literacy level.
from __future__ import annotations

import json
import re
from pathlib import Path

import daedalus_train
import pytest
from lib.briefs import (
    MAX_BRIEF_BYTES,
    BriefError,
    brief_file_problems,
    brief_problems,
    level_of,
)

from tests.conftest import REPO_ROOT

# 0017: the public hygiene test refuses a literal issue reference in a tracked file.
ISSUE = "#" + "75"
GOOD = "\n".join(
    [
        "## Question 1",
        "Header: Finding one",
        "Question: A ledger write can land outside the ledger file. What do we do with this "
        "finding?",
        "Context: The write test put a row in the wrong file. The fix should keep rows in one "
        "place.",
        "Options:",
        f"- Fix it now (Recommended): runs a fix round (0133, {ISSUE}, security-auditor).",
        "- Skip, track or exempt it: exempts the finding (snake_case_ok in the description).",
        "- Stop the train: ends the train.",
    ]
)
# 0153: 18 words; over plain's 15, under standard's 22.
LONG = (
    "The audit found that one ledger write can land outside the ledger file when two "
    "trains run together."
)
# 0153: 27 words; over standard's 22 too.
LONGER = LONG[:-1] + " on the same machine at the same time today."
SHIPPED = (
    REPO_ROOT / "agents" / "orchestrator.md",
    REPO_ROOT / "skills" / "catalog" / "SKILL.md",
    REPO_ROOT / "skills" / "plan" / "SKILL.md",
)
# 0153: a shipped example question is quoted and ends in a question mark.
_QUOTED = re.compile(r'"([^"]*\?)"')
# 0149: a shipped option label is a list item whose backticked head starts with a capital.
_LABEL = re.compile(r"^\s*- `([A-Z][^`<\[]*)`:", re.MULTILINE)


def _brief(question: str = "Which file should hold the rows?", context: str = "") -> str:
    lines = ["## Question 1", "Header: Rows", f"Question: {question}"]
    if context:
        lines.append(f"Context: {context}")
    return "\n".join(
        [*lines, "Options:", "- Keep it (Recommended): keeps it.", "- Drop it: drops it."]
    )


def test_a_plain_brief_passes_every_level() -> None:
    for level in ("plain", "standard", "expert", "profile:docs/voice.md"):
        assert brief_problems(GOOD, level) == [], level


def test_sentence_limits_by_level() -> None:
    long_brief = _brief(context=LONG)
    assert len(LONG.split()) == 18 and len(LONGER.split()) == 27
    plain = brief_problems(long_brief, "plain")
    assert plain == [f"Context sentence has 18 words, over 15 at plain: {LONG}"]
    assert brief_problems(long_brief, "standard") == []
    assert brief_problems(_brief(context=LONGER), "standard") == [
        f"Context sentence has 27 words, over 22 at standard: {LONGER}"
    ]
    assert brief_problems(_brief(context=LONGER), "expert") == []


def test_profile_and_unknown_levels_judge_as_plain() -> None:
    long_brief = _brief(context=LONG)
    for level in ("profile:docs/voice.md", "", "loud", "PLAIN"):
        assert level_of(level) == "plain", level
        assert brief_problems(long_brief, level) == brief_problems(long_brief, "plain"), level
    assert level_of(None) == "plain"


@pytest.mark.parametrize(
    ("text", "problem"),
    [
        ("Should `lock` run first?", "Question carries a backtick: Should `lock` run first?"),
        ("Should lock_sha move?", "Question carries the snake_case token lock_sha"),
        ("Should scripts/checks change?", "Question carries the word scripts/checks with a slash"),
        ("Does 0153-DAE-PLT still hold?", "Question carries the ruling id 0153-DAE-PLT"),
        (f"Is {ISSUE} closed by this?", f"Question carries the issue number {ISSUE}"),
        ("Should the verifier run again?", "Question carries the agent name verifier"),
        ("Should the Orchestrator stop?", "Question carries the agent name Orchestrator"),
        ("Is the verifier's table right?", "Question carries the agent name verifier's"),
        ("Was the planner’s cut right?", "Question carries the agent name planner’s"),
        ("Should daedalus:verifier run?", "Question carries the agent name daedalus:verifier"),
        ("Is the repo-coder's branch done?", "Question carries the agent name repo-coder's"),
        ("Is it planner-written?", "Question carries the agent name planner-written"),
    ],
)
def test_token_rules_at_plain_and_standard(text: str, problem: str) -> None:
    for level in ("plain", "standard"):
        assert brief_problems(_brief(text), level) == [problem], level
    assert brief_problems(_brief(text), "expert") == []


def test_token_rules_read_context_and_labels_but_not_descriptions() -> None:
    context = _brief(context="The row lands in docs/x.md today.")
    assert brief_problems(context, "plain") == ["Context carries the word docs/x.md with a slash"]
    label = _brief().replace("- Drop it: drops it.", f"- Drop {ISSUE}: drops it (0153-DAE-PLT).")
    assert brief_problems(label, "plain") == [f"Option label carries the issue number {ISSUE}"]


def test_context_continuation_lines_join_the_field() -> None:
    text = _brief(context="The row lands in one place.").replace(
        "Options:", "  It moved with lock_sha.\nOptions:"
    )
    assert brief_problems(text, "plain") == ["Context carries the snake_case token lock_sha"]


def test_an_ellipsis_does_not_end_a_sentence() -> None:
    # 0153: 22 words around a bare ellipsis count as one sentence, over plain's 15.
    context = (
        "The check printed an error and then ... the train kept going and wrote "
        "a second brief file for the same finding."
    )
    assert len(context.split()) == 22
    assert brief_problems(_brief(context=context), "plain") == [
        f"Context sentence has 22 words, over 15 at plain: {context}"
    ]


def test_main_and_everyday_words_pass() -> None:
    assert brief_problems(_brief("Should this merge into main now?"), "plain") == []


def test_structural_problems() -> None:
    assert brief_problems("Header: x\nOptions:\n- A: a.\n", "plain") == [
        "the brief holds no Question: line"
    ]
    assert brief_problems(
        _brief("Which one?").replace("Question: Which one?", "Question:"), "plain"
    ) == ["Question is empty"]


def test_every_shipped_example_question_and_label_passes_at_plain() -> None:
    questions: list[str] = []
    labels: list[str] = []
    for path in SHIPPED:
        text = path.read_text(encoding="utf-8")
        questions += _QUOTED.findall(text)
        labels += _LABEL.findall(text)
    assert len({p for p in SHIPPED if _QUOTED.search(p.read_text(encoding="utf-8"))}) == 3
    # pin A1 -> P1: the three gate labels are among the shipped labels.
    for gate in ("Fix it now (Recommended)", "Skip, track or exempt it", "Stop the train"):
        assert gate in labels, gate
    for question in questions:
        assert brief_problems(_brief(question), "plain") == [], question
    options = "\n".join(f"- {label}: x." for label in labels)
    brief = f"Question: Which one?\nOptions:\n{options}\n"
    assert brief_problems(brief, "plain") == []


def _repo(tmp_path: Path, literacy: object = None, manifest: bool = True) -> Path:
    repo = tmp_path.resolve() / "repo"
    (repo / "docs" / ".tmp" / "daedalus" / "t" / "decisions").mkdir(parents=True)
    (repo / ".claude" / "daedalus").mkdir(parents=True)
    if manifest:
        body: dict[str, object] = {} if literacy is None else {"docs": {"literacy": literacy}}
        (repo / "service-manifest.json").write_text(json.dumps(body), encoding="utf-8")
    return repo


def _write(repo: Path, text: str) -> Path:
    path = repo / "docs" / ".tmp" / "daedalus" / "t" / "decisions" / "1.md"
    path.write_text(text, encoding="utf-8")
    return path


@pytest.mark.parametrize(
    ("literacy", "manifest", "level"),
    [
        (None, False, "plain"),
        (None, True, "plain"),
        ("plain", True, "plain"),
        ("standard", True, "standard"),
        ("expert", True, "expert"),
        ("profile:docs/voice.md", True, "plain"),
    ],
)
def test_file_level_comes_from_docs_literacy(
    tmp_path: Path, literacy: str | None, manifest: bool, level: str
) -> None:
    repo = _repo(tmp_path, literacy, manifest)
    assert brief_file_problems(repo, _write(repo, GOOD)) == (level, [])


def test_file_outside_scratch_or_missing_or_large_is_refused(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    outside = repo / "brief.md"
    outside.write_text(GOOD, encoding="utf-8")
    link = repo / "docs" / ".tmp" / "daedalus" / "link.md"
    link.symlink_to(outside)
    for path in (outside, link, repo / "docs" / ".tmp" / "daedalus" / "none.md"):
        with pytest.raises(BriefError, match="is not a file under"):
            brief_file_problems(repo, path)
    big = _write(repo, "x" * (MAX_BRIEF_BYTES + 1))
    with pytest.raises(BriefError, match="bytes. Next:"):
        brief_file_problems(repo, big)
    bad = _write(repo, "")
    bad.write_bytes(b"\xff\xfe")
    with pytest.raises(BriefError, match="could not be read"):
        brief_file_problems(repo, bad)


def test_brief_check_command(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    repo = _repo(tmp_path)
    monkeypatch.chdir(repo)
    good = _write(repo, GOOD)
    assert daedalus_train.main(["brief-check", "--repo", str(repo), "--brief", str(good)]) == 0
    assert capsys.readouterr().out == "brief ok\n"
    bad = _write(repo, _brief("Should lock_sha move?", LONG))
    assert daedalus_train.main(["brief-check", "--repo", str(repo), "--brief", str(bad)]) == 1
    out = capsys.readouterr().out.splitlines()
    assert out == [
        "brief: Question carries the snake_case token lock_sha",
        f"brief: Context sentence has 18 words, over 15 at plain: {LONG}",
        "Next: rewrite each named question, context sentence or option label at the plain "
        "level, then run brief-check again.",
    ]
    outside = repo / "x.md"
    outside.write_text(GOOD, encoding="utf-8")
    assert daedalus_train.main(["brief-check", "--repo", str(repo), "--brief", str(outside)]) == 1
    assert "is not a file under" in capsys.readouterr().out


def test_brief_check_stops_on_a_bad_manifest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    repo = _repo(tmp_path, "loud")
    monkeypatch.chdir(repo)
    good = _write(repo, GOOD)
    assert daedalus_train.main(["brief-check", "--repo", str(repo), "--brief", str(good)]) == 1
    assert "docs.literacy" in capsys.readouterr().out


def test_recipes_name_the_check_and_the_literacy_rule() -> None:
    # 0153: the orchestrator checks each brief; every question writer reads docs.literacy.
    orchestrator = (REPO_ROOT / "agents" / "orchestrator.md").read_text(encoding="utf-8")
    decisions = next(ln for ln in orchestrator.splitlines() if "Operator decisions (0060" in ln)
    check = (
        "run `python3 <plugin root>/scripts/daedalus_train.py brief-check --repo <repo> "
        "--brief <path>` on each brief file"
    )
    assert check in decisions
    assert decisions.index("brief-check") < decisions.index("A brief file holds one section")
    assert "rewrite the brief at the same path and run the check again" in decisions
    assert "return `[STATUS: DECISION]` once its brief check prints `brief ok`" in orchestrator
    for path in (
        REPO_ROOT / "agents" / "orchestrator.md",
        REPO_ROOT / "skills" / "plan" / "SKILL.md",
        REPO_ROOT / "skills" / "brainstorm" / "SKILL.md",
    ):
        flat = " ".join(path.read_text(encoding="utf-8").split())
        assert "`docs.literacy` from `<repo>/service-manifest.json`" in flat, path
        assert "`plain` when the file or key is absent" in flat, path
