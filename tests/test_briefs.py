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
    SECURITY_WORDS,
    BriefError,
    ask_file_problems,
    ask_problems,
    brief_file_problems,
    brief_problems,
    fixed_words,
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
        f"- Fix it now (Recommended): runs a fix round (0133, {ISSUE}, auditor).",
        "- Skip, track or exempt it: exempts the finding (snake_case_ok in the description).",
        "- Stop the run: ends the run.",
    ]
)
# 0153: 18 words; over plain's 15, under standard's 22.
LONG = (
    "The audit found that one ledger write can land outside the ledger file when two "
    "trains run together."
)
# 0153: 27 words; over standard's 22 too.
LONGER = LONG[:-1] + " on the same machine at the same time today."
# 0165: the orchestrator reads the catalog's per-finding prompt; it ships no copy of its own.
SHIPPED = (
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
    # 0211: only the absent key moved; a profile still reads plain.
    assert level_of(None) == "standard"


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
        ("Is the coder's branch done?", "Question carries the agent name coder's"),
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


def test_one_ref_line_per_option_is_skipped_and_a_second_fails() -> None:
    # 0211: the Ref: line holds ids and paths; later option labels are still read.
    ref = f"  Ref: docs/x.md:12, {ISSUE}, 0211-DAE-PLT, lock_sha"
    one = _brief().replace("- Drop it: drops it.", f"- Drop it: drops it.\n{ref}")
    assert brief_problems(one, "plain") == []
    two = one.replace(ref, f"{ref}\n{ref}")
    assert brief_problems(two, "plain") == [
        "Option label Drop it has a second Ref: line; keep one per option"
    ]
    after = (
        _brief()
        .replace("- Drop it: drops it.", f"- Drop {ISSUE}: drops it.")
        .replace("- Keep it (Recommended): keeps it.", "- Keep it (Recommended): keeps it.\n" + ref)
    )
    assert brief_problems(after, "plain") == [f"Option label carries the issue number {ISSUE}"]


SAFETY = (
    "Access impact: The `deploy` role gains s3:PutObject on docs/x.md.",
    "Change nature: A new grant on one bucket.",
    f"Rollback: Remove the grant ({ISSUE}, lock_sha).",
)


@pytest.mark.parametrize(
    ("question", "context", "word"),
    [
        ("Should the deploy role write the bucket?", "", "role"),
        ("Who may change the key policy?", "", "key policy"),
        ("Should we add the permission now?", "", "permission"),
        ("Which one goes first?", "The apply order changes for two stacks.", "apply order"),
        ("Should it move?", "Grants on the access boundary widen.", "Grants"),
        ("Should the firewall stay open?", "", "firewall"),
        ("Who holds the encryption key?", "", "encryption key"),
        ("Should it move?", "The deploy secrets rotate weekly.", "secrets"),
    ],
)
def test_a_security_question_needs_access_change_and_rollback_lines(
    question: str, context: str, word: str
) -> None:
    # 0211: presence only; the three lines' text is never token-checked.
    bare = _brief(question, context)
    lacks = f"Question 1 names {word} and lacks"
    assert brief_problems(bare, "standard") == [
        f"{lacks} Access impact:, Change nature:, Rollback:"
    ]
    partial = bare.replace("Options:", "\n".join(SAFETY[:2]) + "\nOptions:")
    assert brief_problems(partial, "expert") == [f"{lacks} Rollback:"]
    empty = bare.replace("Options:", "\n".join([*SAFETY[:2], "Rollback:"]) + "\nOptions:")
    assert brief_problems(empty, "standard") == [f"{lacks} Rollback:"]
    full = bare.replace("Options:", "\n".join(SAFETY) + "\nOptions:")
    for level in ("plain", "standard", "expert"):
        assert brief_problems(full, level) == [], level


@pytest.mark.parametrize("word", SECURITY_WORDS)
def test_every_security_word_asks_for_the_safety_lines(word: str) -> None:
    # 0211: the one named list is the whole match; each word, in any case, is caught whole.
    assert brief_problems(_brief(f"Should the {word.upper()} change now?"), "expert") == [
        f"Question 1 names {word.upper()} and lacks Access impact:, Change nature:, Rollback:"
    ]


def test_the_safety_lines_are_judged_per_section() -> None:
    # 0211: one section's lines never cover another section's security question.
    full = _brief("Should the role move?").replace("Options:", "\n".join(SAFETY) + "\nOptions:")
    second = _brief("Should the grant stay?").replace("Question 1", "Question 2")
    assert brief_problems(f"{full}\n{second}", "standard") == [
        "Question 2 names grant and lacks Access impact:, Change nature:, Rollback:"
    ]
    assert brief_problems("Question: Should the role move?", "standard") == [
        "The brief names role and lacks Access impact:, Change nature:, Rollback:"
    ]


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
    assert len({p for p in SHIPPED if _QUOTED.search(p.read_text(encoding="utf-8"))}) == 2
    assert _QUOTED.search((REPO_ROOT / "agents" / "orchestrator.md").read_text("utf-8")) is None
    # pin A1 -> P1: the three gate labels are among the shipped labels.
    for gate in ("Fix it now (Recommended)", "Skip, track or exempt it", "Stop the run"):
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
        docs = {"reading_level": literacy}
        body: dict[str, object] = {} if literacy is None else {"docs": docs}
        (repo / "service-manifest.json").write_text(json.dumps(body), encoding="utf-8")
    return repo


def _write(repo: Path, text: str) -> Path:
    path = repo / "docs" / ".tmp" / "daedalus" / "t" / "decisions" / "1.md"
    path.write_text(text, encoding="utf-8")
    return path


@pytest.mark.parametrize(
    ("literacy", "manifest", "level"),
    [
        (None, False, "standard"),
        (None, True, "standard"),
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
    bad = _write(repo, _brief("Should lock_sha move?", LONGER))
    assert daedalus_train.main(["brief-check", "--repo", str(repo), "--brief", str(bad)]) == 1
    out = capsys.readouterr().out.splitlines()
    # 0211: an absent docs.reading_level checks at standard.
    assert out == [
        "brief: Question carries the snake_case token lock_sha",
        f"brief: Context sentence has 27 words, over 22 at standard: {LONGER}",
        "Next: rewrite each named question, context sentence or option label at the standard "
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
    assert "docs.reading_level" in capsys.readouterr().out


# 0251: the target reply of the first live shaping conversation; it must pass every check.
ASK_FIXTURE = "\n".join(
    [
        "Anchor: In Self-Assessment mode the plugin diagnoses itself in a live run and collects "
        "its findings.",
        "Topic: This question is about who notices that something is a finding.",
        "Sides: A script can count fixed events, such as you passing over the offered answer. "
        "Claude can also notice when it had to work around a skill's text to get through.",
        "Case: This morning's wizard walk produced seven findings. A script alone would have "
        "caught two of them.",
        "Question: Who should notice a finding in the first version of Self-Assessment mode?",
        "Choices:",
        "A. Script only: Catches 2 of this morning's 7 findings. Every finding is a counted fact, "
        "so none is a guess.",
        "B. Script, plus Claude's own findings: Catches all 7. Claude's findings are marked "
        "unconfirmed, and some will be wrong.",
        "C. Claude only: Catches the most, with no counted facts to check its findings against.",
    ]
)
ASK_REPLY = ASK_FIXTURE + "\nRests on: <receipts, never shown>\n[STATUS: ASK] n=1"
FIXTURE_WORDS = (
    "Self-Assessment mode",
    "finding",
    "script",
    "Claude",
    "live run",
    "wizard",
    "skill",
)
HANDOFF = "\n".join(
    [
        "## Chosen direction",
        "The plugin diagnoses itself in a live run.",
        "",
        "## Fixed words",
        *(f"- {word}: a word the operator settled on." for word in FIXTURE_WORDS),
        "",
        "## Why this over the alternatives",
        "- A form. Reason: it reads like paperwork.",
    ]
)
ASK_LONG = (
    "The planner found that the tilemap loader reads every chunk at the start of the game, "
    "which is slow."
)
ASK_BAD = "\n".join(
    [
        f"Topic: {ASK_LONG}",
        "Question: Should load_chunks stream?",
        "Choices:",
        "A. Stream the chunks: Read them from src/map as the player walks.",
        "B. Keep `load_chunks` just as it is: Nothing changes.",
    ]
)
ASK_BAD_LINES = [
    f"question: Topic sentence has 19 words, over 18 at plain: {ASK_LONG}",
    "question: Topic carries the agent name planner",
    "question: Question carries the snake_case token load_chunks",
    "question: Choice A carries the word src/map with a slash",
    "question: Choice B label has 6 words, not 2 to 5: Keep `load_chunks` just as it is",
    "question: Choice B label carries a backtick: Keep `load_chunks` just as it is",
    "question: Choice B label carries the snake_case token `load_chunks`",
]


def test_the_target_question_passes_with_and_without_its_fixed_words() -> None:
    # 0250, 0251: the fixture is the shape the check exists for.
    assert ask_problems(ASK_FIXTURE) == []
    assert ask_problems(ASK_REPLY) == []
    assert fixed_words(HANDOFF) == FIXTURE_WORDS
    assert ask_problems(ASK_FIXTURE, FIXTURE_WORDS) == []


def test_ask_problems_reads_every_reader_field_at_plain() -> None:
    assert [f"question: {line}" for line in ask_problems(ASK_BAD)] == ASK_BAD_LINES
    opening = "What I take you to want: A game about load_chunks.\n"
    assert ask_problems(opening + ASK_FIXTURE) == [
        "What I take you to want carries the snake_case token load_chunks"
    ]
    assert ask_problems(ASK_FIXTURE.replace("Case: This", "Case:\nThis")) == []


# (old text of the fixture, new text, the expected problem line)
ASK_BREAKS = (
    (
        "A. Script only:",
        "A. Script plus Claude plus a person:",
        "Choice A label has 6 words, not 2 to 5: Script plus Claude plus a person",
    ),
    ("A. Script only:", "A. Script:", "Choice A label has 1 word, not 2 to 5: Script"),
    (
        "C. Claude only: Catches",
        "C. Claude only, catches",
        "Choice C is not `<label>: <description>`: Claude only, catches the most, with no "
        "counted facts to check its findings against.",
    ),
    (
        "Question: Who should notice a finding in the first version of Self-Assessment mode?",
        "Question: A script notices every finding in Self-Assessment mode.",
        "Question does not end in a question mark: A script notices every finding in "
        "Self-Assessment mode.",
    ),
    (
        "Topic: This question is about who notices that something is a finding.",
        "Topic: This question is about who notices that something is a finding in the plugin "
        "while it runs right now.",
        "Topic sentence has 19 words, over 18 at plain: This question is about who notices that "
        "something is a finding in the plugin while it runs right now.",
    ),
)


@pytest.mark.parametrize(("old", "new", "want"), ASK_BREAKS)
def test_each_shape_rule_fails_on_its_break(old: str, new: str, want: str) -> None:
    assert old in ASK_FIXTURE, old
    assert ask_problems(ASK_FIXTURE.replace(old, new, 1)) == [want]


def test_a_question_needs_a_question_line_and_two_choices() -> None:
    no_choices = ASK_FIXTURE.split("\nChoices:", 1)[0]
    assert ask_problems(no_choices) == [
        "the question holds no Choices: block of two or more lettered lines"
    ]
    one = ASK_FIXTURE.split("\nB. ", 1)[0]
    assert ask_problems(one) == [
        "the question holds no Choices: block of two or more lettered lines"
    ]
    assert ask_problems(
        "Topic: Nothing yet.\nChoices:\nA. Yes please: Go.\nB. No thanks: Stop."
    ) == ["the question holds no Question: line"]


def test_fixed_words_are_never_vocabulary_and_one_must_appear() -> None:
    # 0250: a fixed word that is also an agent name is the operator's word.
    text = ASK_FIXTURE.replace("A script alone", "The writer alone")
    assert ask_problems(text) == ["Case carries the agent name writer"]
    assert ask_problems(text, (*FIXTURE_WORDS, "the writer")) == []
    assert ask_problems(ASK_FIXTURE, ("game board", "tilemap")) == [
        "the question uses none of the fixed words: game board; tilemap"
    ]
    assert fixed_words("## Fixed words\nNone.\n") is None
    assert fixed_words("## Chosen direction\n- script: a program.\n") is None


@pytest.mark.parametrize("literacy", ["expert", "standard", None])
def test_ask_check_command_is_plain_whatever_the_manifest_says(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    literacy: str | None,
) -> None:
    repo = _repo(tmp_path, literacy)
    monkeypatch.chdir(repo)
    # 0199: a folder run's brainstorm folder may sit outside the repository.
    folder = tmp_path / "out" / "brainstorm-20261101"
    folder.mkdir(parents=True)
    good, bad = folder / "ask-1.md", folder / "ask-2.md"
    good.write_text(ASK_FIXTURE, encoding="utf-8")
    bad.write_text(ASK_BAD, encoding="utf-8")
    assert daedalus_train.main(["ask-check", "--repo", str(repo), "--file", str(good)]) == 0
    assert capsys.readouterr().out == "question ok\n"
    assert daedalus_train.main(["ask-check", "--repo", str(repo), "--file", str(bad)]) == 1
    assert capsys.readouterr().out.splitlines() == [
        *ASK_BAD_LINES,
        "Next: reword each named sentence in plain words, then run ask-check again.",
    ]
    missing = folder / "ask-3.md"
    assert daedalus_train.main(["ask-check", "--repo", str(repo), "--file", str(missing)]) == 1
    assert "is not a file. Next:" in capsys.readouterr().out
    big = folder / "ask-4.md"
    big.write_text("Question: Ready?\n" + "x" * MAX_BRIEF_BYTES, encoding="utf-8")
    with pytest.raises(BriefError, match="bytes. Next:"):
        ask_file_problems(big)


def test_ask_check_reads_the_fixed_words_of_the_brief(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # 0250: --brief names the handoff brief; its Fixed words must appear in the question.
    repo = _repo(tmp_path)
    monkeypatch.chdir(repo)
    folder = tmp_path / "brainstorm-20261110"
    folder.mkdir()
    question, brief = folder / "ask-1.md", folder / "handoff.md"
    question.write_text(ASK_FIXTURE, encoding="utf-8")
    brief.write_text(HANDOFF, encoding="utf-8")
    args = ["ask-check", "--repo", str(repo), "--file", str(question), "--brief", str(brief)]
    assert daedalus_train.main(args) == 0
    assert capsys.readouterr().out == "question ok\n"
    question.write_text(
        "Topic: This picks the size.\nQuestion: How big is it?\nChoices:\n"
        "A. Keep it small: Fast.\nB. Make it big: Slow.",
        encoding="utf-8",
    )
    assert daedalus_train.main(args) == 1
    assert (
        capsys.readouterr()
        .out.splitlines()[0]
        .startswith(
            "question: the question uses none of the fixed words: Self-Assessment mode; finding"
        )
    )
    brief.unlink()
    assert daedalus_train.main(args) == 1
    assert "handoff brief" in capsys.readouterr().out


def test_recipes_name_the_check_and_the_literacy_rule() -> None:
    # 0153: the orchestrator checks each brief; every question writer reads docs.reading_level.
    orchestrator = (REPO_ROOT / "agents" / "orchestrator.md").read_text(encoding="utf-8")
    decisions = next(ln for ln in orchestrator.splitlines() if "Operator decisions (0060" in ln)
    check = (
        "run `python3 <plugin root>/scripts/daedalus_train.py brief-check --repo <repo> "
        "--brief <path>` on each brief file"
    )
    assert check in decisions
    assert decisions.index("brief-check") < decisions.index("A brief file holds one section")
    assert "rewrite the brief at the same path and run the check again" in decisions
    # 0165: the audit phase's per-finding step returns its brief after the check.
    audit = (REPO_ROOT / "skills" / "audit" / "SKILL.md").read_text(encoding="utf-8")
    assert "return `[STATUS: DECISION]` once its brief check prints `brief ok`" in audit
    # 0200: the brainstorm is always plain, so it reads no level; test_brainstorm checks it.
    for path in (
        REPO_ROOT / "agents" / "orchestrator.md",
        REPO_ROOT / "skills" / "plan" / "SKILL.md",
    ):
        flat = " ".join(path.read_text(encoding="utf-8").split())
        assert "`docs.reading_level` from `<repo>/service-manifest.json`" in flat, path
        assert "`standard` when the file or key is absent" in flat, path
    # 0211: the main session carries the three safety lines and each Ref: line.
    run = " ".join((REPO_ROOT / "skills" / "run" / "SKILL.md").read_text("utf-8").split())
    assert "`Access impact:`, `Change nature:` and `Rollback:` lines go into its context" in run
    assert "An option's `Ref:` line stays in that option's description" in run
    flat = " ".join(orchestrator.split())
    for phrase in ("`Access impact:`", "`Change nature:`", "`Rollback:`", "one `Ref:` line"):
        assert phrase in decisions, phrase
    assert "no count caps it" in flat and "Each option says what breaks" in flat
