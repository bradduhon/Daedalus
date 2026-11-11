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
# 0254: forty words in one sentence; no level counts words any more.
FORTY = (
    "The audit found that one ledger write can land outside the ledger file when two runs "
    "go together on the same machine at the same time, and the second run then writes its "
    "row into a file that nobody reads."
)
# 0254: the project's own names, as written; none of them is refused now.
NAMES = (
    "Should `load_chunks` in src/map/loader.py stay with the verifier and the "
    "daedalus:planner's lock_sha"
)
ID_HELP = "Give its label or a short excerpt of what it is about instead."
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


def test_the_brief_passes() -> None:
    assert brief_problems(GOOD) == []


def test_real_names_long_sentences_and_no_question_mark_pass_both_checks() -> None:
    # 0254: a backticked name, an underscore name, a slash path, an agent name, forty words.
    assert len(FORTY.split()) == 40
    brief = _brief(NAMES, FORTY).replace("- Drop it:", "- Drop the verifier's src/x.py:")
    assert brief_problems(brief) == []
    ask = f"Topic: {FORTY}\nQuestion: {NAMES}\nChoices:\nA. Keep `load_chunks` in src/map: {FORTY}"
    assert ask_problems(ask) == []


@pytest.mark.parametrize(
    ("literacy", "level"),
    [
        (None, "standard"),
        ("standard", "standard"),
        ("plain", "standard"),
        ("profile:docs/voice.md", "standard"),
        ("", "standard"),
        ("loud", "standard"),
        ("PLAIN", "standard"),
        ("expert", "expert"),
    ],
)
def test_every_value_but_expert_reads_standard(literacy: str | None, level: str) -> None:
    # 0255: two levels; absent, plain, a profile and any other word read standard.
    assert level_of(literacy) == level


@pytest.mark.parametrize(
    ("text", "problem"),
    [
        (
            "Does 0153-DAE-PLT still hold?",
            f"Question carries the ruling id 0153-DAE-PLT. {ID_HELP}",
        ),
        (f"Is {ISSUE} closed by this?", f"Question carries the issue number {ISSUE}. {ID_HELP}"),
    ],
)
def test_an_id_in_the_question_is_refused(text: str, problem: str) -> None:
    assert brief_problems(_brief(text)) == [problem]


def test_ids_are_read_in_context_and_labels_but_not_descriptions() -> None:
    context = _brief(context="The row came from 0153-DAE-PLT today.")
    assert brief_problems(context) == [f"Context carries the ruling id 0153-DAE-PLT. {ID_HELP}"]
    label = _brief().replace("- Drop it: drops it.", f"- Drop {ISSUE}: drops it (0153-DAE-PLT).")
    assert brief_problems(label) == [f"Option label carries the issue number {ISSUE}. {ID_HELP}"]


def test_one_ref_line_per_option_is_skipped_and_a_second_fails() -> None:
    # 0211: the Ref: line holds ids and paths; later option labels are still read.
    ref = f"  Ref: docs/x.md:12, {ISSUE}, 0211-DAE-PLT, lock_sha"
    one = _brief().replace("- Drop it: drops it.", f"- Drop it: drops it.\n{ref}")
    assert brief_problems(one) == []
    two = one.replace(ref, f"{ref}\n{ref}")
    assert brief_problems(two) == [
        "Option label Drop it has a second Ref: line; keep one per option"
    ]
    after = (
        _brief()
        .replace("- Drop it: drops it.", f"- Drop {ISSUE}: drops it.")
        .replace("- Keep it (Recommended): keeps it.", "- Keep it (Recommended): keeps it.\n" + ref)
    )
    assert brief_problems(after) == [f"Option label carries the issue number {ISSUE}. {ID_HELP}"]


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
    assert brief_problems(bare) == [f"{lacks} Access impact:, Change nature:, Rollback:"]
    partial = bare.replace("Options:", "\n".join(SAFETY[:2]) + "\nOptions:")
    assert brief_problems(partial) == [f"{lacks} Rollback:"]
    empty = bare.replace("Options:", "\n".join([*SAFETY[:2], "Rollback:"]) + "\nOptions:")
    assert brief_problems(empty) == [f"{lacks} Rollback:"]
    full = bare.replace("Options:", "\n".join(SAFETY) + "\nOptions:")
    assert brief_problems(full) == []


@pytest.mark.parametrize("word", SECURITY_WORDS)
def test_every_security_word_asks_for_the_safety_lines(word: str) -> None:
    # 0211: the one named list is the whole match; each word, in any case, is caught whole.
    assert brief_problems(_brief(f"Should the {word.upper()} change now?")) == [
        f"Question 1 names {word.upper()} and lacks Access impact:, Change nature:, Rollback:"
    ]


def test_the_safety_lines_are_judged_per_section() -> None:
    # 0211: one section's lines never cover another section's security question.
    full = _brief("Should the role move?").replace("Options:", "\n".join(SAFETY) + "\nOptions:")
    second = _brief("Should the grant stay?").replace("Question 1", "Question 2")
    assert brief_problems(f"{full}\n{second}") == [
        "Question 2 names grant and lacks Access impact:, Change nature:, Rollback:"
    ]
    assert brief_problems("Question: Should the role move?") == [
        "The brief names role and lacks Access impact:, Change nature:, Rollback:"
    ]


def test_context_continuation_lines_join_the_field() -> None:
    text = _brief(context="The row lands in one place.").replace(
        "Options:", f"  It moved with {ISSUE}.\nOptions:"
    )
    assert brief_problems(text) == [f"Context carries the issue number {ISSUE}. {ID_HELP}"]


def test_structural_problems() -> None:
    assert brief_problems("Header: x\nOptions:\n- A: a.\n") == ["the brief holds no Question: line"]
    assert brief_problems(_brief("Which one?").replace("Question: Which one?", "Question:")) == [
        "Question is empty"
    ]


def test_every_shipped_example_question_and_label_passes() -> None:
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
        assert brief_problems(_brief(question)) == [], question
    options = "\n".join(f"- {label}: x." for label in labels)
    brief = f"Question: Which one?\nOptions:\n{options}\n"
    assert brief_problems(brief) == []


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
        ("plain", True, "standard"),
        ("standard", True, "standard"),
        ("expert", True, "expert"),
        ("profile:docs/voice.md", True, "standard"),
    ],
)
def test_file_level_comes_from_docs_literacy(
    tmp_path: Path, literacy: str | None, manifest: bool, level: str
) -> None:
    repo = _repo(tmp_path, literacy, manifest)
    assert brief_file_problems(repo, _write(repo, GOOD)) == (level, [])


@pytest.mark.parametrize("literacy", [None, "plain", "standard", "expert", "profile:docs/v.md"])
def test_an_id_is_refused_at_every_level(tmp_path: Path, literacy: str | None) -> None:
    # 0255: expert once skipped the id check; no level skips it now.
    repo = _repo(tmp_path, literacy)
    brief = _write(repo, _brief(f"Does 0153-DAE-PLT close {ISSUE}?"))
    assert brief_file_problems(repo, brief)[1] == [
        f"Question carries the ruling id 0153-DAE-PLT. {ID_HELP}",
        f"Question carries the issue number {ISSUE}. {ID_HELP}",
    ]


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
    named = _write(repo, _brief("Should lock_sha in src/x.py move", FORTY))
    assert daedalus_train.main(["brief-check", "--repo", str(repo), "--brief", str(named)]) == 0
    assert capsys.readouterr().out == "brief ok\n"
    bad = _write(repo, _brief("Should lock_sha move?", f"The row came from {ISSUE}."))
    assert daedalus_train.main(["brief-check", "--repo", str(repo), "--brief", str(bad)]) == 1
    out = capsys.readouterr().out.splitlines()
    # 0255: an absent docs.reading_level names standard; the level changes no refusal.
    assert out == [
        f"brief: Context carries the issue number {ISSUE}. {ID_HELP}",
        "Next: fix each named line, giving an id's label or a short excerpt of what it is about "
        "in its place, keep the standard level, then run brief-check again.",
    ]
    outside = repo / "x.md"
    outside.write_text(GOOD, encoding="utf-8")
    assert daedalus_train.main(["brief-check", "--repo", str(repo), "--brief", str(outside)]) == 1
    assert "is not a file under" in capsys.readouterr().out


def test_brief_check_stops_on_an_unknown_reading_level(
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
ASK_BAD = "\n".join(
    [
        "Topic: The planner found that `load_chunks` in src/map reads every chunk at the start.",
        "Question: Should load_chunks stream, as 0153-DAE-PLT asked",
        "Choices:",
        "A. Stream the chunks: Read them from src/map as the player walks.",
        f"B. Keep it as {ISSUE} left it: Nothing changes.",
    ]
)
ASK_BAD_LINES = [
    f"question: Question carries the ruling id 0153-DAE-PLT. {ID_HELP}",
    f"question: Choice B carries the issue number {ISSUE}. {ID_HELP}",
]


def test_the_target_question_passes_with_and_without_its_fixed_words() -> None:
    # 0250, 0251: the fixture is the shape the check exists for.
    assert ask_problems(ASK_FIXTURE) == []
    assert ask_problems(ASK_REPLY) == []
    assert fixed_words(HANDOFF) == FIXTURE_WORDS
    assert ask_problems(ASK_FIXTURE, FIXTURE_WORDS) == []


def test_ask_problems_reads_every_reader_field_and_choice_for_ids() -> None:
    assert [f"question: {line}" for line in ask_problems(ASK_BAD)] == ASK_BAD_LINES
    opening = "What I take you to want: A game the 0200-DAE-PLT way.\n"
    assert ask_problems(opening + ASK_FIXTURE) == [
        f"What I take you to want carries the ruling id 0200-DAE-PLT. {ID_HELP}"
    ]
    assert ask_problems(ASK_FIXTURE.replace("Case: This", "Case:\nThis")) == []


# 0254: each old shape rule's break, now read without complaint.
ASK_SHAPES = (
    ("A. Script only:", "A. Script plus Claude plus a person:"),
    ("A. Script only:", "A. Script:"),
    ("C. Claude only: Catches", "C. Claude only, catches"),
    (
        "Question: Who should notice a finding in the first version of Self-Assessment mode?",
        "Question: A script notices every finding in Self-Assessment mode.",
    ),
    (
        "Topic: This question is about who notices that something is a finding.",
        f"Topic: {FORTY}",
    ),
    ("A script alone", "The writer alone"),
)


@pytest.mark.parametrize(("old", "new"), ASK_SHAPES)
def test_each_old_shape_rule_now_passes(old: str, new: str) -> None:
    assert old in ASK_FIXTURE, old
    assert ask_problems(ASK_FIXTURE.replace(old, new, 1)) == []


def test_a_question_needs_a_question_line_and_choices_are_optional() -> None:
    assert ask_problems(ASK_FIXTURE.split("\nChoices:", 1)[0]) == []
    assert ask_problems(ASK_FIXTURE.split("\nB. ", 1)[0]) == []
    assert ask_problems(
        "Topic: Nothing yet.\nChoices:\nA. Yes please: Go.\nB. No thanks: Stop."
    ) == ["the question holds no Question: line"]
    assert ask_problems("Question:") == ["Question is empty"]


def test_one_fixed_word_must_appear() -> None:
    # 0250: the handoff brief's fixed words are the operator's; one must be used.
    assert ask_problems(ASK_FIXTURE, ("game board", "tilemap")) == [
        "the question uses none of the fixed words: game board; tilemap"
    ]
    assert fixed_words("## Fixed words\nNone.\n") is None
    assert fixed_words("## Chosen direction\n- script: a program.\n") is None


@pytest.mark.parametrize("literacy", ["expert", "standard", "plain", None])
def test_ask_check_command_refuses_ids_at_every_level(
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
        "Next: fix each named line, giving an id's label or a short excerpt of what it is about "
        "in its place, then run ask-check again.",
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


# 0251: a setup question file in the layout the setup skill states; the skill and the check agree.
SETUP_SKILL = REPO_ROOT / "skills" / "setup" / "SKILL.md"
SETUP_ASK = "\n".join(
    [
        "Anchor: The reading level sets how plain the questions and docs are. It changes how "
        "Daedalus writes to you. Nothing is set now.",
        "Question: Which reading level should Daedalus write at for this project?",
        "Choices:",
        "A. Standard level: Simple sentences. The repository holds no setting yet.",
        "B. Expert level: Text that assumes you know the project, such as `docs.reading_level`.",
    ]
)


def test_setup_skill_states_the_rules_the_check_reads() -> None:
    flat = " ".join(SETUP_SKILL.read_text(encoding="utf-8").split())
    assert (
        "as an `Anchor:` line holding the sentences before the question sentence, then a "
        "`Question:` line holding the question sentence alone, then a `Choices:` line" in flat
    )
    assert (
        "It ends with one open question about the setting, such as "
        '"Which commands run the unit tests for this project?" No closing sentence says '
        "how to answer (0251)." in flat
    )
    assert "Pick an answer" not in flat
    assert (
        "then a `Choices:` line and one `<letter>. <label>: <description>` line per choice. In "
        "the file, the first choice's label is written without its `Accept:` prefix, and every "
        "label is written whole (0251)." in flat
    )
    # 0255: the check runs at either level; plain and label word counts are gone.
    assert "At either level, write the question text and its choices" in flat
    for gone in ("two to five words", "Plain level", "else plain", "At plain"):
        assert gone not in flat, gone


def test_a_setup_question_file_passes_ask_check_whole() -> None:
    assert ask_problems(SETUP_ASK) == []
    accept = SETUP_ASK.replace("A. Standard level:", "A. Accept: standard level:")
    assert ask_problems(accept) == []
    statement = SETUP_ASK.replace(
        "Question: Which reading level should Daedalus write at for this project?",
        "Question: Pick an answer, or choose Other and type your own.",
    )
    assert ask_problems(statement) == []


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
    # 0255: test_brainstorm checks the brainstorm's level; both writers here name standard.
    for path in (
        REPO_ROOT / "agents" / "orchestrator.md",
        REPO_ROOT / "skills" / "plan" / "SKILL.md",
    ):
        flat = " ".join(path.read_text(encoding="utf-8").split())
        assert "`docs.reading_level` from `<repo>/service-manifest.json`" in flat, path
        assert "`standard` when the file or key is absent" in flat, path
        assert "any value but `expert`" in flat, path
        for gone in ("at most 15 words", "at most 22", "counts as `plain`", "ending in `?`"):
            assert gone not in flat, (path, gone)
    # 0211: the main session carries the three safety lines and each Ref: line.
    run = " ".join((REPO_ROOT / "skills" / "run" / "SKILL.md").read_text("utf-8").split())
    assert "`Access impact:`, `Change nature:` and `Rollback:` lines go into its context" in run
    assert "An option's `Ref:` line stays in that option's description" in run
    flat = " ".join(orchestrator.split())
    for phrase in ("`Access impact:`", "`Change nature:`", "`Rollback:`", "one `Ref:` line"):
        assert phrase in decisions, phrase
    assert "no count caps it" in flat and "Each option says what breaks" in flat
