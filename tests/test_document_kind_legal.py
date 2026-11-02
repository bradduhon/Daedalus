# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0190: the writer's legal kind, a contract-document specialisation of the derived kind.
from __future__ import annotations

import re

import freeze_sources

from tests.conftest import REPO_ROOT

LEGAL = REPO_ROOT / "skills" / "document" / "kinds" / "legal" / "SKILL.md"
DOCUMENT = REPO_ROOT / "skills" / "document" / "SKILL.md"
WRITER = REPO_ROOT / "agents" / "writer.md"
HOWTO = REPO_ROOT / "docs" / "howto" / "README.md"
LEGAL_PATH = "${CLAUDE_PLUGIN_ROOT}/skills/document/kinds/legal/SKILL.md"
FIRST_LINE = (
    "`Draft from the operator's sources. Every term is the operator's; "
    "nothing here is a recommendation or legal advice.`"
)
# Privacy rule: a real party name leaks as a company suffix, an email address or a URL.
_SUFFIX = re.compile(r"\b(?:Inc|LLC|Ltd|GmbH|Corp)\b")
_EMAIL = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")
_URL = re.compile(r"https?://|\bwww\.", re.IGNORECASE)


def _text() -> str:
    return " ".join(LEGAL.read_text(encoding="utf-8").split())


def _leaks(text: str) -> list[str]:
    return [m.group(0) for rx in (_SUFFIX, _EMAIL, _URL) for m in rx.finditer(text)]


def test_legal_kind_skill_exists_and_specialises_the_derived_kind() -> None:
    raw = LEGAL.read_text(encoding="utf-8")
    assert raw.startswith("---\nname: legal\n")
    text = _text()
    assert "`${CLAUDE_PLUGIN_ROOT}/skills/document/kinds/derived/SKILL.md` binds you" in text
    assert "Your dispatch carries no `Worktree:` line, so it records the derived kind" in text
    assert "`Claim: <output path>:<line> <claim> | receipt: <alias>:<line or range>`" in text


def test_every_clause_carries_a_receipt_an_operator_tag_or_a_gap() -> None:
    text = _text()
    assert "every clause carries a `Claim:` line as the derived kind defines it" in text
    assert "carries the tag `[operator term]`" in text
    assert "A `[gap]` is a question for the operator, never a drafted term" in text


def test_writer_never_recommends_or_advises_and_says_so_first() -> None:
    text = _text()
    assert "You never recommend a term, never advise on law" in text
    assert "never state that a clause is standard, enforceable or favourable" in text
    assert f"every output starts with this line, unchanged: {FIRST_LINE}" in text


def _howto_contract_section() -> str:
    howto = HOWTO.read_text(encoding="utf-8")
    start = howto.index("### Writing a contract document")
    end = howto.find("\n#", start + 1)
    return howto[start : end if end != -1 else len(howto)]


def test_every_draft_ends_with_a_references_section() -> None:
    text = _text()
    assert "every draft ends with a final section titled `References`" in text
    assert "`<clause number>: <source alias>:<line or range> <tag>`" in text
    assert "The References section is the receipt surface the verifier reads in claims mode" in text


def test_no_change_table_in_the_kind_skill_or_the_howto() -> None:
    assert "change table" not in LEGAL.read_text(encoding="utf-8").lower()
    assert "change table" not in _howto_contract_section().lower()
    assert "ends with a references section" in _howto_contract_section()


def test_document_phase_skips_the_comparer_for_the_legal_kind() -> None:
    assert "the document phase skips the change gate for a legal document" in _text()
    document = " ".join(DOCUMENT.read_text(encoding="utf-8").split())
    assert "Skipped when the step 11 brief names the legal kind skill" in document


def test_defined_terms_and_values_carry_counting_receipts() -> None:
    text = _text()
    assert "the document has one definitions section." in text
    assert "Each defined term is defined there once" in text
    assert 'grep -c "\\"<Term>\\" means" <draft path>' in text
    assert "come only from a receipted source or an `[operator term]`" in text
    assert "A clean draft carries no square-bracket text but `[gap: ...]`" in text


def test_outputs_and_no_commit_rule_match_the_derived_kind() -> None:
    text = _text()
    assert "exactly the files the brief names, under `output_dir`" in text
    assert "no git, no gh, no network, nothing staged, committed or pushed" in text


def test_tags_and_first_line_pass_the_freeze_placeholder_lint() -> None:
    # 0136 item 4: the step 12 lint must not refuse the tags a clean draft or log carries.
    for tag in ("[gap]", "[gap: who signs]", "[operator term]", FIRST_LINE):
        assert not freeze_sources._PLACEHOLDERS.search(tag), tag


def test_kind_table_and_writer_list_name_the_legal_kind_with_its_path() -> None:
    document = " ".join(DOCUMENT.read_text(encoding="utf-8").split())
    assert f"takes the legal kind, `{LEGAL_PATH}`" in document
    writer = " ".join(WRITER.read_text(encoding="utf-8").split())
    assert "- `legal`: one contract document derived from frozen sources" in writer
    assert f"`Kind skill: {LEGAL_PATH}`" in writer


def test_howto_says_the_writer_never_suggests_a_term() -> None:
    howto = HOWTO.read_text(encoding="utf-8")
    assert "### Writing a contract document" in howto
    assert "The writer never suggests a term, never gives legal advice" in howto


def test_privacy_check_catches_a_made_up_party() -> None:
    sample = "Acme Widgets LLC, legal@acme.example, https://acme.example"
    assert _leaks(sample) == ["LLC", "legal@acme.example", "https://"]


def test_legal_kind_names_no_party() -> None:
    assert _leaks(LEGAL.read_text(encoding="utf-8")) == []
