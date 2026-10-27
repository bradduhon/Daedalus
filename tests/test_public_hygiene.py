# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import hashlib
import re
import subprocess
from pathlib import Path

import pytest

from tests.conftest import REPO_ROOT
from tests.conftest import git as _git

# The public allowlist, as normalized by _entry().
ALLOWLIST = frozenset(
    {
        ".claude-plugin/marketplace.json",
        ".claude-plugin/plugin.json",
        ".claude/settings.json",
        ".gitignore",
        "LICENSE",
        "README.md",
        "VERSION",
        "agents/",
        "hooks/",
        "packs/",
        "pyproject.toml",
        "scripts/",
        "service-manifest.json",
        "skills/",
        "tests/",
        "docs/guardrails.md",
        "docs/howto/README.md",
        "docs/project-requirements.md",
    }
)
# Case-insensitive; a bracketed letter keeps each pattern from matching its own source line.
GENERIC_TERMS = (
    r"/hom[e]/",
    r"-B[O]-",
    r"Confidential an[d] Proprietary",
    r"Unauthorized copyin[g]",
    r"[H]SM",
    r"#[0-9]+",
    r"test_issue_[0-9]",
)
# 0017, issue 26: only [terms] is read; no section widens the allowlist.
SECTIONS = ("[terms]",)
SECTION_HEADER = re.compile(r"\[[a-z][a-z0-9-]*\]")
PUBLIC_REMOTE = re.compile(r"github\.com[:/]bradduhon/Daedalus(?:\.git)?/?$", re.IGNORECASE)
PY_HEADER = ["# Copyright (c) 2026 Brad Duhon.", "# SPDX-License-Identifier: GPL-3.0-or-later"]
MD_HEADER = "<!-- Copyright (c) 2026 Brad Duhon. SPDX-License-Identifier: GPL-3.0-or-later -->"
# sha256 of https://www.gnu.org/licenses/gpl-3.0.txt.
GPL3_SHA256 = "3972dc9744f6499f0f9b2dbf76696f2ae7ad8af9b23dde66d6af86c9dfb36986"


def _tracked() -> list[str]:
    out = subprocess.run(
        ["git", "ls-files", "-z"], cwd=REPO_ROOT, capture_output=True, check=True, text=True
    ).stdout
    return [p for p in out.split("\0") if p]


def _entry(path: str) -> str:
    parts = path.split("/")
    if parts[0] == "docs" and len(parts) > 2 and parts[1] != "howto":
        return f"docs/{parts[1]}/"
    if parts[0] in {"docs", ".claude-plugin", ".claude"}:
        return path
    return parts[0] + ("/" if len(parts) > 1 else "")


def _term_file() -> Path | None:
    for candidate in (
        REPO_ROOT / "docs" / "private" / "hygiene-terms.txt",
        REPO_ROOT / "docs" / "hygiene-terms.txt",
    ):
        if candidate.is_file():
            return candidate
    return None


def _read_sections(path: Path) -> dict[str, list[str]]:
    sections: dict[str, list[str]] = {}
    current: str | None = None
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if SECTION_HEADER.fullmatch(line):
            current = line
            sections.setdefault(line, [])
        elif current is None:
            raise ValueError(f"{path}: entry before any section header: {line}")
        else:
            sections[current].append(line)
    return sections


def _read_terms(path: Path) -> list[str]:
    return _read_sections(path).get("[terms]", [])


def _origin_url(root: Path) -> str:
    proc = subprocess.run(
        ["git", "remote", "get-url", "origin"], cwd=root, capture_output=True, text=True
    )
    return proc.stdout.strip() if proc.returncode == 0 else ""


def _term_file_refusals(path: Path, origin: str) -> list[str]:
    if not PUBLIC_REMOTE.search(origin):
        return []
    return [
        f"{path}: section {name} is not read on the public remote; only [terms] is. "
        f"Next: delete the {name} section; a top-level path it listed goes on ALLOWLIST "
        "or out of the public tree."
        for name in _read_sections(path)
        if name not in SECTIONS
    ]


def _public_files() -> list[str]:
    return [p for p in _tracked() if _entry(p) in ALLOWLIST]


def _hits(patterns: tuple[str, ...] | list[str]) -> list[str]:
    pattern = re.compile("|".join(patterns), re.IGNORECASE)
    hits = []
    for path in _public_files():
        text = (REPO_ROOT / path).read_text(encoding="utf-8", errors="replace")
        for number, line in enumerate(text.splitlines(), 1):
            match = pattern.search(line)
            if match:
                hits.append(f"{path}:{number}: {match.group(0)}")
    return hits


def _md_header_line(text: str) -> str:
    lines = text.splitlines()
    if lines and lines[0] == "---":
        lines = lines[lines.index("---", 1) + 1 :]
    return next((line for line in lines if line.strip()), "")


def test_top_level_equals_allowlist() -> None:
    assert {_entry(p) for p in _tracked()} == ALLOWLIST


def test_no_private_terms() -> None:
    assert _hits(GENERIC_TERMS) == []


def test_no_private_names() -> None:
    path = _term_file()
    if path is None:
        pytest.skip(
            "private term file not mounted at docs/private/hygiene-terms.txt; names check skipped"
        )
    assert _term_file_refusals(path, _origin_url(REPO_ROOT)) == []
    terms = _read_terms(path)
    assert terms, f"{path} has an empty [terms] section"
    assert _hits(terms) == []


def test_every_py_and_md_carries_the_spdx_header() -> None:
    missing = []
    for path in _public_files():
        text = (REPO_ROOT / path).read_text(encoding="utf-8")
        if path.endswith(".py"):
            lines = text.splitlines()
            start = 1 if lines and lines[0].startswith("#!") else 0
            if lines[start : start + 2] != PY_HEADER:
                missing.append(path)
        elif path.endswith(".md") and _md_header_line(text) != MD_HEADER:
            missing.append(path)
    assert missing == []


def test_license_is_gpl3_verbatim() -> None:
    data = (REPO_ROOT / "LICENSE").read_bytes()
    lines = data.decode("utf-8").splitlines()
    assert lines[0].strip() == "GNU GENERAL PUBLIC LICENSE"
    assert lines[1].strip() == "Version 3, 29 June 2007"
    assert hashlib.sha256(data).hexdigest() == GPL3_SHA256


def test_docs_private_is_ignored() -> None:
    # Probe a child path; a dir-only pattern does not match an absent dir.
    probe = subprocess.run(["git", "check-ignore", "-q", "docs/private/probe"], cwd=REPO_ROOT)
    assert probe.returncode == 0


def test_hygiene_allows_packs() -> None:
    # 0019, 0026: the opt-in baseline pack ships under packs/.
    assert "packs/" in ALLOWLIST
    assert "packs/" in {_entry(p) for p in _tracked()}


def test_hygiene_admits_the_adversarial_corpus() -> None:
    # spec 3.3: the shared corpus ships with the public tests and runs in the normal suite.
    corpus = [p for p in _tracked() if p.startswith("tests/adversarial/")]
    assert corpus, "tests/adversarial/ is not tracked"
    assert {_entry(p) for p in corpus} == {"tests/"}
    assert set(corpus) <= set(_public_files())


def test_hygiene_admits_the_guardrails_document() -> None:
    # 0047: docs/guardrails.md is public and every term rule reads it.
    assert "docs/guardrails.md" in ALLOWLIST
    assert "docs/guardrails.md" in _public_files()


def test_pre_split_mode_is_gone(tmp_path: Path) -> None:
    term_file = tmp_path / "hygiene-terms.txt"
    term_file.write_text("[terms]\nalpha\n[pre-split]\nlegacy/\n", encoding="utf-8")
    assert SECTIONS == ("[terms]",)
    assert "_pre_split_entries" not in globals()
    assert _read_terms(term_file) == ["alpha"]


def test_hygiene_refuses_a_pre_split_section_on_the_public_remote(tmp_path: Path) -> None:
    _git(tmp_path, "init", "-q")
    _git(tmp_path, "remote", "add", "origin", "https://github.com/bradduhon/Daedalus.git")
    term_file = tmp_path / "hygiene-terms.txt"
    term_file.write_text("[terms]\nalpha\n[pre-split]\nlegacy/\n", encoding="utf-8")
    refusals = _term_file_refusals(term_file, _origin_url(tmp_path))
    assert len(refusals) == 1
    assert "[pre-split]" in refusals[0] and "Next:" in refusals[0]
    term_file.write_text("[terms]\nalpha\n", encoding="utf-8")
    assert _term_file_refusals(term_file, _origin_url(tmp_path)) == []


def test_extra_section_off_the_public_remote_is_inert(tmp_path: Path) -> None:
    _git(tmp_path, "init", "-q")
    _git(tmp_path, "remote", "add", "origin", "https://example.invalid/private.git")
    term_file = tmp_path / "hygiene-terms.txt"
    term_file.write_text("[terms]\nalpha\n[pre-split]\nlegacy/\n", encoding="utf-8")
    assert _term_file_refusals(term_file, _origin_url(tmp_path)) == []


def test_public_remote_matches_https_and_ssh_forms() -> None:
    for url in (
        "https://github.com/bradduhon/Daedalus",
        "https://github.com/bradduhon/Daedalus.git",
        "git@github.com:bradduhon/Daedalus.git",
    ):
        assert PUBLIC_REMOTE.search(url), url
    assert not PUBLIC_REMOTE.search("https://github.com/bradduhon/Daedalus-private.git")
