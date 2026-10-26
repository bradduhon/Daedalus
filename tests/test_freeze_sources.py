# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0135, 0136, D.7: freeze_sources.py freezes and verifies a train's sources; D.5 doc_outputs.
from __future__ import annotations

import hashlib
import json
import os
import stat
from pathlib import Path

import freeze_sources
import pytest

from tests.conftest import write_train_marker
from tests.hook_chain import load

TRAIN = "20261026-010203"
EN, EM = chr(0x2013), chr(0x2014)


@pytest.fixture
def repo(git_repo: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    (git_repo / ".gitignore").write_text("private/\n", encoding="utf-8")
    source = git_repo / "private" / "source"
    source.mkdir(parents=True)
    (source / "base.sent-2026-10-01.md").write_text("Term one.\nThe fee is 12 dollars.\n")
    (source / "amend.sent-2026-10-06.md").write_text("Amended text.\n")
    (source / "style.sent-2026-10-06.md").write_text("We reply within 5 days. Be warm.\n")
    (source / "draft.md").write_text("draft\n")
    (git_repo / "private" / "package").mkdir()
    data = git_repo / ".claude" / "daedalus"
    data.mkdir(parents=True)
    roots = [{"kind": "path", "path": "<repo_root>/private/"}]
    (data / "config.json").write_text(json.dumps({"excluded_roots": roots}), encoding="utf-8")
    monkeypatch.chdir(git_repo)
    return git_repo


SOURCES = [
    "--source",
    "A=baseline:private/source/base.sent-2026-10-01.md",
    "--source",
    "B=amendment:private/source/amend.sent-2026-10-06.md:group-1,group-2",
    "--source",
    "S=style:private/source/style.sent-2026-10-06.md",
]


def _freeze(*extra: str) -> int:
    return freeze_sources.main(["--train", TRAIN, "--output-dir", "private/package", *extra])


def test_freeze_writes_the_manifest_0600_and_prints_it(
    repo: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert _freeze(*SOURCES) == 0
    path = freeze_sources.manifest_path(repo, TRAIN)
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    text = path.read_text(encoding="utf-8")
    out = capsys.readouterr()
    assert out.out == text
    doc = json.loads(text)
    assert list(doc) == ["train_id", "frozen_at", "output_dir", "private_roots", "sources"]
    assert doc["train_id"] == TRAIN
    assert doc["output_dir"] == f"{repo}/private/package/"
    assert doc["private_roots"] == [f"{repo}/private/"]
    base = repo / "private" / "source" / "base.sent-2026-10-01.md"
    first = doc["sources"][0]
    assert first == {
        "alias": "A",
        "role": "baseline",
        "path": "private/source/base.sent-2026-10-01.md",
        "sha256": hashlib.sha256(base.read_bytes()).hexdigest(),
        "lines": 2,
    }
    assert doc["sources"][1]["allowed_for"] == ["group-1", "group-2"]
    assert doc["sources"][2]["allowed_for"] == []
    assert "warning" not in out.err


def test_no_excluded_roots_is_recorded_and_the_output_warned(
    repo: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    (repo / ".claude" / "daedalus" / "config.json").write_text("{}", encoding="utf-8")
    assert _freeze(*SOURCES[:2]) == 0
    err = capsys.readouterr().err
    assert "[EXCLUDED_ROOTS: none declared]" in err and "under no excluded root" in err


@pytest.mark.parametrize(
    "source",
    [
        "A=baseline:private/source/missing.sent-1.md",
        "A=baseline:private/source",
        "A=baseline:private/source/link.sent-1.md",
    ],
)
def test_a_missing_folder_or_link_source_exits_1(repo: Path, source: str) -> None:
    (repo / "private" / "source" / "link.sent-1.md").symlink_to(
        repo / "private" / "source" / "draft.md"
    )
    assert _freeze("--source", source) == 1


def test_a_working_file_exits_1(repo: Path) -> None:
    glob = ["--working-glob", "private/source/*.md"]
    assert _freeze("--source", "A=baseline:private/source/draft.md", *glob) == 1
    assert _freeze("--source", "A=baseline:private/source/base.sent-2026-10-01.md", *glob) == 0


def test_two_baselines_exit_2_unless_baselines_only(repo: Path) -> None:
    two = SOURCES[:2] + ["--source", "C=baseline:private/source/amend.sent-2026-10-06.md"]
    assert _freeze(*two) == 2
    assert _freeze(*two, "--baselines-only") == 0
    assert _freeze(*SOURCES[:2], "--baselines-only") == 2


@pytest.mark.parametrize(
    "source",
    [
        "S=style:private/source/style.sent-2026-10-06.md:tone",
        "A=nonsense:private/source/base.sent-2026-10-01.md",
        "A:private/source/base.sent-2026-10-01.md",
        "a-b=baseline:private/source/base.sent-2026-10-01.md",
    ],
)
def test_a_style_source_with_topics_or_a_malformed_source_exits_2(repo: Path, source: str) -> None:
    assert _freeze("--source", source) == 2


def test_a_duplicate_alias_or_bad_train_id_exits_2(repo: Path) -> None:
    assert _freeze(*SOURCES[:2], "--source", "A=reference:private/source/draft.md") == 2
    assert freeze_sources.main(["--train", "../x", "--output-dir", "o", *SOURCES[:2]]) == 2


def test_a_path_root_git_does_not_ignore_exits_3(repo: Path) -> None:
    (repo / ".gitignore").write_text("", encoding="utf-8")
    assert _freeze(*SOURCES) == 3


def test_verify_passes_matching_sources_and_clean_outputs(
    repo: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert _freeze(*SOURCES) == 0
    (repo / "private" / "package" / "out.md").write_text("The fee is 12 dollars.\n")
    capsys.readouterr()
    assert freeze_sources.main(["--verify", str(freeze_sources.manifest_path(repo, TRAIN))]) == 0
    assert capsys.readouterr().out.splitlines()[-1].startswith("verify: sources match")


def test_verify_exits_4_on_a_changed_source_and_names_its_alias(
    repo: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert _freeze(*SOURCES) == 0
    (repo / "private" / "source" / "amend.sent-2026-10-06.md").write_text("Changed.\n")
    capsys.readouterr()
    assert freeze_sources.main(["--verify", str(freeze_sources.manifest_path(repo, TRAIN))]) == 4
    out = capsys.readouterr().out
    assert "MISMATCH B private/source/amend.sent-2026-10-06.md" in out
    assert "[STATUS: MANIFEST_INVALID]" in out


def test_verify_exits_4_on_a_malformed_manifest(repo: Path, tmp_path: Path) -> None:
    bad = tmp_path / "bad.sources.json"
    bad.write_text('{"train_id": "x"}', encoding="utf-8")
    assert freeze_sources.main(["--verify", str(bad)]) == 4


def test_verify_lints_dashes_placeholders_and_numbered_style_sentences(
    repo: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert _freeze(*SOURCES) == 0
    body = f"Range 1{EN}2 here.\nA pause{EM}then.\nFee is TBD.\nWe reply within 5 days.\nBe warm.\n"
    out = repo / "private" / "package" / "out.md"
    out.write_text(body, encoding="utf-8")
    capsys.readouterr()
    assert freeze_sources.main(["--verify", str(freeze_sources.manifest_path(repo, TRAIN))]) == 5
    lines = capsys.readouterr().out.splitlines()
    assert f"DASH {out}:1 en dash" in lines
    assert f"DASH {out}:2 em dash" in lines
    assert f"PLACEHOLDER {out}:3 TBD" in lines
    assert f"STYLE {out}:4 matches S:1 we reply within 5 days" in lines
    assert not any("be warm" in line for line in lines)


def _doc_input(repo: Path, tool: str, **fields: str) -> dict[str, object]:
    return {
        "agent_type": "daedalus:doc-deriver",
        "tool_name": tool,
        "tool_input": fields,
        "cwd": str(repo),
    }


def test_doc_outputs_admits_only_the_output_folder(repo: Path) -> None:
    assert _freeze(*SOURCES) == 0
    write_train_marker(repo, TRAIN)
    check = load("doc_outputs")
    inside = str(repo / "private" / "package" / "out.md")
    assert check.decide(_doc_input(repo, "Write", file_path=inside), []).allow
    outside = str(repo / "src.md")
    got = check.decide(_doc_input(repo, "Edit", file_path=outside), [])
    want = check.R_OUTSIDE.format(out=f"{repo}/private/package/", path=outside)
    assert got.reason == want
    assert not check.decide(_doc_input(repo, "Bash", command=f"echo x > {outside}"), []).allow


def test_doc_outputs_refuses_a_manifest_source(repo: Path) -> None:
    (repo / "private" / "package" / "seed.md").write_text("seed\n")
    assert _freeze("--source", "A=baseline:private/package/seed.md") == 0
    write_train_marker(repo, TRAIN)
    target = str(repo / "private" / "package" / "seed.md")
    got = load("doc_outputs").decide(_doc_input(repo, "Write", file_path=target), [])
    assert got.reason is not None and got.reason.startswith(f"{target} is source A")


def test_doc_outputs_refuses_without_a_train_or_its_manifest(repo: Path) -> None:
    check = load("doc_outputs")
    target = str(repo / "private" / "package" / "out.md")
    got = check.decide(_doc_input(repo, "Write", file_path=target), [])
    assert got.reason == check.R_NO_TRAIN.format(repo=repo)
    write_train_marker(repo, TRAIN)
    got = check.decide(_doc_input(repo, "Write", file_path=target), [])
    path = freeze_sources.manifest_path(repo, TRAIN)
    assert got.reason == check.R_NO_MANIFEST.format(train=TRAIN, path=path)


@pytest.mark.parametrize(
    ("out", "constant"),
    [
        (".", "R_OUTPUT_ROOT"),
        ("..", "R_OUTPUT_OUTSIDE"),
        (".claude/daedalus/out", "R_OUTPUT_PROTECTED"),
        (".github", "R_OUTPUT_PROTECTED"),
        ("contracts/out", "R_OUTPUT_PROTECTED"),
    ],
)
def test_an_unbounded_output_folder_exits_1(
    repo: Path, capsys: pytest.CaptureFixture[str], out: str, constant: str
) -> None:
    # audit round 1: the output folder bounds every document agent write.
    capsys.readouterr()
    assert _freeze_to(out) == 1
    err = capsys.readouterr().err
    lead = getattr(freeze_sources, constant).split("{out}", 1)[1].split("{", 1)[0]
    assert lead in err and err.count("Next:") == 1, err
    assert not freeze_sources.manifest_path(repo, TRAIN).exists()


def test_an_output_folder_holding_the_ledger_exits_1(repo: Path) -> None:
    # 0054: an output folder over a protected path is refused, the ledger included.
    (repo / "private" / "package" / "decisions.md").write_text("| a |\n|---|\n")
    ledger = {
        "path": "private/package/decisions.md",
        "format": "markdown-table-row",
        "id_scheme": "{seq:04d}",
        "sequence_source": "last-row-id",
    }
    roots = [{"kind": "path", "path": "<repo_root>/private/"}]
    config = {"excluded_roots": roots, "ledger": ledger}
    (repo / ".claude" / "daedalus" / "config.json").write_text(json.dumps(config))
    assert _freeze_to("private/package") == 1
    assert _freeze_to("private/source/../other") == 0


def test_an_unreadable_service_manifest_leaves_the_output_unchecked(
    repo: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # 0054: no protected list is known, so the freeze fails closed rather than skip the check.
    (repo / "service-manifest.json").write_text("{bad", encoding="utf-8")
    capsys.readouterr()
    assert _freeze_to("private/package") == 1
    err = capsys.readouterr().err
    assert "could not be checked against the protected paths" in err and err.count("Next:") == 1


def _freeze_to(out: str) -> int:
    source = "A=baseline:private/source/base.sent-2026-10-01.md"
    return freeze_sources.main(["--train", TRAIN, "--output-dir", out, "--source", source])


def test_doc_outputs_refuses_a_protected_path_inside_the_output_folder(repo: Path) -> None:
    assert _freeze(*SOURCES) == 0
    write_train_marker(repo, TRAIN)
    target = str(repo / "private" / "package" / ".git" / "config")
    got = load("doc_outputs").decide(_doc_input(repo, "Write", file_path=target), [])
    assert got.reason == load("doc_outputs").jail.R_PROTECTED_BUILTIN.format(target)


@pytest.mark.parametrize("out", ["root", "above"])
def test_doc_outputs_refuses_a_hand_written_unbounded_manifest(repo: Path, out: str) -> None:
    # audit round 1: a sources file frozen before the bound meets it in the hook too.
    assert _freeze(*SOURCES) == 0
    path = freeze_sources.manifest_path(repo, TRAIN)
    doc = json.loads(path.read_text(encoding="utf-8"))
    doc["output_dir"] = f"{repo}/" if out == "root" else f"{repo.parent}/"
    path.write_text(json.dumps(doc), encoding="utf-8")
    write_train_marker(repo, TRAIN)
    check = load("doc_outputs")
    for target in (repo / "service-manifest.json", repo.parent / ".zshrc"):
        got = check.decide(_doc_input(repo, "Write", file_path=str(target)), [])
        assert not got.allow and "output folder" in str(got.reason), target


def test_doc_outputs_refuses_a_write_leaving_the_project(repo: Path, tmp_path: Path) -> None:
    assert _freeze(*SOURCES) == 0
    write_train_marker(repo, TRAIN)
    link = repo / "private" / "package" / "away"
    link.symlink_to(tmp_path, target_is_directory=True)
    target = str(link / "x.md")
    got = load("doc_outputs").decide(_doc_input(repo, "Write", file_path=target), [])
    assert not got.allow
