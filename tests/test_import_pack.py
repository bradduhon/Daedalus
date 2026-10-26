# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0157, Plan 10 spec 2.5: import_pack.py writes an OSCAL pack or a CIS id-map pack, or refuses.
from __future__ import annotations

import ast
import json
import os
import stat
from pathlib import Path

import import_pack
import pytest
from lib import packs
from lib.packs import load_pack, pack_problems

from tests.conftest import SCRIPTS_DIR

STATEMENT = {
    "id": "ac-2_smt",
    "name": "statement",
    "parts": [
        {
            "id": "ac-2_smt.a",
            "name": "item",
            "props": [{"name": "label", "value": "a."}],
            "prose": "Define the types of accounts allowed: {{ insert: param, ac-02_odp.01 }};",
        },
        {
            "id": "ac-2_smt.b",
            "name": "item",
            "props": [{"name": "label", "value": "b."}],
            "prose": "Assign account   managers.",
        },
        "not a part",
    ],
}
CATALOG = {
    "catalog": {
        "uuid": "x",
        "metadata": {"title": "SP 800-53", "version": "5.1.1"},
        "groups": [
            {
                "id": "ac",
                "title": "Access Control",
                "controls": [
                    {
                        "id": "ac-2",
                        "title": "Account   Management",
                        "props": [{"name": "label", "value": "AC-2"}],
                        "parts": [STATEMENT, {"id": "ac-2_gdn", "name": "guidance", "prose": "G"}],
                        "controls": [
                            {
                                "id": "ac-2.1",
                                "title": "Automated System Account Management",
                                "props": [{"name": "label", "value": "AC-2(1)"}],
                                "parts": [{"name": "statement", "prose": "Support it."}],
                            }
                        ],
                    },
                    {
                        "id": "ac-3",
                        "title": "Access Enforcement",
                        "parts": [{"name": "statement", "prose": "Enforce approved access."}],
                    },
                    {"id": "ac-4", "title": "Information Flow Enforcement", "parts": []},
                    "not a control",
                ],
            }
        ],
    }
}


@pytest.fixture
def repo(git_repo: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    data = git_repo / ".claude" / "daedalus"
    data.mkdir(parents=True)
    roots = [{"kind": "path", "path": "<repo_root>/private/"}]
    (data / "config.json").write_text(json.dumps({"excluded_roots": roots}), encoding="utf-8")
    (git_repo / "private").mkdir()
    (git_repo / "catalog.json").write_text(json.dumps(CATALOG), encoding="utf-8")
    (git_repo / "map.csv").write_text("cis_id,control_id\n1.4,AWS-IAM-3\n1.5,AWS-IAM-5\n")
    monkeypatch.chdir(git_repo)
    return git_repo


def _oscal(*extra: str, ids: str = "AC-2,ac-3", out: str = "packs/nist") -> int:
    return import_pack.main(
        ["oscal", "--catalog", "catalog.json", "--ids", ids, "--out", out, *extra]
    )


def _cis(*extra: str, out: str = "packs/cis", map_: str = "map.csv") -> int:
    args = ["cis-map", "--map", map_, "--benchmark", "CIS AWS Foundations", "--out", out]
    return import_pack.main([*args, "--version", "3.0.0", *extra])


def _err(capsys: pytest.CaptureFixture[str]) -> str:
    captured = capsys.readouterr()
    assert captured.out == ""
    return captured.err


# oscal mode (requirements 10 and 12).


def test_oscal_writes_the_named_controls_and_one_line(
    repo: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert _oscal() == 0
    folder = repo / "packs" / "nist"
    assert capsys.readouterr().out == f"wrote {folder} (2 controls)\n"
    assert pack_problems(folder) == []
    pack = load_pack(folder)
    assert (pack.id, pack.version, pack.license) == ("nist", "5.1.1", packs.NIST_LICENSE)
    assert pack.source == str(repo / "catalog.json")
    first, second = pack.controls
    assert (first.id, first.title, first.service) == ("AC-2", "Account Management", "any")
    assert first.statement == (
        "a. Define the types of accounts allowed: [ac-02_odp.01]; b. Assign account managers."
    )
    assert first.refs == packs.Refs(("AC-2",), (), ())
    assert (second.id, second.statement) == ("AC-3", "Enforce approved access.")
    assert first.verify == import_pack.OSCAL_VERIFY and first.look_for == import_pack.OSCAL_LOOK_FOR
    for name in ("pack.json", "controls.json"):
        assert stat.S_IMODE(os.stat(folder / name).st_mode) == 0o644


def test_oscal_takes_a_version_and_overwrites_its_own_pack(repo: Path) -> None:
    assert _oscal() == 0
    assert _oscal("--version", "2.0.0", ids="AC-3") == 0
    pack = load_pack(repo / "packs" / "nist")
    assert pack.version == "2.0.0" and [c.id for c in pack.controls] == ["AC-3"]


@pytest.mark.parametrize(
    ("ids", "want"),
    [
        ("AC-99", "--ids AC-99 is not in the catalog"),
        (" , ", "the --ids list names no control"),
        ("AC-4", "AC-4 has no statement prose"),
        ("AC-2(1)", "refs.nist id 'AC-2(1)' is not in nist-control-ids.txt"),
    ],
)
def test_oscal_refuses_an_id_it_cannot_write(
    repo: Path, capsys: pytest.CaptureFixture[str], ids: str, want: str
) -> None:
    assert _oscal(ids=ids) == 1
    assert want in _err(capsys)
    assert not (repo / "packs").exists()


@pytest.mark.parametrize(
    ("body", "want"),
    [
        (b"\xff", "--catalog is not UTF-8 JSON"),
        (b"{", "--catalog is not UTF-8 JSON"),
        (b"[]", "the catalog has no catalog object"),
        (b'{"catalog": {"metadata": {"version": "rev5"}}}', "--version 'rev5' is not three"),
    ],
)
def test_oscal_refuses_a_file_that_is_not_a_catalog(
    repo: Path, capsys: pytest.CaptureFixture[str], body: bytes, want: str
) -> None:
    (repo / "catalog.json").write_bytes(body)
    assert _oscal() == 1
    assert want in _err(capsys)


def test_oscal_refuses_a_linked_or_oversized_catalog(
    repo: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    os.symlink(repo / "catalog.json", repo / "link.json")
    assert import_pack.main(["oscal", "--catalog", "link.json", "--ids", "AC-2", "--out", "p"]) == 1
    assert "is not a regular file" in _err(capsys)
    size = import_pack.CATALOG_MAX
    monkeypatch.setattr(import_pack, "CATALOG_MAX", 10)
    assert _oscal() == 1
    assert "is larger than 10 bytes" in _err(capsys)
    monkeypatch.setattr(import_pack, "CATALOG_MAX", size)
    (repo / "catalog.json").chmod(0)
    assert _oscal() == 1
    assert "could not be read" in _err(capsys)


def test_the_importer_never_fetches() -> None:
    # 2.5: no network module is imported, directly or through lib.fetch.
    tree = ast.parse((SCRIPTS_DIR / "import_pack.py").read_text(encoding="utf-8"))
    names = {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.Import | ast.ImportFrom)
        for alias in node.names
    } | {node.module or "" for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)}
    assert not names & {"urllib", "urllib.request", "http.client", "socket", "fetch", "lib.fetch"}


# cis-map mode (requirements 11 and 12).


def test_cis_map_writes_an_id_map_pack(repo: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert _cis() == 0
    folder = repo / "packs" / "cis"
    assert capsys.readouterr().out == f"wrote {folder} (2 controls)\n"
    assert pack_problems(folder) == []
    pack = load_pack(folder)
    assert pack.license == "operator-licensed, ids only" and pack.version == "3.0.0"
    first = pack.controls[0]
    assert (first.id, first.maps_to, first.title) == ("1.4", "AWS-IAM-3", "CIS AWS Foundations 1.4")
    assert first.refs == packs.Refs((), ("1.4",), ())
    assert first.statement is None and first.verify is None


@pytest.mark.parametrize(
    ("text", "want"),
    [
        ("cis_id,control_id,title\n1.4,AWS-IAM-3,Ensure\n", "--map header must be exactly"),
        ("control_id,cis_id\nAWS-IAM-3,1.4\n", "--map header must be exactly"),
        ("cis_id\n1.4\n", "--map header must be exactly"),
        ("", "--map header must be exactly"),
        ("cis_id,control_id\n1.4,AWS-IAM-3,Ensure the text\n", "--map line 2 has 3 cells"),
        ("cis_id,control_id\n", "the --map file holds no rows"),
        ("cis_id,control_id\n1.4,NOPE-1\n", "maps_to 'NOPE-1', which no loaded pack holds"),
        ("cis_id,control_id\n1.4,AWS-IAM-3\n1.4,AWS-IAM-5\n", "control 1.4 is a duplicate id"),
        ('cis_id,control_id\n"1 4",AWS-IAM-3\n', "id must match"),
    ],
)
def test_cis_map_refuses_any_other_shape(
    repo: Path, capsys: pytest.CaptureFixture[str], text: str, want: str
) -> None:
    (repo / "map.csv").write_text(text)
    assert _cis() == 1
    assert want in _err(capsys)
    assert not (repo / "packs").exists()


def test_cis_map_refuses_a_file_that_is_not_utf8(
    repo: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    (repo / "map.csv").write_bytes(b"cis_id,control_id\n\xff,x\n")
    assert _cis() == 1
    assert "--map is not a UTF-8 CSV" in _err(capsys)


def test_cis_map_reads_a_mapped_control_in_a_pack_beside_it(repo: Path) -> None:
    assert _oscal() == 0
    (repo / "map.csv").write_text("cis_id,control_id\n1.4,AC-2\n")
    assert _cis() == 0
    assert pack_problems(repo / "packs" / "cis") == []


@pytest.mark.parametrize(
    ("args", "want"),
    [
        (["--benchmark", ""], "--benchmark must be one printable line"),
        (["--benchmark", "x" * 81], "--benchmark must be one printable line"),
        (["--version", "3.0"], "--version '3.0' is not three"),
    ],
)
def test_cis_map_refuses_a_bad_benchmark_or_version(
    repo: Path, capsys: pytest.CaptureFixture[str], args: list[str], want: str
) -> None:
    assert _cis(*args) == 1
    assert want in _err(capsys)


# --out refusals (requirement 12).


@pytest.mark.parametrize("mode", ["oscal", "cis-map"])
@pytest.mark.parametrize(
    ("out", "want"),
    [
        ("../elsewhere", "is outside the project"),
        (".", "is outside the project"),
        ("private/packs", "is under the excluded root"),
        ("packs/Bad_Name", "is the pack id and must match"),
    ],
)
def test_both_modes_refuse_a_bad_out(
    repo: Path, capsys: pytest.CaptureFixture[str], mode: str, out: str, want: str
) -> None:
    code = _oscal(out=out) if mode == "oscal" else _cis(out=out)
    assert code == 1
    assert want in _err(capsys)
    assert not (repo / "private" / "packs").exists()


def test_out_through_a_link_outside_the_project_is_refused(
    repo: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    (tmp_path / "outside").mkdir()
    os.symlink(tmp_path / "outside", repo / "packs")
    assert _cis() == 1
    assert "is outside the project" in _err(capsys)


def test_unresolvable_excluded_roots_refuse(repo: Path, capsys: pytest.CaptureFixture[str]) -> None:
    (repo / ".claude" / "daedalus" / "config.json").write_text("{")
    assert _cis() == 1
    assert "excluded_roots could not be resolved" in _err(capsys)


def test_a_linked_pack_folder_is_refused(repo: Path, capsys: pytest.CaptureFixture[str]) -> None:
    (repo / "real").mkdir()
    (repo / "packs").mkdir()
    os.symlink(repo / "real", repo / "packs" / "cis")
    assert _cis() == 1
    assert "is a symlink" in _err(capsys)
