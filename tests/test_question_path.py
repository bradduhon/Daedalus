# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0252, question-path spec 4 and 5: the path store, its three checks and its commands.
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import pytest
from lib import question_path, storage

BRIEF_SENTENCE = "Finding files are kept for thirty days."


@pytest.fixture
def env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    monkeypatch.setattr(storage, "TMP_ROOT", tmp_path / "tmproot")
    repo = tmp_path / "repo"
    (repo / ".git").mkdir(parents=True)
    brief = tmp_path / "brief.md"
    brief.write_text(f"Intro.\n{BRIEF_SENTENCE}  Other words.\n", encoding="utf-8")
    rules = tmp_path / "rules.md"
    rules.write_text(
        "| Id | Name |\n|---|---|\n| 0252 | Storage in two places |\n", encoding="utf-8"
    )
    return {"repo": str(repo), "brief": str(brief), "rules": str(rules)}


def call(capsys: pytest.CaptureFixture[str], *argv: str) -> tuple[int, str]:
    code = question_path.main(list(argv))
    return code, capsys.readouterr().out


def row(ident: int, kind: str, **over: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "id": ident,
        "kind": kind,
        "gap": f"gap {ident}",
        "predicted": "yes",
        "source": "default",
        "source_ref": "shipped",
        "depends_on": [],
        "folds_into": None,
        "is_rule": False,
    }
    base.update(over)
    return base


def storage_rows(folded: bool) -> list[dict[str, Any]]:
    fold = 1 if folded else None
    rows = [row(i, "storage", folds_into=fold) for i in (2, 3, 4, 5)]
    return [row(1, "storage", is_rule=True, source="rule", source_ref="0252"), *rows]


class Conv:
    def __init__(self, env: dict[str, Any], capsys: pytest.CaptureFixture[str]) -> None:
        self.env, self.capsys = env, capsys
        code, out = call(capsys, "open", "--repo", env["repo"])
        assert code == 0, out
        self.conv = out.split("conv=")[1].split()[0]
        self.handover = Path(out.split("handover=")[1].strip())

    def run(self, cmd: str, *extra: str, hand: object = None) -> tuple[int, str]:
        if hand is not None:
            self.handover.write_text(json.dumps(hand), encoding="utf-8")
        return call(self.capsys, cmd, "--repo", self.env["repo"], "--conv", self.conv, *extra)

    def check(self, rows: list[dict[str, Any]], cmd: str = "check") -> tuple[int, str]:
        files = ["--brief", self.env["brief"], "--rules", self.env["rules"]]
        return self.run(cmd, *files, hand={"rows": rows})


@pytest.fixture
def conv(env: dict[str, Any], capsys: pytest.CaptureFixture[str]) -> Conv:
    return Conv(env, capsys)


def walk_rows() -> list[dict[str, Any]]:
    return [
        *storage_rows(True),
        row(6, "who", source="rule", source_ref="0252", predicted="the planner"),
        row(7, "scope", source="stated", source_ref=BRIEF_SENTENCE),
        row(8, "behaviour", source="none", predicted="", source_ref="", depends_on=[6]),
        row(9, "format", source="setting", source_ref="docs.reading_level", predicted="plain"),
        row(10, "naming", source="rule", source_ref="0252", predicted="short"),
    ]


def test_storage_fixture_fails_unfolded_and_passes_folded(conv: Conv) -> None:
    unfolded = [row(i, "storage") for i in (1, 2, 3, 4)]
    code, out = conv.check(unfolded)
    assert code == 1
    assert "path: kind storage has 4 rows and no rule; fold them into one rule row" in out
    assert "Next:" in out and not conv.handover.exists()
    assert not list(conv.handover.parent.glob("path-v*.json"))
    code, out = conv.check(storage_rows(True))
    assert (code, out.strip()) == (0, "path ok v=1 gaps=5 rules=1 decided=0 ask=0")


def test_whole_conversation(conv: Conv) -> None:
    rows = walk_rows()
    assert conv.check(rows)[1].startswith("path ok v=1 gaps=10")
    # naming rule row 10 stays decided; who row 6 is medium so it is asked
    assert conv.run("next")[0] == 1
    text = conv.run("propose")[1]
    assert text.splitlines()[0] == "10 gaps: 3 decided, 1 rules, 2 to ask, 0 answered"
    assert "covers row 2: gap 2" in text and "(a project rule)" in text
    assert str(conv.handover.parent) not in text
    assert conv.run("ratify")[1].strip() == "ratified v=1"
    assert conv.run("ratify")[0] == 1
    assert conv.run("next")[1].strip() == "next: 6"
    hit = {"id": 6, "response": "ok", "chosen": " The  PLANNER ", "typed": False, "touches": []}
    assert conv.run("record", hand=hit)[1].strip() == "recorded id=6 outcome=hit shift=no"
    assert conv.run("next")[1].strip() == "next: 8"
    typed = {"id": 8, "response": "a\nb", "chosen": "x", "typed": False, "touches": [9]}
    assert conv.run("record", hand=typed)[1].strip() == "recorded id=8 outcome=hit shift=no"
    assert conv.run("next")[1].strip() == "next: none"
    status = conv.run("status")[1].splitlines()
    assert status[1] == "shift=no ratified=yes v=1"


def test_miss_on_medium_row_blocks_next_then_regenerate_moves_one_row(conv: Conv) -> None:
    rows = walk_rows()
    conv.check(rows)
    conv.run("ratify")
    conv.run("next")
    miss = {"id": 6, "response": "no", "chosen": "someone else", "typed": False, "touches": []}
    assert conv.run("record", hand=miss)[1].strip() == "recorded id=6 outcome=miss shift=yes"
    code, out = conv.run("next")
    assert code == 1 and "path: a shift is pending" in out
    again = [dict(r) for r in rows]
    again[8]["predicted"] = "expert"
    again.append(row(11, "other", source="none", predicted="", source_ref=""))
    code, out = conv.check(again, "regenerate")
    assert code == 0
    assert "moved: row 9: plain -> expert" in out
    assert "moved: row 11" not in out
    assert out.strip().splitlines()[-1].endswith("moved=1")
    assert conv.run("next")[0] == 1
    assert conv.run("ratify")[1].strip() == "ratified v=2"
    assert conv.run("next")[1].strip() == "next: 8"


def test_regenerate_with_no_moved_row_inherits_the_ratification(conv: Conv) -> None:
    rows = walk_rows()
    conv.check(rows)
    conv.run("ratify")
    fact = {"fact": "the docs say otherwise", "kind": "web"}
    assert conv.run("fact", hand=fact)[1].strip() == "fact recorded shift=yes"
    assert conv.run("regenerate")[0] == 1
    code, out = conv.check(rows, "regenerate")
    assert code == 0 and out.strip().endswith("moved=0")
    assert conv.run("status")[1].splitlines()[1] == "shift=no ratified=yes v=2"


def test_regenerate_refused_without_shift_and_answered_rows_stay(conv: Conv) -> None:
    rows = walk_rows()
    conv.check(rows)
    code, out = conv.check(rows, "regenerate")
    assert code == 1 and "no shift is pending" in out
    conv.run("ratify")
    conv.run("next")
    typed = {"id": 6, "response": "mine", "chosen": "mine", "typed": True, "touches": []}
    assert "outcome=typed shift=yes" in conv.run("record", hand=typed)[1]
    kept = [{**r, "depends_on": []} for r in rows if r["id"] != 6]
    code, out = conv.check(kept, "regenerate")
    assert code == 1 and "row 6 was answered and cannot be dropped" in out
    changed = [dict(r) for r in rows]
    changed[5]["gap"] = "another gap"
    assert "kind and gap must stay" in conv.check(changed, "regenerate")[1]
    dropped = [r for r in rows if r["id"] != 8]
    assert conv.check(dropped, "regenerate")[0] == 0


def test_check_refusals_name_the_bad_value(conv: Conv) -> None:
    cases: list[tuple[dict[str, Any], str]] = [
        (row(1, "weird"), "kind 'weird' is not one of storage"),
        (row(1, "who", source="telepathy"), "source 'telepathy' is not one of setting"),
        (row(1, "who", source="profile"), "path: row 1: the profile source is not available yet"),
        (
            row(1, "who", source="setting", source_ref="nope.key"),
            "'nope.key' is not a settings key",
        ),
        (row(1, "who", source="stated", source_ref="Never said."), "is not in the brief"),
        (row(1, "who", source="rule", source_ref="9999"), "rule '9999' not found"),
        (row(1, "who", source="none"), "source none needs empty"),
        (row(1, "who", gap=""), "gap must be 1 to 300 characters"),
        (row(1, "who", predicted="a\nb"), "predicted must be one line"),
        (row(1, "who", depends_on=[1]), "cycle among rows 1"),
        (row(1, "who", depends_on=[7]), "depends_on names row 7"),
        (row(1, "who", folds_into=3), "folds_into names a missing row 3"),
        (row(1, "who", is_rule=True, folds_into=1), "a rule row must have folds_into null"),
    ]
    for bad, want in cases:
        code, out = conv.check([bad], "check")
        assert code == 1 and want in out, (want, out)
        assert "Traceback" not in out and not conv.handover.exists()
    extra = row(1, "who")
    extra["colour"] = 1
    assert "unexpected colour" in conv.check([extra])[1]
    assert "appears more than once" in conv.check([row(1, "who"), row(1, "scope")])[1]
    wrong = [row(1, "who", is_rule=True), row(2, "scope", folds_into=1)]
    assert "must name a rule row of kind scope" in conv.check(wrong)[1]
    assert conv.run("check", hand=["x"])[0] == 1
    assert conv.run("check")[0] == 1


def test_status_is_computed_by_the_script(conv: Conv) -> None:
    rows = [
        row(1, "who", source="setting", source_ref="docs.reading_level"),
        row(2, "scope", source="default"),
        row(3, "other", source="default", source_ref="x"),
        row(4, "format", source="default"),
        row(5, "naming", source="none", predicted="", source_ref=""),
    ]
    assert conv.check(rows)[0] == 0
    got = json.loads((conv.handover.parent / "path-v1.json").read_text())["rows"]
    assert [(r["confidence"], r["status"]) for r in got] == [
        ("high", "decide"),
        ("low", "ask"),
        ("low", "ask"),
        ("low", "decide"),
        ("none", "ask"),
    ]
    assert conv.check(rows)[0] == 1


def test_handover_limits_and_links(conv: Conv, tmp_path: Path) -> None:
    conv.handover.write_text(" " * (question_path.MAX_HANDOVER_BYTES + 1), encoding="utf-8")
    code, out = conv.run("check")
    assert code == 1 and "over 65536 bytes" in out and not conv.handover.exists()
    target = tmp_path / "elsewhere.json"
    target.write_text('{"rows": []}', encoding="utf-8")
    os.symlink(target, conv.handover)
    code, out = conv.run("check")
    assert code == 1 and "link" in out and target.exists() and not conv.handover.exists()


def test_record_must_name_the_row_handed_out(conv: Conv) -> None:
    conv.check(walk_rows())
    conv.run("ratify")
    hand = {"id": 6, "response": "r", "chosen": "c", "typed": False, "touches": []}
    assert "not the row last handed out" in conv.run("record", hand=hand)[1]
    conv.run("next")
    assert "path: row 6 was handed out" in conv.run("next")[1]
    assert "touches must be a list" in conv.run("record", hand={**hand, "touches": [99]})[1]
    assert conv.run("record", hand={**hand, "id": 8})[0] == 1
    assert conv.run("record", hand=hand)[0] == 0
    assert conv.run("record", hand=hand)[0] == 1


def test_fact_kind_is_allow_listed(conv: Conv) -> None:
    conv.check(walk_rows())
    code, out = conv.run("fact", hand={"fact": "x", "kind": "gossip"})
    assert code == 1 and "kind 'gossip' is not one of web, refuted, changed-answer" in out


def test_bad_stamp_missing_folder_and_unknown_command(
    env: dict[str, Any], capsys: pytest.CaptureFixture[str]
) -> None:
    for argv in (
        ["status", "--repo", env["repo"], "--conv", "../x"],
        ["status", "--repo", env["repo"], "--conv", "20260101T000000Z"],
        ["bogus", "--repo", env["repo"]],
        ["status"],
    ):
        code, out = call(capsys, *argv)
        assert code == 1 and "path:" in out and "Next:" in out
    code, out = call(capsys, "open", "--repo", env["repo"])
    assert code == 0 and out.startswith("path: open conv=")


def test_stated_source_may_quote_an_earlier_answer(conv: Conv) -> None:
    conv.check(walk_rows())
    conv.run("ratify")
    conv.run("next")
    said = "Keep files seven days."
    hand = {"id": 6, "response": f"I say: {said}", "chosen": "x", "typed": True, "touches": []}
    conv.run("record", hand=hand)
    rows = walk_rows()
    rows.append(row(11, "other", source="stated", source_ref=said))
    assert conv.check(rows, "regenerate")[0] == 0
