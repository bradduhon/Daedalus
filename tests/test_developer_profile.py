# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0252, question-path spec 6: the Developer Profile store and its commands.
from __future__ import annotations

import json
import os
import stat
from pathlib import Path
from typing import Any

import pytest
from lib import developer_profile as dp
from lib import question_path, storage

TEXT = "The planner writes the findings."


@pytest.fixture
def env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    monkeypatch.setattr(storage, "TMP_ROOT", tmp_path / "tmproot")
    home = tmp_path / "home"
    (home / ".claude" / "daedalus").mkdir(parents=True)
    monkeypatch.setenv("HOME", str(home))
    data = tmp_path / "data"
    data.mkdir()
    monkeypatch.setenv("CLAUDE_PLUGIN_DATA", str(data))
    repo = tmp_path / "repo"
    (repo / ".git").mkdir(parents=True)
    (repo / "service-manifest.json").write_text("{}", encoding="utf-8")
    return {"repo": str(repo), "home": home, "data": data / "developer-profile"}


def turn(env: dict[str, Any], on: bool) -> None:
    path = env["home"] / ".claude" / "daedalus" / "operator.json"
    path.write_text(json.dumps({"developer_profile": on}), encoding="utf-8")


def call(capsys: pytest.CaptureFixture[str], env: dict[str, Any], *argv: str) -> tuple[int, str]:
    code = dp.main([*argv[:1], "--repo", env["repo"], *argv[1:]])
    return code, capsys.readouterr().out


def hand(env: dict[str, Any], body: object) -> Path:
    folder = storage.make_tmp_dir(dp.FEATURE, env["repo"])
    path = folder / dp.HANDOVER
    path.write_text(body if isinstance(body, str) else json.dumps(body), encoding="utf-8")
    return path


def rule_hand(**over: Any) -> dict[str, Any]:
    base: dict[str, Any] = {"kind": "who", "rule": TEXT, "how": "stated", "replaces": None}
    base.update(over)
    return base


def tree(root: Path) -> list[str]:
    return sorted(str(p.relative_to(root)) for p in root.rglob("*"))


def test_the_flag_defaults_off_and_fails_closed(env: dict[str, Any]) -> None:
    assert dp.enabled(env["repo"]) is False
    turn(env, True)
    assert dp.enabled(env["repo"]) is True
    path = env["home"] / ".claude" / "daedalus" / "operator.json"
    path.write_text('{"developer_profile": "yes"}', encoding="utf-8")
    assert dp.enabled(env["repo"]) is False
    path.write_text("{not json", encoding="utf-8")
    assert dp.enabled(env["repo"]) is False


def test_off_prints_the_off_line_writes_nothing_and_deletes_the_handover(
    env: dict[str, Any], capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    path = hand(env, rule_hand())
    before = tree(tmp_path / "data")
    for cmd in (
        ["status"],
        ["rule"],
        ["tally"],
        ["list"],
        ["forget", "--fingerprint", "0123456789ab"],
    ):
        assert call(capsys, env, *cmd) == (0, "developer-profile: off\n")
    assert not path.exists() and tree(tmp_path / "data") == before
    assert not env["data"].exists()


def test_off_makes_no_temporary_folder(
    env: dict[str, Any], capsys: pytest.CaptureFixture[str]
) -> None:
    assert call(capsys, env, "status")[1] == "developer-profile: off\n"
    assert not storage.TMP_ROOT.exists()


def test_one_life_of_a_rule(env: dict[str, Any], capsys: pytest.CaptureFixture[str]) -> None:
    turn(env, True)
    code, out = call(capsys, env, "status")
    path = hand(env, rule_hand())
    assert code == 0 and out == (f"developer-profile: on rules=0 contested=0 handover={path}\n")
    fp = dp.fingerprint("who", TEXT)
    assert call(capsys, env, "rule") == (0, f"rule saved {fp} kind=who\n")
    assert not path.exists()
    hand(env, rule_hand(rule="  the PLANNER writes   the findings.  "))
    assert call(capsys, env, "rule") == (0, f"rule unchanged {fp} kind=who\n")
    listed = f"{fp} kind=who usable=yes contested=no applied=0: {TEXT}\n"
    assert call(capsys, env, "list") == (0, listed)
    for _ in range(3):
        hand(env, {"kind": "who", "outcome": "hit", "rule": None})
        assert call(capsys, env, "tally")[0] == 0
    hand(env, {"kind": "who", "outcome": "hit", "rule": fp})
    assert call(capsys, env, "tally") == (0, "tally kind=who outcome=hit streak=4\n")
    hand(env, {"kind": "who", "outcome": "typed", "rule": fp})
    assert call(capsys, env, "tally") == (0, "tally kind=who outcome=typed streak=0\n")
    assert (
        call(capsys, env, "list")[1] == f"{fp} kind=who usable=no contested=yes applied=1: {TEXT}\n"
    )
    assert "contested=1" in call(capsys, env, "status")[1]
    tallies = json.loads((env["data"] / "tallies.json").read_text())
    assert tallies == {"who": {"predicted": 5, "hit": 4, "miss": 1, "streak": 0}}
    new = "The orchestrator writes the findings."
    hand(env, rule_hand(rule=new, how="ratified", replaces=fp))
    out = call(capsys, env, "rule")[1]
    fp2 = dp.fingerprint("who", new)
    assert out == f"rule saved {fp2} kind=who\n"
    assert call(capsys, env, "list")[1].startswith(f"{fp2} kind=who usable=no contested=no")
    for _ in range(3):
        hand(env, {"kind": "who", "outcome": "hit", "rule": None})
        assert call(capsys, env, "tally")[0] == 0
    assert call(capsys, env, "list")[1].startswith(f"{fp2} kind=who usable=yes contested=no")
    assert call(capsys, env, "forget", "--fingerprint", fp2) == (0, f"rule forgotten {fp2}\n")
    assert call(capsys, env, "list")[1] == "developer-profile: on, no rules saved\n"


def test_a_stated_rule_is_usable_at_streak_zero_and_a_ratified_one_after_three_hits(
    env: dict[str, Any], capsys: pytest.CaptureFixture[str]
) -> None:
    turn(env, True)
    other = "The orchestrator writes the findings."
    for text, how in ((TEXT, "stated"), (other, "ratified")):
        hand(env, rule_hand(rule=text, how=how))
        call(capsys, env, "rule")
    stated, ratified = dp.fingerprint("who", TEXT), dp.fingerprint("who", other)
    rules, tallies = dp.load_rules(), dp.load_tallies()
    assert dp.is_usable(rules[stated], tallies) and not dp.is_usable(rules[ratified], tallies)
    for _ in range(2):
        hand(env, {"kind": "who", "outcome": "hit", "rule": None})
        call(capsys, env, "tally")
    assert not dp.is_usable(dp.load_rules()[ratified], dp.load_tallies())
    hand(env, {"kind": "who", "outcome": "hit", "rule": None})
    call(capsys, env, "tally")
    assert dp.is_usable(dp.load_rules()[ratified], dp.load_tallies())


def test_a_miss_contests_a_stated_rule_and_restating_it_makes_it_usable_again(
    env: dict[str, Any], capsys: pytest.CaptureFixture[str]
) -> None:
    turn(env, True)
    fp = dp.fingerprint("who", TEXT)
    hand(env, rule_hand())
    call(capsys, env, "rule")
    hand(env, {"kind": "who", "outcome": "miss", "rule": fp})
    call(capsys, env, "tally")
    assert not dp.is_usable(dp.load_rules()[fp], dp.load_tallies())
    assert "is contested" in str(dp.unusable_reason(dp.load_rules()[fp], dp.load_tallies()))
    hand(env, rule_hand(replaces=fp))
    call(capsys, env, "rule")
    assert dp.is_usable(dp.load_rules()[fp], dp.load_tallies())


def test_the_rule_file_holds_exactly_its_keys_and_the_modes_are_private(
    env: dict[str, Any], capsys: pytest.CaptureFixture[str]
) -> None:
    turn(env, True)
    hand(env, rule_hand())
    call(capsys, env, "rule")
    fp = dp.fingerprint("who", TEXT)
    file = env["data"] / "rules" / f"who-{fp}.json"
    data = json.loads(file.read_text(encoding="utf-8"))
    assert list(data) == sorted(dp.RULE_KEYS)
    assert data["rule"] == TEXT and data["applied"] == 0 and data["contested"] is False
    assert len(data["stated_on"]) == 10 and data["how"] == "stated"
    assert stat.S_IMODE(file.stat().st_mode) == 0o600
    for folder in (env["data"], env["data"] / "rules"):
        assert stat.S_IMODE(folder.stat().st_mode) == 0o700
    hand(env, {"kind": "who", "outcome": "hit", "rule": None})
    call(capsys, env, "tally")
    assert stat.S_IMODE((env["data"] / "tallies.json").stat().st_mode) == 0o600


def test_the_fingerprint_is_twelve_hex_of_kind_newline_and_the_folded_rule() -> None:
    import hashlib

    want = hashlib.sha256(b"who\nthe planner writes the findings.").hexdigest()[:12]
    assert dp.fingerprint("who", "The  PLANNER writes the findings.") == want
    assert dp.fingerprint("scope", TEXT) != dp.fingerprint("who", TEXT)


def test_the_kinds_and_outcomes_are_the_question_paths_own() -> None:
    assert dp.KINDS is question_path.KINDS and dp.OUTCOMES is question_path.OUTCOMES


@pytest.mark.parametrize(
    ("over", "want"),
    [
        ({"rule": "a\nb"}, "one printable line"),
        ({"rule": "a\x00b"}, "one printable line"),
        ({"rule": "a\tb"}, "one printable line"),
        ({"rule": "x" * 501}, "rule must be 1 to 500 characters"),
        ({"rule": ""}, "rule must be 1 to 500 characters"),
        ({"rule": "   "}, "one printable line"),
        ({"rule": 5}, "rule must be 1 to 500 characters"),
        ({"kind": "weird"}, "kind 'weird' is not one of storage"),
        ({"how": "guessed"}, "how 'guessed' is not one of stated, ratified"),
        ({"replaces": "ABCDEF012345"}, "replaces 'ABCDEF012345' is not null or 12 hex"),
        ({"replaces": "0123456789ab"}, "replaces 0123456789ab is not an existing rule"),
    ],
)
def test_a_bad_rule_handover_is_refused_by_name_and_deleted(
    env: dict[str, Any], capsys: pytest.CaptureFixture[str], over: dict[str, Any], want: str
) -> None:
    turn(env, True)
    path = hand(env, rule_hand(**over))
    code, out = call(capsys, env, "rule")
    assert code == 1 and want in out and "Next:" in out and "Traceback" not in out
    assert not path.exists() and not (env["data"] / "rules").exists()
    assert len(rule_hand(**over)["rule"] if isinstance(over.get("rule"), str) else "") <= 600


def test_a_five_hundred_character_rule_is_accepted(
    env: dict[str, Any], capsys: pytest.CaptureFixture[str]
) -> None:
    turn(env, True)
    hand(env, rule_hand(rule="x" * 500))
    assert call(capsys, env, "rule")[0] == 0


@pytest.mark.parametrize(
    "body",
    [
        "{not json",
        "[]",
        '{"kind": "who"}',
        json.dumps({**rule_hand(), "extra": 1}),
        "x" * 9000,
    ],
)
def test_a_malformed_handover_is_a_refusal_not_a_traceback(
    env: dict[str, Any], capsys: pytest.CaptureFixture[str], body: str
) -> None:
    turn(env, True)
    path = hand(env, body)
    code, out = call(capsys, env, "rule")
    assert code == 1 and "profile:" in out and "Traceback" not in out and not path.exists()


def test_a_missing_or_linked_handover_is_refused(
    env: dict[str, Any], capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    turn(env, True)
    storage.make_tmp_dir(dp.FEATURE, env["repo"])
    assert "there is no handover file" in call(capsys, env, "rule")[1]
    target = tmp_path / "elsewhere.json"
    target.write_text(json.dumps(rule_hand()), encoding="utf-8")
    link = storage.tmp_dir(dp.FEATURE, env["repo"]) / dp.HANDOVER
    os.symlink(target, link)
    code, out = call(capsys, env, "rule")
    assert code == 1 and "link or cannot be read" in out
    assert not os.path.lexists(link) and target.exists()


@pytest.mark.parametrize(
    ("body", "want"),
    [
        ({"kind": "weird", "outcome": "hit", "rule": None}, "kind 'weird' is not one of"),
        ({"kind": "who", "outcome": "maybe", "rule": None}, "outcome 'maybe' is not one of hit"),
        ({"kind": "who", "outcome": "hit", "rule": "xyz"}, "rule 'xyz' is not null or 12 hex"),
        ({"kind": "who", "outcome": "hit", "rule": "0123456789ab"}, "is not an existing rule"),
        ({"kind": "who", "outcome": "hit"}, "lacks rule"),
    ],
)
def test_a_bad_tally_is_refused_and_changes_nothing(
    env: dict[str, Any], capsys: pytest.CaptureFixture[str], body: dict[str, Any], want: str
) -> None:
    turn(env, True)
    hand(env, body)
    code, out = call(capsys, env, "tally")
    assert code == 1 and want in out
    assert not (env["data"] / "tallies.json").exists()


def test_a_tally_naming_a_rule_of_another_kind_is_refused(
    env: dict[str, Any], capsys: pytest.CaptureFixture[str]
) -> None:
    turn(env, True)
    hand(env, rule_hand())
    call(capsys, env, "rule")
    hand(env, {"kind": "scope", "outcome": "hit", "rule": dp.fingerprint("who", TEXT)})
    assert "is not an existing rule of kind scope" in call(capsys, env, "tally")[1]


def test_a_streak_counts_per_kind_and_a_miss_resets_it(
    env: dict[str, Any], capsys: pytest.CaptureFixture[str]
) -> None:
    turn(env, True)
    for kind, outcome in (("who", "hit"), ("who", "hit"), ("scope", "hit"), ("who", "miss")):
        hand(env, {"kind": kind, "outcome": outcome, "rule": None})
        call(capsys, env, "tally")
    tallies = dp.load_tallies()
    assert tallies["who"] == {"predicted": 3, "hit": 2, "miss": 1, "streak": 0}
    assert tallies["scope"]["streak"] == 1


def test_list_filters_by_kind_and_refuses_an_unknown_kind(
    env: dict[str, Any], capsys: pytest.CaptureFixture[str]
) -> None:
    turn(env, True)
    for kind in ("who", "scope"):
        hand(env, rule_hand(kind=kind))
        call(capsys, env, "rule")
    out = call(capsys, env, "list", "--kind", "scope")[1]
    assert out.count("\n") == 1 and "kind=scope" in out
    code, out = call(capsys, env, "list", "--kind", "weird")
    assert code == 1 and "kind 'weird' is not one of storage" in out


@pytest.mark.parametrize(
    "bad", ["", "ABCDEF012345", "0123456789a", "0123456789abc", "../../x", "0123456789ag"]
)
def test_forget_takes_only_twelve_lowercase_hex(
    env: dict[str, Any], capsys: pytest.CaptureFixture[str], bad: str
) -> None:
    turn(env, True)
    code, out = call(capsys, env, "forget", "--fingerprint", bad)
    assert code == 1 and "lowercase hex" in out and "Traceback" not in out


def test_forget_of_a_missing_rule_is_refused(
    env: dict[str, Any], capsys: pytest.CaptureFixture[str]
) -> None:
    turn(env, True)
    assert "no rule 0123456789ab" in call(capsys, env, "forget", "--fingerprint", "0123456789ab")[1]


def test_restating_a_contested_rule_in_its_own_words_clears_it(
    env: dict[str, Any], capsys: pytest.CaptureFixture[str]
) -> None:
    turn(env, True)
    fp = dp.fingerprint("who", TEXT)
    hand(env, rule_hand())
    call(capsys, env, "rule")
    hand(env, {"kind": "who", "outcome": "miss", "rule": fp})
    call(capsys, env, "tally")
    assert dp.load_rules()[fp]["contested"] is True
    hand(env, rule_hand(replaces=fp))
    assert call(capsys, env, "rule") == (0, f"rule saved {fp} kind=who\n")
    assert dp.load_rules()[fp]["contested"] is False


def test_damaged_files_are_refusals_and_are_never_overwritten(
    env: dict[str, Any], capsys: pytest.CaptureFixture[str]
) -> None:
    turn(env, True)
    hand(env, rule_hand())
    call(capsys, env, "rule")
    fp = dp.fingerprint("who", TEXT)
    file = env["data"] / "rules" / f"who-{fp}.json"
    good = file.read_text(encoding="utf-8")
    for bad in (
        "{oops",
        "[]",
        json.dumps({"kind": "who"}),
        good.replace('"how": "stated"', '"how": "x"'),
    ):
        file.write_text(bad, encoding="utf-8")
        for cmd in (["list"], ["status"], ["forget", "--fingerprint", fp]):
            code, out = call(capsys, env, *cmd)
            assert code == 1 and "is damaged" in out and "Traceback" not in out, (bad, cmd)
        assert file.read_text(encoding="utf-8") == bad
    file.write_text(good, encoding="utf-8")
    renamed = file.with_name(f"who-{'0' * 12}.json")
    file.rename(renamed)
    assert "does not match" in call(capsys, env, "list")[1]
    renamed.rename(file)
    (env["data"] / "rules" / "notes.txt").write_text("x", encoding="utf-8")
    assert "not a rule file name" in call(capsys, env, "list")[1]
    (env["data"] / "rules" / "notes.txt").unlink()
    (env["data"] / "tallies.json").write_text('{"who": {"hit": -1}}', encoding="utf-8")
    hand(env, {"kind": "who", "outcome": "hit", "rule": None})
    code, out = call(capsys, env, "tally")
    assert code == 1 and "tallies.json" in out and "is damaged" in out
    assert (env["data"] / "tallies.json").read_text(encoding="utf-8") == '{"who": {"hit": -1}}'


def test_an_unreadable_data_folder_is_a_refusal(
    env: dict[str, Any], capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    turn(env, True)
    monkeypatch.delenv("CLAUDE_PLUGIN_DATA")
    monkeypatch.setattr(
        storage,
        "data_dir",
        lambda feature, root=None: (_ for _ in ()).throw(RuntimeError("no data folder")),
    )
    code, out = call(capsys, env, "list")
    assert code == 1 and "no data folder" in out and "Traceback" not in out


def test_the_project_folder_is_unchanged_after_every_command(
    env: dict[str, Any], capsys: pytest.CaptureFixture[str]
) -> None:
    turn(env, True)
    repo = Path(env["repo"])
    before = {p: p.read_bytes() for p in repo.rglob("*") if p.is_file()}
    names = tree(repo)
    fp = dp.fingerprint("who", TEXT)
    steps: list[tuple[list[str], object]] = [
        (["status"], None),
        (["rule"], rule_hand()),
        (["tally"], {"kind": "who", "outcome": "hit", "rule": fp}),
        (["list"], None),
        (["forget", "--fingerprint", fp], None),
    ]
    for argv, body in steps:
        if body is not None:
            hand(env, body)
        assert call(capsys, env, *argv)[0] == 0
        assert tree(repo) == names
    assert {p: p.read_bytes() for p in repo.rglob("*") if p.is_file()} == before


def test_the_module_has_no_traceback_path_for_a_bad_command_line(
    env: dict[str, Any], capsys: pytest.CaptureFixture[str]
) -> None:
    code, out = dp.main(["bogus"]), capsys.readouterr().out
    assert code == 1 and "profile:" in out and "Next:" in out
    assert dp.main(["forget", "--repo", env["repo"]]) == 1
    assert "Traceback" not in capsys.readouterr().out


def test_the_feature_is_on_the_storage_allow_list() -> None:
    assert dp.FEATURE in storage.FEATURES
    assert dp.MIN_STREAK == 3 and dp.MAX_HANDOVER_BYTES == 8192
