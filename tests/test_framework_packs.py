# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0157, Plan 10 spec 2.3 and 2.4: the pack format checks and the two shipped packs.
from __future__ import annotations

import json
import os
import re
import shlex
from pathlib import Path

import pytest
from lib import packs
from lib.packs import PackError, load_pack, pack_folders, pack_problems

from tests.conftest import CFG
from tests.hook_chain import decide
from tests.test_checks_credential_paths import _bash_in, _key_repo

SHIPPED = {"aws-default": 34, "nist-distilled": 27, "stripe-default": 5, "cost-tier": 8}
# 0192: cost-tier is off until frameworks.packs names it.
OFF_BY_DEFAULT = {"cost-tier"}
AWS_ID = re.compile(r"AWS-([A-Z0-9]+)-[0-9]+")


def _control(ident: str = "X-1", **extra: object) -> dict[str, object]:
    base: dict[str, object] = {
        "id": ident,
        "service": "any",
        "title": "A title",
        "statement": "A statement.",
        "look_for": "A hint.",
        "verify": "rg -n x .",
        "refs": {"nist": ["AC-2"], "cis": [], "asvs": []},
    }
    return {**base, **extra}


def _make(
    folder: Path,
    controls: list[dict[str, object]] | None = None,
    text: str | None = None,
    **meta: object,
) -> Path:
    folder.mkdir(parents=True, exist_ok=True)
    body = text if text is not None else packs.controls_text(controls or [_control()])
    (folder / "controls.json").write_text(body, encoding="utf-8")
    doc: dict[str, object] = {
        "id": folder.name,
        "version": "1.0.0",
        "source": "test",
        "license": "GPL-3.0-or-later",
        "pinned_on": "2026-10-26",
        "sha256": packs.digest(body.encode("utf-8")),
    }
    doc.update(meta)
    (folder / "pack.json").write_text(json.dumps(doc), encoding="utf-8")
    return folder


def _problems(folder: Path) -> str:
    found = pack_problems(folder, known=())
    assert found
    return "\n".join(found)


# The shipped packs (requirements 7 to 9 and 13).


@pytest.mark.parametrize(("name", "count"), sorted(SHIPPED.items()))
def test_shipped_pack_loads_with_no_problem(name: str, count: int) -> None:
    folder = packs.FRAMEWORKS_DIR / name
    assert pack_problems(folder) == []
    pack = load_pack(folder)
    assert (pack.id, pack.source, pack.license) == (name, "daedalus", "GPL-3.0-or-later")
    assert pack.sha256 == packs.digest((folder / "controls.json").read_bytes())
    assert len(pack.controls) == count
    assert not (folder / "rules.md").exists()


def test_frameworks_folder_holds_no_standards_pack() -> None:
    # 2.4: no rules.md anywhere, so the standards lookup never takes it for a standards pack.
    assert list(packs.FRAMEWORKS_DIR.rglob("rules.md")) == []
    assert sorted(p.name for p in packs.FRAMEWORKS_DIR.iterdir()) == sorted(SHIPPED)


def test_aws_default_controls_name_their_service_verify_and_nist_ids() -> None:
    pack = load_pack(packs.FRAMEWORKS_DIR / "aws-default")
    services = {control.service for control in pack.controls}
    assert services == set(packs.SERVICES) - {"any", "payments"}
    for control in pack.controls:
        match = AWS_ID.fullmatch(control.id)
        assert match and match.group(1) == control.service.upper(), control.id
        assert control.verify and control.verify.startswith("rg -n"), control.id
        assert control.refs.nist and control.refs.cis == (), control.id
        assert control.statement and control.look_for and control.maps_to is None


def test_nist_distilled_controls_are_any_service_and_cite_themselves() -> None:
    pack = load_pack(packs.FRAMEWORKS_DIR / "nist-distilled")
    for control in pack.controls:
        assert control.service == "any"
        assert control.refs.nist == (control.id,)
        assert control.verify and control.verify.startswith("rg -n")


def test_shipped_packs_hold_no_long_quote() -> None:
    # 0024: a tripwire for pasted text, as the rubric test was.
    for name in SHIPPED:
        text = (packs.FRAMEWORKS_DIR / name / "controls.json").read_text(encoding="utf-8")
        assert chr(0x2013) not in text and chr(0x2014) not in text
        assert [s for s in re.findall("“([^”]*)”", text) if len(s) > 40] == []


def _verify_commands() -> list[tuple[str, str]]:
    return [
        (control.id, control.verify or "")
        for name in SHIPPED
        for control in load_pack(packs.FRAMEWORKS_DIR / name).controls
    ]


@pytest.mark.usefixtures("jail_fakes")
def test_every_shipped_verify_command_passes_the_jail_beside_a_reply_key(tmp_path: Path) -> None:
    # 2.3, SC-12: run from a checkout holding .claude/daedalus/reply-hmac.key, each verify is
    # admitted, since rg skips the hidden .claude folder; grep -r and git grep are refused.
    repo = _key_repo(tmp_path)
    assert (repo / ".claude" / "daedalus" / "reply-hmac.key").is_file()
    refused = [
        ident
        for ident, command in _verify_commands()
        if not decide(_bash_in(repo, "framework-specialist", command), CFG).allow
    ]
    assert refused == []
    for bad in ("grep -rn x .", "rg -n --hidden x .", "rg -nu x .", "git grep -n x"):
        assert not decide(_bash_in(repo, "framework-specialist", bad), CFG).allow, bad


def test_every_shipped_verify_pattern_compiles() -> None:
    # 2.3: rg -n[i] '<pattern>' [-g '<glob>'...] . with no hidden-folder flag; Python re as a proxy.
    for ident, command in _verify_commands():
        words = shlex.split(command)
        assert words[0] == "rg" and words[1] in ("-n", "-ni") and words[-1] == ".", ident
        assert all(w == "-g" for w in words[3:-1:2]), ident
        re.compile(words[2])


NIST_IDS = packs.NIST_IDS


def test_nist_distillation_ids_exist_in_the_catalog() -> None:
    # 0024, 0157: moved from the agent tests; every distilled control is a base catalog control.
    catalog = set(NIST_IDS.read_text().split())
    rows = [c.id for c in load_pack(packs.FRAMEWORKS_DIR / "nist-distilled").controls]
    assert rows
    assert len(rows) == len(set(rows))
    assert [row for row in rows if row not in catalog] == []


def test_rubric_controls_have_unique_ids_and_cite_no_unchecked_cis_number() -> None:
    # 0024, 0157: moved from the agent tests; no CIS number was checked against a licensed copy.
    pack = load_pack(packs.FRAMEWORKS_DIR / "aws-default")
    ids = [control.id for control in pack.controls]
    assert ids and len(ids) == len(set(ids))
    assert [control.id for control in pack.controls if control.refs.cis] == []


def test_rubric_controls_hold_no_long_quote() -> None:
    # 0024, 0157: moved from the agent tests; a tripwire for pasted benchmark text.
    pack = load_pack(packs.FRAMEWORKS_DIR / "aws-default")
    texts = [t for c in pack.controls for t in (c.title, c.statement, c.look_for) if t]
    spans = [s for t in texts for s in re.findall('"([^"]*)"|“([^”]*)”', t)]
    assert [s for pair in spans for s in pair if len(s) > 40] == []


# Problem kinds (requirements 2, 3 and 13).


def test_a_good_fixture_pack_loads(tmp_path: Path) -> None:
    folder = _make(tmp_path / "good", [_control(live_check="aws iam list-roles")])
    pack = load_pack(folder, known=())
    assert pack.controls[0].live_check == "aws iam list-roles"
    assert pack.controls[0].refs == packs.Refs(("AC-2",), (), ())


@pytest.mark.parametrize("name", ["pack.json", "controls.json"])
def test_a_missing_file_is_a_problem(tmp_path: Path, name: str) -> None:
    folder = _make(tmp_path / "p")
    (folder / name).unlink()
    assert pack_problems(folder) == [f"{name} is missing"]


def test_a_linked_file_is_a_problem(tmp_path: Path) -> None:
    folder = _make(tmp_path / "p")
    (folder / "pack.json").rename(tmp_path / "real.json")
    os.symlink(tmp_path / "real.json", folder / "pack.json")
    assert pack_problems(folder) == ["pack.json is a symlink"]
    with pytest.raises(PackError, match="pack.json is a symlink"):
        load_pack(folder)


def test_a_missing_folder_is_a_problem(tmp_path: Path) -> None:
    assert pack_problems(tmp_path / "none") == [f"{tmp_path / 'none'} is not a folder"]


def test_a_file_over_the_size_cap_is_a_problem(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    folder = _make(tmp_path / "p")
    monkeypatch.setattr(packs, "MAX_BYTES", 10)
    assert "pack.json is larger than 10 bytes" in _problems(folder)


def test_an_unreadable_file_is_a_problem(tmp_path: Path) -> None:
    folder = _make(tmp_path / "p")
    (folder / "controls.json").chmod(0)
    assert _problems(folder) == "controls.json could not be read (Permission denied)"


def test_a_hash_mismatch_is_a_problem(tmp_path: Path) -> None:
    folder = _make(tmp_path / "p", sha256="0" * 64)
    assert "not the " + "0" * 64 + " pack.json declares" in _problems(folder)


@pytest.mark.parametrize(
    ("meta", "want"),
    [
        ({"extra": 1}, "pack.json has the key 'extra', which is off the spec 2.3 tables"),
        ({"id": "Bad_Id"}, "pack.json id must be"),
        ({"version": "1.0"}, "pack.json version must be"),
        ({"source": ""}, "pack.json source must be"),
        ({"license": 7}, "pack.json license must be"),
        ({"pinned_on": "2026-02-30"}, "pack.json pinned_on must be"),
        ({"pinned_on": "26-10-2026"}, "pack.json pinned_on must be"),
        ({"sha256": "ABC"}, "pack.json sha256 must be"),
    ],
)
def test_a_bad_pack_json_value_is_a_problem(
    tmp_path: Path, meta: dict[str, object], want: str
) -> None:
    assert want in _problems(_make(tmp_path / "p", **meta))


def test_a_missing_pack_json_key_is_a_problem(tmp_path: Path) -> None:
    folder = _make(tmp_path / "p")
    doc = json.loads((folder / "pack.json").read_text())
    del doc["pinned_on"]
    (folder / "pack.json").write_text(json.dumps(doc))
    assert _problems(folder) == "pack.json lacks the key 'pinned_on'"


@pytest.mark.parametrize(
    ("text", "want"),
    [
        ("[]", "pack.json is not a JSON object"),
        ("{", "pack.json is not valid UTF-8 JSON"),
        ('{"id": "p", "id": "q"}', "key 'id' is named twice"),
    ],
)
def test_a_malformed_pack_json_is_a_problem(tmp_path: Path, text: str, want: str) -> None:
    folder = _make(tmp_path / "p")
    (folder / "pack.json").write_text(text)
    assert want in _problems(folder)


@pytest.mark.parametrize(
    ("doc", "want"),
    [
        (
            {"schema": "daedalus-controls/1", "controls": [], "x": 1},
            "controls.json has the key 'x'",
        ),
        ({"schema": "other/1", "controls": []}, "controls.json schema must be"),
        ({"schema": "daedalus-controls/1", "controls": {}}, "controls must be a list"),
        ([], "controls.json is not a JSON object"),
        ({"schema": "daedalus-controls/1", "controls": [1]}, "controls[0] is not a JSON object"),
    ],
)
def test_a_bad_controls_json_is_a_problem(tmp_path: Path, doc: object, want: str) -> None:
    assert want in _problems(_make(tmp_path / "p", text=json.dumps(doc)))


def test_controls_json_that_is_not_json_is_a_problem(tmp_path: Path) -> None:
    assert "controls.json is not valid UTF-8 JSON" in _problems(_make(tmp_path / "p", text="{"))


@pytest.mark.parametrize(
    ("control", "want"),
    [
        (_control(extra="x"), "control X-1 has the key 'extra', which is off the spec 2.3 tables"),
        (_control(refs={"nist": [], "cis": [], "asvs": [], "x": []}), "refs has the key 'x'"),
        (_control(refs=[]), "refs must be an object"),
        (_control(refs={"nist": [], "cis": ["a b"], "asvs": []}), "refs.cis must be a list"),
        (_control(refs={"nist": [], "cis": []}), "refs.asvs must be a list"),
        (_control(service="rds"), "service must be one of"),
        (_control(title="two\nlines"), "title must be one printable line"),
        (_control(verify=""), "verify must be one printable line"),
        (_control(statement="x" * 4001), "statement must be one printable line"),
        (_control("bad id"), "controls[0] id must match"),
        (_control(maps_to="no such id!"), "maps_to must be a control id"),
    ],
)
def test_a_bad_control_value_is_a_problem(
    tmp_path: Path, control: dict[str, object], want: str
) -> None:
    assert want in _problems(_make(tmp_path / "p", [control]))


@pytest.mark.parametrize(
    "key", ["id", "service", "title", "refs", "statement", "look_for", "verify"]
)
def test_a_missing_control_key_is_a_problem(tmp_path: Path, key: str) -> None:
    control = _control()
    del control[key]
    assert f"lacks the key {key!r}" in _problems(_make(tmp_path / "p", [control]))


def test_an_id_map_control_needs_no_statement_hint_or_command(tmp_path: Path) -> None:
    mapped = {"id": "1.1", "service": "any", "title": "B 1.1", "maps_to": "X-1"}
    mapped["refs"] = {"nist": [], "cis": ["1.1"], "asvs": []}
    folder = _make(tmp_path / "p", [_control(), mapped])
    assert pack_problems(folder, known=()) == []


def test_a_duplicate_control_id_is_a_problem(tmp_path: Path) -> None:
    folder = _make(tmp_path / "p", [_control(), _control()])
    assert _problems(folder) == "control X-1 is a duplicate id"


def test_a_maps_to_naming_no_loaded_control_is_a_problem(tmp_path: Path) -> None:
    folder = _make(tmp_path / "p", [_control(maps_to="AWS-IAM-99")])
    want = "control X-1 maps_to 'AWS-IAM-99', which no loaded pack holds"
    assert pack_problems(folder) == [want]
    assert pack_problems(folder, known={"AWS-IAM-99"}) == []


def test_maps_to_reads_the_packs_beside_it_and_the_shipped_packs(tmp_path: Path) -> None:
    _make(tmp_path / "base", [_control("BASE-1")])
    shipped = _make(tmp_path / "s", [_control(maps_to="AWS-IAM-1")])
    folder = _make(tmp_path / "p", [_control(maps_to="BASE-1")])
    assert pack_problems(folder) == [] and pack_problems(shipped) == []
    assert "maps_to 'BASE-1'" in "".join(pack_problems(folder, known=()))


def test_a_nist_id_outside_the_catalog_list_is_a_problem(tmp_path: Path) -> None:
    folder = _make(tmp_path / "p", [_control(refs={"nist": ["AC-999"], "cis": [], "asvs": []})])
    assert _problems(folder) == "control X-1 refs.nist id 'AC-999' is not in nist-control-ids.txt"


def test_a_nist_ref_holding_a_list_is_a_problem_not_a_crash(tmp_path: Path) -> None:
    # prepush-2026-10-27 finding 5: an unhashable id never reaches the catalog lookup.
    refs = {"nist": [["AC-2"], {"x": 1}, "AC-2"], "cis": [], "asvs": []}
    folder = _make(tmp_path / "p", [_control(refs=refs)])
    assert _problems(folder) == "control X-1 refs.nist must be a list of ids"


# 113, prepush-2026-10-27 finding 2: verify commands the specialist's jail refuses.
HOSTILE_VERIFY = (
    "rg --ignore-file /tmp/ig -n BEGIN .",
    "rg --ignore-file=/tmp/ig -n BEGIN .",
    "rg -L -n BEGIN .",
    "rg --follow BEGIN .",
    "rg --hidden -n BEGIN .",
    "rg -n BEGIN ~/.ssh",
    "rg -g .claude -g '*.key' -l . .",
    "RIPGREP_CONFIG_PATH=/tmp/rc rg -n BEGIN .",
    "git diff --stat",
    "rg -n x . | head",
    "rg --pre cat x .",
)


@pytest.mark.parametrize("command", HOSTILE_VERIFY)
def test_a_verify_the_specialists_jail_refuses_is_a_pack_problem(
    tmp_path: Path, command: str
) -> None:
    folder = _make(tmp_path / "p", [_control(verify=command)])
    found = _problems(folder)
    assert found.startswith("control X-1 verify is refused by the framework specialist's jail: ")
    with pytest.raises(PackError):
        load_pack(folder, known=())


# prepush2-2026-10-27 item 4: verify paths that leave the project tree.
OUTSIDE_VERIFY = (
    ("rg -n x /", "/"),
    ("rg -n x ~", "~"),
    ("rg --files /srv/someone", "/srv/someone"),
    ("rg -n x /srv/someone/.claude", "/srv/someone/.claude"),
    ("rg -n x ..", ".."),
    ("rg -n x src/../..", "src/../.."),
    ("rg -n x . ../other", "../other"),
    ("rg -f /etc/hostname .", "/etc/hostname"),
    ("rg --file=/etc/hostname .", "/etc/hostname"),
)


@pytest.mark.parametrize(("command", "path"), OUTSIDE_VERIFY)
def test_a_verify_searching_outside_the_tree_is_a_pack_problem(
    tmp_path: Path, command: str, path: str
) -> None:
    folder = _make(tmp_path / "p", [_control(verify=command)])
    want = f"control X-1 verify searches {path!r} outside the project tree"
    assert want in _problems(folder)


def test_a_verify_inside_the_tree_is_no_problem(tmp_path: Path) -> None:
    for command in ("rg -n x src", "rg --files src", "rg -n x ./src", "rg -n '/api/..' ."):
        assert pack_problems(_make(tmp_path / "p", [_control(verify=command)]), known=()) == []


def test_a_plain_rg_verify_is_no_problem(tmp_path: Path) -> None:
    for command in ("rg -n x .", "rg -n -F 'AC-2(1)' .", "rg -n 'a|b' -g '*.tf' -g '*.yml' ."):
        assert pack_problems(_make(tmp_path / "p", [_control(verify=command)]), known=()) == []


def test_an_unreadable_nist_list_is_a_problem(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(packs, "NIST_IDS", tmp_path / "missing.txt")
    assert "refs.nist cannot be checked" in _problems(_make(tmp_path / "p"))


@pytest.mark.parametrize(
    ("license_", "length", "flagged"),
    [
        ("operator-licensed, ids only", 401, True),
        ("operator-licensed", 401, True),
        ("operator-licensed, ids only", 400, False),
        ("GPL-3.0-or-later", 401, False),
    ],
)
def test_a_long_statement_in_an_operator_licensed_pack_is_a_problem(
    tmp_path: Path, license_: str, length: int, flagged: bool
) -> None:
    folder = _make(tmp_path / "p", [_control(statement="s" * length)], license=license_)
    found = pack_problems(folder, known=())
    want = f"control X-1 statement is {length} characters, over 400 in an operator-licensed pack"
    assert found == ([want] if flagged else [])


def test_load_pack_raises_with_every_problem(tmp_path: Path) -> None:
    folder = _make(tmp_path / "p", [_control(), _control()], sha256="0" * 64)
    with pytest.raises(PackError) as caught:
        load_pack(folder, known=())
    assert len(caught.value.problems) == 2
    assert "duplicate id" in str(caught.value)


def test_control_ids_skip_an_unreadable_pack(tmp_path: Path) -> None:
    good = _make(tmp_path / "good", [_control("G-1")])
    bad = _make(tmp_path / "bad", text="{")
    assert packs.control_ids([good, bad, tmp_path / "none"]) == {"G-1"}


# pack_folders (requirement 4).


def _manifest(repo: Path, frameworks: object) -> None:
    doc = {} if frameworks is None else {"frameworks": frameworks}
    (repo / "service-manifest.json").write_text(json.dumps(doc), encoding="utf-8")


def _shipped() -> list[Path]:
    return [packs.FRAMEWORKS_DIR / name for name in sorted(set(SHIPPED) - OFF_BY_DEFAULT)]


def test_pack_folders_reads_the_shipped_packs_with_no_folder_named(repo_cwd: Path) -> None:
    # 0157 (12.1): no manifest, or one with no frameworks block, reads the shipped packs.
    assert pack_folders(repo_cwd) == _shipped()
    _manifest(repo_cwd, None)
    assert pack_folders(repo_cwd) == _shipped()


def test_pack_folders_reads_the_declared_folder_then_the_shipped_packs(repo_cwd: Path) -> None:
    root = repo_cwd / "compliance" / "packs"
    one, two = _make(root / "one"), _make(root / "two")
    (root / "empty").mkdir()
    (root / "notes.txt").write_text("x")
    os.symlink(one, root / "linked")
    _manifest(repo_cwd, {"pack_dir": "compliance/packs"})
    assert pack_folders(repo_cwd) == [one, two, *_shipped()]
    _manifest(repo_cwd, {"pack_dir": "compliance/packs", "default_packs": False})
    assert pack_folders(repo_cwd) == [one, two]


def test_pack_folders_with_a_missing_declared_folder(repo_cwd: Path) -> None:
    _manifest(repo_cwd, {"pack_dir": "absent", "default_packs": False})
    assert pack_folders(repo_cwd) == []
    _manifest(repo_cwd, {"pack_dir": "absent"})
    assert pack_folders(repo_cwd) == _shipped()


# prepush-2026-10-27 finding 6: the train step that runs pack_problems before the specialist.


def test_train_packs_prints_the_checked_folders_or_stops(
    repo_cwd: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    import daedalus_train

    monkeypatch.chdir(repo_cwd)
    run = ["packs", "--repo", str(repo_cwd)]
    one = _make(repo_cwd / "packs" / "one")
    _manifest(repo_cwd, {"pack_dir": "packs", "default_packs": False})
    assert daedalus_train.main(run) == 0
    assert capsys.readouterr().out == f"Packs: {one}\n"
    _make(repo_cwd / "packs" / "two", [_control(verify="rg --ignore-file /tmp/x -n . .")])
    assert daedalus_train.main(run) == 1
    out = capsys.readouterr().out.splitlines()
    assert out[0].startswith("pack two: control X-1 verify is refused by the framework")
    assert out[-1].startswith("Next: run /daedalus:doctor and fix each pack it names")
    _manifest(repo_cwd, {"pack_dir": "absent", "default_packs": False})
    assert daedalus_train.main(run) == 1
    assert capsys.readouterr().out.startswith("No control pack was found")


# 0192: the default and triggers keys of pack.json, and the two game stack packs.


def test_a_default_false_pack_is_read_only_when_named(repo_cwd: Path) -> None:
    cost = packs.FRAMEWORKS_DIR / "cost-tier"
    assert load_pack(cost).default is False
    assert cost not in pack_folders(repo_cwd)
    _manifest(repo_cwd, {"packs": ["cost-tier"]})
    assert pack_folders(repo_cwd) == sorted([*_shipped(), cost])
    _manifest(repo_cwd, {"packs": ["cost-tier"], "default_packs": False})
    assert pack_folders(repo_cwd) == [cost]
    assert packs.unknown_named(repo_cwd) == []
    _manifest(repo_cwd, {"packs": ["no-such-pack"]})
    assert packs.unknown_named(repo_cwd) == ["no-such-pack"]


@pytest.mark.parametrize(
    ("key", "value", "want"),
    [
        ("default", "no", "pack.json default must be true or false"),
        ("triggers", [], "pack.json triggers must be a list of 1 to 32 path globs"),
        ("triggers", "**/*stripe*", "pack.json triggers must be a list"),
        ("triggers", ["ok", 3], "pack.json triggers must be a list"),
        ("triggers", ["x\ny"], "pack.json triggers must be a list"),
    ],
)
def test_a_bad_default_or_triggers_value_is_a_problem(
    tmp_path: Path, key: str, value: object, want: str
) -> None:
    folder = _make(tmp_path / "p")
    meta = json.loads((folder / "pack.json").read_text(encoding="utf-8"))
    (folder / "pack.json").write_text(json.dumps({**meta, key: value}), encoding="utf-8")
    assert want in _problems(folder)


def _as_shipped(monkeypatch: pytest.MonkeyPatch, folder: Path) -> Path:
    # 0192: default and triggers load only from the shipped folder, so tests stand one up.
    folder.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(packs, "FRAMEWORKS_DIR", folder)
    return folder


def test_default_and_triggers_load_and_absent_reads_as_on_with_no_triggers(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    shipped = _as_shipped(monkeypatch, tmp_path / "shipped")
    plain = load_pack(_make(shipped / "plain"), known=())
    assert (plain.default, plain.triggers) == (True, None)
    folder = _make(shipped / "trig", default=False, triggers=["**/*stripe*"])
    pack = load_pack(folder, known=())
    assert (pack.default, pack.triggers) == (False, ("**/*stripe*",))


@pytest.mark.parametrize(("key", "value"), [("default", True), ("triggers", ["**/*.py"])])
def test_a_project_pack_with_default_or_triggers_is_refused(
    tmp_path: Path, key: str, value: object
) -> None:
    folder = _make(tmp_path / "compliance" / "p")
    meta = json.loads((folder / "pack.json").read_text(encoding="utf-8"))
    (folder / "pack.json").write_text(json.dumps({**meta, key: value}), encoding="utf-8")
    want = f"pack.json {key} applies only to a pack Daedalus ships; remove it from this pack"
    assert pack_problems(folder, known=()) == [want]
    with pytest.raises(PackError, match="applies only to a pack Daedalus ships"):
        load_pack(folder, known=())


@pytest.mark.parametrize(
    ("path", "hit"),
    [
        ("stripe.ts", True),
        ("src/payments/stripe-webhook.ts", True),
        (".env", True),
        ("apps/web/.env.local", True),
        ("package.json", True),
        ("apps/web/pnpm-lock.yaml", True),
        ("src/main.ts", False),
        ("infra/main.tf", False),
        (".env.example", True),
        ("src/StripeClient.ts", True),
        ("apps/web/.ENV.Local", True),
        ("Package.JSON", True),
    ],
)
def test_the_stripe_triggers_match_the_game_stack_paths(path: str, hit: bool) -> None:
    folder = packs.FRAMEWORKS_DIR / "stripe-default"
    chosen, matched = packs.select_packs([folder], [path])
    assert (folder in chosen, folder in matched) == (hit, hit), path


def test_a_pack_with_triggers_is_named_only_when_a_path_matches(tmp_path: Path) -> None:
    plain = _make(tmp_path / "plain")
    trig = _make(tmp_path / "trig", triggers=["**/*stripe*", "docs/*.md"])
    assert packs.select_packs([plain, trig], ["src/a.py"]) == ([plain], [])
    assert packs.select_packs([plain, trig], ["src/stripe.py"]) == ([plain, trig], [trig])
    assert packs.select_packs([plain, trig], ["docs/a.md"]) == ([plain, trig], [trig])
    assert packs.select_packs([trig], []) == ([], [])
    assert packs.trigger_match("**/*STRIPE*", "src/StripeClient.ts")


def test_train_packs_with_a_diff_prints_the_triggered_packs(
    repo_cwd: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    import daedalus_train

    from tests.conftest import git

    monkeypatch.chdir(repo_cwd)
    shipped = _as_shipped(monkeypatch, tmp_path / "shipped")
    plain = _make(shipped / "plain")
    trig = _make(shipped / "trig", triggers=["**/*stripe*"])
    _make(shipped / "off", default=False)
    git(repo_cwd, "commit", "-q", "--allow-empty", "-m", "base")
    (repo_cwd / "main.py").write_text("x\n", encoding="utf-8")
    git(repo_cwd, "add", "-A")
    git(repo_cwd, "commit", "-q", "-m", "plain change")
    run = ["packs", "--repo", str(repo_cwd), "--diff", "HEAD^...HEAD"]
    assert daedalus_train.main(run) == 0
    assert capsys.readouterr().out == f"Packs: {plain}\nTriggered: none\n"
    (repo_cwd / "src").mkdir()
    (repo_cwd / "src" / "stripe.ts").write_text("x\n", encoding="utf-8")
    git(repo_cwd, "add", "-A")
    git(repo_cwd, "commit", "-q", "-m", "stripe change")
    assert daedalus_train.main(run) == 0
    assert capsys.readouterr().out == f"Packs: {plain}, {trig}\nTriggered: {trig}\n"
    for bad in ("--output", "HEAD"):
        assert daedalus_train.main(["packs", "--repo", str(repo_cwd), f"--diff={bad}"]) == 1
        assert "is not a <base>...<branch> range" in capsys.readouterr().out
    assert daedalus_train.main(["packs", "--repo", str(repo_cwd), "--diff", "nope...HEAD"]) == 1
    assert "git diff --name-only nope...HEAD failed" in capsys.readouterr().out


def test_train_packs_with_a_diff_and_no_pack_goes_on_but_a_broken_pack_stops(
    repo_cwd: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # 0192: default_packs false and no project pack must not stop a docs-only audit.
    import daedalus_train

    from tests.conftest import git

    monkeypatch.chdir(repo_cwd)
    _manifest(repo_cwd, {"default_packs": False})
    git(repo_cwd, "add", "-A")
    git(repo_cwd, "commit", "-q", "-m", "base")
    (repo_cwd / "README.md").write_text("x\n", encoding="utf-8")
    git(repo_cwd, "add", "-A")
    git(repo_cwd, "commit", "-q", "-m", "docs change")
    run = ["packs", "--repo", str(repo_cwd), "--diff", "HEAD^...HEAD"]
    assert daedalus_train.main(run) == 0
    assert capsys.readouterr().out == "Packs: none\nTriggered: none\n"
    assert daedalus_train.main(["packs", "--repo", str(repo_cwd)]) == 1
    assert capsys.readouterr().out.startswith("No control pack was found")
    bad = _make(repo_cwd / "packs" / "bad", version="1.0")
    _manifest(repo_cwd, {"pack_dir": "packs", "default_packs": False})
    assert daedalus_train.main(run) == 1
    assert capsys.readouterr().out.startswith(f"pack {bad.name}: pack.json version must be")


def test_train_packs_stops_on_a_named_pack_daedalus_does_not_ship(
    repo_cwd: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    import daedalus_train

    monkeypatch.chdir(repo_cwd)
    _manifest(repo_cwd, {"packs": ["no-such-pack"]})
    assert daedalus_train.main(["packs", "--repo", str(repo_cwd)]) == 1
    out = capsys.readouterr().out.splitlines()
    assert out[0] == (
        "pack no-such-pack: frameworks.packs names no-such-pack, which is not a pack Daedalus ships"
    )


def test_stripe_and_cost_controls_name_their_ids_services_and_rg_verify() -> None:
    stripe = load_pack(packs.FRAMEWORKS_DIR / "stripe-default")
    assert [c.id for c in stripe.controls] == [f"STRIPE-{n}" for n in range(1, 6)]
    assert {c.service for c in stripe.controls} == {"payments"}
    cost = load_pack(packs.FRAMEWORKS_DIR / "cost-tier")
    assert [c.id for c in cost.controls] == [
        "COST-KMS-1",
        "COST-KMS-2",
        "COST-S3-1",
        "COST-COMPUTE-1",
        "COST-DATA-1",
        "COST-NET-1",
        "COST-LOG-1",
        "COST-TF-1",
    ]
    for control in (*stripe.controls, *cost.controls):
        assert control.statement and "fails" in control.statement, control.id
        assert control.look_for and control.refs.nist, control.id
        assert control.verify and control.verify.startswith("rg -n"), control.id
    for control in cost.controls:
        globs = re.findall(r"-g '([^']+)'", control.verify or "")
        assert globs == ["*.tf", "*.tfvars", "*.json", "*.yaml", "*.yml"], control.id


@pytest.mark.usefixtures("jail_fakes")
def test_every_shipped_verify_command_passes_the_jail_beside_an_env_file(tmp_path: Path) -> None:
    # 0192: the .env deny leaves each shipped verify open in a project holding .env files.
    repo = _key_repo(tmp_path)
    for name in (".env", ".env.local"):
        (repo / name).write_text("STRIPE_SECRET_KEY=placeholder\n", encoding="utf-8")
    refused = [
        ident
        for ident, command in _verify_commands()
        if not decide(_bash_in(repo, "framework-specialist", command), CFG).allow
    ]
    assert refused == []
