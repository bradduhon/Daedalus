# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# A2, 0252: start, save and show of the finding store, in temporary home, tmp and data folders.
from __future__ import annotations

import hashlib
import json
import os
import stat
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from lib import findings, self_assessment, storage

from tests.conftest import REPO_ROOT, SCRIPTS_DIR

SINCE = "20260101T000000Z"
GOOD = {
    "kind": "bug",
    "skill": "setup",
    "step": "step 3",
    "text_said": "ask one question",
    "happened": "the model asked two",
    "model_did": "asked one at a time",
    "result_changed": "no",
}


@pytest.fixture
def env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    home = tmp_path / "home"
    (home / ".claude" / "daedalus").mkdir(parents=True)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("CLAUDE_PLUGIN_DATA", str(tmp_path / "data"))
    (tmp_path / "data").mkdir()
    monkeypatch.setattr(storage, "TMP_ROOT", tmp_path / "tmproot")
    return tmp_path


@pytest.fixture
def repo(env: Path) -> Path:
    folder = env / "repo"
    (folder / ".git").mkdir(parents=True)
    return folder


def _mode(env: Path, on: bool) -> None:
    body = json.dumps({"self_assessment": on})
    (env / "home" / ".claude" / "daedalus" / "operator.json").write_text(body, encoding="utf-8")


def _handover(repo: Path, body: object, since: str = SINCE) -> Path:
    folder = self_assessment.make_handover_dir(repo)
    path = folder / self_assessment.handover_name(since)
    path.write_text(body if isinstance(body, str) else json.dumps(body), encoding="utf-8")
    return path


def _saved(env: Path) -> list[Path]:
    return sorted((env / "data" / "self-assessment" / "findings").glob("*.json"))


def _tree(root: Path) -> list[str]:
    return sorted(str(p.relative_to(root)) for p in root.rglob("*"))


def test_start_on_prints_stamp_and_path_and_makes_the_folder(env: Path, repo: Path) -> None:
    _mode(env, True)
    code, lines = findings.start(str(repo))
    assert code == 0 and len(lines) == 1
    head, _, rest = lines[0].partition(" since=")
    stamp, _, path = rest.partition(" handover=")
    assert head == "self-assessment: on"
    assert findings.STAMP.fullmatch(stamp)
    assert path == str(self_assessment.handover_dir(repo) / f"handover-{stamp}.json")
    assert self_assessment.handover_dir(repo).is_dir()


def test_start_off_makes_no_folder(env: Path, repo: Path) -> None:
    _mode(env, False)
    assert findings.start(str(repo)) == (0, ["self-assessment: off"])
    assert not (env / "tmproot").exists()


def test_start_refuses_a_bad_folder(env: Path, repo: Path) -> None:
    _mode(env, True)
    (env / "elsewhere").mkdir()
    (env / "tmproot").symlink_to(env / "elsewhere")
    code, lines = findings.start(str(repo))
    assert code == 1 and lines[0].startswith("self-assessment: refused: ")


def test_save_writes_exact_keys_and_derived_fields(env: Path, repo: Path) -> None:
    _mode(env, True)
    target = _handover(repo, GOOD)
    code, lines = findings.save(str(repo), SINCE)
    assert code == 0 and not target.exists()
    (file,) = _saved(env)
    fp = hashlib.sha256(
        "\n".join(["bug", "setup", "step 3", "ask one question"]).encode()
    ).hexdigest()[:12]
    assert lines == [f"saved: {file.name} fingerprint={fp}"]
    assert findings.FINDING_NAME.fullmatch(file.name) and file.name.endswith(f"-{fp}.json")
    record = json.loads(file.read_text(encoding="utf-8"))
    assert set(record) == {*findings.KEYS, "fingerprint", "plugin_version", "skill_hash"}
    assert record["fingerprint"] == fp
    manifest = json.loads((REPO_ROOT / ".claude-plugin" / "plugin.json").read_text())
    assert record["plugin_version"] == manifest["version"]
    skill = (REPO_ROOT / "skills" / "setup" / "SKILL.md").read_bytes()
    assert record["skill_hash"] == hashlib.sha256(skill).hexdigest()[:12]
    for folder in (file.parent, file.parent.parent):
        assert stat.S_IMODE(folder.stat().st_mode) == 0o700


def test_save_accepts_a_nested_skill_name(env: Path, repo: Path) -> None:
    names = findings._skill_files()
    nested = [n for n, p in names.items() if "kinds" in p.parts]
    assert nested, "the document kinds skill files are on the allow list"


def test_save_off_deletes_the_handover_and_saves_nothing(env: Path, repo: Path) -> None:
    _mode(env, False)
    target = _handover(repo, GOOD)
    assert findings.save(str(repo), SINCE) == (0, ["self-assessment: off; nothing saved"])
    assert not target.exists() and not _saved(env)


def test_save_missing_file(env: Path, repo: Path) -> None:
    _mode(env, True)
    self_assessment.make_handover_dir(repo)
    assert findings.save(str(repo), SINCE) == (1, ["refused: hand-over: no file"])


def test_save_refuses_a_symlink_and_removes_it(env: Path, repo: Path) -> None:
    _mode(env, True)
    real = env / "real.json"
    real.write_text(json.dumps(GOOD), encoding="utf-8")
    folder = self_assessment.make_handover_dir(repo)
    link = folder / self_assessment.handover_name(SINCE)
    link.symlink_to(real)
    code, lines = findings.save(str(repo), SINCE)
    assert code == 1 and lines[0].startswith("refused: hand-over: ")
    assert not link.is_symlink() and real.exists() and not _saved(env)


def test_save_refuses_an_oversize_file_and_deletes_it(env: Path, repo: Path) -> None:
    _mode(env, True)
    target = _handover(repo, " " * (self_assessment.MAX_HANDOVER_BYTES + 1))
    code, lines = findings.save(str(repo), SINCE)
    assert code == 1 and lines[0].startswith("refused: hand-over: is over")
    assert not target.exists()


def test_save_refuses_a_folder_check_failure(env: Path, repo: Path) -> None:
    _mode(env, True)
    _handover(repo, GOOD)
    os.chmod(self_assessment.handover_dir(repo), 0o770)
    code, lines = findings.save(str(repo), SINCE)
    assert code == 1 and lines[0].startswith("refused: hand-over: ")
    assert not _saved(env)


@pytest.mark.parametrize("body", ["{not json", "[1]", '"x"', "\xff\xfe"])
def test_save_malformed_handover_is_one_line(env: Path, repo: Path, body: str) -> None:
    _mode(env, True)
    target = _handover(repo, body)
    code, lines = findings.save(str(repo), SINCE)
    assert code == 1 and len(lines) == 1 and lines[0].startswith("refused: hand-over: ")
    assert not target.exists()


def test_save_refuses_a_bad_stamp(env: Path, repo: Path) -> None:
    _mode(env, True)
    code, lines = findings.save(str(repo), "yesterday")
    assert code == 1 and lines[0].startswith("refused: hand-over: ")


def test_save_names_missing_and_extra_keys(env: Path, repo: Path) -> None:
    _mode(env, True)
    body = {k: v for k, v in GOOD.items() if k != "step"} | {"extra": "x"}
    _handover(repo, body)
    code, lines = findings.save(str(repo), SINCE)
    assert code == 1
    assert lines == ["refused: step: missing", "refused: extra: not allowed"]
    assert not _saved(env)


@pytest.mark.parametrize(
    ("field", "value", "word"),
    [
        ("kind", "idea", "bug or feature"),
        ("result_changed", "maybe", "yes or no"),
        ("skill", "nonesuch", "shipped skill"),
        ("skill", ["setup"], "shipped skill"),
        ("step", "", "empty"),
        ("step", "   ", "empty"),
        ("text_said", "a\nb", "line break"),
        ("happened", "a\r", "line break"),
        ("model_did", "x" * 501, "500"),
        ("step", 7, "text"),
        ("step", "a\x1b[31mred", "control character"),
        ("happened", "a\tb", "control character"),
        ("model_did", "a​b", "control character"),
        ("text_said", "a‮b", "control character"),
    ],
)
def test_save_refuses_each_broken_field(
    env: Path, repo: Path, field: str, value: object, word: str
) -> None:
    _mode(env, True)
    target = _handover(repo, GOOD | {field: value})
    code, lines = findings.save(str(repo), SINCE)
    assert code == 1 and len(lines) == 1
    assert lines[0].startswith(f"refused: {field}: ") and word in lines[0]
    assert not target.exists() and not _saved(env)


def test_save_boundary_text_of_500_passes(env: Path, repo: Path) -> None:
    _mode(env, True)
    _handover(repo, GOOD | {"step": "x" * 500})
    assert findings.save(str(repo), SINCE)[0] == 0


def test_a_project_path_in_a_text_field_is_refused_and_no_file_holds_it(
    env: Path, repo: Path
) -> None:
    _mode(env, True)
    _handover(repo, GOOD | {"happened": f"it opened {repo}/x.py"})
    code, lines = findings.save(str(repo), SINCE)
    assert code == 1 and lines == ["refused: happened: holds the project's absolute path"]
    _handover(repo, GOOD)
    assert findings.save(str(repo), SINCE)[0] == 0
    for file in env.rglob("*.json"):
        assert str(repo) not in file.read_text(encoding="utf-8")


def test_show_lists_bugs_and_features_since(env: Path, repo: Path) -> None:
    _mode(env, True)
    for kind, said in (("bug", "one"), ("feature", "two")):
        _handover(repo, GOOD | {"kind": kind, "text_said": said})
        assert findings.save(str(repo), SINCE)[0] == 0
    code, lines = findings.show(str(repo), SINCE)
    assert code == 0
    assert lines == [
        "Bugs (1)",
        "setup: step 3: the model asked two",
        "Features (1)",
        "setup: step 3: the model asked two",
    ]
    future = findings.utc_stamp(datetime.now(UTC) + timedelta(days=1))
    assert findings.show(str(repo), future)[1] == ["Bugs (0)", "Features (0)"]


def test_show_deletes_old_findings_and_handovers(env: Path, repo: Path) -> None:
    _mode(env, True)
    _handover(repo, GOOD)
    assert findings.save(str(repo), SINCE)[0] == 0
    folder = _saved(env)[0].parent
    old = findings.utc_stamp(datetime.now(UTC) - timedelta(days=31))
    young = findings.utc_stamp(datetime.now(UTC) - timedelta(days=29))
    (folder / f"{old}-aaaaaaaaaaaa.json").write_text("{}", encoding="utf-8")
    (folder / f"{young}-bbbbbbbbbbbb.json").write_text("{}", encoding="utf-8")
    (folder / "notes.txt").write_text("keep", encoding="utf-8")
    left = _handover(repo, GOOD, "20260102T000000Z")
    assert findings.show(str(repo), SINCE)[0] == 0
    names = {p.name for p in folder.iterdir()}
    assert f"{old}-aaaaaaaaaaaa.json" not in names
    assert f"{young}-bbbbbbbbbbbb.json" in names and "notes.txt" in names
    assert not left.exists()


@pytest.mark.parametrize("bad", ["a\x1b[31mb", "a\tb", "a​b", "a‮b", 5, ""])
def test_show_skips_a_stored_finding_with_unprintable_fields(
    env: Path, repo: Path, bad: object
) -> None:
    _mode(env, True)
    _handover(repo, GOOD)
    assert findings.save(str(repo), SINCE)[0] == 0
    folder = _saved(env)[0].parent
    record = json.loads(_saved(env)[0].read_text(encoding="utf-8"))
    stamp = findings.utc_stamp()
    (folder / f"{stamp}-cccccccccccc.json").write_text(
        json.dumps(record | {"happened": bad}), encoding="utf-8"
    )
    lines = findings.show(str(repo), SINCE)[1]
    assert lines == ["Bugs (1)", "setup: step 3: the model asked two", "Features (0)"]


def test_show_off(env: Path, repo: Path) -> None:
    _mode(env, False)
    assert findings.show(str(repo), SINCE) == (0, ["self-assessment: off"])


def test_show_without_a_data_folder_is_one_line(
    env: Path, repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _mode(env, True)
    monkeypatch.delenv("CLAUDE_PLUGIN_DATA")
    code, lines = findings.show(str(repo), SINCE)
    assert code == 1 and len(lines) == 1 and lines[0].startswith("refused: findings: ")


def test_save_without_a_data_folder_is_one_line(
    env: Path, repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _mode(env, True)
    _handover(repo, GOOD)
    monkeypatch.delenv("CLAUDE_PLUGIN_DATA")
    code, lines = findings.save(str(repo), SINCE)
    assert code == 1 and len(lines) == 1 and lines[0].startswith("refused: findings: ")


def test_an_unreadable_personal_file_reads_as_off(env: Path, repo: Path) -> None:
    (env / "home" / ".claude" / "daedalus" / "operator.json").write_text("{bad", encoding="utf-8")
    assert findings.start(str(repo)) == (0, ["self-assessment: off"])


def test_the_project_is_unchanged_by_start_save_and_show(env: Path, repo: Path) -> None:
    _mode(env, True)
    before = _tree(repo)
    _, lines = findings.start(str(repo))
    stamp = lines[0].split("since=")[1].split(" ")[0]
    _handover(repo, GOOD, stamp)
    findings.save(str(repo), stamp)
    findings.show(str(repo), stamp)
    assert _tree(repo) == before


def test_the_command_line_runs_without_a_traceback(env: Path, repo: Path) -> None:
    _mode(env, True)
    run_env = os.environ | {"HOME": str(env / "home"), "CLAUDE_PLUGIN_DATA": str(env / "data")}
    script = str(SCRIPTS_DIR / "daedalus_findings.py")
    done = subprocess.run(
        [sys.executable, script, "save", "--repo", str(repo), "--since", SINCE],
        capture_output=True,
        text=True,
        env=run_env,
        check=False,
    )
    assert done.returncode == 1 and "Traceback" not in done.stderr
    assert done.stdout.startswith("refused: hand-over: ")
