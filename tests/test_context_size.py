# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0273: the context size reader, every reason from a real file state in a temp folder.
from __future__ import annotations

import json
import os
import stat
from collections.abc import Callable
from pathlib import Path

import pytest
from lib import context_size as cs
from lib.context_size import Handling, Measured, Reason, Unmeasured, context_size

SESSION = "s-1_a"
AGENT = "a1b2c3"
OPUS = "claude-opus-5-5"


def _usage(total: int, model: str = OPUS, **override: object) -> str:
    usage: dict[str, object] = {
        "input_tokens": total - 30,
        "cache_creation_input_tokens": 10,
        "cache_read_input_tokens": 10,
        "output_tokens": 10,
    }
    usage.update(override)
    return json.dumps({"type": "assistant", "message": {"model": model, "usage": usage}})


def _boundary(post: object) -> str:
    meta = {"trigger": "auto", "preTokens": 900000, "postTokens": post}
    return json.dumps({"type": "system", "subtype": "compact_boundary", "compactMetadata": meta})


def _filler(size: int) -> str:
    line = json.dumps({"type": "user", "message": {"content": "x" * 1000}})
    return "\n".join([line] * (size // (len(line) + 1) + 1))


class Tree:
    def __init__(self, tmp: Path) -> None:
        self.root = tmp / "projects"
        self.project = self.root / "proj"
        self.sub = self.project / SESSION / "subagents"
        self.sub.mkdir(parents=True)
        self.main = self.project / f"{SESSION}.jsonl"
        self.file = self.sub / f"agent-{AGENT}.jsonl"
        self.meta = self.sub / f"agent-{AGENT}.meta.json"

    def write(self, *lines: str, end: str = "\n") -> None:
        self.file.write_text("\n".join(lines) + end, encoding="utf-8")
        self.file.chmod(0o600)

    def set_meta(self, model: object) -> None:
        self.meta.write_text(json.dumps({"agentType": "x", "model": model}), encoding="utf-8")

    def read(self, transcript: object = None, agent: object = AGENT) -> cs.SizeResult:
        path = str(self.main) if transcript is None else transcript
        return context_size(path, SESSION, agent, projects_root=self.root)


@pytest.fixture
def tree(tmp_path: Path) -> Tree:
    return Tree(tmp_path)


def _reason(result: cs.SizeResult) -> Reason:
    assert isinstance(result, Unmeasured), result
    return result.reason


def test_every_reason_carries_its_handling() -> None:
    allowed = {Reason.MAIN_SESSION, Reason.NO_TRANSCRIPT, Reason.NO_USAGE_YET}
    assert len(Reason) == 11
    for reason in Reason:
        want = Handling.ALLOW_WARN if reason in allowed else Handling.REFUSE
        assert reason.handling is want, reason
        assert reason.label


def test_count_is_the_four_usage_fields(tree: Tree) -> None:
    tree.write(_usage(1000), _usage(5000))
    assert tree.read() == Measured(5000)


def test_main_session_has_no_agent_id(tree: Tree) -> None:
    assert _reason(tree.read(agent=None)) is Reason.MAIN_SESSION


@pytest.mark.parametrize("agent", ["a/b", "..", "a..b", "Ab12", "", 12, "a b", "a-b"])
def test_agent_id_outside_its_shape(tree: Tree, agent: object) -> None:
    assert _reason(tree.read(agent=agent)) is Reason.BAD_ID


@pytest.mark.parametrize("session", ["s/1", "..", "", None, "s.1"])
def test_session_id_outside_its_shape(tree: Tree, session: object) -> None:
    result = context_size(str(tree.main), session, AGENT, projects_root=tree.root)
    assert _reason(result) is Reason.BAD_ID


@pytest.mark.parametrize("path", [None, 7, "relative/s.jsonl", "/abs/with\x00nul.jsonl"])
def test_path_not_derivable(tree: Tree, path: object) -> None:
    result = context_size(path, SESSION, AGENT, projects_root=tree.root)
    assert _reason(result) is Reason.NO_PATH


def test_transcript_path_already_in_subagent_shape(tree: Tree) -> None:
    tree.write(_usage(4200))
    assert tree.read(transcript=str(tree.file)) == Measured(4200)


def test_file_outside_the_root(tree: Tree, tmp_path: Path) -> None:
    other = Tree(tmp_path / "elsewhere")
    other.write(_usage(4200))
    assert other.read() == Measured(4200)
    result = context_size(str(other.main), SESSION, AGENT, projects_root=tree.root)
    assert _reason(result) is Reason.OUTSIDE_ROOT


def test_dot_dot_out_of_the_root(tree: Tree, tmp_path: Path) -> None:
    escape = str(tree.root / ".." / ".." / "x.jsonl")
    assert _reason(tree.read(transcript=escape)) is Reason.OUTSIDE_ROOT


def test_symlinked_folder_pointing_outside_the_root(tree: Tree, tmp_path: Path) -> None:
    outside = Tree(tmp_path / "outside")
    outside.write(_usage(4200))
    (tree.root / "linked").symlink_to(outside.project, target_is_directory=True)
    path = str(tree.root / "linked" / f"{SESSION}.jsonl")
    assert _reason(tree.read(transcript=path)) is Reason.OUTSIDE_ROOT


def test_symlink_transcript(tree: Tree, tmp_path: Path) -> None:
    real = tree.sub / "real.jsonl"
    real.write_text(_usage(4200) + "\n", encoding="utf-8")
    os.symlink(real, tree.file)
    assert _reason(tree.read()) is Reason.SYMLINK


def test_symlink_folder_on_the_walk(tree: Tree) -> None:
    # 0273: a component swapped for a symlink after the string check is refused by the openat walk.
    (tree.project / "swapped").symlink_to(tree.project / SESSION, target_is_directory=True)
    with pytest.raises(cs._Refused) as caught:
        cs._open_folder(str(tree.root), ["proj", "swapped", "subagents"])
    assert caught.value.reason is Reason.SYMLINK


def test_fifo_is_not_regular(tree: Tree) -> None:
    os.mkfifo(tree.file, 0o600)
    assert _reason(tree.read()) is Reason.NOT_REGULAR


def test_folder_is_not_regular(tree: Tree) -> None:
    tree.file.mkdir()
    assert _reason(tree.read()) is Reason.NOT_REGULAR


def test_group_or_world_writable(tree: Tree) -> None:
    tree.write(_usage(4200))
    tree.file.chmod(0o666)
    assert _reason(tree.read()) is Reason.BAD_OWNER
    tree.file.chmod(0o620)
    assert _reason(tree.read()) is Reason.BAD_OWNER


def _stat(mode: int, uid: int) -> os.stat_result:
    return os.stat_result((mode, 1, 1, 1, uid, uid, 0, 0, 0, 0))


def test_owner_predicate_on_constructed_stat() -> None:
    # 0273: another owner cannot be made without root, so the predicate gets a built stat.
    me = os.getuid()
    assert cs.owner_ok(_stat(stat.S_IFREG | 0o600, me), me)
    assert cs.owner_ok(_stat(stat.S_IFREG | 0o644, me), me)
    assert not cs.owner_ok(_stat(stat.S_IFREG | 0o600, me + 1), me)
    assert not cs.owner_ok(_stat(stat.S_IFREG | 0o602, me), me)
    assert not cs.owner_ok(_stat(stat.S_IFREG | 0o620, me), me)


def test_no_transcript_yet(tree: Tree) -> None:
    assert _reason(tree.read()) is Reason.NO_TRANSCRIPT


def test_no_session_folder_yet(tree: Tree) -> None:
    result = context_size(str(tree.main), "other", AGENT, projects_root=tree.root)
    assert _reason(result) is Reason.NO_TRANSCRIPT


def test_no_usage_entry_yet(tree: Tree) -> None:
    tree.write(json.dumps({"type": "user", "message": {"content": "brief"}}))
    assert _reason(tree.read()) is Reason.NO_USAGE_YET
    tree.write("", end="")
    assert _reason(tree.read()) is Reason.NO_USAGE_YET


@pytest.mark.skipif(os.getuid() == 0, reason="root reads a mode 000 file")
def test_unreadable(tree: Tree) -> None:
    tree.write(_usage(4200))
    tree.file.chmod(0)
    assert _reason(tree.read()) is Reason.UNREADABLE


def test_half_written_last_line(tree: Tree) -> None:
    tree.write(_usage(4200), _usage(9000)[:40], end="")
    assert tree.read() == Measured(4200)


def test_file_smaller_than_the_window_keeps_its_first_line(tree: Tree) -> None:
    tree.write(_usage(4200))
    assert tree.file.stat().st_size < cs.FIRST_WINDOW
    assert tree.read() == Measured(4200)


def test_usage_beyond_the_first_window_inside_the_cap(tree: Tree) -> None:
    tree.write(_usage(4200), _filler(300 * 1024))
    assert tree.read() == Measured(4200)


def test_no_usage_inside_the_cap(tree: Tree) -> None:
    tree.write(_usage(4200), _filler(cs.WINDOW_CAP + 1024))
    assert _reason(tree.read()) is Reason.NO_USAGE_IN_CAP


def test_boundary_newer_than_every_usage(tree: Tree) -> None:
    tree.write(_usage(700000), _boundary(16487))
    assert tree.read() == Measured(16487)


def test_boundary_older_than_the_newest_usage(tree: Tree) -> None:
    tree.write(_usage(700000), _boundary(16487), _usage(20000))
    assert tree.read() == Measured(20000)


def test_boundary_with_unusable_post_tokens(tree: Tree) -> None:
    tree.write(_usage(700000), _boundary("16487"))
    assert _reason(tree.read()) is Reason.NO_USAGE_IN_CAP


def test_side_call_on_another_model_is_skipped(tree: Tree) -> None:
    tree.set_meta("opus")
    tree.write(_usage(300000), _usage(300500), _usage(800, model="claude-haiku-5-5"))
    assert tree.read() == Measured(300500)


def test_synthetic_entry_is_skipped(tree: Tree) -> None:
    tree.set_meta("opus")
    tree.write(_usage(300000), _usage(30, model="<synthetic>"))
    assert tree.read() == Measured(300000)


def test_meta_model_as_full_id(tree: Tree) -> None:
    tree.set_meta(OPUS)
    tree.write(_usage(300000), _usage(800, model="claude-haiku-5-5"))
    assert tree.read() == Measured(300000)


def test_without_meta_the_most_common_model_wins(tree: Tree) -> None:
    tree.write(_usage(300000), _usage(300500), _usage(800, model="claude-haiku-5-5"))
    assert tree.read() == Measured(300500)


def test_meta_file_that_is_a_symlink_is_ignored(tree: Tree, tmp_path: Path) -> None:
    planted = tree.sub / "planted.json"
    planted.write_text(json.dumps({"model": "haiku"}), encoding="utf-8")
    os.symlink(planted, tree.meta)
    tree.write(_usage(300000), _usage(300500), _usage(800, model="claude-haiku-5-5"))
    assert tree.read() == Measured(300500)


def test_world_writable_meta_file_is_ignored(tree: Tree) -> None:
    tree.set_meta("haiku")
    tree.meta.chmod(0o666)
    tree.write(_usage(300000), _usage(300500), _usage(800, model="claude-haiku-5-5"))
    assert tree.read() == Measured(300500)


@pytest.mark.parametrize("bad", ["12", 12.0, True, -1, None])
def test_unusable_usage_values_are_skipped(tree: Tree, bad: object) -> None:
    tree.write(_usage(4200), _usage(9000, output_tokens=bad))
    assert tree.read() == Measured(4200)


def test_missing_usage_key_is_skipped(tree: Tree) -> None:
    entry = json.loads(_usage(9000))
    del entry["message"]["usage"]["cache_read_input_tokens"]
    tree.write(_usage(4200), json.dumps(entry))
    assert tree.read() == Measured(4200)


def test_only_unusable_entries_is_not_a_first_call(tree: Tree) -> None:
    tree.write(_usage(9000, input_tokens="x"))
    assert _reason(tree.read()) is Reason.NO_USAGE_IN_CAP


def test_non_object_lines_never_crash(tree: Tree) -> None:
    tree.write(_usage(4200), '"usage"', "[1]", '{"usage": 1}', '{"type": "assistant", "usage"}')
    assert tree.read() == Measured(4200)


def test_checks_and_reads_run_on_the_opened_descriptor(
    tree: Tree, monkeypatch: pytest.MonkeyPatch
) -> None:
    # 0273: the file swapped for a symlink right after the open is not what gets read.
    tree.write(_usage(4200))
    decoy = tree.sub / "decoy.jsonl"
    decoy.write_text(_usage(999999) + "\n", encoding="utf-8")
    real_open: Callable[..., int] = os.open

    def open_then_swap(name: str, flags: int, *args: object, **kw: object) -> int:
        fd = real_open(name, flags, *args, **kw)
        if name == tree.file.name:
            tree.file.unlink()
            os.symlink(decoy, tree.file)
        return fd

    monkeypatch.setattr(cs.os, "open", open_then_swap)
    assert tree.read() == Measured(4200)


def test_default_root_with_an_empty_home(
    tree: Tree, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    assert cs.default_root() == home / ".claude" / "projects"
    tree.write(_usage(4200))
    assert _reason(context_size(str(tree.main), SESSION, AGENT)) is Reason.OUTSIDE_ROOT
    missing = home / ".claude" / "projects" / "p" / f"{SESSION}.jsonl"
    assert _reason(context_size(str(missing), SESSION, AGENT)) is Reason.NO_TRANSCRIPT
