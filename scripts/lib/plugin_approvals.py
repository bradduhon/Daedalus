# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0253: the plugin's one approval list. The jail hook asks it only at a clean allow of a
# main-session call; a row name approves the call, None leaves it as it was.
# 0221: exact shapes from one typed table; anything off a row, or any error, is no approval.
from __future__ import annotations

import os
import stat
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from lib import shparse

FINDINGS_SCRIPT = ("scripts", "daedalus_findings.py")
_BASH_KEYS = frozenset({"command", "description", "timeout"})
# A Bash flag key is admitted only when it is present and exactly False.
_BASH_FLAGS = frozenset({"run_in_background", "dangerouslyDisableSandbox"})
_WRITE_KEYS = frozenset({"file_path", "content"})


@dataclass(frozen=True)
class Slot:
    kind: str


PATH = Slot("path")
STAMP = Slot("stamp")


@dataclass(frozen=True)
class Approval:
    name: str
    tool: str
    # The words after `python3 <findings script>`: a str is matched by its raw text, a Slot by type.
    words: tuple[str | Slot, ...]


APPROVALS: tuple[Approval, ...] = (
    Approval("findings-start", "Bash", ("start", "--repo", PATH)),
    Approval("findings-save", "Bash", ("save", "--repo", PATH, "--since", STAMP)),
    Approval("findings-show", "Bash", ("show", "--repo", PATH, "--since", STAMP)),
    Approval("handover-write", "Write", ()),
)


def approve(payload: Mapping[str, object]) -> str | None:
    # A3 req 8: an exception is no approval.
    try:
        return _approve(payload)
    except Exception:  # noqa: BLE001
        return None


def _approve(payload: Mapping[str, object]) -> str | None:
    if not _main_session(payload):
        return None
    tool = payload.get("tool_name")
    tool_input = payload.get("tool_input")
    cwd = payload.get("cwd")
    if not isinstance(tool_input, dict) or not isinstance(cwd, str) or not os.path.isabs(cwd):
        return None
    for row in APPROVALS:
        if row.tool != tool:
            continue
        matched = _bash(row, tool_input) if tool == "Bash" else _write(tool_input, cwd)
        if matched:
            return row.name
    return None


def _main_session(payload: Mapping[str, object]) -> bool:
    # A3 req 2, 0106: the same test as the hook's _bare_main; a helper's call keeps its own jail.
    return not payload.get("agent_id") and str(payload.get("agent_type") or "main") == "main"


def _bash(row: Approval, tool_input: dict[str, object]) -> bool:
    if not set(tool_input) <= _BASH_KEYS | _BASH_FLAGS:
        return False
    if any(tool_input[key] is not False for key in _BASH_FLAGS & set(tool_input)):
        return False
    command = tool_input.get("command")
    words = _simple_words(command) if isinstance(command, str) else None
    if words is None or len(words) != 2 + len(row.words):
        return False
    if words[0].raw != "python3" or not _findings_script(words[1]):
        return False
    return all(_word_ok(word, want) for word, want in zip(words[2:], row.words, strict=True))


def _simple_words(command: str) -> list[shparse.Word] | None:
    # A3 req 3: one simple command; no pipe, list, redirect, substitution, assignment or expansion.
    script = shparse.parse(command)
    if len(script.items) != 1 or script.separators != [""]:
        return None
    item = script.items[0]
    if not isinstance(item, shparse.Pipeline) or item.negated or item.timed or item.pipes:
        return None
    if len(item.commands) != 1 or not isinstance(item.commands[0], shparse.Command):
        return None
    cmd = item.commands[0]
    if shparse.assignments(cmd) or cmd.redirects:
        return None
    if shparse.opaque(script) or shparse.substitutions(script) or shparse.heredocs(script):
        return None
    words = shparse.command_words(cmd)
    if any(shparse.expands(word) for word in words):
        return None
    # One line, words joined by single spaces: no comment, continuation or trailing text.
    return words if command.strip() == " ".join(word.raw for word in words) else None


def _findings_script(word: shparse.Word) -> bool:
    # A3 req 3: the exact path under the hook's own plugin root; no `..`, link or other root.
    root = os.environ.get("CLAUDE_PLUGIN_ROOT", "")
    if not os.path.isabs(root) or os.path.normpath(root) != root:
        return False
    expected = os.path.join(root, *FINDINGS_SCRIPT)
    if shparse.literal(word) != expected:
        return False
    if not stat.S_ISREG(os.lstat(expected).st_mode):
        return False
    return Path(expected).resolve() == Path(root).resolve().joinpath(*FINDINGS_SCRIPT)


def _word_ok(word: shparse.Word, want: str | Slot) -> bool:
    text = shparse.literal(word)
    if text is None:
        return False
    if isinstance(want, str):
        return word.raw == want
    if want is PATH:
        return bool(text) and not text.startswith("-")
    if want is STAMP:
        from lib import self_assessment

        return word.raw == text and self_assessment.handover_name(text) == f"handover-{text}.json"
    return False


def _write(tool_input: dict[str, object], cwd: str) -> bool:
    # A3 req 5; imported here so a Bash call loads no settings code.
    from lib import self_assessment

    if set(tool_input) != _WRITE_KEYS:
        return False
    file_path = tool_input["file_path"]
    content = tool_input["content"]
    if not isinstance(file_path, str) or not isinstance(content, str):
        return False
    if not os.path.isabs(file_path) or os.path.normpath(file_path) != file_path:
        return False
    folder, name = os.path.split(file_path)
    if not self_assessment.HANDOVER_NAME.fullmatch(name):
        return False
    if name != self_assessment.handover_name(name[len("handover-") : -len(".json")]):
        return False
    if folder != str(self_assessment.handover_dir(cwd)):
        return False
    if len(content.encode("utf-8")) > self_assessment.MAX_HANDOVER_BYTES:
        return False
    if self_assessment.enabled(cwd) is not True:
        return False
    if self_assessment.check_dirs(cwd) is not None:
        return False
    # The folder start made must exist as a real folder; the target, when present, a plain file.
    if not stat.S_ISDIR(os.lstat(folder).st_mode):
        return False
    try:
        target = os.lstat(file_path)
    except FileNotFoundError:
        return True
    return stat.S_ISREG(target.st_mode)
