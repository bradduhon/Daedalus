# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0273: how many tokens sit in a subagent's context now, read from the tail of its own
# transcript. Pure: no writes, and no file read but the transcript and its meta file.
from __future__ import annotations

import enum
import errno
import json
import os
import stat
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

from lib.audit import SESSION_ID
from lib.narrow import integer, obj

FIRST_WINDOW = 64 * 1024
WINDOW_CAP = 4 * 1024 * 1024
META_CAP = 64 * 1024
# 0273: the client's own stand-in reply, all-zero usage; never measured or counted.
SYNTHETIC = "<synthetic>"
AGENT_ID_CHARS = frozenset("abcdefghijklmnopqrstuvwxyz0123456789")
USAGE_KEYS = (
    "input_tokens",
    "cache_creation_input_tokens",
    "cache_read_input_tokens",
    "output_tokens",
)
_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
# 0273: O_NONBLOCK so a FIFO planted at the path cannot hang the open.
_FILE_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK


class Handling(enum.Enum):
    ALLOW_WARN = "allow with a warning"
    REFUSE = "refuse"


class Reason(enum.Enum):
    label: str
    handling: Handling

    MAIN_SESSION = ("main session", Handling.ALLOW_WARN)
    BAD_ID = ("id outside its shape", Handling.REFUSE)
    NO_PATH = ("path not derivable", Handling.REFUSE)
    OUTSIDE_ROOT = ("path outside the trusted root", Handling.REFUSE)
    SYMLINK = ("symlink", Handling.REFUSE)
    NOT_REGULAR = ("not a regular file", Handling.REFUSE)
    BAD_OWNER = ("wrong owner or group or world writable", Handling.REFUSE)
    # 0273: a fork has no transcript under subagents/ and reads as this reason; the caller decides.
    NO_TRANSCRIPT = ("no transcript yet", Handling.ALLOW_WARN)
    NO_USAGE_YET = ("no usage entry yet", Handling.ALLOW_WARN)
    NO_USAGE_IN_CAP = ("no usage found within the cap", Handling.REFUSE)
    UNREADABLE = ("unreadable", Handling.REFUSE)

    def __init__(self, label: str, handling: Handling) -> None:
        self.label = label
        self.handling = handling


@dataclass(frozen=True)
class Measured:
    tokens: int


@dataclass(frozen=True)
class Unmeasured:
    reason: Reason


SizeResult = Measured | Unmeasured


class _Refused(Exception):
    def __init__(self, reason: Reason) -> None:
        super().__init__(reason.label)
        self.reason = reason


def default_root() -> Path:
    return Path.home() / ".claude" / "projects"


def context_size(
    transcript_path: object,
    session_id: object,
    agent_id: object,
    projects_root: Path | None = None,
) -> SizeResult:
    if agent_id is None:
        return Unmeasured(Reason.MAIN_SESSION)
    if not isinstance(agent_id, str) or not isinstance(session_id, str):
        return Unmeasured(Reason.BAD_ID)
    if not agent_id_ok(agent_id) or not session_id_ok(session_id):
        return Unmeasured(Reason.BAD_ID)
    path = transcript_file(transcript_path, session_id, agent_id)
    if path is None:
        return Unmeasured(Reason.NO_PATH)
    root = os.path.realpath(projects_root if projects_root is not None else default_root())
    parts = _parts_under(root, os.path.realpath(os.path.dirname(path)))
    if parts is None:
        return Unmeasured(Reason.OUTSIDE_ROOT)
    try:
        return _measure(root, parts, agent_id)
    except _Refused as refused:
        return Unmeasured(refused.reason)


def agent_id_ok(agent_id: object) -> bool:
    return isinstance(agent_id, str) and bool(agent_id) and set(agent_id) <= AGENT_ID_CHARS


def session_id_ok(session_id: object) -> bool:
    return isinstance(session_id, str) and SESSION_ID.fullmatch(session_id) is not None


def transcript_file(transcript_path: object, session_id: str, agent_id: str) -> str | None:
    if not isinstance(transcript_path, str) or not os.path.isabs(transcript_path):
        return None
    if "\x00" in transcript_path:
        return None
    name = f"agent-{agent_id}.jsonl"
    if transcript_path.endswith(f"/subagents/{name}"):
        return transcript_path
    folder = os.path.dirname(transcript_path)
    return os.path.join(folder, session_id, "subagents", name)


def _parts_under(root: str, folder: str) -> list[str] | None:
    # 0273: maps the string onto the root only; the openat chain below is the trust proof.
    root_parts = Path(root).parts
    folder_parts = Path(folder).parts
    if folder_parts[: len(root_parts)] != root_parts:
        return None
    return list(folder_parts[len(root_parts) :])


def owner_ok(st: os.stat_result, uid: int) -> bool:
    return st.st_uid == uid and not st.st_mode & (stat.S_IWGRP | stat.S_IWOTH)


def _measure(root: str, parts: list[str], agent_id: str) -> SizeResult:
    folder_fd = _open_folder(root, parts)
    try:
        fd = _open_checked(folder_fd, f"agent-{agent_id}.jsonl")
        try:
            main_model = _meta_model(folder_fd, agent_id)
            return _read_tail(fd, main_model)
        finally:
            os.close(fd)
    finally:
        os.close(folder_fd)


def _open_folder(root: str, parts: list[str]) -> int:
    try:
        fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    except FileNotFoundError:
        raise _Refused(Reason.NO_TRANSCRIPT) from None
    except OSError:
        raise _Refused(Reason.UNREADABLE) from None
    for part in parts:
        try:
            child = os.open(part, _DIR_FLAGS, dir_fd=fd)
        except OSError as exc:
            reason = _open_error(exc, fd, part, Reason.UNREADABLE)
            os.close(fd)
            raise _Refused(reason) from None
        os.close(fd)
        fd = child
    return fd


def _open_error(exc: OSError, folder_fd: int, name: str, other: Reason) -> Reason:
    # 0273: ENOENT from the open itself is the only way to "no transcript yet".
    if exc.errno == errno.ENOENT:
        return Reason.NO_TRANSCRIPT
    if exc.errno in (errno.ELOOP, errno.EMLINK):
        return Reason.SYMLINK
    if exc.errno == errno.ENOTDIR:
        try:
            st = os.stat(name, dir_fd=folder_fd, follow_symlinks=False)
        except OSError:
            return Reason.UNREADABLE
        return Reason.SYMLINK if stat.S_ISLNK(st.st_mode) else other
    return Reason.UNREADABLE


def _open_checked(folder_fd: int, name: str) -> int:
    try:
        fd = os.open(name, _FILE_FLAGS, dir_fd=folder_fd)
    except OSError as exc:
        raise _Refused(_open_error(exc, folder_fd, name, Reason.NOT_REGULAR)) from None
    try:
        # 0273: every check runs on the open descriptor, never on the path string.
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise _Refused(Reason.NOT_REGULAR)
        if not owner_ok(st, os.getuid()):
            raise _Refused(Reason.BAD_OWNER)
    except OSError:
        os.close(fd)
        raise _Refused(Reason.UNREADABLE) from None
    except _Refused:
        os.close(fd)
        raise
    return fd


def _meta_model(folder_fd: int, agent_id: str) -> str | None:
    # 0273: a meta file failing any check is ignored and the window's most common model is used.
    try:
        fd = _open_checked(folder_fd, f"agent-{agent_id}.meta.json")
    except _Refused:
        return None
    try:
        data = os.pread(fd, META_CAP, 0)
    except OSError:
        return None
    finally:
        os.close(fd)
    try:
        meta = json.loads(data)
    except (ValueError, RecursionError):
        return None
    model = meta.get("model") if isinstance(meta, dict) else None
    return model if isinstance(model, str) and model else None


def same_model(entry_model: str, main_model: str) -> bool:
    # 0273: meta.json holds an alias such as opus; entries hold claude-opus-5-5.
    return entry_model == main_model or entry_model.startswith(f"claude-{main_model}-")


def count(value: object) -> int | None:
    if not isinstance(value, dict):
        return None
    total = 0
    for key in USAGE_KEYS:
        part = integer(value, key, -1)
        if part < 0:
            return None
        total += part
    return total


def _read_tail(fd: int, main_model: str | None) -> SizeResult:
    try:
        size = os.fstat(fd).st_size
    except OSError:
        return Unmeasured(Reason.UNREADABLE)
    window = FIRST_WINDOW
    while True:
        start = max(0, size - window)
        try:
            data = os.pread(fd, size - start, start)
        except OSError:
            return Unmeasured(Reason.UNREADABLE)
        lines = data.split(b"\n")
        if start > 0:
            lines = lines[1:]
        found, seen = _scan(lines, main_model)
        if found is not None:
            return found
        if start == 0:
            # 0273: a fully read file with no usage or boundary entry is a first call.
            return Unmeasured(Reason.NO_USAGE_IN_CAP if seen else Reason.NO_USAGE_YET)
        if window >= WINDOW_CAP:
            return Unmeasured(Reason.NO_USAGE_IN_CAP)
        window *= 2


def _scan(lines: list[bytes], main_model: str | None) -> tuple[SizeResult | None, bool]:
    entries: list[tuple[str, object, int | None]] = []
    for line in reversed(lines):
        if b'"usage"' not in line and b"compact_boundary" not in line:
            continue
        try:
            entry = json.loads(line)
        except (ValueError, RecursionError):
            continue
        if not isinstance(entry, dict):
            continue
        if entry.get("type") == "system" and entry.get("subtype") == "compact_boundary":
            post = integer(obj(entry, "compactMetadata"), "postTokens", -1)
            entries.append(("boundary", None, post if post >= 0 else None))
            continue
        message = entry.get("message")
        if entry.get("type") == "assistant" and isinstance(message, dict):
            usage = message.get("usage")
            if isinstance(usage, dict):
                entries.append(("usage", message.get("model"), count(usage)))
    models = [m for kind, m, _ in entries if kind == "usage" and isinstance(m, str) and m]
    models = [m for m in models if m != SYNTHETIC]
    # 0273: a meta model matching no entry of the window falls back like an absent meta file.
    if main_model is None or not any(same_model(m, main_model) for m in models):
        common = Counter(models).most_common(1)
        main_model = common[0][0] if common else None
    for kind, model, tokens in entries:
        if kind == "boundary":
            # 0273: a boundary newer than every usable entry; unusable postTokens is no count.
            if tokens is None:
                return Unmeasured(Reason.NO_USAGE_IN_CAP), True
            return Measured(tokens), True
        if not isinstance(model, str) or main_model is None or tokens is None:
            continue
        if model == SYNTHETIC:
            continue
        if not same_model(model, main_model):
            continue
        return Measured(tokens), True
    return None, bool(entries)
