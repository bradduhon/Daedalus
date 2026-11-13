# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0273, 0284: past the context limit a bound agent in a run may make one call, the Write of
# its own hand-off file. The jail asks check() first; the hand-back check shares handoff_path.
from __future__ import annotations

import enum
import os
import stat
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from lib import agent_files, atomic, storage
from lib.config import Config
from lib.context_size import (
    Handling,
    Measured,
    SizeResult,
    agent_id_ok,
    context_size,
    default_root,
)
from lib.operator_file import load_user, overlay

FEATURE = "handoffs"
STATUS = "[STATUS: HANDOFF]"
INLINE = "inline"
HEADING = "## Hand-off"
WRITE = "Write"
R_PAST_LIMIT = (
    "the context is past the limit of {limit} tokens at {tokens}. Write a hand-off to {path} "
    "with the Write tool, holding what is done, what is left, the files touched, the next step "
    "and any open question; then hand back. Next: write {path}, then hand back with the last "
    "line `[STATUS: HANDOFF] path={path}`."
)
R_HANDOFF_WRITTEN = (
    "the context is past the limit of {limit} tokens at {tokens}, and the hand-off at {path} is "
    "written, so the only call left is the hand-back. Next: hand back now with the last line "
    "`[STATUS: HANDOFF] path={path}`."
)
R_PAST_LIMIT_INLINE = (
    "the context is past the limit of {limit} tokens at {tokens}, so hand back now. End the "
    "reply with a `## Hand-off` section holding what is done, what is left, the files read or "
    "touched, the next step and any open question. Next: hand back now with the last line "
    "`[STATUS: HANDOFF] inline`."
)
R_NO_HANDOFF_FILE = (
    "the context is past the limit of {limit} tokens at {tokens}, and the hand-off file cannot "
    "be written ({why}). Next: hand back now and tell the operator the reason."
)
R_UNMEASURED = (
    "this agent's context size could not be measured ({label}), so no call of it runs during a "
    "run (0284). Next: look at this agent's transcript in its session's subagents folder under "
    "{root}, and tell the operator the reason."
)
R_LIMIT_UNREAD = (
    "the context limit could not be read from {file} ({why}), so no call of this agent runs "
    "during a run (0284). Next: repair {file} with the settings wizard, /daedalus:setup."
)
W_UNMEASURED = "the context size was not measured ({label}), so the call went on unchecked (0284)"
W_NO_TRANSCRIPT_PATH = (
    "the hook input carried no transcript path, so the context size was not measured and the "
    "call went on unchecked (0284)"
)
ADMITTED = "the hand-off write past the context limit (0284)"
# 0253, 0284: the approval name the jail prints for an admitted hand-off write.
APPROVAL = "handoff-write"


class Step(enum.Enum):
    GO = "go on to the other checks"
    WARN = "go on to the other checks, recorded as a warning"
    ADMIT = "admit the hand-off write"
    REFUSE = "refuse"


@dataclass(frozen=True)
class Outcome:
    step: Step
    text: str | None = None


@dataclass(frozen=True)
class AllowRow:
    tool: str
    path_field: str


# 0221, 0284: the one call admitted past the limit, by exact tool name and path field.
PAST_LIMIT_ROWS: tuple[AllowRow, ...] = (AllowRow(WRITE, "file_path"),)
GO = Outcome(Step.GO)


def active_limit(limit: int | None) -> int | None:
    # 0284: 0 and null both turn the check off.
    return limit if limit else None


def limit_for(config: Config) -> int | None:
    # 0284: the personal context_limit with this project's personal_overrides laid over it.
    return active_limit(overlay(load_user(), config.operator).context_limit)


# 0284: the one resume line of the hand-off write, and the brief line naming the hand-off file.
WRITE_LINE = "Write your hand-off"
BRIEF_PREFIX = "Hand-off: "
FILE_MODE = 0o600


def handoff_path(hook_input: dict[str, object]) -> Path | None:
    # 0284: one hand-off file per agent; the host's own cwd, not a run binding's, names the project.
    agent_id = hook_input.get("agent_id")
    cwd = hook_input.get("payload_cwd") or hook_input.get("cwd")
    if not agent_id_ok(agent_id) or not isinstance(cwd, str) or not os.path.isabs(cwd):
        return None
    folder = os.path.realpath(storage.tmp_dir(FEATURE, cwd))
    return Path(folder) / f"{agent_id}.md"


def _linkless(path: Path) -> bool:
    # 0284: no symlink in any part; the folder was built resolved, so a link anywhere differs.
    return os.path.realpath(path) == str(path)


def written(path: Path) -> bool:
    # 0284: a regular file, never a link, holding at least one byte.
    try:
        info = os.lstat(path)
    except OSError:
        return False
    return stat.S_ISREG(info.st_mode) and info.st_size > 0 and _linkless(path)


def holds_write(agent: str, plugin_root: Path) -> bool:
    # 0284: the hand-off form follows the agent file's tools line, read by the agent file loader.
    path = plugin_root / "agents" / f"{agent}.md"
    if not agent_files.AGENT_NAME.fullmatch(agent) or not path.is_file():
        return False
    return WRITE in agent_files.load(path).tools


def _names_handoff(hook_input: dict[str, object], path: Path) -> bool:
    tool_input = hook_input.get("tool_input")
    if not isinstance(tool_input, dict):
        return False
    tool = hook_input.get("tool_name")
    return any(
        tool == row.tool and tool_input.get(row.path_field) == str(path) for row in PAST_LIMIT_ROWS
    )


def _leaf_ok(path: Path) -> bool:
    # 0284: absent, or a regular file; a link, a folder or a FIFO at the path is refused.
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return _linkless(path)
    except OSError:
        return False
    return stat.S_ISREG(info.st_mode) and _linkless(path)


def _past(hook_input: dict[str, object], agent: str, shown: dict[str, int], root: Path) -> Outcome:
    if not holds_write(agent, root):
        return Outcome(Step.REFUSE, R_PAST_LIMIT_INLINE.format(**shown))
    path = handoff_path(hook_input)
    if path is None:
        why = "the agent id or its working folder is not usable"
        return Outcome(Step.REFUSE, R_NO_HANDOFF_FILE.format(why=why, **shown))
    if not _leaf_ok(path):
        why = f"something other than a regular file sits at {path}"
        return Outcome(Step.REFUSE, R_NO_HANDOFF_FILE.format(why=why, **shown))
    if _names_handoff(hook_input, path):
        cwd = str(hook_input.get("payload_cwd") or hook_input.get("cwd"))
        try:
            made = storage.make_tmp_dir(FEATURE, cwd)
        except (OSError, RuntimeError, ValueError) as exc:
            return Outcome(Step.REFUSE, R_NO_HANDOFF_FILE.format(why=str(exc), **shown))
        if os.path.realpath(made) != str(path.parent) or not _leaf_ok(path):
            why = f"the folder of {path} moved or holds a link"
            return Outcome(Step.REFUSE, R_NO_HANDOFF_FILE.format(why=why, **shown))
        return Outcome(Step.ADMIT, ADMITTED)
    text = R_HANDOFF_WRITTEN if written(path) else R_PAST_LIMIT
    return Outcome(Step.REFUSE, text.format(path=path, **shown))


def inline_text(reply: str) -> str | None:
    # 0284: the last `## Hand-off` section of an inline reply, up to its status line.
    lines = reply.rstrip().splitlines()
    heads = [i for i, line in enumerate(lines[:-1]) if line.strip() == HEADING]
    if not heads or lines[-1].strip() != f"{STATUS} {INLINE}":
        return None
    body = "\n".join(lines[heads[-1] : -1]).strip()
    return body + "\n" if body != HEADING else None


def save_inline(hook_input: dict[str, object], reply: str) -> Path | None:
    # 0284: the run's copy of an inline hand-off at the agent's own path; a new agent reads a file.
    path, text = handoff_path(hook_input), inline_text(reply)
    if path is None or text is None or not _leaf_ok(path):
        return None
    made = storage.make_tmp_dir(FEATURE, str(hook_input.get("payload_cwd") or hook_input["cwd"]))
    if os.path.realpath(made) != str(path.parent) or not _leaf_ok(path):
        return None
    atomic.write_atomic(path, text, FILE_MODE)
    return path


def recorded_tokens(units: list[dict[str, object]], agent: str) -> int | None:
    # 0284: the largest size any unit recorded for the agent at a return; a context only grows.
    from lib.train_state import SIZES

    found: list[int] = []
    for unit in units:
        sizes = unit.get(SIZES)
        cell = sizes.get(agent) if isinstance(sizes, dict) else None
        tokens = cell.get("tokens") if isinstance(cell, dict) else None
        if isinstance(tokens, int) and not isinstance(tokens, bool):
            found.append(tokens)
    return max(found) if found else None


def check(
    hook_input: dict[str, object],
    agent: str,
    config: Config,
    plugin_root: Path,
    reader: Callable[[object, object, object], SizeResult] | None = None,
) -> Outcome:
    # 0284: a bound agent's call in a run; the caller passes only routed Daedalus agents.
    from lib.project_root import train_marked

    if not hook_input.get("agent_id") or not train_marked(hook_input.get("cwd")):
        return GO
    from lib.operator_file import OPERATOR_FILE, OperatorError

    try:
        limit = limit_for(config)
    except OperatorError as exc:
        # 0284: one Next line, so the reader's own is cut and the wizard's is given.
        why = str(exc).split(" Next:", 1)[0]
        file = f"~/{OPERATOR_FILE.as_posix()}"
        return Outcome(Step.REFUSE, R_LIMIT_UNREAD.format(file=file, why=why))
    if limit is None:
        return GO
    if hook_input.get("transcript_path") is None:
        # 0284: no agent can drop a hook input field; its absence is the client's doing.
        return Outcome(Step.WARN, W_NO_TRANSCRIPT_PATH)
    read = reader if reader is not None else context_size
    size = read(
        hook_input.get("transcript_path"), hook_input.get("session_id"), hook_input.get("agent_id")
    )
    if not isinstance(size, Measured):
        label = size.reason.label
        if size.reason.handling is Handling.ALLOW_WARN:
            return Outcome(Step.WARN, W_UNMEASURED.format(label=label))
        return Outcome(Step.REFUSE, R_UNMEASURED.format(label=label, root=default_root()))
    if size.tokens <= limit:
        return GO
    return _past(hook_input, agent, {"limit": limit, "tokens": size.tokens}, plugin_root)
