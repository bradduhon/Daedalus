#!/usr/bin/env python3
# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import importlib
import json
import os
import shlex
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

_LIBS = ("lib.audit", "lib.config", "lib.jail")
_LOAD_NEXT = "Next: run the plugin with Python 3.12 and an intact scripts/lib directory."
_CONFIG_NEXT = (
    " Next: fix the Daedalus project config <repo>/.claude/daedalus/config.json and retry."
)
_REPORT_NEXT = " Next: report this hook failure to the operator."
_WRITE_TOOLS = frozenset({"Write", "Edit", "MultiEdit", "NotebookEdit"})
# issue 30: past these caps the fast path hands the call to the full jail.
_WORD_CAP = 256
_ROOT_CAP = 16


_TRAIN_MARKER = Path(".claude") / "daedalus" / "train.active"


def _inline_repo_root(path: str) -> Path:
    # 0035: private copy of lib.repo_root.repo_root for an install whose lib cannot import.
    start = Path(path)
    for folder in (start, *start.parents):
        dot = folder / ".git"
        if dot.is_dir():
            return folder
        if not dot.is_file():
            continue
        try:
            text = dot.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            return folder
        if not text.startswith("gitdir:"):
            return folder
        gitdir = folder / text[len("gitdir:") :].strip()
        try:
            common = gitdir / (gitdir / "commondir").read_text(encoding="utf-8").strip()
        except (OSError, UnicodeDecodeError):
            common = gitdir
        return Path(os.path.normpath(common)).parent
    return next((p for p in (start, *start.parents) if p.is_dir()), start)


def _inline_train_marked(cwd: Any) -> bool:
    # 0035: no absolute cwd means the repo is unknown, so the hook acts as if a train runs.
    if not isinstance(cwd, str) or not os.path.isabs(cwd):
        return True
    return os.path.lexists(_inline_repo_root(cwd) / _TRAIN_MARKER)


def _marker_finder() -> tuple[Callable[[Any], bool], Exception | None]:
    # 0035: a broken lib must not block a repo without a train, so the inline finder decides.
    try:
        from lib.repo_root import train_marked
    except Exception as exc:  # noqa: BLE001
        return _inline_train_marked, exc
    return train_marked, None


def _named_paths(tool: str, tool_input: dict[str, Any]) -> list[str] | None:
    # issue 30: every word that could name a path; None when the command cannot be split.
    if tool in _WRITE_TOOLS:
        return [str(tool_input.get(k) or "") for k in ("file_path", "notebook_path")]
    if tool != "Bash":
        return []
    lexer = shlex.shlex(str(tool_input.get("command") or ""), posix=True, punctuation_chars=True)
    lexer.whitespace_split = True
    try:
        words = list(lexer)
    except ValueError:
        return None
    if len(words) > _WORD_CAP:
        return None
    found: list[str] = []
    for word in words:
        word = word.replace("${HOME}", "~").replace("$HOME", "~")
        found += [word, word.rpartition("=")[2]]
        cut = min((i for i in (word.find("/"), word.find("~")) if i > 0), default=-1)
        if cut > 0:
            found.append(word[cut:])
    return found


def _names_marked_repo(tool: str, tool_input: dict[str, Any], cwd: str) -> bool:
    # issue 30: a train in any repo the call names counts; the full jail then judges precisely.
    from lib.repo_root import TRAIN_MARKER, repo_root

    words = _named_paths(tool, tool_input)
    if words is None:
        return True
    home = repo_root(cwd)
    roots: set[Path] = {home}
    for word in words:
        if not word or word.startswith("-"):
            continue
        root = repo_root(os.path.normpath(os.path.join(cwd, os.path.expanduser(word))))
        if root in roots:
            continue
        roots.add(root)
        if len(roots) > _ROOT_CAP or os.path.lexists(root / TRAIN_MARKER):
            return True
    return False


def _fast_path(payload: dict[str, Any], agent: str, cwd: str) -> int:
    # 0023, 0035: outside a train, main and foreign agents meet only the credential read deny.
    from lib.credential_paths import CREDENTIAL_TOOLS, path_reason

    tool = str(payload.get("tool_name"))
    tool_input = payload.get("tool_input") or {}
    reason = path_reason(tool, tool_input, cwd) if tool in CREDENTIAL_TOOLS else None
    return _block(agent, reason) if reason else 0


def _block(agent: str, message: str, next_step: str = _REPORT_NEXT) -> int:
    if "Next:" not in message:
        message += next_step
    try:
        print(f"daedalus-jail[{agent}]: {message}", file=sys.stderr)
    except OSError:
        pass  # m5: a closed stderr must not turn the block into exit 1.
    return 2


def _note(agent: str, message: str) -> None:
    try:
        print(f"daedalus-jail[{agent}]: {message}", file=sys.stderr)
    except OSError:
        pass  # m5: a closed stderr must not turn an allow into exit 1.


def _load_failed(exc: Exception, in_train: bool) -> int:
    # 0035: exit 1 does not block a PreToolUse hook, so a train's broken jail must exit 2.
    if in_train:
        return _block("?", f"hook could not load its libraries ({exc}). {_LOAD_NEXT}")
    _note(
        "?",
        f"hook could not load its libraries ({exc}); no train runs in this repository, "
        f"so the call proceeds. {_LOAD_NEXT}",
    )
    return 0


def _warn_fallback(cwd: str) -> None:
    from lib.audit import root_info

    try:
        print(
            f"daedalus-audit: project root fell back to cwd ({root_info(cwd)[2]})", file=sys.stderr
        )
    except OSError:
        pass  # m5: a closed stderr must not turn an allow into exit 1.


def _record_and_block(
    payload: dict[str, Any], agent: str, message: str, next_step: str = _REPORT_NEXT
) -> int:
    from lib.audit import audit_append

    if "Next:" not in message:
        message += next_step
    try:
        audit_append(payload, "block", message)
    except Exception:  # noqa: BLE001, S110
        pass  # 8.5: best effort; the block stands whether or not the record lands.
    return _block(agent, message)


def _judge(payload: dict[str, Any], agent: str) -> int:
    from lib.audit import audit_append
    from lib.config import Config, load_config
    from lib.jail import CREDENTIAL_TOOLS, Decision, decide

    cwd = payload.get("cwd")
    # 0023: reads carry only the credential deny, so a broken data dir never closes them.
    read = payload.get("tool_name") in CREDENTIAL_TOOLS and isinstance(cwd, str)
    read = read and Path(cwd).is_absolute()
    try:
        config = load_config(cwd)
    except Exception as exc:  # noqa: BLE001
        if not read:
            return _record_and_block(payload, agent, str(exc), _CONFIG_NEXT)
        config = Config()
    decision: Decision = decide(payload, config)
    agent = decision.agent or agent
    try:
        record = audit_append(payload, "allow" if decision.allow else "block", decision.reason)
    except Exception as exc:  # noqa: BLE001
        if read and decision.allow:
            # spec 8: an allowed read is non-blocking on a failed record, as audit_log.py is.
            _note(agent, f"audit log unavailable ({exc}); the read proceeds unrecorded.")
            return 0
        # 8.5: no record, no action. The jail fails closed when the chain cannot be written.
        detail = f"audit log unavailable ({exc})."
        if "Next:" not in detail:
            detail += " Next: fix the project data dir (<repo>/.claude/daedalus) and retry."
        return _block(agent, detail)
    if record is not None and record.get("root_source") == "cwd-fallback":
        _warn_fallback(str(payload.get("cwd")))
    if decision.allow:
        return 0
    return _block(agent, str(decision.reason))


def main() -> int:
    # Every path but a clean allow exits 2, except a library failure outside a train.
    try:
        text = sys.stdin.read()
        if not text.strip():
            return _block("?", "hook input is empty.")
        payload = json.loads(text)
    except Exception as exc:  # noqa: BLE001
        return _block("?", f"hook input could not be parsed ({exc}).")
    if not isinstance(payload, dict):
        return _block("?", "hook input is not a JSON object.")
    agent = str(payload.get("agent_type") or "main")
    tool_name = payload.get("tool_name")
    if not isinstance(tool_name, str) or not tool_name:
        return _block(agent, "hook input has no tool_name string.")
    if "tool_input" in payload and not isinstance(payload["tool_input"], dict):
        return _block(agent, "hook input tool_input is not an object.")
    cwd = payload.get("cwd")
    train_marked, lib_error = _marker_finder()
    in_train = train_marked(cwd)
    if lib_error is not None:
        return _load_failed(lib_error, in_train)
    if not in_train and isinstance(cwd, str):
        try:
            from lib.credential_paths import CREDENTIAL_TOOLS
            from lib.train_scope import policed_outside_train
        except Exception as exc:  # noqa: BLE001
            return _load_failed(exc, in_train)
        try:
            named = _names_marked_repo(tool_name, payload.get("tool_input") or {}, cwd)
        except Exception:  # noqa: BLE001
            named = True  # issue 30: unsure means the full jail judges the call.
        if not policed_outside_train(agent) and not named:
            try:
                return _fast_path(payload, agent, cwd)
            except Exception as exc:  # noqa: BLE001
                if tool_name in CREDENTIAL_TOOLS:
                    return _block(agent, f"the credential check failed ({exc}).")
                _note(agent, f"hook error ({exc}); no train runs here, so the call proceeds.")
                return 0
    try:
        for name in _LIBS:
            importlib.import_module(name)
    except Exception as exc:  # noqa: BLE001
        return _load_failed(exc, in_train)
    try:
        return _judge(payload, agent)
    except Exception as exc:  # noqa: BLE001
        return _record_and_block(payload, agent, str(exc))


if __name__ == "__main__":
    sys.exit(main())
