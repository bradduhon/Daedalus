#!/usr/bin/env python3
# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import importlib
import json
import os
import shlex
import sys
import time
from collections.abc import Callable
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

_LIBS = (
    "lib.audit",
    "lib.config",
    "lib.jail",
    "lib.router",
    "lib.agent_files",
    "lib.dispatch_binding",
)
_LOAD_NEXT = "Next: run the plugin with Python 3.12 and an intact scripts/lib directory."
_CONFIG_NEXT = (
    " Next: fix the Daedalus project config <repo>/.claude/daedalus/config.json and retry."
)
_REPORT_NEXT = " Next: report this hook failure to the operator."
_WRITE_TOOLS = frozenset({"Write", "Edit", "MultiEdit", "NotebookEdit"})
# issue 30: past these caps the fast path hands the call to the full jail.
_WORD_CAP = 256
_ROOT_CAP = 16
# 6.1: the reason prefix for blocks this hook decides itself, main and foreign agents alike.
_JAIL_HOOK = "jail"
_CONFIG_HOOK = "config"
# 0106: ask texts for the operator's own session; IA-5g and AU-5 require this wording.
_CREDENTIAL_ASK = (
    "This path holds credentials; reading it puts the secret into the session transcript. "
    "Approve to proceed anyway. The jail's finding: "
)
_LOAD_ASK = "the jail's library failed to load; approving runs this call unjudged during a train"
_AUDIT_ASK = "the audit log cannot be written; approving leaves this call unrecorded"
_CONFIG_ASK = "the project config failed to load; approving runs this call unjudged during a train"
_JUDGE_ASK = "the jail failed while judging this call; approving runs it unjudged during a train"


_TRAIN_MARKER = Path(".claude") / "daedalus" / "train.active"
_MANIFEST = "service-manifest.json"
_DATA_DIR = Path(".claude") / "daedalus"


def _inline_git_root(path: str) -> Path | None:
    # 0035, 0043 exception: private copy of lib.repo_root.git_root for a lib that cannot import.
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
    return None


def _inline_project_root(cwd: Path) -> Path:
    # 0077, 0035, 0043 exception, CM-5: copy of lib.project_root.project_root; change together.
    start = Path(cwd)
    for folder in (start, *start.parents):
        if (folder / _MANIFEST).is_file() or (folder / _DATA_DIR).is_dir():
            main = _inline_git_root(str(folder)) if (folder / ".git").is_file() else None
            return main if main is not None and (main / ".git").is_dir() else folder
    return _inline_git_root(str(start)) or start


def _inline_train_marked(cwd: object) -> bool:
    # 0035: no absolute cwd means the repo is unknown, so the hook acts as if a train runs.
    if not isinstance(cwd, str) or not os.path.isabs(cwd):
        return True
    return os.path.lexists(_inline_project_root(Path(cwd)) / _TRAIN_MARKER)


def _marker_finder() -> tuple[Callable[[object], bool], Exception | None]:
    # 0035: a broken lib must not block a repo without a train, so the inline finder decides.
    try:
        from lib.project_root import train_marked
    except Exception as exc:  # noqa: BLE001
        return _inline_train_marked, exc
    return train_marked, None


def _named_paths(tool: str, tool_input: dict[str, object]) -> list[str] | None:
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


def _names_marked_repo(tool: str, tool_input: dict[str, object], cwd: str) -> bool:
    # issue 30: a train in any repo the call names counts; the full jail then judges precisely.
    from lib.project_root import TRAIN_MARKER, project_root

    words = _named_paths(tool, tool_input)
    if words is None:
        return True
    home = project_root(Path(cwd))
    roots: set[Path] = {home}
    for word in words:
        if not word or word.startswith("-"):
            continue
        root = project_root(Path(os.path.normpath(os.path.join(cwd, os.path.expanduser(word)))))
        if root in roots:
            continue
        roots.add(root)
        if len(roots) > _ROOT_CAP or os.path.lexists(root / TRAIN_MARKER):
            return True
    return False


def _fast_path(payload: dict[str, object], agent: str, cwd: str) -> int:
    # 0023, 0035: outside a train, main and foreign agents meet only the credential read deny.
    from lib.credential_paths import CREDENTIAL_TOOLS, path_reason

    tool = str(payload.get("tool_name"))
    raw_input = payload.get("tool_input")
    tool_input: dict[str, object] = raw_input if isinstance(raw_input, dict) else {}
    reason = path_reason(tool, tool_input, cwd) if tool in CREDENTIAL_TOOLS else None
    if reason and _bare_main(payload):
        # 0106, IA-5g, AC-3: the operator approves each credential read; the text stays literal.
        return _ask(_CREDENTIAL_ASK + reason)
    return _block(agent, reason) if reason else 0


def _bare_main(payload: dict[str, object]) -> bool:
    # 0106: the operator's own thread, the only caller with no agent_id and no agent type.
    return not payload.get("agent_id") and str(payload.get("agent_type") or "main") == "main"


def _block(agent: str, message: str, next_step: str = _REPORT_NEXT) -> int:
    if "Next:" not in message:
        message += next_step
    try:
        print(f"daedalus-jail[{agent}]: {message}", file=sys.stderr)
    except OSError:
        pass  # m5: a closed stderr must not turn the block into exit 1.
    return 2


def _ask(message: str) -> int:
    # 0105: exit 0 with the PreToolUse ask decision; the operator approves or denies the call.
    out = {"hookEventName": "PreToolUse", "permissionDecision": "ask"}
    out["permissionDecisionReason"] = message
    print(json.dumps({"hookSpecificOutput": out}))
    return 0


def _note(agent: str, message: str) -> None:
    try:
        print(f"daedalus-jail[{agent}]: {message}", file=sys.stderr)
    except OSError:
        pass  # m5: a closed stderr must not turn an allow into exit 1.


def _load_failed(exc: Exception, in_train: bool, main_session: bool) -> int:
    # 0035: exit 1 does not block a PreToolUse hook, so a train's broken jail must exit 2.
    if in_train and main_session:
        # 0106: the operator's own session is asked, never blocked; agents keep the deny.
        return _ask(f"{_LOAD_ASK} ({exc}). {_LOAD_NEXT}")
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
    payload: dict[str, object], agent: str, message: str, next_step: str = _REPORT_NEXT
) -> int:
    from lib.audit import audit_append

    if "Next:" not in message:
        message += next_step
    try:
        audit_append(payload, "block", message)
    except Exception:  # noqa: BLE001, S110
        pass  # 8.5: best effort; the block stands whether or not the record lands.
    return _block(agent, message)


def _hook_failed(
    payload: dict[str, object],
    agent: str,
    hook: str,
    exc: Exception,
    ask_lead: str,
    next_step: str = _REPORT_NEXT,
) -> int:
    # 0106: a hook failure asks the operator's own session; agents keep the recorded block.
    # 0010: no absolute cwd names no repository to record in, so that call stays blocked.
    cwd = payload.get("cwd")
    if not _bare_main(payload) or not (isinstance(cwd, str) and os.path.isabs(cwd)):
        return _record_and_block(payload, agent, f"{hook}: {exc}", next_step)
    from lib.audit import audit_append

    record = f"{hook}: {exc}"
    text = f"{ask_lead} ({exc})."
    if "Next:" not in record:
        record += next_step
        text += next_step
    try:
        audit_append(payload, "ask", record)
    except Exception as audit_exc:  # noqa: BLE001
        # 0106, AU-5: the stderr line is the alert; the operator may run the call unrecorded.
        _note(agent, f"audit log unavailable ({audit_exc}).")
        return _ask(f"{_AUDIT_ASK} ({audit_exc}). The jail's finding: {text}")
    return _ask(text)


def _judge(payload: dict[str, object], agent: str) -> int:
    from lib.audit import audit_append
    from lib.config import Config, load_config
    from lib.jail import CREDENTIAL_TOOLS, decide, normalize_agent
    from lib.router import route, routed

    cwd = payload.get("cwd")
    # 0023: reads carry only the credential deny, so a broken data dir never closes them.
    read = payload.get("tool_name") in CREDENTIAL_TOOLS and isinstance(cwd, str)
    read = read and Path(str(cwd)).is_absolute()
    try:
        config = load_config(cwd if isinstance(cwd, str) else None)
    except Exception as exc:  # noqa: BLE001
        if not read:
            # 0106: the operator's own session is asked; an agent's call stays blocked.
            return _hook_failed(payload, agent, _CONFIG_HOOK, exc, _CONFIG_ASK, _CONFIG_NEXT)
        config = Config()
    ask = False
    finding: str | None = None
    if routed(agent):
        # 0044: a Daedalus agent's call runs the hooks its agent file names.
        allow, reason, hook = route(payload, Path(__file__).resolve().parents[1])
        reason = f"{hook}: {reason}" if reason else None
        agent = normalize_agent(agent)
    else:
        decision = decide(payload, config)
        allow, finding, ask = decision.allow, decision.reason, decision.ask
        agent = decision.agent or agent
        # 0105, 6.1: the record carries the hook prefix; the operator's ask text does not.
        reason = f"{_JAIL_HOOK}: {finding}" if finding else None
    try:
        verdict = "ask" if ask else "allow" if allow else "block"
        record = audit_append(payload, verdict, reason)
    except Exception as exc:  # noqa: BLE001
        if read and allow:
            # spec 8: an allowed read is non-blocking on a failed record, as audit_log.py is.
            _note(agent, f"audit log unavailable ({exc}); the read proceeds unrecorded.")
            return 0
        if (allow or ask) and _bare_main(payload):
            # 0106, AU-5: the stderr line is the alert; the operator may run the call unrecorded.
            _note(agent, f"audit log unavailable ({exc}).")
            unrecorded = f"{_AUDIT_ASK} ({exc})."
            return _ask(f"{unrecorded} The jail's finding: {finding}" if ask else unrecorded)
        # 8.5: no record, no action. The jail fails closed when the chain cannot be written.
        detail = f"audit log unavailable ({exc})."
        if "Next:" not in detail:
            detail += " Next: fix the project data dir (<repo>/.claude/daedalus) and retry."
        return _block(agent, detail)
    if record is not None and record.get("root_source") == "cwd-fallback":
        _warn_fallback(str(payload.get("cwd")))
    if allow:
        return 0
    if ask:
        return _ask(str(finding))
    return _block(agent, str(reason))


def main() -> int:
    # Every path but a clean allow exits 2, except a library failure outside a train
    # and 0106 asks to the operator's own session.
    try:
        text = sys.stdin.read()
        started = time.monotonic()
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
    main_session = _bare_main(payload)
    train_marked, lib_error = _marker_finder()
    in_train = train_marked(cwd)
    if lib_error is not None:
        return _load_failed(lib_error, in_train, main_session)
    if not in_train and isinstance(cwd, str):
        try:
            from lib.credential_paths import CREDENTIAL_TOOLS
            from lib.train_scope import policed_outside_train
        except Exception as exc:  # noqa: BLE001
            return _load_failed(exc, in_train, main_session)
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
        return _load_failed(exc, in_train, main_session)
    from lib.audit import mark_judge_start

    # 6.1: the fast path loads no lib, so the read-time clock is handed over once lib.audit loads.
    mark_judge_start(started)
    try:
        return _judge(payload, agent)
    except Exception as exc:  # noqa: BLE001
        # 0106: the operator's own session is asked; an agent's call stays blocked.
        return _hook_failed(payload, agent, _JAIL_HOOK, exc, _JUDGE_ASK)


if __name__ == "__main__":
    sys.exit(main())
