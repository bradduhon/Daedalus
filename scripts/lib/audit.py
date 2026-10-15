# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
from datetime import UTC, datetime
from functools import lru_cache
from pathlib import Path
from typing import Any

from lib.locks import bounded_flock
from lib.redact import redact

GENESIS = "0" * 64
# 8.2: character count of the stored head, not bytes; non-ASCII heads may exceed 4096 bytes.
HEAD_BYTES = 4096
MESSAGE_HEAD_CHARS = 2048
# m1: redaction window past the cut so a secret straddling HEAD_BYTES is masked before slicing.
_REDACT_SLACK = 512
_OPEN_URL = re.compile(r"://[^\s\"']*$")
LOCK_TIMEOUT_S = 5.0
LOCK_POLL_S = 0.05
_SESSION_ID = re.compile(r"[A-Za-z0-9_-]+")


class AuditCorruptError(RuntimeError):
    pass


def cache_dir() -> Path:
    root = os.environ.get("CLAUDE_PLUGIN_DATA")
    if not root:
        raise RuntimeError(
            "CLAUDE_PLUGIN_DATA not set. Next: run inside Claude Code with the plugin loaded."
        )
    return Path(root)


NO_CACHE = (
    "no plugin cache dir found. Next: run /daedalus:doctor inside Claude Code once so the "
    "plugin data directory exists."
)


def cache_dir_matches() -> list[Path]:
    base = Path.home() / ".claude" / "plugins" / "data"
    # I5: inline sorts last so an installed copy's cache wins when both exist.
    found = [p for p in base.glob("daedalus*") if p.is_dir()]
    return sorted(found, key=lambda p: (p.name == "daedalus-inline", p.name))


def cache_dir_or_probe() -> Path:
    # 0010: operator shells lack CLAUDE_PLUGIN_DATA, so fall back to the first probed cache dir.
    env = os.environ.get("CLAUDE_PLUGIN_DATA")
    if env:
        return Path(env).resolve()
    matches = cache_dir_matches()
    if matches:
        return matches[0].resolve()
    raise RuntimeError(NO_CACHE)


class DataDirError(RuntimeError):
    def __init__(self, message: str, kind: str) -> None:
        super().__init__(message)
        self.kind = kind


# 0010: env vars that would redirect git away from the cwd's own repository.
_GIT_REDIRECT_ENV = ("GIT_DIR", "GIT_COMMON_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE")
_SYMLINK_NEXT = (
    "Next: remove the symlink; the plugin data directory must be a real directory inside the repo."
)
_TRACKED_NEXT = (
    "Next: remove .claude/daedalus from git history or move it aside; "
    "a tracked plugin config is not trusted."
)
_MARKER_NEXT = "Next: restore the `*` marker in .claude/daedalus/.gitignore."
# 0010: ls-files runs at most once per root per process to keep hook latency low.
_TRACKED: dict[str, list[str]] = {}


def _git_env() -> dict[str, str]:
    return {k: v for k, v in os.environ.items() if k not in _GIT_REDIRECT_ENV}


@lru_cache(maxsize=32)
def root_info(cwd: str) -> tuple[Path, str, str | None]:
    cmd = ["git", "-C", cwd, "rev-parse", "--path-format=absolute", "--git-common-dir"]
    try:
        out = subprocess.run(
            cmd, capture_output=True, text=True, timeout=2, env=_git_env(), check=False
        )
    except subprocess.TimeoutExpired:
        return Path(cwd), "cwd-fallback", "git timed out after 2 s"
    except (OSError, subprocess.SubprocessError) as exc:
        return Path(cwd), "cwd-fallback", f"git could not run: {exc}"
    common = out.stdout.strip()
    if out.returncode != 0 or not common or not os.path.isabs(common):
        detail = (out.stderr.strip().splitlines() or ["no common dir"])[0]
        return Path(cwd), "cwd-fallback", detail
    # 0010: the common dir is shared by every worktree; its parent is the main working tree.
    return Path(common).parent, "git", None


def project_root(cwd: str) -> Path:
    return root_info(cwd)[0]


def project_data_dir(cwd: str) -> Path:
    return project_root(cwd) / ".claude" / "daedalus"


def _tracked_files(root: Path) -> list[str]:
    key = str(root)
    if key not in _TRACKED:
        cmd = ["git", "-C", key, "ls-files", "-z", "--", ".claude/daedalus"]
        try:
            out = subprocess.run(
                cmd, capture_output=True, text=True, timeout=2, env=_git_env(), check=False
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise DataDirError(
                f"could not list tracked files under {root}/.claude/daedalus ({exc}). "
                + _TRACKED_NEXT,
                "tracked",
            ) from exc
        if out.returncode != 0:
            first = (out.stderr.strip().splitlines() or ["no stderr"])[0]
            raise DataDirError(
                f"git could not list files under {root} ({first}); the repo layout is not one "
                "the plugin resolves yet (separate-git-dir, bare, submodule). Next: run the "
                "plugin from a standard clone, or see the tracked issue on root resolution.",
                "layout",
            )
        _TRACKED[key] = [f for f in out.stdout.split("\0") if f]
    return _TRACKED[key]


def check_project_data_dir(cwd: str) -> Path:
    root, source, _ = root_info(cwd)
    data = root / ".claude" / "daedalus"
    # 0010: a symlinked component would redirect hook writes or config reads out of the repo.
    for part in (root / ".claude", data, data / "audit", data / ".gitignore", data / "config.json"):
        if part.is_symlink():
            raise DataDirError(f"{part} is a symlink. " + _SYMLINK_NEXT, "symlink")
    if source == "git":
        tracked = _tracked_files(root)
        if tracked:
            raise DataDirError(
                f"git tracks {len(tracked)} file(s) under {data} ({tracked[0]}). " + _TRACKED_NEXT,
                "tracked",
            )
    marker = data / ".gitignore"
    if marker.exists():
        try:
            content = marker.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            content = None
        if content not in ("*", "*\n"):
            raise DataDirError(f"{marker} does not hold exactly `*`. " + _MARKER_NEXT, "marker")
    return data


def ensure_project_data_dir(cwd: str) -> Path:
    data = check_project_data_dir(cwd)
    data.mkdir(parents=True, exist_ok=True)
    os.chmod(data, 0o700)
    marker = data / ".gitignore"
    if not marker.exists():
        # 0010: written whole then linked in, so a concurrent hook never reads a partial marker.
        tmp = data / f".gitignore.{os.getpid()}.tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write("*\n")
        try:
            os.link(tmp, marker)
        except FileExistsError:
            pass
        finally:
            tmp.unlink()
        return check_project_data_dir(cwd)
    return data


def _require_cwd(cwd: Any) -> str:
    if not isinstance(cwd, str) or not os.path.isabs(cwd):
        raise ValueError(
            f"hook input cwd must be an absolute path (got {cwd!r}). "
            "Next: report the hook input; the project data dir is located from cwd."
        )
    return cwd


def _session_file(session_id: str | None, cwd: Any) -> tuple[Path, Path]:
    session = str(session_id or "unknown")
    if not _SESSION_ID.fullmatch(session):
        raise ValueError(
            f"session_id must match [A-Za-z0-9_-]+ (got {session!r}). Next: report the hook input."
        )
    audit_dir = project_data_dir(_require_cwd(cwd)) / "audit"
    return audit_dir / f"{session}.jsonl", audit_dir / f"{session}.lock"


def log_path(session_id: str, cwd: str) -> Path:
    return _session_file(session_id, cwd)[0]


def canonical(record: dict[str, Any]) -> str:
    body = {key: value for key, value in record.items() if key != "hash"}
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def record_hash(record: dict[str, Any]) -> str:
    return hashlib.sha256(canonical(record).encode("utf-8")).hexdigest()


def _result_fields(hook_input: dict[str, Any]) -> tuple[str | None, str | None]:
    raw = hook_input.get("tool_response", hook_input.get("error"))
    if raw is None:
        return None, None
    text = raw if isinstance(raw, str) else json.dumps(raw, sort_keys=True, separators=(",", ":"))
    # Lone surrogates must not crash the digest; valid text hashes identically.
    digest = hashlib.sha256(text.encode("utf-8", "surrogatepass")).hexdigest()
    return digest, _head(text)


def _head(text: str, limit: int = HEAD_BYTES) -> str:
    window = str(redact(text[: limit + _REDACT_SLACK]))
    if len(text) > limit + _REDACT_SLACK:
        # R1-M2: a URL cut before its @ may still hold userinfo; mask the tail.
        window = _OPEN_URL.sub("://***", window)
    return window[:limit]


def _error_field(error: Any) -> Any:
    return _head(error) if isinstance(error, str) else redact(error)


def build_record(
    hook_input: dict[str, Any], decision: str | None = None, reason: str | None = None
) -> dict[str, Any]:
    event = hook_input.get("hook_event_name")
    tool_name = hook_input.get("tool_name")
    tool_input = hook_input.get("tool_input")
    # 8.2: Read logs its path only; mutating tools log full input.
    if tool_name == "Read" and isinstance(tool_input, dict):
        tool_input = {"file_path": tool_input.get("file_path")}
    result_sha, result_head = (None, None)
    if event in ("PostToolUse", "PostToolUseFailure"):
        result_sha, result_head = _result_fields(hook_input)
    last = hook_input.get("last_assistant_message")
    # R2-M3: same slack window and tail mask as result_head.
    last_head = _head(last, MESSAGE_HEAD_CHARS) if isinstance(last, str) and last else None
    # 8.2: error, source and stop_reason are event-specific; null when absent.
    return {
        "ts": datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
        "session_id": hook_input.get("session_id"),
        "event": event,
        "agent_id": hook_input.get("agent_id"),
        "agent_type": hook_input.get("agent_type") or "main",
        "cwd": hook_input.get("cwd"),
        "tool_name": tool_name,
        "tool_use_id": hook_input.get("tool_use_id"),
        "tool_input": redact(tool_input),
        "prompt": redact(hook_input.get("prompt")),
        "last_message_head": last_head,
        "decision": decision,
        "reason": redact(reason),
        "result_sha256": result_sha,
        "result_head": result_head,
        "error": _error_field(hook_input.get("error")),
        "source": hook_input.get("source"),
        "stop_reason": hook_input.get("stop_reason"),
    }


def _tail_record(path: Path) -> dict[str, Any] | None:
    if not path.exists() or path.stat().st_size == 0:
        return None
    with open(path, "rb") as fh:
        fh.seek(0, os.SEEK_END)
        pos = fh.tell()
        buf = b""
        while pos > 0:
            step = min(4096, pos)
            pos -= step
            fh.seek(pos)
            buf = fh.read(step) + buf
            if buf.count(b"\n") >= 2:
                break
    last = buf.rstrip(b"\n").split(b"\n")[-1]
    try:
        return json.loads(last)
    except json.JSONDecodeError as exc:
        raise AuditCorruptError(
            f"{path} ends with an unparseable record. "
            "Next: move the file aside and report it; the chain head is lost."
        ) from exc


def audit_append(
    hook_input: dict[str, Any], decision: str | None = None, reason: str | None = None
) -> dict[str, Any]:
    path, lock = _session_file(hook_input.get("session_id"), hook_input.get("cwd"))
    ensure_project_data_dir(hook_input["cwd"])
    audit_dir = path.parent
    audit_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(audit_dir, 0o700)
    root, source, _ = root_info(hook_input["cwd"])
    record = build_record(hook_input, decision, reason)
    record["project_root"] = str(root)
    record["root_source"] = source
    with open(lock, "w") as lock_fh:
        bounded_flock(lock_fh, LOCK_TIMEOUT_S, LOCK_POLL_S, label="audit lock")
        tail = _tail_record(path)
        record["seq"] = 1 if tail is None else int(tail["seq"]) + 1
        record["prev_hash"] = GENESIS if tail is None else tail["hash"]
        record["hash"] = record_hash(record)
        line = json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(line + "\n")
        os.chmod(path, 0o600)
    return record
