# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 233: ruling "sealed one-time pass"; the operator admits one exact refused command once.
# A pass is a JSON file keyed by the command's sha256, sealed with the run's reply key; only
# admit's refusal path reads it, and a matching call deletes it before it runs.
from __future__ import annotations

import hashlib
import hmac
import json
import os
import stat
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from lib import atomic
from lib.audit import (
    DataDirError,
    ReplyKeyError,
    audit_append,
    canonical,
    ensure_project_data_dir,
    message_hmac,
    project_data_dir,
    reply_key,
)
from lib.train_state import active_train

GRANTS = "grants"
PASS_EVENT = "PassConsumed"
_MAX_BYTES = 65536
_FIELDS = frozenset(
    {"agent_id", "command_sha256", "cwd", "expires", "single_use", "reason", "ledger_id"}
    | {"granted_at", "seal"}
)


class PassError(RuntimeError):
    pass


@dataclass(frozen=True)
class Pass:
    agent_id: str
    command_sha256: str
    cwd: str
    expires: str
    single_use: bool
    reason: str
    ledger_id: str
    granted_at: str
    seal: str


def command_sha256(command: str) -> str:
    # 233: the digest admit's Refusal carries, over the exact text; never a normalised copy.
    return hashlib.sha256(command.encode("utf-8", "surrogatepass")).hexdigest()


def _norm(cwd: str) -> str:
    return os.path.realpath(cwd)


def _grants_dir(repo: Path) -> Path:
    return project_data_dir(str(repo)) / GRANTS


def _seal(key: bytes, fields: dict[str, object]) -> str:
    return message_hmac(key, canonical(fields).encode("utf-8"))


def _unsealed(record: Pass) -> dict[str, object]:
    fields: dict[str, object] = asdict(record)
    del fields["seal"]
    return fields


def _expired(record: Pass, now: datetime) -> bool:
    try:
        expires = datetime.fromisoformat(record.expires)
    except ValueError:
        return True
    return expires.tzinfo is None or expires <= now


def load(path: Path) -> Pass | None:
    # 233: a link, a non-file or any field off its type is no pass; the file stays as it is.
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd, "rb") as fh:
            if not stat.S_ISREG(os.fstat(fh.fileno()).st_mode):
                return None
            raw = fh.read(_MAX_BYTES + 1)
        data = json.loads(raw.decode("utf-8"))
    except (OSError, ValueError):
        return None
    if len(raw) > _MAX_BYTES or not isinstance(data, dict) or set(data) != _FIELDS:
        return None
    if data["single_use"] is not True:
        return None
    texts = _FIELDS - {"single_use"}
    if not all(isinstance(data[name], str) for name in texts):
        return None
    return Pass(**{name: data[name] for name in _FIELDS})


def _sealed(record: Pass, key: bytes) -> bool:
    return hmac.compare_digest(record.seal, _seal(key, _unsealed(record)))


def _remove(path: Path) -> bool:
    try:
        os.unlink(path)
    except FileNotFoundError:
        return False
    return True


def write_pass(
    repo: Path,
    agent_id: str,
    command: str,
    cwd: str,
    reason: str,
    ledger_id: str,
    ttl_seconds: int = 300,
) -> Path:
    # 233: refuses with no active run (no reply key), an empty command or a live pass for it.
    if active_train(repo) is None:
        raise PassError(
            f"no run is active in {repo}, so no pass can be sealed (233). "
            "Next: grant a pass only while the run that refused the command is active."
        )
    try:
        key = reply_key(str(repo), create=False)
    except ReplyKeyError as exc:
        raise PassError(f"no reply key seals a pass here ({exc}) (233).") from exc
    if not command.strip():
        raise PassError("the command file is empty (233). Next: write the exact command to it.")
    for name, value in (("--agent", agent_id), ("--reason", reason), ("--ledger-id", ledger_id)):
        if not value.strip():
            raise PassError(f"{name} is empty (233). Next: pass a value for {name}.")
    if not os.path.isabs(cwd):
        raise PassError(f"--cwd {cwd} is not absolute (233). Next: pass the absolute folder.")
    if ttl_seconds <= 0:
        raise PassError(f"ttl_seconds {ttl_seconds} is not positive (233).")
    try:
        ensure_project_data_dir(str(repo))
        grants = _grants_dir(repo)
        grants.mkdir(mode=0o700, exist_ok=True)
        atomic.refuse_links(grants)
    except (DataDirError, atomic.LinkRefused, OSError) as exc:
        raise PassError(f"the grants folder could not be prepared ({exc}) (233).") from exc
    digest = command_sha256(command)
    path = grants / f"{digest}.json"
    now = datetime.now(UTC)
    old = load(path)
    if old is not None and _sealed(old, key) and _expired(old, now):
        _remove(path)  # 233: an expired pass is deleted on sight.
    if os.path.lexists(path):
        raise PassError(
            f"a pass for this command exists ({digest[:12]}) (233). "
            "Next: let the agent run the command once, or wait for the pass to expire."
        )
    fields: dict[str, object] = {
        "agent_id": agent_id,
        "command_sha256": digest,
        "cwd": _norm(cwd),
        "expires": (now + timedelta(seconds=ttl_seconds)).isoformat(timespec="seconds"),
        "single_use": True,
        "reason": reason,
        "ledger_id": ledger_id,
        "granted_at": now.isoformat(timespec="seconds"),
    }
    body = json.dumps({**fields, "seal": _seal(key, fields)}, sort_keys=True, indent=2)
    try:
        atomic.create_once(path, body + "\n", 0o600)
    except FileExistsError as exc:
        raise PassError(f"a pass for this command exists ({digest[:12]}) (233).") from exc
    return path


def consume_pass(repo: Path, agent_id: str, command: str, cwd: str) -> Pass | None:
    # 233: seal, agent, folder and expiry match exactly, then the file goes; a mismatch keeps it.
    if not command or not os.path.isabs(cwd):
        return None
    digest = command_sha256(command)
    try:
        grants = _grants_dir(repo)
        atomic.refuse_links(grants)
        key = reply_key(str(repo), create=False)
    except (atomic.LinkRefused, ReplyKeyError, OSError):
        return None
    path = grants / f"{digest}.json"
    record = load(path)
    if record is None or not _sealed(record, key) or record.command_sha256 != digest:
        return None
    if _expired(record, datetime.now(UTC)):
        _remove(path)  # 233: an expired pass is deleted on sight.
        return None
    if record.agent_id != agent_id or record.cwd != _norm(cwd):
        return None
    return record if _remove(path) else None


def consumed_line(record: Pass) -> str:
    return (
        f"pass consumed agent={record.agent_id} sha256={record.command_sha256[:12]} "
        f"reason={record.reason}"
    )


def pass_admits(
    repo: Path, agent_id: str, command: str, cwd: str, hook_input: dict[str, object]
) -> bool:
    # 233: called on admit's refusal path only; True once the audit line for the pass is written.
    if active_train(repo) is None:
        return False
    record = consume_pass(repo, agent_id, command, cwd)
    if record is None:
        return False
    event = {**hook_input, "hook_event_name": PASS_EVENT}
    return audit_append(event, "allow", consumed_line(record)) is not None
