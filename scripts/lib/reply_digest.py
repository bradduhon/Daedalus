# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0205 (digest returns): a hand-back of a listed agent is saved whole under the run's
# evidence/replies folder and reaches its caller as a short keyed digest of fixed lines.
# The digest keeps every line a route or a record reads: the verifier's two verdict lines,
# its Unit worktree: key line and its corrected line, the coder's receipts block and
# COMPLETE line, contract-spec's packet_version line and charter-docs' status line.
# Anything else passes unchanged.
from __future__ import annotations

import hashlib
import re
from datetime import UTC, datetime
from pathlib import Path

from lib.atomic import create_once

DIGESTED = frozenset({"coder", "verifier", "contract-spec", "charter-docs"})
REPLIES = Path("evidence") / "replies"
RECEIPTS = "## Receipts"
PACKET = "## Locked Contract Packet"
COMPLETE = "[STATUS: COMPLETE]"
VERDICT = "[VERDICT: "
UNIT_KEY = "Unit worktree: "
_CORRECTED = re.compile(r"corrected=[0-9]+")
_VERSION = re.compile(r".*packet_version\W*[0-9]+.*")
_SAFE = re.compile(r"[^A-Za-z0-9]")


def report_line(path: Path, text: str) -> str:
    sha = hashlib.sha256(text.encode("utf-8", "surrogatepass")).hexdigest()
    return f"report: {path} sha256={sha} lines={len(text.splitlines())}"


def kept_lines(agent: str, message: str) -> list[str] | None:
    # 0205: None leaves the message whole: an off-contract reply reaches the caller as written.
    lines = [line.rstrip() for line in message.rstrip().splitlines()]
    body = [line.strip() for line in lines if line.strip()]
    if not body:
        return None
    last = body[-1]
    if agent == "verifier":
        if not (body[0].startswith(VERDICT) and last.startswith(VERDICT)) or len(body) < 2:
            return None
        corrected = [body[-2]] if len(body) > 2 and _CORRECTED.fullmatch(body[-2]) else []
        # 0231: the key line rides as the second line, where the merge gate reads it.
        key = [body[1]] if len(body) > 2 and body[1].startswith(UNIT_KEY) else []
        return [body[0], *key, *corrected, last]
    if agent == "coder":
        if not last.startswith(COMPLETE) or RECEIPTS not in lines:
            return None
        return lines[len(lines) - lines[::-1].index(RECEIPTS) - 1 :]
    if agent == "contract-spec":
        if PACKET not in lines:
            return None
        section = lines[len(lines) - lines[::-1].index(PACKET) :]
        version = next((line for line in section if _VERSION.fullmatch(line)), None)
        return None if version is None else [PACKET, version.strip()]
    if agent == "charter-docs" and last.startswith("[STATUS: "):
        return [last]
    return None


def digest(
    agent: str, message: str, repo: Path, train: str, agent_id: str, now: datetime | None = None
) -> str | None:
    # 0205: the report is written before the digest names it; a digest no shorter passes as is.
    kept = kept_lines(agent, message) if agent in DIGESTED else None
    if kept is None:
        return None
    stamp = (now or datetime.now(UTC)).strftime("%Y%m%dT%H%M%S%fZ")
    folder = repo / "docs" / ".tmp" / "daedalus" / train / REPLIES
    path = folder / f"{agent}-{_SAFE.sub('', agent_id) or 'none'}-{stamp}.md"
    line = report_line(path, message)
    if agent == "verifier":
        keys = kept[1:2] if kept[1].startswith(UNIT_KEY) else []
        short = "\n".join([kept[0], *keys, line, *kept[1 + len(keys) :]])
    else:
        short = "\n".join([line, "", *kept] if agent == "coder" else [line, *kept])
    if len(short) >= len(message):
        return None
    folder.mkdir(parents=True, exist_ok=True)
    create_once(path, message, 0o600)
    return short
