# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0217, 0213: whether the session can start Fable; config first, then the session's own record.
# Every unreadable or missing source reads as not available, never a stop or an error.
from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from lib.config import Config

FABLE = "fable"
SESSION_PREFIX = "claude-fable"
BY_CONFIG, BY_SESSION, NOT_AVAILABLE, OFF_BY_CONFIG = "config", "session", "", "off"


def session_model(repo: Path) -> str | None:
    # 0217: only a marked train writes the log, so its newest log is this session's.
    try:
        from lib.audit_proof import newest_log, read_chain
        from lib.project_root import project_root, train_marked

        root = project_root(repo)
        if not train_marked(str(root)):
            return None
        records = read_chain(newest_log(root))
    except Exception:  # noqa: BLE001
        return None
    starts = [r for r in records if r.get("event") == "SessionStart"]
    model = starts[-1].get("model") if starts else None
    return model if isinstance(model, str) else None


def availability(config: Config, repo: Path | None) -> str:
    # 0217: a config value wins over session evidence; absent both, Fable is not available.
    if config.fable_available is not None:
        return BY_CONFIG if config.fable_available else OFF_BY_CONFIG
    model = session_model(repo) if repo is not None else None
    return BY_SESSION if model is not None and model.startswith(SESSION_PREFIX) else NOT_AVAILABLE


def available(config: Config, repo: Path | None) -> bool:
    return availability(config, repo) in (BY_CONFIG, BY_SESSION)
