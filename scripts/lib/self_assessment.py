# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# A1, 0252: the Self-Assessment flag and its hand-over and findings folders, placed by lib.storage.
# The hook imports this module, so nothing here loads audit code at import time.
from __future__ import annotations

import re
from pathlib import Path

from lib import storage
from lib.operator_file import load
from lib.project_root import project_root

FEATURE = "self-assessment"
MAX_HANDOVER_BYTES = 8192
_STAMP = re.compile(r"[0-9]{8}T[0-9]{6}Z")
HANDOVER_NAME = re.compile(r"handover-[0-9]{8}T[0-9]{6}Z\.json")


def project_key(path: str | Path) -> str:
    return storage.project_key(path)


def handover_dir(path: str | Path) -> Path:
    return storage.tmp_dir(FEATURE, path)


def handover_name(stamp: str) -> str:
    if not _STAMP.fullmatch(stamp):
        raise ValueError(f"stamp {stamp!r} is not YYYYMMDDTHHMMSSZ")
    return f"handover-{stamp}.json"


def check_dirs(path: str | Path) -> str | None:
    return storage.check_tmp_dirs(FEATURE, path)


def make_handover_dir(path: str | Path) -> Path:
    return storage.make_tmp_dir(FEATURE, path)


def findings_dir() -> Path:
    return storage.data_dir(FEATURE) / "findings"


def enabled(path: str | Path) -> bool:
    # A1: fail closed; a missing, unreadable or refused personal file is false.
    try:
        return load(project_root(Path(path))).self_assessment is True
    except Exception:
        return False
