# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0187: the model tier of one coder dispatch, from the unit's files and its refutation count.
# lib.config reads the coder_models key against TIERS; the train runner maps a tier to a model.
from __future__ import annotations

import posixpath
from collections.abc import Sequence

from lib import manifest

DEFAULT, CONTROL_PATH, ESCALATED = "default", "control_path", "escalated"
TIERS = (DEFAULT, CONTROL_PATH, ESCALATED)
DEFAULT_CODER_MODELS = {DEFAULT: "sonnet", CONTROL_PATH: "opus", ESCALATED: "opus"}
REASON_DEFAULT = "default"
REASON_ESCALATED = "second refutation"
# agents/verifier.md: the verdict line a refuting verifier ends its reply with.
REFUTED_PREFIX = "[VERDICT: REFUTED]"
# 0187: the refutation count at which a fresh coder takes the unit on the escalated tier.
ESCALATE_AT = 2
_GLOB_CHARS = "*?["


def _glob_reaches(name: str, control_paths: Sequence[str]) -> bool:
    # 0187: fail closed; a glob whose literal prefix could reach a control path counts as one.
    prefix = name[: min(name.index(c) for c in _GLOB_CHARS if c in name)].casefold()
    return any(
        p.casefold().startswith(prefix) or prefix.startswith(p.casefold()) for p in control_paths
    )


def coder_tier(
    files: Sequence[str], control_paths: Sequence[str], refutations: int
) -> tuple[str, str]:
    """0187, 0183: tier and reason; a second refutation first, then any control path file."""
    if refutations >= ESCALATE_AT:
        return ESCALATED, REASON_ESCALATED
    hit = manifest.Manifest(tuple(control_paths))
    for name in files:
        # 0187: fail closed on an absolute, parent or whole-repository path, as the contract check.
        whole = posixpath.normpath(name) in (".", "")
        if whole or posixpath.isabs(name) or ".." in name.split("/"):
            return CONTROL_PATH, f"unsafe path {name}"
        if any(c in name for c in _GLOB_CHARS):
            if _glob_reaches(name, control_paths):
                return CONTROL_PATH, f"control path {name}"
            continue
        if manifest.path_hit(hit, posixpath.normpath(name)):
            return CONTROL_PATH, f"control path {name}"
    return DEFAULT, REASON_DEFAULT
