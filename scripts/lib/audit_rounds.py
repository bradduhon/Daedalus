# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0109, spec 3.4: the auditor's finding list and the round number; pure, so the table test owns it.
# 0133: no stall rule and no budget; the operator decides each finding.
from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass

SEVERITIES = ("critical", "high", "medium", "low")
_SEP = " | "
_ROUND_KEY = re.compile(r"[1-9][0-9]{0,5}")


class FindingsError(ValueError):
    pass


@dataclass(frozen=True)
class Finding:
    key: str
    severity: str
    kind: str


def parse(text: str, where: str) -> dict[str, Finding]:
    # pin C3 -> C1: one `<key> | <severity> | <class>` line per blocking finding.
    found: dict[str, Finding] = {}
    for number, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line:
            continue
        parts = [part.strip() for part in line.rsplit(_SEP, 2)]
        if len(parts) != 3 or not all(parts) or not line.isprintable():
            raise FindingsError(
                f"{where} line {number} is not `<key> | <severity> | <class>`. "
                "Next: have the auditor rewrite the finding list in that form."
            )
        key, severity, kind = parts
        if severity not in SEVERITIES:
            raise FindingsError(
                f"{where} line {number} names severity {severity!r}. "
                f"Next: have the auditor use one of {', '.join(SEVERITIES)}."
            )
        if key in found:
            raise FindingsError(
                f"{where} names {key} twice. Next: have the auditor list each finding once."
            )
        found[key] = Finding(key, severity, kind)
    return found


def next_round(rounds: Mapping[str, object]) -> int:
    # 67: one more than the highest round key the train recorded, else 1; other keys are skipped.
    return max((int(key) for key in rounds if _ROUND_KEY.fullmatch(key)), default=0) + 1
