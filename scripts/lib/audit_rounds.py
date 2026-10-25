# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0109, spec 3.4: the auditor's finding list and the stall rule; pure, so the table test owns it.
# The orchestrator obeys the printed word and never judges the stall itself.
from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass

SEVERITIES = ("critical", "high", "medium", "low")
HIGH = frozenset({"critical", "high"})
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


def judge(
    previous: Mapping[str, str] | None, current: Mapping[str, str], used: int, budget: int
) -> str:
    # spec 3.4: maps are key to severity; continue while the set shrinks, no new high, in budget.
    if previous is not None:
        raised = sorted(
            key for key, sev in current.items() if sev in HIGH and previous.get(key) not in HIGH
        )
        if raised:
            return f"escalate reason=new-high key={raised[0]}"
        recurring = sorted(set(current) & set(previous))
        if recurring and not set(current) < set(previous):
            return f"escalate reason=recurring key={recurring[0]}"
    if used >= budget:
        return "escalate reason=budget"
    return f"continue round={used + 1} budget_left={budget - used}"
