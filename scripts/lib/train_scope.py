# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# Standard library only: the jail's entry script imports this before the rest of lib.
from __future__ import annotations

from pathlib import Path

# 0044: every shipped agent file is a known agent; computed once at import.
KNOWN_AGENTS = frozenset(
    {"main"} | {p.stem for p in (Path(__file__).resolve().parents[2] / "agents").glob("*.md")}
)
# Plugin agents arrive as <plugin>:<agent>; only these prefixes unwrap.
AGENT_NAMESPACES = ("daedalus",)
# tests/fixtures/live-agent namespace; accepted only when DAEDALUS_LIVE_TEST=1.
TEST_NAMESPACE = "daedalus-probe"


def policed_outside_train(raw_agent: str) -> bool:
    # 0023, 0035: Daedalus agents meet the jail always; main and foreign agents only in a train.
    prefix, sep, _ = raw_agent.partition(":")
    if sep:
        return prefix in (*AGENT_NAMESPACES, TEST_NAMESPACE)
    return raw_agent in KNOWN_AGENTS and raw_agent != "main"
