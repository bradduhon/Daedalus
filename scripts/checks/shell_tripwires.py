# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0044, 8.5: the worker shell model; unsupported constructs, tripwires, env prefix, hygiene, pipes.
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from lib import hook_io, jail, shell  # noqa: E402

TOOLS: frozenset[str] = frozenset({"Bash"})
FLAGS: dict[str, hook_io.Flag] = {"--no-pipes": hook_io.Flag()}
PARSER = hook_io.build_parser(Path(__file__).stem, FLAGS)


def judge(hook_input: dict[str, object], flags: argparse.Namespace) -> str | None:
    command = hook_io.text(hook_io.tool_input(hook_input), "command")
    agent = jail.normalize_agent(str(hook_input.get("agent_type") or "main"))
    scanned = shell._scan(command)
    parsed = shell.tokenize(command)
    # 8.5: || is a fallback chain the jail does not reason about, blocked for workers.
    if parsed is None or scanned is None or "||" in scanned[1]:
        return shell.R_UNSUPPORTED
    for segment in parsed:
        reason = shell._segment_reason(segment, 0, main=False)
        if reason == shell._FALLBACK:
            reason = shell._regex_tripwire(command)
        if reason:
            return reason
    segments = shell.worker_segments(command) or []
    if not all(segments):
        return shell.R_ENV
    for segment in segments:
        reason = shell._worker_hygiene(segment, agent)
        if reason:
            return reason
    no_pipes: bool = flags.no_pipes
    return jail.R_PIPE if no_pipes and "|" in scanned[1] else None


def main() -> int:
    return hook_io.run(judge, TOOLS, PARSER)


if __name__ == "__main__":
    sys.exit(main())
