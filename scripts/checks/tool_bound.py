# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0044, 0039: refuses a tool the agent file's tools line omits, and every meta or MCP tool.
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from lib import agent_files, hook_io, jail  # noqa: E402

TOOLS: frozenset[str] = hook_io.EVERY_TOOL
FLAGS: dict[str, hook_io.Flag] = {}
PARSER = hook_io.build_parser(Path(__file__).stem, FLAGS)
PLUGIN_ROOT = Path(__file__).resolve().parents[2]
# 0044: a name outside this form reads as a missing agent file.
_AGENT_NAME = re.compile(r"[a-z0-9][a-z0-9-]*")
R_NO_AGENT_FILE = (
    "agents/{agent}.md is missing, so its tools are unknown (0044). "
    "Next: add the agent file with its tools line, or start a catalog agent."
)


def judge(hook_input: dict[str, object], flags: argparse.Namespace) -> str | None:
    tool = hook_io.text(hook_input, "tool_name")
    if tool in jail.WORKER_DENIED_TOOLS or tool.startswith("mcp__"):
        return jail.R_TOOL
    agent = jail.normalize_agent(str(hook_input.get("agent_type") or "main"))
    path = PLUGIN_ROOT / "agents" / f"{agent}.md"
    if not _AGENT_NAME.fullmatch(agent) or not path.is_file():
        return R_NO_AGENT_FILE.format(agent=agent)
    listed = agent_files.frontmatter(path).get("tools", "")
    return None if tool in {t.strip() for t in listed.split(",")} else jail.R_TOOL


def main() -> int:
    return hook_io.run(judge, TOOLS, PARSER)


if __name__ == "__main__":
    sys.exit(main())
