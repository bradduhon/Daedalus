#!/usr/bin/env python3
# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0044: prints the agent, shape and hooks matrix that README.md carries between its markers.
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from lib import agent_files  # noqa: E402

AGENTS_DIR = Path(__file__).resolve().parents[1] / "agents"


def matrix(agents_dir: Path) -> str:
    rows = ["| Agent | Shape | Hooks |", "|---|---|---|"]
    for name, agent in sorted(agent_files.load_all(agents_dir).items()):
        hooks = ", ".join(" ".join((hook.script, *hook.flags)) for hook in agent.hooks)
        rows.append(f"| {name} | {agent.shape} | {hooks} |")
    return "\n".join(rows) + "\n"


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="catalog.py")
    commands = parser.add_subparsers(dest="command", required=True)
    table = commands.add_parser("matrix")
    table.add_argument("--agents-dir", type=Path, default=AGENTS_DIR)
    args = parser.parse_args(argv)
    try:
        out = matrix(args.agents_dir)
    except agent_files.AgentFileError as exc:
        print(exc, file=sys.stderr)
        return 1
    except Exception as exc:  # noqa: BLE001
        print(f"catalog.py matrix failed ({exc!r}). Next: fix the agent files.", file=sys.stderr)
        return 1
    sys.stdout.write(out)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
