#!/usr/bin/env python3
# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0044: prints the agent, shape and hooks matrix that README.md carries between its markers.
# 0088, spec 9.1: prints the agent table README.md and the catalog skill carry the same way.
from __future__ import annotations

import argparse
import sys
from collections.abc import Callable
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from lib import agent_files, agent_models  # noqa: E402
from lib.audit import DataDirError  # noqa: E402
from lib.config import Config, ConfigError, load_config  # noqa: E402

AGENTS_DIR = Path(__file__).resolve().parents[1] / "agents"


def matrix(agents_dir: Path) -> str:
    rows = ["| Agent | Shape | Hooks |", "|---|---|---|"]
    for name, agent in sorted(agent_files.load_all(agents_dir).items()):
        hooks = ", ".join(" ".join((hook.script, *hook.flags)) for hook in agent.hooks)
        rows.append(f"| {name} | {agent.shape} | {hooks} |")
    return "\n".join(rows) + "\n"


def job(description: str) -> str:
    # 9.1: the job column is the description's first sentence.
    head, sep, _ = description.partition(". ")
    return f"{head}." if sep else description


def table(agents_dir: Path, config: Config | None = None) -> str:
    # spec 4, pin C2 -> C1: with a config the Model cell is the effective model, else the file's.
    rows = [
        "| Agent | Shape | Model | Tools | Job | Reply lines | Phases |",
        "|---|---|---|---|---|---|---|",
    ]
    for name, agent in sorted(agent_files.load_all(agents_dir).items()):
        model = agent.model
        if config is not None:
            model = agent_models.resolve(name, config, agents_dir=agents_dir)
        cells = (
            name,
            agent.shape,
            model,
            ", ".join(sorted(agent.tools)),
            job(agent.description),
            "; ".join(f"`{line}`" for line in agent.status_lines),
            ", ".join(agent.phases),
        )
        rows.append("| " + " | ".join(cell.replace("|", "\\|") for cell in cells) + " |")
    return "\n".join(rows) + "\n"


def _table(args: argparse.Namespace) -> str:
    config = load_config(cwd=str(args.repo.resolve())) if args.repo is not None else None
    return table(args.agents_dir, config)


COMMANDS: dict[str, Callable[[argparse.Namespace], str]] = {
    "matrix": lambda args: matrix(args.agents_dir),
    "table": _table,
}


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="catalog.py")
    commands = parser.add_subparsers(dest="command", required=True)
    for name in COMMANDS:
        command = commands.add_parser(name)
        command.add_argument("--agents-dir", type=Path, default=AGENTS_DIR)
    # spec 4: --repo reads that project's config, so the Model column shows agent_models.
    commands.choices["table"].add_argument("--repo", type=Path)
    args = parser.parse_args(argv)
    try:
        out = COMMANDS[args.command](args)
    except (
        agent_files.AgentFileError,
        agent_models.AgentModelError,
        ConfigError,
        DataDirError,
    ) as exc:
        print(exc, file=sys.stderr)
        return 1
    except Exception as exc:  # noqa: BLE001
        print(
            f"catalog.py {args.command} failed ({exc!r}). Next: fix the agent files.",
            file=sys.stderr,
        )
        return 1
    sys.stdout.write(out)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
