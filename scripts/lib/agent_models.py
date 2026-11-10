# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# spec 4: the one place the model order lives: the override, then config agent_models, then
# the agent file's prefer line when Fable is available (0217), then its model line.
# Config is a type only here, since lib.config imports MODELS.
from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from lib import agent_files, fable

if TYPE_CHECKING:
    from lib.config import Config

MODELS = ("sonnet", "opus", "haiku", "fable")
AGENTS_DIR = Path(__file__).resolve().parents[2] / "agents"


class AgentModelError(ValueError):
    pass


def resolve(
    name: str,
    config: Config,
    override: str | None = None,
    *,
    agents_dir: Path = AGENTS_DIR,
    repo: Path | None = None,
) -> str:
    path = agents_dir / f"{name}.md"
    if not agent_files.AGENT_NAME.fullmatch(name) or not path.is_file():
        raise AgentModelError(
            f"{name!r} is not a catalog agent. "
            "Next: name an agent the catalog lists, without the daedalus: prefix."
        )
    if override is not None:
        if override not in MODELS:
            raise AgentModelError(
                f"model {override!r} is not one of {', '.join(MODELS)}. "
                "Next: pass one of those four models, or no override."
            )
        return override
    configured = config.agent_models.get(name)
    if configured is not None:
        return configured
    fields = agent_files.frontmatter(path)
    try:
        prefer = agent_files.preference(path, fields.get("prefer"))
    except agent_files.AgentFileError as exc:
        raise AgentModelError(str(exc)) from exc
    # 0217: a preferred model only when Fable is available; else the file's model line.
    if prefer is not None and fable.available(config, repo):
        return prefer
    return fields["model"]
