# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0284: a marked repo, a temp home and a temp storage root for the context limit cases.
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

import pytest
from lib import handoff, storage
from lib.config import Config
from lib.context_size import Measured, SizeResult
from lib.operator_file import CONTEXT_LIMIT

from tests.conftest import REPO_ROOT, git, write_train_marker

AGENT_ID = "a0123456789abcdef"
OTHER_ID = "a00000000000000ff"
SESSION = "sess-handoff"
PAST = CONTEXT_LIMIT + 1


@dataclass(frozen=True)
class Case:
    repo: Path
    home: Path
    tmp_root: Path

    def payload(self, agent: str, tool: str, tool_input: dict[str, object]) -> dict[str, object]:
        return {
            "session_id": SESSION,
            "hook_event_name": "PreToolUse",
            "cwd": str(self.repo),
            "agent_id": AGENT_ID,
            "agent_type": agent,
            "transcript_path": str(self.home / ".claude" / "projects" / "p" / f"{SESSION}.jsonl"),
            "tool_name": tool,
            "tool_input": tool_input,
        }

    def handoff(self) -> Path:
        path = handoff.handoff_path({"agent_id": AGENT_ID, "cwd": str(self.repo)})
        assert path is not None
        return path


def make_case(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Case:
    root = tmp_path.resolve()
    home = root / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    tmp_root = root / "tmproot"
    monkeypatch.setattr(storage, "TMP_ROOT", tmp_root)
    repo = root / "repo"
    repo.mkdir()
    git(repo, "init", "-q", "-b", "main")
    write_train_marker(repo)
    return Case(repo, home, tmp_root)


def sized(tokens: int) -> Callable[[object, object, object], SizeResult]:
    def read(_path: object, _session: object, _agent: object) -> SizeResult:
        return Measured(tokens)

    return read


def check(
    payload: dict[str, object],
    tokens: int = PAST,
    config: Config | None = None,
) -> handoff.Outcome:
    agent = str(payload["agent_type"])
    return handoff.check(payload, agent, config or Config(), REPO_ROOT, sized(tokens))


def assert_refused(outcome: handoff.Outcome) -> None:
    assert outcome.step is handoff.Step.REFUSE and outcome.text, outcome
    assert outcome.text.count("Next:") == 1, outcome.text
