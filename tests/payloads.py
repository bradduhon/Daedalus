# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# W1.4: the hook payload builders the jail test modules share; one copy per payload shape.
from __future__ import annotations

from pathlib import Path
from typing import Any

from tests.conftest import CWD


def _w(agent: str | None, path: str, tool: str = "Write") -> dict[str, Any]:
    payload: dict[str, Any] = {"tool_name": tool, "tool_input": {"file_path": path}, "cwd": CWD}
    if agent:
        payload["agent_type"] = agent
    return payload


def _b(agent: str | None, command: str) -> dict[str, Any]:
    payload: dict[str, Any] = {"tool_name": "Bash", "tool_input": {"command": command}, "cwd": CWD}
    if agent:
        payload["agent_type"] = agent
    return payload


def _t(agent: str, tool: str) -> dict[str, Any]:
    return {"tool_name": tool, "tool_input": {}, "cwd": CWD, "agent_type": agent}


def _wr(cwd: Path, path: Path, tool: str = "Write") -> dict[str, Any]:
    payload = _w("charter-docs", str(path), tool)
    payload["cwd"] = str(cwd)
    return payload


def _cwd(payload: dict[str, Any], cwd: Path) -> dict[str, Any]:
    payload["cwd"] = str(cwd)
    payload.setdefault("session_id", "s")
    return payload


def _cred(agent: str | None, tool: str, cwd: str = CWD, **tool_input: str) -> dict[str, Any]:
    payload: dict[str, Any] = {"tool_name": tool, "tool_input": tool_input, "cwd": cwd}
    if agent:
        payload["agent_type"] = agent
    return payload
