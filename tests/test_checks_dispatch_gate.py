# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# spec 4, pin C2 -> C5: the dispatch gate admits no model field or one of the four models.
from __future__ import annotations

import pytest
from lib.agent_models import MODELS

from tests.conftest import CWD
from tests.hook_chain import evaluate, load
from tests.test_orchestrator import _call, _start


def _with_model(model: object) -> dict[str, object]:
    payload = _start(CWD, "daedalus:web-researcher")
    tool_input = payload["tool_input"]
    assert isinstance(tool_input, dict)
    tool_input["model"] = model
    return payload


def test_a_start_without_a_model_field_is_admitted() -> None:
    assert evaluate("dispatch_gate", _start(CWD, "daedalus:web-researcher")) is None


@pytest.mark.parametrize("model", MODELS)
def test_each_of_the_four_models_is_admitted(model: str) -> None:
    assert evaluate("dispatch_gate", _with_model(model)) is None


@pytest.mark.parametrize("model", ["gpt-4", "Opus", "inherit", "", None, 3, ["opus"]])
def test_a_model_outside_the_four_is_refused(model: object) -> None:
    gate = load("dispatch_gate")
    reason = evaluate("dispatch_gate", _with_model(model))
    assert reason == gate.R_MODEL
    assert "sonnet, opus, haiku, fable" in reason and "Next:" in reason


def test_a_foreign_agent_is_refused_before_its_model() -> None:
    gate = load("dispatch_gate")
    payload = _call("Agent", CWD, subagent_type="general-purpose", prompt="x", model="bogus")
    assert evaluate("dispatch_gate", payload) == gate.R_FOREIGN_AGENT


def test_a_resume_carries_no_model_check() -> None:
    payload = _call("SendMessage", CWD, to="a1", message="go", model="bogus")
    assert evaluate("dispatch_gate", payload) is None
