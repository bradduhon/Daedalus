# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0044, 0039: each agent file's hooks block agrees with its shape, its tools and the hook scripts.
from __future__ import annotations

import json
import re

import pytest
from lib import agent_files, gh_policy, hook_io
from lib.agent_files import AgentFile, Hook

from tests.conftest import REPO_ROOT, SCRIPTS_DIR
from tests.hook_chain import CHAINS, load

AGENTS = REPO_ROOT / "agents"
CHECKS = SCRIPTS_DIR / "checks"
SHAPES: dict[str, list[str | list[str]]] = json.loads(
    (CHECKS / "shapes.json").read_text(encoding="utf-8")
)
LOADED: dict[str, AgentFile] = agent_files.load_all(AGENTS)
# 0044: flags that grant rather than narrow, and the one shape that may carry each.
WIDENING = {"--web": "finder", "--gh": "mover", "--conductor": "mover"}


def _flag_map(flags: tuple[str, ...]) -> dict[str, set[str]]:
    out: dict[str, set[str]] = {}
    option = ""
    for token in flags:
        if token.startswith("--"):
            option, _, value = token.partition("=")
            out[option] = set(value.split(",")) if value else set()
        else:
            out[option] |= set(token.split(","))
    return out


def _entry(text: str) -> Hook:
    script, *flags = text.split()
    return Hook(script, tuple(flags))


def _applies(script: str, agent: AgentFile) -> bool:
    tools: frozenset[str] = load(script).TOOLS
    return tools == hook_io.EVERY_TOOL or bool(tools & agent.tools)


def _carried(agent: AgentFile, want: Hook) -> bool:
    for hook in agent.hooks:
        if hook.script != want.script:
            continue
        have = _flag_map(hook.flags)
        if all(o in have and v <= have[o] for o, v in _flag_map(want.flags).items()):
            return True
    return False


def _shape_scripts(shape: str) -> set[str]:
    flat: list[str] = []
    for entry in SHAPES[shape]:
        flat += entry if isinstance(entry, list) else [entry]
    return {_entry(text).script for text in flat}


def test_every_agent_has_shape_and_hooks() -> None:
    assert set(LOADED) == {p.stem for p in AGENTS.glob("*.md")}
    for name, agent in LOADED.items():
        assert agent.shape in SHAPES, name
        assert agent.hooks, name
        assert len({hook.script for hook in agent.hooks}) == len(agent.hooks), name


ROUTER_COMMENT = (
    "# 0044: run by the Daedalus router; Claude Code ignores hooks on plugin agents "
    "(sub-agents.md:239)."
)


def test_every_hooks_block_carries_the_router_comment() -> None:
    paths = sorted(AGENTS.glob("*.md"))
    assert {p.stem for p in paths} == set(LOADED)
    for path in paths:
        lines = path.read_text(encoding="utf-8").splitlines()
        assert lines.count("hooks:") == 1, path.name
        assert lines[lines.index("hooks:") - 1] == ROUTER_COMMENT, path.name


def test_every_named_hook_is_a_shipped_script() -> None:
    for name, agent in LOADED.items():
        for hook in agent.hooks:
            assert (CHECKS / f"{hook.script}.py").is_file(), (name, hook.script)


def test_every_hook_script_is_named_by_a_shape_list_or_an_agent() -> None:
    named = {hook.script for agent in LOADED.values() for hook in agent.hooks}
    for shape in SHAPES:
        named |= _shape_scripts(shape)
    shipped = {p.stem for p in CHECKS.glob("*.py")}
    assert shipped
    assert shipped - named == set()


def test_hook_tools_intersect_agent_tools() -> None:
    # 0039: a hook for a tool the agent's frontmatter does not grant is a dead hook.
    for name, agent in LOADED.items():
        for hook in agent.hooks:
            assert _applies(hook.script, agent), (name, hook.script)


def test_agent_carries_every_applicable_hook_of_its_shape() -> None:
    # 0044: one-of groups pick exactly one member; extra hooks outside the list only narrow.
    for name, agent in LOADED.items():
        for entry in SHAPES[agent.shape]:
            if isinstance(entry, list):
                members = [_entry(text) for text in entry]
                if any(_applies(m.script, agent) for m in members):
                    assert sum(_carried(agent, m) for m in members) == 1, (name, entry)
            elif _applies(_entry(entry).script, agent):
                assert _carried(agent, _entry(entry)), (name, entry)
        extra = [h for h in agent.hooks if h.script not in _shape_scripts(agent.shape)]
        for hook in extra:
            assert not set(_flag_map(hook.flags)) & set(WIDENING), (name, hook)


def test_flags_are_declared_by_the_hook() -> None:
    for name, agent in LOADED.items():
        for hook in agent.hooks:
            module = load(hook.script)
            parsed = hook_io._parse(list(hook.flags), module.PARSER)
            assert not isinstance(parsed, str), (name, hook, parsed)


def test_only_a_finder_may_carry_web() -> None:
    carriers = {n for n, a in LOADED.items() for h in a.hooks if "--web" in _flag_map(h.flags)}
    assert carriers == {"web-researcher"}
    for name, agent in LOADED.items():
        for hook in agent.hooks:
            for flag in set(_flag_map(hook.flags)) & set(WIDENING):
                assert agent.shape == WIDENING[flag], (name, hook)


def test_only_a_producer_writes_and_only_a_finder_fetches() -> None:
    # 0044: the shape, not a hand list, says which agents may write files or reach the web.
    # spec 3.1: a shaper writes too; its shape list binds it to root_writes --touch scratch.
    for name, agent in LOADED.items():
        if agent.shape not in {"producer", "shaper"}:
            assert not agent.tools & {"Write", "Edit", "MultiEdit", "NotebookEdit"}, name
        if agent.shape != "finder":
            assert not agent.tools & {"WebFetch", "WebSearch"}, name


def test_agent_files_match_the_parity_chains() -> None:
    # 0044: tests/hook_chain.py is the data the parity test runs; it equals the agent files.
    got = {n: tuple((h.script, h.flags) for h in a.hooks) for n, a in LOADED.items()}
    assert got == CHAINS


CONDUCTOR = AGENTS / "pr-train-conductor.md"
_GH = re.compile(r"`gh ([a-z]+) ([a-z]+)`")


def test_conductor_gh_text_matches_the_built_set() -> None:
    text = " ".join(CONDUCTOR.read_text(encoding="utf-8").split())
    allowed = text.split("The hook allows only ", 1)[1].split("`. ", 1)[0] + "`"
    assert set(_GH.findall(allowed)) == gh_policy.CONDUCTOR_GH
    named = set(_GH.findall(text))
    assert named - gh_policy.CONDUCTOR_GH == {("pr", "merge"), ("pr", "close")}
    assert "`gh pr merge` and `gh pr close` are refused" in text
    for drift in ("gh pr status", "gh pr comment", "gh pr diff"):
        assert drift not in text, drift


@pytest.mark.parametrize("shape", sorted(SHAPES))
def test_shape_entries_name_declared_flags(shape: str) -> None:
    # 0044: a shape list's minimum flags parse under the hook's own FLAGS.
    flat: list[str] = []
    for entry in SHAPES[shape]:
        flat += entry if isinstance(entry, list) else [entry]
    for text in flat:
        hook = _entry(text)
        parsed = hook_io._parse(list(hook.flags), load(hook.script).PARSER)
        assert not isinstance(parsed, str), (shape, text, parsed)
