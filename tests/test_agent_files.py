# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0044: the agent-file parser reads the accepted YAML subset and refuses everything else.
from __future__ import annotations

import re
from pathlib import Path

import pytest
from lib import agent_files
from lib.agent_files import AgentFileError, Hook

from tests.conftest import REPO_ROOT

AGENTS = REPO_ROOT / "agents"
ENTRY = '        - {type: command, command: "python3 ${CLAUDE_PLUGIN_ROOT}/scripts/checks/%s"}'
HEAD = [
    "---",
    "name: probe",
    "description: A probe agent.",
    "tools: Read, Bash",
    "disallowedTools: Agent, Task, SendMessage",
    "model: sonnet",
    "shape: judge",
]
BLOCK = ["hooks:", "  PreToolUse:", "    - hooks:", ENTRY % "credential_paths.py"]
BODY = ["---", "Body.", "", "## Status contract", "- `[STATUS: DONE] <x>`", ""]


def _write(tmp_path: Path, lines: list[str]) -> Path:
    path = tmp_path / "probe.md"
    path.write_text("\n".join(lines), encoding="utf-8")
    return path


def test_parser_reads_every_agent_file() -> None:
    loaded = agent_files.load_all(AGENTS)
    assert set(loaded) == {p.stem for p in AGENTS.glob("*.md")}
    for name, agent in loaded.items():
        assert agent.name == name
        assert agent.shape
        assert agent.model
        assert agent.tools
        assert agent.hooks
        assert all(isinstance(hook, Hook) for hook in agent.hooks)
    coder = loaded["repo-coder"]
    assert coder.tools == frozenset({"Read", "Write", "Edit", "Bash", "Glob", "Grep"})
    assert coder.hooks[0] == Hook("credential_paths", ())
    assert Hook("git_grammar", ("--allow", "coder")) in coder.hooks


def test_parser_accepts_comments_and_a_file_without_hooks(tmp_path: Path) -> None:
    comment = "# 0044: a full-line comment anywhere in the frontmatter is ignored."
    lines = [*HEAD, comment, *BLOCK[:3], "      # nested comment", *BLOCK[3:], *BODY]
    agent = agent_files.load(_write(tmp_path, lines))
    assert agent.hooks == (Hook("credential_paths", ()),)
    assert agent_files.load(_write(tmp_path, [*HEAD, *BODY])).hooks == ()


UNSUPPORTED = {
    "anchor": [*HEAD[:-1], "shape: &s judge", *BLOCK],
    "alias": [*HEAD[:-1], "shape: *s", *BLOCK],
    "tag": [*HEAD[:-1], "shape: !!str judge", *BLOCK],
    "anchor on hooks": [*HEAD, "hooks: &h", *BLOCK[1:]],
    "block scalar literal": [*HEAD[:2], "description: |", "  text", *HEAD[3:], *BLOCK],
    "block scalar folded": [*HEAD[:2], "description: >", "  text", *HEAD[3:], *BLOCK],
    "second event": [*HEAD, *BLOCK, "  PostToolUse:", "    - hooks:", ENTRY % "tool_bound.py"],
    "second entry": [*HEAD, *BLOCK, "    - hooks:", ENTRY % "tool_bound.py"],
    "matcher key": [*HEAD, *BLOCK[:3], "      matcher: Bash", *BLOCK[3:]],
    "timeout key": [
        *HEAD,
        *BLOCK[:3],
        '        - {type: command, command: "python3 ${CLAUDE_PLUGIN_ROOT}/scripts/checks/'
        'tool_bound.py", timeout: 5}',
    ],
    "unknown key in mapping": [
        *HEAD,
        *BLOCK[:3],
        '        - {type: command, command: "python3 ${CLAUDE_PLUGIN_ROOT}/scripts/checks/'
        'tool_bound.py", if: x}',
    ],
    "unknown top-level key": [*HEAD, "memory: user", *BLOCK],
    "duplicate key": [*HEAD, "shape: mover", *BLOCK],
    "wrong indentation": [*HEAD, "hooks:", "   PreToolUse:", "    - hooks:", BLOCK[3]],
    "tab indentation": [*HEAD, "hooks:", "\tPreToolUse:", "    - hooks:", BLOCK[3]],
    "empty block": [*HEAD, "hooks:", "  PreToolUse:", "    - hooks:"],
    "type not command": [
        *HEAD,
        *BLOCK[:3],
        '        - {type: prompt, command: "python3 ${CLAUDE_PLUGIN_ROOT}/scripts/checks/'
        'tool_bound.py"}',
    ],
    "escape in command": [*HEAD, *BLOCK[:3], ENTRY % 'tool_bound.py \\" x'],
    "flow list tools": [*HEAD[:3], "tools: [Read, Bash]", *HEAD[4:], *BLOCK],
    "quoted scalar": [*HEAD[:5], 'model: "sonnet"', *HEAD[6:], *BLOCK],
    "indented scalar continuation": [*HEAD, "  more text", *BLOCK],
    "name differs from file": [HEAD[0], "name: other", *HEAD[2:], *BLOCK],
    # 9.1: phases is the one flow list, of known phase tokens, each once.
    "unknown phase": [*HEAD, "phases: [plan, deploy]", *BLOCK],
    "phases not a list": [*HEAD, "phases: plan", *BLOCK],
    "repeated phase": [*HEAD, "phases: [plan, plan]", *BLOCK],
    "empty phases": [*HEAD, "phases: []", *BLOCK],
    "phases without spaces": [*HEAD, "phases: [plan,audit]", *BLOCK],
}


def test_parser_reads_phases(tmp_path: Path) -> None:
    lines = [*HEAD, "phases: [clarification, commit, release]", *BLOCK, *BODY]
    assert agent_files.load(_write(tmp_path, lines)).phases == (
        "clarification",
        "commit",
        "release",
    )
    assert agent_files.load(_write(tmp_path, [*HEAD, *BLOCK, *BODY])).phases == ()
    assert agent_files.PHASES == (
        "context",
        "clarification",
        "plan",
        "implementation",
        "audit",
        "commit",
        "release",
    )


def test_frontmatter_reads_top_level_pairs(tmp_path: Path) -> None:
    # W1.3: nested, comment and list lines are skipped by the shared reader.
    lines = [*HEAD, "# note", "- item", *BLOCK, *BODY]
    fields = agent_files.frontmatter(_write(tmp_path, lines))
    assert fields["model"] == "sonnet" and fields["hooks"] == ""
    assert "PreToolUse" not in fields and "- item" not in fields


FRONTMATTER_DEFECTS = {
    "no frontmatter": ["name: probe", "---"],
    "never closes": ["---", "name: probe"],
    "malformed line": ["---", "name probe", "---"],
}


@pytest.mark.parametrize("case", sorted(FRONTMATTER_DEFECTS))
def test_frontmatter_is_strict_unless_lenient(case: str, tmp_path: Path) -> None:
    # W1.3: the strict reader raises with a Next line; lenient skips the defect instead.
    lines = FRONTMATTER_DEFECTS[case]
    with pytest.raises(AgentFileError, match="Next: "):
        agent_files.frontmatter(_write(tmp_path, lines))
    with pytest.raises(AgentFileError, match="Next: "):
        agent_files.parse_frontmatter(lines, tmp_path / "probe.md")
    assert agent_files.parse_frontmatter(lines, tmp_path / "probe.md", lenient=True) == {}


def test_lenient_frontmatter_keeps_the_good_pairs() -> None:
    lines = ["---", "bad line", "sequence_id: 4", "---"]
    assert agent_files.parse_frontmatter(lines, Path("x.md"), lenient=True) == {"sequence_id": "4"}


@pytest.mark.parametrize("case", sorted(UNSUPPORTED))
def test_parser_refuses_unsupported_yaml(case: str, tmp_path: Path) -> None:
    path = _write(tmp_path, [*UNSUPPORTED[case], *BODY])
    with pytest.raises(AgentFileError, match="Next: "):
        agent_files.load(path)


OUTSIDE_FORM = {
    "another interpreter": "python ${CLAUDE_PLUGIN_ROOT}/scripts/checks/tool_bound.py",
    "bash interpreter": "bash ${CLAUDE_PLUGIN_ROOT}/scripts/checks/tool_bound.py",
    "path outside checks": "python3 ${CLAUDE_PLUGIN_ROOT}/scripts/enforce_agent_jail.py",
    "lib path": "python3 ${CLAUDE_PLUGIN_ROOT}/scripts/lib/jail.py",
    "absolute path": "python3 /tmp/scripts/checks/tool_bound.py",
    "expanded root": "python3 /plugin/scripts/checks/tool_bound.py",
    "dot dot in path": "python3 ${CLAUDE_PLUGIN_ROOT}/scripts/checks/../lib/jail.py",
    "dot dot in flag": "python3 ${CLAUDE_PLUGIN_ROOT}/scripts/checks/root_writes.py --name a..b",
    "semicolon": "python3 ${CLAUDE_PLUGIN_ROOT}/scripts/checks/tool_bound.py; rm x",
    "pipe": "python3 ${CLAUDE_PLUGIN_ROOT}/scripts/checks/tool_bound.py | cat",
    "and chain": "python3 ${CLAUDE_PLUGIN_ROOT}/scripts/checks/tool_bound.py && id",
    "substitution": "python3 ${CLAUDE_PLUGIN_ROOT}/scripts/checks/tool_bound.py $(id)",
    "backtick": "python3 ${CLAUDE_PLUGIN_ROOT}/scripts/checks/tool_bound.py `id`",
    "redirect": "python3 ${CLAUDE_PLUGIN_ROOT}/scripts/checks/tool_bound.py > x",
    "variable flag": "python3 ${CLAUDE_PLUGIN_ROOT}/scripts/checks/tool_bound.py $X",
    "double space": "python3  ${CLAUDE_PLUGIN_ROOT}/scripts/checks/tool_bound.py",
    "trailing space": "python3 ${CLAUDE_PLUGIN_ROOT}/scripts/checks/tool_bound.py ",
    "uppercase name": "python3 ${CLAUDE_PLUGIN_ROOT}/scripts/checks/Tool_bound.py",
    "not shipped": "python3 ${CLAUDE_PLUGIN_ROOT}/scripts/checks/no_such_hook.py",
}


@pytest.mark.parametrize("case", sorted(OUTSIDE_FORM))
def test_parser_refuses_a_command_outside_the_checks_form(case: str, tmp_path: Path) -> None:
    line = f'        - {{type: command, command: "{OUTSIDE_FORM[case]}"}}'
    path = _write(tmp_path, [*HEAD, *BLOCK[:3], line, *BODY])
    with pytest.raises(AgentFileError, match="Next: "):
        agent_files.load(path)


def test_parser_reads_flags_in_the_checks_form(tmp_path: Path) -> None:
    flags = "root_writes.py --touch contracts,charter-specs --ledger-guard"
    agent = agent_files.load(_write(tmp_path, [*HEAD, *BLOCK[:3], ENTRY % flags, *BODY]))
    want = Hook("root_writes", ("--touch", "contracts,charter-specs", "--ledger-guard"))
    assert agent.hooks == (want,)
    # spec 3.1: a --name glob value is one token; quotes stay outside the accepted form.
    glob = agent_files.load(
        _write(tmp_path, [*HEAD, *BLOCK[:3], ENTRY % "root_writes.py --name plan*.md", *BODY])
    )
    assert glob.hooks == (Hook("root_writes", ("--name", "plan*.md")),)
    quoted = [*HEAD, *BLOCK[:3], ENTRY % "root_writes.py --name 'plan*.md'", *BODY]
    with pytest.raises(AgentFileError, match="Next: "):
        agent_files.load(_write(tmp_path, quoted))


@pytest.mark.parametrize("name", sorted(p.stem for p in AGENTS.glob("*.md")))
def test_status_lines_match_the_status_contract_section(name: str) -> None:
    text = (AGENTS / f"{name}.md").read_text(encoding="utf-8")
    section = text.split("\n## Status contract\n", 1)[1].split("\n## ", 1)[0]
    items = [line for line in section.splitlines() if line.startswith("- ")]
    lines = agent_files.load(AGENTS / f"{name}.md").status_lines
    assert len(lines) == len(items) > 0
    for line, item in zip(lines, items, strict=True):
        assert item.startswith(f"- `{line}`")
    if name == "repo-coder":
        assert lines[-1] == (
            "[STATUS: COMPLETE] branch=<b> packet_version=<n> files=<list> "
            "tests=<summary> ledger_notes=<text> contract=<12 hex> standards=<12 hex>"
        )
    assert not any(re.search("`", line) for line in lines)
