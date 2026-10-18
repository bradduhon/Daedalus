# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0044: reads agents/<name>.md; the frontmatter reader and the hooks-block parser.
# load accepts one YAML subset (packet section 7.1) and refuses everything else.
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

# 0044: an agent name outside this form reads as a missing agent file.
AGENT_NAME = re.compile(r"[a-z0-9][a-z0-9-]*")
_KEY = re.compile(r"[A-Za-z][A-Za-z0-9_]*")
_TOP_KEYS = ("name", "description", "tools", "disallowedTools", "model", "shape", "hooks")
_REQUIRED = ("name", "description", "tools", "model")
_TOOL = re.compile(r"[A-Za-z][A-Za-z0-9_]*")
# 0044: YAML indicators a plain scalar may not start with (anchors, aliases, tags, blocks, flows).
_INDICATORS = frozenset("&*!|>{}[]\"'%@`#,?:-")
_EVENT = "  PreToolUse:"
_ITEM = "    - hooks:"
_ENTRY = re.compile(r'        - \{type: command, command: "([^"\\]*)"\}')
_COMMAND = re.compile(
    r"python3 \$\{CLAUDE_PLUGIN_ROOT\}/scripts/checks/([a-z][a-z_]*)\.py"
    r"((?: (?:--[a-z][a-z-]*|[A-Za-z0-9][A-Za-z0-9_.,-]*))*)"
)
_CHECKS = Path(__file__).resolve().parents[1] / "checks"
_STATUS_HEADING = "## Status contract"
_BACKTICKED = re.compile(r"`([^`]+)`")


class AgentFileError(ValueError):
    pass


@dataclass(frozen=True)
class Hook:
    script: str
    flags: tuple[str, ...]


@dataclass(frozen=True)
class AgentFile:
    name: str
    shape: str
    tools: frozenset[str]
    model: str
    hooks: tuple[Hook, ...]
    status_lines: tuple[str, ...]


def _lines(path: Path) -> tuple[list[str], int]:
    # 0044: the file's lines and the index of the --- line that closes the frontmatter.
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError) as exc:
        raise AgentFileError(
            f"{path} could not be read ({exc}). Next: restore the agent file from git."
        ) from exc
    if not lines or lines[0] != "---":
        raise AgentFileError(f"{path} has no frontmatter. Next: start the file with a --- line.")
    if "---" not in lines[1:]:
        raise AgentFileError(
            f"{path} frontmatter never closes. Next: end the frontmatter with a --- line."
        )
    return lines, lines.index("---", 1)


def _pair(path: Path, line: str) -> tuple[str, str]:
    key, sep, value = line.partition(":")
    if not sep or not _KEY.fullmatch(key):
        raise AgentFileError(
            f"{path} frontmatter line {line!r} is not `key: value`. "
            "Next: write each top-level field as key: value."
        )
    return key, value.strip()


def frontmatter(path: Path) -> dict[str, str]:
    # 0044: top-level `key: value` lines only; nested, comment and list lines are skipped.
    lines, end = _lines(path)
    out: dict[str, str] = {}
    for line in lines[1:end]:
        if not line.strip() or line[0] in " \t#-":
            continue
        key, value = _pair(path, line)
        out[key] = value
    return out


def _refuse(path: Path, line: str, why: str) -> AgentFileError:
    return AgentFileError(
        f"{path} frontmatter line {line!r} {why}. "
        "Next: use only the hooks block form of spec 5.4 and plain `key: value` fields."
    )


def _hook(path: Path, line: str) -> Hook:
    entry = _ENTRY.fullmatch(line)
    if entry is None:
        raise _refuse(path, line, 'is not a `{type: command, command: "..."}` entry')
    command = _COMMAND.fullmatch(entry.group(1))
    if command is None or ".." in entry.group(1):
        raise _refuse(
            path, line, "runs something other than python3 ${CLAUDE_PLUGIN_ROOT}/scripts/checks"
        )
    script = command.group(1)
    if not (_CHECKS / f"{script}.py").is_file():
        raise _refuse(path, line, f"names {script}, which is not a shipped hook script")
    return Hook(script, tuple(command.group(2).split()))


def _hooks(path: Path, block: list[str]) -> tuple[Hook, ...]:
    # 0044: exactly one PreToolUse event holding exactly one `- hooks:` item of entries.
    if block[:2] != [_EVENT, _ITEM]:
        raise _refuse(path, block[0] if block else "hooks:", "does not open the PreToolUse block")
    if len(block) < 3:
        raise _refuse(path, "hooks:", "holds no hook entries")
    return tuple(_hook(path, line) for line in block[2:])


def _scalar(path: Path, line: str, key: str, value: str) -> str:
    if key == "hooks":
        if value:
            raise _refuse(path, line, "carries a value on the hooks key")
        return value
    if not value or value[0] in _INDICATORS:
        raise _refuse(path, line, "is not a plain one-line scalar")
    return value


def _tools(path: Path, key: str, value: str) -> frozenset[str]:
    items = [item.strip() for item in value.split(",")]
    for item in items:
        if not _TOOL.fullmatch(item):
            raise _refuse(path, f"{key}: {value}", f"names {item!r}, which is not a tool name")
    return frozenset(items)


def _status_lines(path: Path, body: list[str]) -> tuple[str, ...]:
    if _STATUS_HEADING not in body:
        return ()
    out: list[str] = []
    for line in body[body.index(_STATUS_HEADING) + 1 :]:
        if line.startswith("## "):
            break
        if not line.startswith("- "):
            continue
        found = _BACKTICKED.search(line)
        if found is None:
            raise AgentFileError(
                f"{path} status contract line {line!r} has no backticked text. "
                "Next: write each status line as - `<line>`."
            )
        out.append(found.group(1))
    return tuple(out)


def load(path: Path) -> AgentFile:
    lines, end = _lines(path)
    fields: dict[str, str] = {}
    block: list[str] = []
    in_block = False
    for line in lines[1:end]:
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if line[0] in " \t":
            if not in_block:
                raise _refuse(path, line, "is indented outside the hooks block")
            block.append(line)
            continue
        key, value = _pair(path, line)
        if key not in _TOP_KEYS or key in fields:
            raise _refuse(path, line, "is an unknown or repeated key")
        fields[key] = _scalar(path, line, key, value)
        in_block = key == "hooks"
    missing = [key for key in _REQUIRED if key not in fields]
    if missing:
        raise AgentFileError(
            f"{path} frontmatter lacks {', '.join(missing)}. Next: add the missing fields."
        )
    if fields["name"] != path.stem:
        raise _refuse(path, f"name: {fields['name']}", f"differs from the file name {path.stem}")
    hooks = _hooks(path, block) if "hooks" in fields else ()
    if "disallowedTools" in fields:
        _tools(path, "disallowedTools", fields["disallowedTools"])
    return AgentFile(
        name=fields["name"],
        shape=fields.get("shape", ""),
        tools=_tools(path, "tools", fields["tools"]),
        model=fields["model"],
        hooks=hooks,
        status_lines=_status_lines(path, lines[end + 1 :]),
    )


def load_all(agents_dir: Path) -> dict[str, AgentFile]:
    return {path.stem: load(path) for path in sorted(agents_dir.glob("*.md"))}
