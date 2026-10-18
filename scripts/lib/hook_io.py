# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0044: hook input and output for the scripts under scripts/checks, and the order of judgement.
# Standard library plus lib.config only; any failure on the path to a decision denies.
from __future__ import annotations

import argparse
import json
import re
import sys
import traceback
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import NoReturn

from lib.config import Config, load_config

EVERY_TOOL: frozenset[str] = frozenset({"*"})


@dataclass(frozen=True)
class Flag:
    values: frozenset[str] = frozenset()  # empty: a boolean flag
    many: bool = False  # the value is a comma list, each item in values
    pattern: str | None = None  # a free value that must fullmatch this regex


Judge = Callable[[dict[str, object], argparse.Namespace], str | None]


class _FlagError(ValueError):
    pass


class _HookParser(argparse.ArgumentParser):
    # 0044: carries the FLAGS it was built from; parse errors raise, never print or exit.
    def __init__(self, name: str, flags: Mapping[str, Flag]) -> None:
        super().__init__(prog=name, add_help=False, allow_abbrev=False, exit_on_error=False)
        self.hook_flags: dict[str, Flag] = dict(flags)

    def error(self, message: str) -> NoReturn:
        raise _FlagError(message)

    def exit(self, status: int = 0, message: str | None = None) -> NoReturn:
        raise _FlagError(message or f"exit {status}")


def read_input() -> dict[str, object]:
    # 0044: empty, malformed or non-object stdin reads as {}, which evaluate denies.
    try:
        payload = json.loads(sys.stdin.read())
    except Exception:  # noqa: BLE001
        return {}
    return payload if isinstance(payload, dict) else {}


def emit(reason: str | None) -> int:
    decision = "allow" if reason is None else "deny"
    out = {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": decision,
            "permissionDecisionReason": reason or "",
        }
    }
    print(json.dumps(out))
    return 0


def build_parser(name: str, flags: Mapping[str, Flag]) -> argparse.ArgumentParser:
    parser = _HookParser(name, flags)
    for option, flag in flags.items():
        if not flag.values and flag.pattern is None:
            parser.add_argument(option, action="store_true")
        elif flag.many:
            parser.add_argument(option, type=lambda v: tuple(v.split(",")))
        else:
            parser.add_argument(option)
    return parser


def failed_closed(name: str, cause: BaseException | str) -> str:
    if isinstance(cause, BaseException):
        cause = "".join(traceback.format_exception_only(cause)).strip()
    return f"hook {name} failed closed ({cause})"


def hook_config(cwd: str) -> Config:
    # 0044: the one name hooks read the project config through; a bad file raises.
    return load_config(cwd)


def _value_error(option: str, flag: Flag, value: str) -> str | None:
    items = value.split(",") if flag.many else [value]
    for item in items:
        if flag.values and item not in flag.values:
            allowed = ", ".join(sorted(flag.values))
            return f"flag {option} value {item} is not one of {allowed}"
        if flag.pattern is not None and not re.fullmatch(flag.pattern, item):
            return f"flag {option} value {item} does not match {flag.pattern}"
    return None


def _flag_tokens(argv: list[str], flags: Mapping[str, Flag]) -> list[str] | str:
    # 0044: an allowlist pass before argparse; returns --opt=value tokens or the deny cause.
    seen: set[str] = set()
    tokens: list[str] = []
    i = 0
    while i < len(argv):
        token = argv[i]
        if not token.startswith("--"):
            return f"unexpected argument {token}"
        option, eq, value = token.partition("=")
        flag = flags.get(option)
        if flag is None:
            return f"unknown flag {token}"
        if option in seen:
            return f"flag {option} is given twice"
        seen.add(option)
        i += 1
        if not flag.values and flag.pattern is None:
            if eq:
                return f"flag {option} takes no value"
            tokens.append(option)
            continue
        if not eq:
            if i >= len(argv) or argv[i].startswith("--"):
                return f"flag {option} needs a value"
            value = argv[i]
            i += 1
        error = _value_error(option, flag, value)
        if error is not None:
            return error
        tokens.append(f"{option}={value}")
    return tokens


def _parse(argv: list[str], parser: argparse.ArgumentParser) -> argparse.Namespace | str:
    if not isinstance(parser, _HookParser):
        return "parser was not built by hook_io.build_parser"
    tokens = _flag_tokens(argv, parser.hook_flags)
    return tokens if isinstance(tokens, str) else parser.parse_args(tokens)


def evaluate(
    hook_input: dict[str, object],
    argv: list[str],
    judge: Judge,
    tools: frozenset[str],
    parser: argparse.ArgumentParser,
) -> str | None:
    # 0044: tool_name, then flags, then the tool filter, then tool_input, then the judge.
    name = parser.prog
    tool = hook_input.get("tool_name")
    if not isinstance(tool, str) or not tool:
        return failed_closed(name, "hook input has no tool_name")
    try:
        flags = _parse(argv, parser)
    except Exception as exc:  # noqa: BLE001
        return failed_closed(name, exc)
    if isinstance(flags, str):
        return failed_closed(name, flags)
    if tools != EVERY_TOOL and tool not in tools:
        return None
    if "tool_input" in hook_input and not isinstance(hook_input["tool_input"], dict):
        return failed_closed(name, "tool_input is not an object")
    try:
        return judge(hook_input, flags)
    except Exception as exc:  # noqa: BLE001
        return failed_closed(name, exc)


def run(judge: Judge, tools: frozenset[str], parser: argparse.ArgumentParser) -> int:
    try:
        return emit(evaluate(read_input(), sys.argv[1:], judge, tools, parser))
    except Exception as exc:  # noqa: BLE001
        return emit(failed_closed(parser.prog, exc))


# 0044: field readers every judge shares; evaluate has already refused a non-object tool_input.
def tool_input(hook_input: dict[str, object]) -> dict[str, object]:
    value = hook_input.get("tool_input")
    return value if isinstance(value, dict) else {}


def text(mapping: dict[str, object], key: str) -> str:
    return str(mapping.get(key) or "")


def write_path(hook_input: dict[str, object]) -> str:
    fields = tool_input(hook_input)
    return text(fields, "file_path") or text(fields, "notebook_path")
