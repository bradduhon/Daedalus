# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# line 70: the mutation operators over one corpus command. Each operator is a pure function from a
# command text to its mutants; it reads shparse.parse and splices at a parsed span, so every
# mutant names the one word, separator or command it changed. No regex reads the raw text.
from __future__ import annotations

import shlex
from collections.abc import Callable, Iterator
from dataclasses import dataclass

from lib import shparse
from lib.shparse import Command, Literal, Script, Word

Span = tuple[int, int]
# line 70: the probe command an append operator adds; every read-only table admits it bare.
PROBE = "ls"
# line 70: the file a write redirect names, relative to the row's folder.
WRITE_FILE = "mutant.out"
# line 70: tools whose first non-option word is a subcommand, never the first operand.
SUBCOMMAND_TOOLS = frozenset(
    {"git", "gh", "npm", "npx", "yarn", "pnpm", "terraform", "cargo", "go", "uv", "pip", "pip3"}
)


@dataclass(frozen=True)
class Mutant:
    operator: str
    target: str
    text: str
    # line 70: "same" keeps the record; "append" adds one trailing PROBE; "write" and "null"
    # add WRITE_FILE or /dev/null to the writes where the role types a redirect as a write.
    effect: str = "same"
    # line 70: the new spelling a word operator wrote in place of the word.
    word: str = ""


@dataclass(frozen=True)
class Operator:
    name: str
    probes: str
    mutate: Callable[[str], list[Mutant]]


def _q(text: str) -> str:
    return shlex.quote(text) if text else ""


def _splice(text: str, span: Span, new: str) -> str:
    return text[: span[0]] + new + text[span[1] :]


def _commands(script: Script) -> Iterator[Command]:
    for cmd, _ in shparse.walk(script):
        yield cmd


def _words(text: str) -> Iterator[tuple[int, Word, str]]:
    # line 70: every bare word of every command; respelling a quoted word could unhide it.
    for cmd in _commands(shparse.parse(text)):
        for i, word in enumerate(cmd.words):
            bare = all(isinstance(p, Literal) and p.quoted == "" for p in word.parts)
            lit = word.literal
            if bare and lit and lit == word.raw:
                yield i, word, lit


def _label(i: int, word: Word) -> str:
    return f"word {i} {word.raw!r}"


def _per_word(name: str, build: Callable[[int, str], list[str]]) -> Callable[[str], list[Mutant]]:
    def mutate(text: str) -> list[Mutant]:
        out: list[Mutant] = []
        for i, word, lit in _words(text):
            for new in build(i, lit):
                mutant = _splice(text, word.span, new)
                out.append(Mutant(name, _label(i, word), mutant, word=new))
        return out

    return mutate


def _single(_: int, lit: str) -> list[str]:
    return [f"'{lit}'"] if "'" not in lit else []


def _double(_: int, lit: str) -> list[str]:
    return [f'"{lit}"'] if not set(lit) & set('"$`\\!') else []


def _split(_: int, lit: str) -> list[str]:
    return [_q(lit[:1]) + "''" + _q(lit[1:])] if len(lit) > 1 else []


def _escape(_: int, lit: str) -> list[str]:
    k = 1 if len(lit) > 1 else 0
    if not lit or lit[k] in "\n'":
        return []
    return [_q(lit[:k]) + "\\" + lit[k] + _q(lit[k + 1 :])]


def _empty_param(_: int, lit: str) -> list[str]:
    if not lit:
        return []
    return [_q(lit[:1]) + "${X}" + _q(lit[1:]), _q(lit) + "$X"]


def _brace(_: int, lit: str) -> list[str]:
    return ["{" + _q(lit) + ",}"] if lit else []


def _path_operand(i: int, lit: str) -> bool:
    return i > 0 and "/" in lit and not lit.startswith("-")


def _tilde(i: int, lit: str) -> list[str]:
    return ["~" + _q(lit)] if _path_operand(i, lit) else []


def _glob(i: int, lit: str) -> list[str]:
    return [_q(lit[:-1]) + "?"] if _path_operand(i, lit) and len(lit) > 1 else []


def _option_case(i: int, lit: str) -> list[str]:
    if i == 0 or not lit.startswith("-") or lit == "--":
        return []
    body = lit.lstrip("-")
    flipped = body.swapcase()
    return [_q(lit[: len(lit) - len(body)] + flipped)] if flipped != body else []


def _tab(text: str) -> list[Mutant]:
    # line 70: one blank between two words of one command becomes a tab.
    out: list[Mutant] = []
    for cmd in _commands(shparse.parse(text)):
        for i in range(1, len(cmd.words)):
            gap = (cmd.words[i - 1].span[1], cmd.words[i].span[0])
            at = text.find(" ", gap[0], gap[1])
            if at >= 0:
                new = _splice(text, (at, at + 1), "\t")
                out.append(Mutant("tab_for_space", f"blank before word {i}", new))
    return out


def _separators(text: str) -> Iterator[tuple[int, str, Span]]:
    for node in shparse.nodes(shparse.parse(text)):
        if not isinstance(node, Script):
            continue
        for i in range(len(node.items) - 1):
            sep = node.separators[i]
            if sep not in (";", "&&"):
                continue
            lo, hi = node.items[i].span[1], node.items[i + 1].span[0]
            at = text.find(sep, lo, hi)
            if at >= 0:
                yield i, sep, (at, at + len(sep))


def _sep_to(name: str, new: str) -> Callable[[str], list[Mutant]]:
    def mutate(text: str) -> list[Mutant]:
        return [
            Mutant(name, f"separator {i} {sep!r}", _splice(text, span, new))
            for i, sep, span in _separators(text)
        ]

    return mutate


def _wrapper(name: str) -> Callable[[str], list[Mutant]]:
    def mutate(text: str) -> list[Mutant]:
        out: list[Mutant] = []
        for n, cmd in enumerate(_commands(shparse.parse(text))):
            if cmd.words:
                at = cmd.words[0].span[0]
                new = _splice(text, (at, at), f"{name} ")
                out.append(Mutant(f"wrapper_{name}", f"command {n} {cmd.words[0].raw!r}", new))
        return out

    return mutate


def _double_dash(text: str) -> list[Mutant]:
    # line 70: `--` before the first operand, only where no option follows it: a no-op for getopt.
    out: list[Mutant] = []
    for n, cmd in enumerate(_commands(shparse.parse(text))):
        raws = [w.literal for w in cmd.words]
        if not raws or raws[0] is None or "--" in raws:
            continue
        skip = 1 if raws[0] in SUBCOMMAND_TOOLS else 0
        for i in range(1, len(raws)):
            lit, prev = raws[i], raws[i - 1]
            if lit is None or lit.startswith("-"):
                continue
            if prev is not None and prev.startswith("-") and "=" not in prev and i > 1:
                continue
            if skip:
                skip -= 1
                continue
            if any(r is None or r.startswith("-") for r in raws[i + 1 :]):
                break
            at = cmd.words[i].span[0]
            new = _splice(text, (at, at), "-- ")
            out.append(Mutant("double_dash", f"command {n} before word {i}", new))
            break
    return out


def _heredoc(text: str) -> bool:
    return bool(shparse.heredocs(shparse.parse(text)))


def _append(text: str) -> list[Mutant]:
    # line 70: a heredoc's delimiter line takes no `;`, so its rows append on a new line.
    sep = "\n" if _heredoc(text) or text.rstrip().endswith("&") else " ; "
    return [Mutant("append_command", "end of script", f"{text}{sep}{PROBE}", "append")]


def _subshell(text: str) -> list[Mutant]:
    return [Mutant("subshell", "whole script", f"( {text}\n)")]


def _brace_group(text: str) -> list[Mutant]:
    return [Mutant("brace_group", "whole script", "{ " + text + "\n}")]


def _bash_c(text: str) -> list[Mutant]:
    return [Mutant("bash_c", "whole script", f"bash -c {shlex.quote(text)}")]


def _redirect(name: str, target: str, effect: str) -> Callable[[str], list[Mutant]]:
    def mutate(text: str) -> list[Mutant]:
        out: list[Mutant] = []
        for n, cmd in enumerate(_commands(shparse.parse(text))):
            if cmd.words:
                at = max(w.span[1] for w in cmd.words)
                new = _splice(text, (at, at), f" >{target}")
                out.append(Mutant(name, f"command {n} {cmd.words[0].raw!r}", new, effect))
        return out

    return mutate


OPERATORS: tuple[Operator, ...] = (
    Operator("quote_single", "SS-4 quoting", _per_word("quote_single", _single)),
    Operator("quote_double", "SS-4 quoting", _per_word("quote_double", _double)),
    Operator("split_quote", "SS-4 quoting", _per_word("split_quote", _split)),
    Operator("backslash_escape", "SS-4 quoting", _per_word("backslash_escape", _escape)),
    Operator("tab_for_space", "SS-6 word splitting", _tab),
    Operator("separator_newline", "SS-6 separators", _sep_to("separator_newline", "\n")),
    Operator("separator_or", "SS-6 separators", _sep_to("separator_or", "||")),
    Operator("empty_parameter", "SS-4 expansion", _per_word("empty_parameter", _empty_param)),
    Operator("brace_list", "SS-4 brace form", _per_word("brace_list", _brace)),
    Operator("tilde_prefix", "SS-4 tilde", _per_word("tilde_prefix", _tilde)),
    Operator("glob_char", "SS-4 glob", _per_word("glob_char", _glob)),
    Operator("wrapper_env", "SS-2 lookup through a wrapper", _wrapper("env")),
    Operator("wrapper_command", "SS-2 lookup through a wrapper", _wrapper("command")),
    Operator("wrapper_nice", "SS-2 lookup through a wrapper", _wrapper("nice")),
    Operator("double_dash", "SS-5 end of options", _double_dash),
    Operator("append_command", "SS-6 separators", _append),
    Operator("subshell", "SS-3 grouped body", _subshell),
    Operator("brace_group", "SS-3 grouped body", _brace_group),
    Operator("bash_c", "SS-3 command string body", _bash_c),
    Operator("redirect_null", "redirect target", _redirect("redirect_null", "/dev/null", "null")),
    Operator("redirect_file", "redirect target", _redirect("redirect_file", WRITE_FILE, "write")),
    Operator("option_case", "SS-5 option spelling", _per_word("option_case", _option_case)),
)
BY_NAME: dict[str, Operator] = {op.name: op for op in OPERATORS}
