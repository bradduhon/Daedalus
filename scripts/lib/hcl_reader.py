# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0212: the stdlib-only Terraform reader finding tests import; regex extraction is banned.
# parse() returns blocks with attributes as source text; policy_statements() reads the
# aws_iam_policy_document statements. Bad input raises HclError naming the line, never a part.
from __future__ import annotations

import bisect
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass

# 0212: one cap on block, bracket and template nesting; deeper input raises HclError.
MAX_DEPTH = 32

IDENT = "ident"
STRING = "string"
HEREDOC = "heredoc"
NUMBER = "number"
PUNCT = "punct"
NEWLINE = "newline"

_PUNCT = frozenset("{}[]()=,.:?*%/+-!<>&|")
_OPEN = {"{": "}", "[": "]", "(": ")"}
_CLOSE = frozenset(_OPEN.values())
_HEREDOC = re.compile(r"<<(-?)([A-Za-z_][A-Za-z0-9_-]*)[ \t]*\r?\n")
_NUMBER = re.compile(r"[0-9]+(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?")
_ESCAPES = {"n": "\n", "r": "\r", "t": "\t", '"': '"', "\\": "\\"}
_HEX = frozenset("0123456789abcdefABCDEF")
_LITERALS = frozenset({"true", "false", "null"})
_POLICY_DOC = "aws_iam_policy_document"


class HclError(ValueError):
    def __init__(self, line: int, message: str) -> None:
        super().__init__(f"line {line}: {message}")
        self.line = line


@dataclass(frozen=True)
class Token:
    kind: str
    start: int
    end: int
    line: int


@dataclass(frozen=True)
class Block:
    type: str
    labels: tuple[str, ...]
    attributes: dict[str, str]
    blocks: tuple[Block, ...]
    line: int
    attribute_lines: dict[str, int]


@dataclass(frozen=True)
class Principal:
    type: str | None
    identifiers: tuple[str, ...]
    dynamic: bool


@dataclass(frozen=True)
class Condition:
    test: str | None
    variable: str | None
    values: tuple[str, ...]
    dynamic: bool


@dataclass(frozen=True)
class Statement:
    document: str
    sid: str | None
    effect: str | None
    actions: tuple[str, ...]
    not_actions: tuple[str, ...]
    resources: tuple[str, ...]
    not_resources: tuple[str, ...]
    principals: tuple[Principal, ...]
    conditions: tuple[Condition, ...]
    dynamic: bool
    line: int


class _Scanner:
    def __init__(self, text: str, first_line: int = 1) -> None:
        self.text = text
        self.first_line = first_line
        self.breaks = [i for i, ch in enumerate(text) if ch == "\n"]

    def line(self, pos: int) -> int:
        return self.first_line + bisect.bisect_left(self.breaks, pos)

    def string_end(self, pos: int, depth: int) -> int:
        # 0212: pos sits on the opening quote; returns the index after the closing quote.
        if depth > MAX_DEPTH:
            raise HclError(self.line(pos), f"nesting deeper than MAX_DEPTH={MAX_DEPTH}")
        text, i = self.text, pos + 1
        while i < len(text):
            ch = text[i]
            if ch == "\\":
                if i + 1 >= len(text) or text[i + 1] == "\n":
                    break
                i += 2 + self._escape_width(i)
            elif ch == '"':
                return i + 1
            elif ch == "\n":
                break
            elif text.startswith(("$${", "%%{"), i):
                i += 3
            elif text.startswith(("${", "%{"), i):
                i = self.template_end(i, depth + 1)
            else:
                i += 1
        raise HclError(self.line(pos), "unterminated string")

    def _escape_width(self, pos: int) -> int:
        # 0212: a bad escape fails at parse time, so no attribute holds an undecodable string.
        nxt = self.text[pos + 1]
        if nxt in _ESCAPES:
            return 0
        width = {"u": 4, "U": 8}.get(nxt, 0)
        digits = self.text[pos + 2 : pos + 2 + width]
        if (
            width == 0
            or len(digits) != width
            or not all(c in _HEX for c in digits)
            or int(digits, 16) > 0x10FFFF
        ):
            raise HclError(self.line(pos), f"bad escape \\{nxt}")
        return width

    def template_end(self, pos: int, depth: int) -> int:
        # 0212: pos sits on the $ or % of an opener; nested braces and quotes are skipped whole.
        if depth > MAX_DEPTH:
            raise HclError(self.line(pos), f"nesting deeper than MAX_DEPTH={MAX_DEPTH}")
        text, i, braces = self.text, pos + 2, 1
        while i < len(text):
            ch = text[i]
            if ch == '"':
                i = self.string_end(i, depth + 1)
                continue
            if ch == "{":
                braces += 1
                if depth + braces > MAX_DEPTH:
                    raise HclError(self.line(i), f"nesting deeper than MAX_DEPTH={MAX_DEPTH}")
            elif ch == "}":
                braces -= 1
                if braces == 0:
                    return i + 1
            i += 1
        raise HclError(self.line(pos), "unterminated template")

    def heredoc_end(self, pos: int, match: re.Match[str]) -> int:
        marker, i = match.group(2), match.end()
        while i <= len(self.text):
            stop = self.text.find("\n", i)
            stop = len(self.text) if stop < 0 else stop
            if self.text[i:stop].strip() == marker:
                return stop
            if stop >= len(self.text):
                break
            i = stop + 1
        raise HclError(self.line(pos), f"unterminated heredoc {marker}")

    def tokens(self) -> list[Token]:
        text, i = self.text, 0
        out: list[Token] = []
        stack: list[tuple[str, int]] = []
        while i < len(text):
            ch, start = text[i], i
            if ch in " \t\r":
                i += 1
                continue
            if ch == "\n":
                out.append(Token(NEWLINE, i, i + 1, self.line(i)))
                i += 1
                continue
            if ch == "#" or text.startswith("//", i):
                stop = text.find("\n", i)
                i = len(text) if stop < 0 else stop
                continue
            if text.startswith("/*", i):
                stop = text.find("*/", i + 2)
                if stop < 0:
                    raise HclError(self.line(i), "unterminated comment")
                i = stop + 2
                continue
            if ch == '"':
                i = self.string_end(i, len(stack) + 1)
                out.append(Token(STRING, start, i, self.line(start)))
                continue
            if text.startswith("<<", i):
                match = _HEREDOC.match(text, i)
                if match is None:
                    raise HclError(self.line(i), "malformed heredoc opener")
                i = self.heredoc_end(i, match)
                out.append(Token(HEREDOC, start, i, self.line(start)))
                continue
            if ch.isalpha() or ch == "_":
                i += 1
                while i < len(text) and (text[i].isalnum() or text[i] in "_-"):
                    i += 1
                out.append(Token(IDENT, start, i, self.line(start)))
                continue
            number = _NUMBER.match(text, i)
            if number is not None:
                i = number.end()
                out.append(Token(NUMBER, start, i, self.line(start)))
                continue
            if ch not in _PUNCT:
                raise HclError(self.line(i), f"unexpected character {ch!r}")
            if ch in _OPEN:
                stack.append((ch, self.line(i)))
                if len(stack) > MAX_DEPTH:
                    raise HclError(self.line(i), f"nesting deeper than MAX_DEPTH={MAX_DEPTH}")
            elif ch in _CLOSE:
                if not stack or _OPEN[stack[-1][0]] != ch:
                    raise HclError(self.line(i), f"unexpected {ch!r}")
                stack.pop()
            out.append(Token(PUNCT, start, i + 1, self.line(start)))
            i += 1
        if stack:
            opener, line = stack[-1]
            raise HclError(line, f"unclosed {opener!r}")
        return out


def tokenize(text: str, first_line: int = 1) -> list[Token]:
    if not isinstance(text, str):
        raise HclError(first_line, f"input is {type(text).__name__}, not text")
    return _Scanner(text, first_line).tokens()


class _Parser:
    def __init__(self, text: str) -> None:
        self.text = text
        self.toks = tokenize(text)
        self.i = 0

    def _peek(self) -> Token | None:
        return self.toks[self.i] if self.i < len(self.toks) else None

    def _src(self, tok: Token) -> str:
        return self.text[tok.start : tok.end]

    def _is(self, tok: Token | None, kind: str, src: str | None = None) -> bool:
        return tok is not None and tok.kind == kind and (src is None or self._src(tok) == src)

    def body(self, opener: Token | None) -> tuple[list[Block], dict[str, str], dict[str, int]]:
        blocks: list[Block] = []
        attrs: dict[str, str] = {}
        lines: dict[str, int] = {}
        while True:
            tok = self._peek()
            if self._is(tok, NEWLINE):
                self.i += 1
                continue
            if tok is None:
                if opener is not None:
                    raise HclError(opener.line, "unclosed '{'")
                return blocks, attrs, lines
            if self._is(tok, PUNCT, "}"):
                if opener is None:
                    raise HclError(tok.line, "unexpected '}'")
                self.i += 1
                return blocks, attrs, lines
            if tok.kind != IDENT:
                raise HclError(tok.line, f"expected a name, found {self._src(tok)[:20]!r}")
            self.i += 1
            name = self._src(tok)
            if self._is(self._peek(), PUNCT, "="):
                self.i += 1
                if name in attrs:
                    raise HclError(tok.line, f"attribute {name} set twice")
                attrs[name] = self._expression(tok)
                lines[name] = tok.line
            else:
                blocks.append(self._block(tok, name))

    def _expression(self, name: Token) -> str:
        depth, first, last = 0, None, None
        while True:
            tok = self._peek()
            if tok is None:
                break
            src = self._src(tok)
            if depth == 0 and (tok.kind == NEWLINE or (tok.kind == PUNCT and src == "}")):
                break
            if tok.kind == PUNCT and src in _OPEN:
                depth += 1
            elif tok.kind == PUNCT and src in _CLOSE:
                depth -= 1
            if tok.kind != NEWLINE:
                first = first or tok
                last = tok
            self.i += 1
        if first is None or last is None:
            raise HclError(name.line, f"attribute {self._src(name)} has no value")
        return self.text[first.start : last.end]

    def _block(self, name_tok: Token, name: str) -> Block:
        labels: list[str] = []
        while True:
            tok = self._peek()
            if tok is None:
                raise HclError(name_tok.line, f"block {name} has no body")
            if tok.kind == STRING:
                labels.append(_label(self._src(tok), tok.line))
            elif tok.kind == IDENT:
                labels.append(self._src(tok))
            elif self._is(tok, PUNCT, "{"):
                break
            else:
                raise HclError(tok.line, f"unexpected {self._src(tok)[:20]!r} in block {name}")
            self.i += 1
        self.i += 1
        blocks, attrs, lines = self.body(tok)
        after = self._peek()
        if after is not None and not (self._is(after, NEWLINE) or self._is(after, PUNCT, "}")):
            raise HclError(after.line, f"expected a new line after block {name}")
        return Block(name, tuple(labels), attrs, tuple(blocks), name_tok.line, lines)


def _label(src: str, line: int) -> str:
    value = _decode(src, line)
    if "${" in value.replace("$${", "") or "%{" in value.replace("%%{", ""):
        raise HclError(line, "a block label cannot hold a template")
    return value


def _decode(src: str, line: int) -> str:
    # 0212: escapes decode; templates and $${ stay literal so substitute() sees them whole.
    scan, out, i, end = _Scanner(src, line), [], 1, len(src) - 1
    while i < end:
        ch = src[i]
        if ch == "\\":
            nxt = src[i + 1]
            if nxt in _ESCAPES:
                out.append(_ESCAPES[nxt])
                i += 2
                continue
            width = scan._escape_width(i)
            out.append(chr(int(src[i + 2 : i + 2 + width], 16)))
            i += 2 + width
        elif src.startswith(("$${", "%%{"), i):
            out.append(src[i : i + 3])
            i += 3
        elif src.startswith(("${", "%{"), i):
            stop = scan.template_end(i, 1)
            out.append(src[i:stop])
            i = stop
        else:
            out.append(ch)
            i += 1
    return "".join(out)


def parse(text: str) -> list[Block]:
    parser = _Parser(text)
    blocks, attrs, lines = parser.body(None)
    if attrs:
        name = next(iter(attrs))
        raise HclError(lines[name], f"attribute {name} outside a block")
    return blocks


def _value_tokens(source: str, line: int) -> list[Token]:
    return [t for t in tokenize(source, line) if t.kind != NEWLINE]


def string_value(source: str, line: int = 1) -> str:
    """A quoted string attribute, decoded; any other value raises HclError."""
    toks = _value_tokens(source, line)
    if len(toks) != 1 or toks[0].kind != STRING:
        raise HclError(line, f"expected a quoted string, found {source[:40]!r}")
    return _decode(source, line)


def scalar_value(source: str, line: int = 1) -> str:
    """A quoted string decoded, or a reference kept as its source text."""
    toks = _value_tokens(source, line)
    if len(toks) == 1 and toks[0].kind == STRING:
        return _decode(source, line)
    if not toks or toks[0].kind == HEREDOC or source[toks[0].start : toks[0].end] in ("[", "{"):
        raise HclError(line, f"expected a single value, found {source[:40]!r}")
    return source


def list_value(source: str, line: int = 1) -> tuple[str, ...]:
    # 0212: a reference or call is one item of source text; a scalar or nested list raises.
    toks = _value_tokens(source, line)
    if not toks:
        raise HclError(line, "empty list value")
    first = source[toks[0].start : toks[0].end]
    if (
        toks[0].kind in (STRING, HEREDOC, NUMBER)
        or first == "{"
        or (len(toks) == 1 and first in _LITERALS)
    ):
        raise HclError(toks[0].line, f"expected a list, found {source[:40]!r}")
    if first != "[" or source[toks[-1].start : toks[-1].end] != "]":
        return (source,)
    if len(toks) > 1 and toks[1].kind == IDENT and source[toks[1].start : toks[1].end] == "for":
        return (source,)
    items: list[str] = []
    group: list[Token] = []
    depth = 0
    for tok in toks[1:-1]:
        src = source[tok.start : tok.end]
        if tok.kind == PUNCT and src == "," and depth == 0:
            items.append(_item(source, group, tok.line))
            group = []
            continue
        if tok.kind == PUNCT and src in _OPEN:
            if depth == 0 and not group:
                raise HclError(tok.line, "nested list or object in a list of strings")
            depth += 1
        elif tok.kind == PUNCT and src in _CLOSE:
            depth -= 1
        group.append(tok)
    if group:
        items.append(_item(source, group, group[0].line))
    return tuple(items)


def _item(source: str, group: Sequence[Token], line: int) -> str:
    if not group:
        raise HclError(line, "empty list item")
    if len(group) == 1 and group[0].kind == STRING:
        return _decode(source[group[0].start : group[0].end], group[0].line)
    if group[0].kind == HEREDOC:
        raise HclError(group[0].line, "heredoc in a list of strings")
    return source[group[0].start : group[-1].end]


def substitute(value: str, mapping: Mapping[str, str]) -> str:
    """Replace each ${name} whose name is a mapping key; every other token stays literal."""
    if not isinstance(value, str) or not all(
        isinstance(k, str) and isinstance(v, str) for k, v in mapping.items()
    ):
        raise HclError(1, "substitute needs text and a mapping of text to text")
    scan, out, i = _Scanner(value), [], 0
    while i < len(value):
        if value.startswith(("$${", "%%{"), i):
            out.append(value[i : i + 3])
            i += 3
        elif value.startswith(("${", "%{"), i):
            try:
                stop = scan.template_end(i, 1)
            except HclError:
                out.append(value[i:])
                break
            name = value[i + 2 : stop - 1].strip()
            out.append(mapping[name] if value[i] == "$" and name in mapping else value[i:stop])
            i = stop
        else:
            out.append(value[i])
            i += 1
    return "".join(out)


def _children(block: Block, kind: str) -> list[tuple[Block, bool]]:
    # 0212: a dynamic "<kind>" block contributes its content body, marked dynamic.
    found: list[tuple[Block, bool]] = []
    for child in block.blocks:
        if child.type == kind and not child.labels:
            found.append((child, False))
        elif child.type == "dynamic" and child.labels == (kind,):
            content = [b for b in child.blocks if b.type == "content"]
            if len(content) != 1:
                raise HclError(child.line, f'dynamic "{kind}" needs one content block')
            found.append((content[0], True))
    return found


def _optional(block: Block, name: str) -> str | None:
    if name not in block.attributes:
        return None
    return scalar_value(block.attributes[name], block.attribute_lines[name])


def _listed(block: Block, name: str) -> tuple[str, ...]:
    if name not in block.attributes:
        return ()
    return list_value(block.attributes[name], block.attribute_lines[name])


def policy_statements(blocks: Sequence[Block], name: str | None = None) -> list[Statement]:
    """The statement blocks of data "aws_iam_policy_document" blocks, dynamic ones marked."""
    found: list[Statement] = []
    for block in blocks:
        if not isinstance(block, Block):
            raise HclError(1, f"expected a Block, found {type(block).__name__}")
        if block.type != "data" or len(block.labels) != 2 or block.labels[0] != _POLICY_DOC:
            continue
        if name is not None and block.labels[1] != name:
            continue
        for stmt, dynamic in _children(block, "statement"):
            principals = tuple(
                Principal(_optional(p, "type"), _listed(p, "identifiers"), dyn)
                for p, dyn in _children(stmt, "principals")
            )
            conditions = tuple(
                Condition(_optional(c, "test"), _optional(c, "variable"), _listed(c, "values"), dyn)
                for c, dyn in _children(stmt, "condition")
            )
            found.append(
                Statement(
                    document=block.labels[1],
                    sid=_optional(stmt, "sid"),
                    effect=_optional(stmt, "effect"),
                    actions=_listed(stmt, "actions"),
                    not_actions=_listed(stmt, "not_actions"),
                    resources=_listed(stmt, "resources"),
                    not_resources=_listed(stmt, "not_resources"),
                    principals=principals,
                    conditions=conditions,
                    dynamic=dynamic,
                    line=stmt.line,
                )
            )
    return found
