# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 228: the one bash parse every jail check reads. parse(text) returns a Script whose every node
# carries a span into text. The parser reports structure and never judges; a construct the model
# does not bound is an Opaque node with a one-line why, and parse never raises on input text.
from __future__ import annotations

import re
from collections.abc import Iterator
from dataclasses import dataclass

Span = tuple[int, int]

_BLANKS = " \t"
_META = " \t\n|&;()<>"
_QUOTES = "'\"\\$`"
_REDIRECT_OPS = ("&>>", "<<-", "<<<", "&>", ">>", ">|", "<>", "<&", ">&", "<<", "<", ">")
_SEPARATORS = ("&&", "||", ";;&", ";;", ";&", ";", "&", "\n")
_CASE_ENDS = (";;&", ";;", ";&")
_CLOSERS = frozenset({"then", "elif", "else", "fi", "esac", "do", "done", "}"})
_STARTERS = frozenset(
    {"if", "case", "for", "select", "while", "until", "function", "{", "[[", "coproc"}
)
_PARAM_OPS = ":-=?+#%/^,@["
_PARAM_UNSAFE = "$`'\"\\~"
_ANSI_SIMPLE = {
    "a": "\a",
    "b": "\b",
    "e": "\x1b",
    "E": "\x1b",
    "f": "\f",
    "n": "\n",
    "r": "\r",
    "t": "\t",
    "v": "\v",
    "\\": "\\",
    "'": "'",
    '"': '"',
    "?": "?",
}
_NEST_CAP = 60
# 228 R1: the lexer's own patterns; no regex over command text lives outside this module.
_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_ASSIGN = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)(\[[^\]\s'\"\\$`|&;()<>]*\])?(\+?=)")
_ASSIGN_SHAPE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(?:\[[^\]\s|&;()<>]*\])?\+?=")
_OPEN_SUBSCRIPT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\[")
_FD_NAME = re.compile(r"\{[A-Za-z_][A-Za-z0-9_]*\}")
_FD_DIGITS = re.compile(r"[0-9]+")
_PARAM = re.compile(r"(#?)([A-Za-z_][A-Za-z0-9_]*|[0-9]+|[@*#?$!\-])(.*)\Z", re.DOTALL)
_SEQUENCE = re.compile(r"(?:-?[0-9]+\.\.-?[0-9]+|[A-Za-z]\.\.[A-Za-z])(?:\.\.-?[0-9]+)?")
_USER = re.compile(r"[A-Za-z0-9._+\-]*")


@dataclass(frozen=True)
class Opaque:
    span: Span
    why: str


@dataclass(frozen=True)
class Literal:
    text: str
    quoted: str
    span: Span


@dataclass(frozen=True)
class Param:
    name: str
    op: str
    span: Span
    quoted: str = ""


@dataclass(frozen=True)
class CommandSub:
    inner: Script | Opaque
    span: Span
    quoted: str = ""


@dataclass(frozen=True)
class ProcSub:
    direction: str
    inner: Script | Opaque
    span: Span


@dataclass(frozen=True)
class Arith:
    span: Span
    quoted: str = ""


@dataclass(frozen=True)
class BraceList:
    items: list[Word]
    span: Span
    sequence: bool = False


@dataclass(frozen=True)
class Glob:
    span: Span


@dataclass(frozen=True)
class Tilde:
    user: str
    span: Span


Part = Literal | Param | CommandSub | ProcSub | Arith | BraceList | Glob | Tilde | Opaque


@dataclass(frozen=True)
class Word:
    raw: str
    parts: list[Part]
    span: Span

    @property
    def literal(self) -> str | None:
        if all(isinstance(part, Literal) for part in self.parts):
            return "".join(part.text for part in self.parts if isinstance(part, Literal))
        return None

    @property
    def expands(self) -> bool:
        return self.literal is None

    @property
    def kinds(self) -> frozenset[str]:
        out: set[str] = set()
        for part in self.parts:
            out.add(_KIND[type(part)])
            if isinstance(part, BraceList):
                for item in part.items:
                    out |= item.kinds
        return frozenset(out)


@dataclass(frozen=True)
class Assignment:
    name: str
    op: str
    subscript: Word | None
    value: Word
    span: Span


@dataclass(frozen=True)
class Heredoc:
    delimiter: Word
    quoted: bool
    body: str
    body_span: Span
    span: Span
    parts: list[Part]


@dataclass(frozen=True)
class Redirect:
    fd: int | Word | None
    op: str
    target: Word
    span: Span
    heredoc: Heredoc | Opaque | None = None


@dataclass(frozen=True)
class Command:
    assignments: list[Assignment]
    words: list[Word]
    redirects: list[Redirect]
    span: Span


@dataclass(frozen=True)
class Control:
    kind: str
    clauses: list[tuple[Script | None, Script]]
    name: Word | None
    words: list[Word]
    redirects: list[Redirect]
    span: Span


@dataclass(frozen=True)
class Pipeline:
    commands: list[Command | Control | Opaque]
    pipes: list[str]
    negated: bool
    timed: bool
    span: Span


Item = Pipeline | Control | Opaque


@dataclass(frozen=True)
class Script:
    items: list[Item]
    separators: list[str]
    span: Span


Node = (
    Script
    | Pipeline
    | Control
    | Command
    | Assignment
    | Redirect
    | Heredoc
    | Word
    | Literal
    | Param
    | CommandSub
    | ProcSub
    | Arith
    | BraceList
    | Glob
    | Tilde
    | Opaque
)
_KIND: dict[type, str] = {
    Literal: "literal",
    Param: "param",
    CommandSub: "command",
    ProcSub: "process",
    Arith: "arith",
    BraceList: "brace",
    Glob: "glob",
    Tilde: "tilde",
    Opaque: "opaque",
}


class _Syntax(Exception):
    # 228 R2: raised inside the parser only; parse turns it into an Opaque to the end of text.
    def __init__(self, why: str) -> None:
        super().__init__(why)
        self.why = why


class _Pending:
    def __init__(self, redirect: Redirect, delimiter: str, dash: bool, quoted: bool) -> None:
        self.redirect = redirect
        self.delimiter = delimiter
        self.dash = dash
        self.quoted = quoted


def _attach(redirect: Redirect, heredoc: Heredoc | Opaque) -> None:
    # 228 R1: a body follows its line, so the frozen redirect is filled once before parse returns.
    object.__setattr__(redirect, "heredoc", heredoc)


class _Parts:
    # 228: merges adjacent literal characters of one quoting into one Literal part.
    def __init__(self) -> None:
        self.parts: list[Part] = []
        self._buf: list[str] = []
        self._quoted = ""
        self._start = -1
        self._end = -1

    def char(self, text: str, quoted: str, start: int, end: int) -> None:
        if self._buf and (quoted != self._quoted or start != self._end):
            self.flush()
        if not self._buf:
            self._quoted, self._start = quoted, start
        self._buf.append(text)
        self._end = end

    def add(self, part: Part | list[Part]) -> None:
        self.flush()
        self.parts.extend(part if isinstance(part, list) else [part])

    def flush(self) -> None:
        if self._buf:
            text = "".join(self._buf)
            self.parts.append(Literal(text, self._quoted, (self._start, self._end)))
            self._buf = []

    def done(self) -> list[Part]:
        self.flush()
        return self.parts


class _Parser:
    def __init__(self, text: str, start: int, limit: int, nest: int, outer: bool) -> None:
        self.text = text
        self.pos = start
        self.limit = limit
        self.nest = nest
        self.outer = outer
        self.pending: list[_Pending] = []

    # -- characters --------------------------------------------------------------------------
    def ch(self, k: int = 0) -> str:
        i = self.pos + k
        return self.text[i] if 0 <= i < self.limit else ""

    def at(self, token: str) -> bool:
        return self.pos + len(token) <= self.limit and self.text.startswith(token, self.pos)

    def eof(self) -> bool:
        return self.pos >= self.limit

    def _continuation(self, at: int) -> bool:
        return at + 1 < self.limit and self.text[at] == "\\" and self.text[at + 1] == "\n"

    def skip_blanks(self) -> None:
        while not self.eof():
            if self.ch() in _BLANKS:
                self.pos += 1
            elif self._continuation(self.pos):
                self.pos += 2
            else:
                return

    def skip_space(self, newlines: bool) -> None:
        while True:
            self.skip_blanks()
            if self.ch() == "#":
                end = self.text.find("\n", self.pos, self.limit)
                self.pos = self.limit if end < 0 else end
            elif newlines and self.ch() == "\n":
                self.pos += 1
                self.read_heredocs()
            else:
                return

    def _glued(self) -> None:
        # 228 R1: a line continuation between operator characters joins them in bash.
        if self._continuation(self.pos) and self.text[self.pos + 2 : self.pos + 3] in tuple(
            "|&;<>"
        ):
            raise _Syntax("line continuation inside an operator")

    def peek_word(self) -> str | None:
        # The unquoted word at pos with continuations removed, or None when quoting is in it.
        out: list[str] = []
        j = self.pos
        while j < self.limit:
            if self._continuation(j):
                j += 2
                continue
            c = self.text[j]
            if c in _META:
                break
            if c in _QUOTES:
                return None
            out.append(c)
            j += 1
        return "".join(out) if out else None

    def take_word(self, word: str) -> None:
        if self.peek_word() != word:
            raise _Syntax(f"expected {word}")
        seen = 0
        while seen < len(word):
            if self._continuation(self.pos):
                self.pos += 2
                continue
            self.pos += 1
            seen += 1

    def stopped(self, stops: frozenset[str]) -> bool:
        if not stops:
            return False
        if ")" in stops and self.ch() == ")":
            return True
        if any(self.at(end) for end in _CASE_ENDS) and ";;" in stops:
            return True
        word = self.peek_word()
        return word is not None and word in stops

    # -- lists and pipelines -----------------------------------------------------------------
    def script(self) -> Script:
        items: list[Item] = []
        seps: list[str] = []
        start = self.pos
        while True:
            begin = self.pos
            try:
                if not self._item(items, seps, frozenset()):
                    break
            except (_Syntax, RecursionError) as exc:
                why = exc.why if isinstance(exc, _Syntax) else "nesting too deep"
                del items[len(seps) :]
                items.append(Opaque((begin, self.limit), why))
                seps.append("")
                self.pos = self.limit
                break
        for pending in self.pending:
            span = (pending.redirect.span[0], self.limit)
            _attach(pending.redirect, Opaque(span, "missing heredoc delimiter line"))
        self.pending = []
        return Script(items, seps, (start, self.limit))

    def parse_list(self, stops: frozenset[str]) -> Script:
        items: list[Item] = []
        seps: list[str] = []
        start = self.pos
        while self._item(items, seps, stops):
            pass
        end = items[-1].span[1] if items else start
        return Script(items, seps, (start, end))

    def _item(self, items: list[Item], seps: list[str], stops: frozenset[str]) -> bool:
        # One item and its separator; False when the list ends here.
        self.skip_space(newlines=True)
        if self.eof() or self.stopped(stops):
            return False
        items.append(self.pipeline())
        self.skip_space(newlines=False)
        sep = next((op for op in _SEPARATORS if self.at(op)), "")
        if sep in _CASE_ENDS:
            if ";;" not in stops:
                raise _Syntax(f"{sep} outside case")
            seps.append("")
            return False
        if not sep:
            seps.append("")
            if self.eof() or self.stopped(stops):
                return False
            raise _Syntax(f"unexpected {self.ch()!r} after a command")
        self.pos += len(sep)
        self._glued()
        seps.append(sep)
        if sep == "\n":
            self.read_heredocs()
        if sep in ("&&", "||"):
            self.skip_space(newlines=True)
            if self.eof() or self.stopped(stops):
                raise _Syntax(f"missing command after {sep}")
        return True

    def pipeline(self) -> Item:
        start = self.pos
        negated = timed = False
        while True:
            word = self.peek_word()
            if word == "!":
                self.take_word("!")
                negated = not negated
            elif word == "time" and not timed and not negated:
                self.take_word("time")
                timed = True
                self.skip_blanks()
                if self.peek_word() == "-p":
                    self.take_word("-p")
            else:
                break
            self.skip_blanks()
        commands: list[Command | Control | Opaque] = [self.command()]
        pipes: list[str] = []
        while True:
            self.skip_blanks()
            op = "|&" if self.at("|&") else "|" if self.at("|") and not self.at("||") else ""
            if not op:
                break
            self.pos += len(op)
            self._glued()
            pipes.append(op)
            self.skip_space(newlines=True)
            if self.eof():
                raise _Syntax(f"missing command after {op}")
            commands.append(self.command())
        only = commands[0]
        if len(commands) == 1 and not negated and not timed and isinstance(only, Control):
            return only
        return Pipeline(commands, pipes, negated, timed, (start, commands[-1].span[1]))

    # -- commands ----------------------------------------------------------------------------
    def command(self) -> Command | Control | Opaque:
        self.skip_blanks()
        if self.eof():
            raise _Syntax("missing command")
        if self.nest > _NEST_CAP:
            raise _Syntax("nesting too deep")
        start = self.pos
        if self.at("(("):
            end = self.arith_end(self.pos + 2)
            if end is not None:
                self.pos = end
                return Opaque((start, end), "arithmetic command")
        if self.ch() == "(":
            self.pos += 1
            body = self.nested(frozenset({")"}))
            if self.ch() != ")":
                raise _Syntax("unclosed (")
            self.pos += 1
            return self.control("subshell", [(None, body)], None, [], start)
        if self.ch() in ")|;\n" or (self.ch() == "&" and not self.at("&>")):
            raise _Syntax(f"unexpected {self.ch()!r}")
        word = self.peek_word()
        if word in _CLOSERS or word in ("!", "time"):
            raise _Syntax(f"unexpected {word}")
        if word == "[[":
            return self.conditional(start)
        if word == "coproc":
            raise _Syntax("coproc")
        if word in _STARTERS:
            self.nest += 1
            try:
                return self.compound(str(word), start)
            finally:
                self.nest -= 1
        return self.simple()

    def nested(self, stops: frozenset[str]) -> Script:
        self.nest += 1
        try:
            return self.parse_list(stops)
        finally:
            self.nest -= 1

    def control(
        self,
        kind: str,
        clauses: list[tuple[Script | None, Script]],
        name: Word | None,
        words: list[Word],
        start: int,
    ) -> Control:
        end = self.pos
        redirects: list[Redirect] = []
        while True:
            self.skip_blanks()
            redirect = self.redirect()
            if redirect is None:
                break
            redirects.append(redirect)
            end = redirect.span[1]
        return Control(kind, clauses, name, words, redirects, (start, end))

    def compound(self, word: str, start: int) -> Control:
        self.take_word(word)
        if word == "{":
            body = self.nested(frozenset({"}"}))
            self.take_word("}")
            return self.control("group", [(None, body)], None, [], start)
        if word == "if":
            clauses: list[tuple[Script | None, Script]] = []
            cond = self.nested(frozenset({"then"}))
            self.take_word("then")
            clauses.append((cond, self.nested(frozenset({"elif", "else", "fi"}))))
            while self.peek_word() == "elif":
                self.take_word("elif")
                cond = self.nested(frozenset({"then"}))
                self.take_word("then")
                clauses.append((cond, self.nested(frozenset({"elif", "else", "fi"}))))
            if self.peek_word() == "else":
                self.take_word("else")
                clauses.append((None, self.nested(frozenset({"fi"}))))
            self.take_word("fi")
            return self.control("if", clauses, None, [], start)
        if word in ("while", "until"):
            cond = self.nested(frozenset({"do"}))
            self.take_word("do")
            body = self.nested(frozenset({"done"}))
            self.take_word("done")
            return self.control(word, [(cond, body)], None, [], start)
        if word in ("for", "select"):
            return self.for_loop(word, start)
        if word == "case":
            return self.case(start)
        return self.function(start, keyword=True)

    def for_loop(self, kind: str, start: int) -> Control:
        self.skip_blanks()
        if self.at("(("):
            raise _Syntax("arithmetic for loop")
        name = self.word()
        if name is None or name.literal is None or not _NAME.fullmatch(name.raw):
            raise _Syntax(f"bad {kind} variable")
        words: list[Word] = []
        self.skip_space(newlines=True)
        if self.peek_word() == "in":
            self.take_word("in")
            while True:
                self.skip_blanks()
                if self.ch() in (";", "\n") or self.eof():
                    break
                word = self.word()
                if word is None:
                    raise _Syntax(f"unexpected {self.ch()!r} in a {kind} list")
                words.append(word)
            if self.eof():
                raise _Syntax(f"unclosed {kind}")
        else:
            # 228: no `in` list iterates "$@"; a zero-width word says so.
            at = self.pos
            words.append(Word("", [Param("@", "", (at, at), '"')], (at, at)))
        if self.ch() == ";":
            self.pos += 1
        self.skip_space(newlines=True)
        self.take_word("do")
        body = self.nested(frozenset({"done"}))
        self.take_word("done")
        return self.control(kind, [(None, body)], name, words, start)

    def case(self, start: int) -> Control:
        self.skip_blanks()
        subject = self.word()
        if subject is None:
            raise _Syntax("case without a word")
        self.skip_space(newlines=True)
        self.take_word("in")
        held = len(self.pending)
        clauses: list[tuple[Script | None, Script]] = []
        while True:
            self.skip_space(newlines=True)
            if self.peek_word() == "esac":
                self.take_word("esac")
                break
            if self.eof():
                raise _Syntax("unclosed case")
            begin = self.pos
            if self.ch() == "(":
                self.pos += 1
            while True:
                self.skip_blanks()
                if self.word() is None:
                    raise _Syntax("bad case pattern")
                self.skip_blanks()
                if self.ch() == "|":
                    self.pos += 1
                    continue
                if self.ch() == ")":
                    self.pos += 1
                    break
                raise _Syntax("bad case pattern")
            self.nested(frozenset({";;", "esac"}))
            for end in _CASE_ENDS:
                if self.at(end):
                    self.pos += len(end)
                    break
            # 228: a case body is one Opaque node per clause.
            span = (begin, self.pos)
            clauses.append((None, Script([Opaque(span, "case clause")], [""], span)))
        if len(self.pending) > held:
            raise _Syntax("heredoc body after a case")
        return self.control("case", clauses, None, [subject], start)

    def function(self, start: int, keyword: bool, name: Word | None = None) -> Control:
        if keyword:
            self.skip_blanks()
            name = self.word()
            self.skip_blanks()
            if self.ch() == "(":
                self.pos += 1
                self.skip_blanks()
                if self.ch() != ")":
                    raise _Syntax("bad function definition")
                self.pos += 1
        if name is None or name.literal is None or name.raw != name.literal:
            raise _Syntax("bad function name")
        self.skip_space(newlines=True)
        body = self.command()
        if not isinstance(body, Control):
            raise _Syntax("function body is not a compound command")
        script = Script([body], [""], body.span)
        return Control("function", [(None, script)], name, [], [], (start, body.span[1]))

    def conditional(self, start: int) -> Opaque:
        # 228: a [[ ]] body is bounded at the next standalone ]] and kept opaque.
        j = self.pos + 2
        while j < self.limit:
            c = self.text[j]
            if c == "\\":
                j += 2
                continue
            if c in "'\"":
                close = self.quote_end(j)
                if close is None:
                    raise _Syntax("unterminated quote in [[")
                j = close
                continue
            if (
                self.text.startswith("]]", j)
                and self.text[j - 1] in _BLANKS
                and (j + 2 >= self.limit or self.text[j + 2] in _META)
            ):
                self.pos = j + 2
                return Opaque((start, j + 2), "conditional command")
            j += 1
        raise _Syntax("unclosed [[")

    def quote_end(self, j: int) -> int | None:
        # The index past the quote opened at j, for bounding scans only.
        quote = self.text[j]
        k = j + 1
        while k < self.limit:
            c = self.text[k]
            if c == "\\" and quote == '"':
                k += 2
                continue
            if c == quote:
                return k + 1
            k += 1
        return None

    def simple(self) -> Command | Control:
        start = self.pos
        assigns: list[Assignment] = []
        words: list[Word] = []
        redirects: list[Redirect] = []
        end = start
        while True:
            self.skip_blanks()
            if self.eof() or self.ch() == "#":
                break
            redirect = self.redirect()
            if redirect is not None:
                redirects.append(redirect)
                end = redirect.span[1]
                continue
            if self.ch() in _META and not self.procsub_at():
                if self.ch() == "(" and len(words) == 1 and not assigns and not redirects:
                    return self.definition(start, words[0])
                break
            if not words:
                assignment = self.assignment()
                if assignment is not None:
                    assigns.append(assignment)
                    end = assignment.span[1]
                    continue
                if _OPEN_SUBSCRIPT.match(self.text, self.pos):
                    self.subscript_guard()
            word = self.word()
            if word is None:
                break
            if self.ch() in ("<", ">") and "\\\n" in word.raw and not self.procsub_at():
                raise _Syntax("line continuation before a redirect")
            words.append(word)
            end = word.span[1]
        if not (assigns or words or redirects):
            raise _Syntax(f"unexpected {self.ch()!r}" if not self.eof() else "missing command")
        return Command(assigns, words, redirects, (start, end))

    def subscript_guard(self) -> None:
        # 228 R2: bash reads name[...] in command position across blanks; refuse what splits.
        j = self.pos
        depth = 0
        while j < self.limit:
            c = self.text[j]
            if c == "[":
                depth += 1
            elif c == "]":
                depth -= 1
                if depth == 0:
                    return
            elif c in _META or c in _QUOTES:
                if depth > 0:
                    raise _Syntax("subscript with blanks or quoting in command position")
                return
            j += 1
        if depth > 0:
            raise _Syntax("unclosed subscript in command position")

    def definition(self, start: int, name: Word) -> Control:
        self.pos += 1
        self.skip_blanks()
        if self.ch() != ")":
            raise _Syntax("unexpected '('")
        self.pos += 1
        return self.function(start, keyword=False, name=name)

    def assignment(self) -> Assignment | None:
        match = _ASSIGN.match(self.text, self.pos, self.limit)
        if match is None:
            return None
        start = self.pos
        subscript: Word | None = None
        if match.group(2):
            sub_start = match.start(2) + 1
            sub_end = match.end(2) - 1
            subscript = self.sub_word(sub_start, sub_end, brace=False, glob=False)
        self.pos = match.end()
        if self.ch() == "(":
            close = self.paren_end(self.pos)
            value = Word(
                self.text[self.pos : close],
                [Opaque((self.pos, close), "array assignment")],
                (self.pos, close),
            )
            self.pos = close
        else:
            value = self.word(brace=False, glob=False, assign=True) or Word(
                "", [], (self.pos, self.pos)
            )
        return Assignment(match.group(1), match.group(3), subscript, value, (start, self.pos))

    def paren_end(self, j: int) -> int:
        depth = 0
        while j < self.limit:
            c = self.text[j]
            if c == "\\":
                j += 2
                continue
            if c in "'\"":
                close = self.quote_end(j)
                if close is None:
                    raise _Syntax("unterminated quote")
                j = close
                continue
            if c == "(":
                depth += 1
            elif c == ")":
                depth -= 1
                if depth == 0:
                    return j + 1
            j += 1
        raise _Syntax("unclosed (")

    def procsub_at(self) -> bool:
        return self.ch() in ("<", ">") and self.ch(1) == "("

    # -- redirects and heredocs --------------------------------------------------------------
    def redirect(self) -> Redirect | None:
        start = self.pos
        fd: int | Word | None = None
        digits = _FD_DIGITS.match(self.text, self.pos, self.limit)
        named = _FD_NAME.match(self.text, self.pos, self.limit)
        lead = digits or named
        if lead is not None and self.text[lead.end() : lead.end() + 1] in ("<", ">"):
            if self.text[lead.end() + 1 : lead.end() + 2] != "(":
                raw = lead.group(0)
                fd = int(raw) if digits else Word(raw, [Literal(raw, "", lead.span())], lead.span())
                self.pos = lead.end()
        if self.procsub_at():
            self.pos = start
            return None
        op = next((op for op in _REDIRECT_OPS if self.at(op)), "")
        if not op:
            self.pos = start
            return None
        self.pos += len(op)
        self._glued()
        self.skip_blanks()
        if op in ("<<", "<<-"):
            target = self.word(brace=False, glob=False, tilde=False)
            if target is None:
                raise _Syntax(f"missing heredoc delimiter after {op}")
            if self.outer:
                raise _Syntax("heredoc in a substitution while an outer heredoc is pending")
            delimiter, quoted = _delimiter(target)
            redirect = Redirect(fd, op, target, (start, target.span[1]))
            self.pending.append(_Pending(redirect, delimiter, op == "<<-", quoted))
            return redirect
        target = self.word()
        if target is None:
            raise _Syntax(f"missing target after {op}")
        return Redirect(fd, op, target, (start, target.span[1]))

    def read_heredocs(self) -> None:
        # 228 R1: bodies start after the newline that ends their line, in operator order.
        pending, self.pending = self.pending, []
        for item in pending:
            _attach(item.redirect, self.heredoc(item))

    def heredoc(self, item: _Pending) -> Heredoc | Opaque:
        body_start = j = self.pos
        while j < self.limit:
            stop = self.text.find("\n", j, self.limit)
            line_end = self.limit if stop < 0 else stop
            after = self.limit if stop < 0 else stop + 1
            line = self.text[j:line_end]
            if (line.lstrip("\t") if item.dash else line) == item.delimiter:
                self.pos = after
                return self.body(item, body_start, j, after)
            trailing = len(line) - len(line.rstrip("\\"))
            if not item.quoted and trailing % 2 == 1 and stop >= 0:
                self.pos = self.limit
                return Opaque((body_start, self.limit), "line continuation in an unquoted heredoc")
            j = after
        self.pos = self.limit
        return Opaque((item.redirect.span[0], self.limit), "missing heredoc delimiter line")

    def body(self, item: _Pending, start: int, end: int, after: int) -> Heredoc:
        raw = self.text[start:end]
        if item.dash:
            raw = "".join(line.lstrip("\t") for line in raw.splitlines(keepends=True))
        parts: list[Part] = [] if item.quoted else self.body_parts(start, end, item.dash)
        target = item.redirect.target
        return Heredoc(target, item.quoted, raw, (start, end), (start, after), parts)

    def body_parts(self, start: int, end: int, dash: bool) -> list[Part]:
        sub = _Parser(self.text, start, end, self.nest + 1, False)
        return sub.double_parts(heredoc=True, dash=dash)

    # -- words -------------------------------------------------------------------------------
    def sub_word(self, start: int, end: int, brace: bool, glob: bool) -> Word:
        if start == end:
            return Word("", [], (start, end))
        sub = _Parser(self.text, start, end, self.nest + 1, self.outer or bool(self.pending))
        word = sub.word(brace=brace, glob=glob, tilde=False)
        if word is None or sub.pos != end:
            return Word(
                self.text[start:end], [Opaque((start, end), "unbounded word")], (start, end)
            )
        return word

    def word(
        self, brace: bool = True, glob: bool = True, tilde: bool = True, assign: bool = False
    ) -> Word | None:
        start = self.pos
        parts = _Parts()
        # 228 R1: bash expands ~ after the first = of an assignment-shaped word and after each :.
        shape = None if assign or not tilde else _ASSIGN_SHAPE.match(self.text, start, self.limit)
        tilde_at = {start} if tilde or assign else set()
        if shape is not None:
            tilde_at.add(shape.end())
        colon_tilde = assign or shape is not None
        while not self.eof():
            c = self.ch()
            here = self.pos
            if c in _META:
                if self.procsub_at():
                    parts.add(self.procsub())
                    continue
                break
            if c == "\\":
                if self.ch(1) == "\n":
                    self.pos += 2
                elif self.pos + 1 >= self.limit:
                    parts.char("\\", "", here, here + 1)
                    self.pos += 1
                else:
                    parts.char(self.text[here + 1], "\\", here, here + 2)
                    self.pos += 2
            elif c == "'":
                parts.add(self.single())
            elif c == '"':
                parts.add(self.double('"'))
            elif c == "$":
                parts.add(self.dollar(""))
            elif c == "`":
                parts.add(self.backtick(""))
            elif c == "{" and brace:
                part = self.brace(start)
                if part is None:
                    parts.char("{", "", here, here + 1)
                    self.pos += 1
                else:
                    parts.add(part)
            elif c in "*?" and glob:
                parts.add(Glob((here, here + 1)))
                self.pos += 1
            elif c == "[" and glob:
                part = self.bracket()
                if part is None:
                    parts.char("[", "", here, here + 1)
                    self.pos += 1
                else:
                    parts.add(part)
            elif c == "~" and here in tilde_at:
                parts.add(self.tilde(colon_tilde))
            else:
                parts.char(c, "", here, here + 1)
                self.pos += 1
                if c == ":" and colon_tilde and (shape is None or here >= shape.end()):
                    tilde_at.add(self.pos)
        if self.pos == start:
            return None
        return Word(self.text[start : self.pos], parts.done(), (start, self.pos))

    def single(self) -> Literal:
        start = self.pos
        close = self.text.find("'", start + 1, self.limit)
        if close < 0:
            raise _Syntax("unterminated single quote")
        self.pos = close + 1
        return Literal(self.text[start + 1 : close], "'", (start, close + 1))

    def double(self, kind: str) -> list[Part]:
        # kind is '"' or '$"'; one Literal when every part inside is literal.
        start = self.pos
        self.pos += len(kind)
        inner = self.double_parts(heredoc=False, dash=False, kind=kind)
        if self.ch() != '"':
            raise _Syntax("unterminated double quote")
        self.pos += 1
        if all(isinstance(part, Literal) for part in inner):
            text = "".join(part.text for part in inner if isinstance(part, Literal))
            return [Literal(text, kind, (start, self.pos))]
        return inner

    def double_parts(self, heredoc: bool, dash: bool, kind: str = '"') -> list[Part]:
        parts = _Parts()
        escapes = "$`\\\n" if heredoc else '$`"\\\n'
        line_start = True
        while not self.eof():
            c = self.ch()
            here = self.pos
            if heredoc and dash and line_start and c == "\t":
                self.pos += 1
                continue
            line_start = False
            if c == '"' and not heredoc:
                break
            if c == "\\" and self.ch(1) in tuple(escapes):
                if self.ch(1) != "\n":
                    parts.char(self.ch(1), kind, here, here + 2)
                self.pos += 2
            elif c == "$" and self.ch(1) not in ("'", '"'):
                parts.add(self.dollar(kind))
            elif c == "`":
                parts.add(self.backtick(kind))
            else:
                parts.char(c, kind, here, here + 1)
                self.pos += 1
                line_start = c == "\n"
        return parts.done()

    def dollar(self, quoted: str) -> Part | list[Part]:
        start = self.pos
        nxt = self.ch(1)
        if self._continuation(self.pos + 1):
            raise _Syntax("line continuation after $")
        if nxt == "'" and not quoted:
            return self.ansi_c()
        if nxt == '"' and not quoted:
            return self.double('$"')
        if nxt == "(":
            if self.ch(2) == "(":
                end = self.arith_end(self.pos + 3)
                if end is not None:
                    self.pos = end
                    return Arith((start, end), quoted)
            self.pos += 2
            inner = self.substitution(")")
            return CommandSub(inner, (start, self.pos), quoted)
        if nxt == "{":
            return self.param_brace(quoted)
        if nxt == "[":
            close = self.bracket_end(self.pos + 1)
            self.pos = close
            return Opaque((start, close), "legacy arithmetic")
        name = _NAME.match(self.text, self.pos + 1, self.limit)
        if name is not None:
            self.pos = name.end()
            return Param(name.group(0), "", (start, self.pos), quoted)
        if nxt and (nxt.isdigit() or nxt in "@*#?$!-"):
            self.pos += 2
            return Param(nxt, "", (start, self.pos), quoted)
        self.pos += 1
        return Literal("$", quoted, (start, start + 1))

    def bracket_end(self, j: int) -> int:
        depth = 0
        while j < self.limit:
            c = self.text[j]
            if c == "[":
                depth += 1
            elif c == "]":
                depth -= 1
                if depth == 0:
                    return j + 1
            j += 1
        raise _Syntax("unclosed $[")

    def arith_end(self, j: int) -> int | None:
        # 228 R1: $(( and (( are arithmetic only when the matching close is a double paren.
        depth = 0
        while j < self.limit:
            c = self.text[j]
            if c == "\\":
                j += 2
                continue
            if c in "'\"":
                close = self.quote_end(j)
                if close is None:
                    return None
                j = close
                continue
            if c == "(":
                depth += 1
            elif c == ")":
                if depth == 0:
                    return j + 2 if self.text[j + 1 : j + 2] == ")" else None
                depth -= 1
            j += 1
        return None

    def substitution(self, close: str) -> Script:
        outer = self.outer or bool(self.pending)
        sub = _Parser(self.text, self.pos, self.limit, self.nest + 1, outer)
        script = sub.parse_list(frozenset({close}))
        if sub.ch() != close:
            raise _Syntax("unclosed $(")
        if sub.pending:
            raise _Syntax("heredoc without its body inside a substitution")
        self.pos = sub.pos + 1
        return script

    def procsub(self) -> ProcSub:
        start = self.pos
        direction = self.ch()
        self.pos += 2
        inner = self.substitution(")")
        return ProcSub(direction, inner, (start, self.pos))

    def backtick(self, quoted: str) -> CommandSub:
        start = self.pos
        j = start + 1
        while j < self.limit and self.text[j] != "`":
            j += 2 if self.text[j] == "\\" else 1
        if j >= self.limit:
            raise _Syntax("unterminated backtick")
        self.pos = j + 1
        span = (start, j + 1)
        if "\\" in self.text[start + 1 : j]:
            return CommandSub(Opaque((start + 1, j), "backslash inside backticks"), span, quoted)
        sub = _Parser(self.text, start + 1, j, self.nest + 1, False)
        try:
            script = sub.parse_list(frozenset())
            if sub.pos < j or sub.pending:
                raise _Syntax("unbounded backtick body")
        except (_Syntax, RecursionError) as exc:
            why = exc.why if isinstance(exc, _Syntax) else "nesting too deep"
            return CommandSub(Opaque((start + 1, j), why), span, quoted)
        return CommandSub(script, span, quoted)

    def param_brace(self, quoted: str) -> Part:
        start = self.pos
        close = self.brace_close(start + 2, quoted)
        self.pos = close + 1
        span = (start, close + 1)
        content = self.text[start + 2 : close]
        match = _PARAM.match(content)
        if match is None:
            return Opaque(span, "bad substitution")
        length, name, op = match.groups()
        if any(c in _PARAM_UNSAFE for c in op):
            return Opaque(span, "expansion inside a parameter operator")
        if length:
            if op:
                return Opaque(span, "length with an operator")
            return Param(name, "#", span, quoted)
        if op and op[0] not in _PARAM_OPS:
            return Opaque(span, "indirect or unknown parameter form")
        if op in ("#", "##", "%", "%%"):
            return Opaque(span, "empty pattern operator")
        return Param(name, op, span, quoted)

    def brace_close(self, j: int, quoted: str) -> int:
        # 228 R1: ${ closes at the first unquoted } outside a nested ${ (probed, not counted).
        while j < self.limit:
            c = self.text[j]
            if c == "\\":
                j += 2
                continue
            if c == "'":
                if quoted:
                    raise _Syntax("single quote inside ${ } in double quotes")
                close = self.quote_end(j)
                if close is None:
                    raise _Syntax("unterminated quote inside ${ }")
                j = close
                continue
            if c == '"':
                close = self.quote_end(j)
                if close is None or "$(" in self.text[j:close] or "`" in self.text[j:close]:
                    raise _Syntax("substitution or open quote inside ${ }")
                j = close
                continue
            if c == "`" or self.text.startswith("$(", j):
                raise _Syntax("substitution inside ${ }")
            if self.text.startswith("${", j):
                j = self.brace_close(j + 2, quoted) + 1
                continue
            if c == "}":
                return j
            j += 1
        raise _Syntax("unclosed ${")

    def ansi_c(self) -> Part:
        start = self.pos
        close = start + 2
        while close < self.limit and self.text[close] != "'":
            close += 2 if self.text[close] == "\\" else 1
        if close >= self.limit:
            raise _Syntax("unterminated $'")
        self.pos = close + 1
        out: list[str] = []
        j = start + 2
        while j < close:
            if self.text[j] != "\\":
                out.append(self.text[j])
                j += 1
                continue
            value, j = _ansi_escape(self.text, j + 1, close)
            if value is None:
                return Opaque((start, self.pos), "NUL, raw byte or bad escape inside $'...'")
            out.append(value)
        return Literal("".join(out), "$'", (start, self.pos))

    def brace(self, word_start: int) -> Part | None:
        # 228 R1: {a,b} and {1..3} expand; anything else at { is a literal brace.
        start = self.pos
        j = start + 1
        depth = 0
        commas: list[int] = []
        plain = True
        while j < self.limit:
            c = self.text[j]
            if c in _META:
                if c in "<>" and self.text[j + 1 : j + 2] == "(":
                    return self._brace_opaque(start)
                return None
            if c == "\\":
                plain = False
                j += 2
                continue
            if c in "'\"":
                plain = False
                close = self.quote_end(j)
                if close is None:
                    return None
                if c == '"' and ("$(" in self.text[j:close] or "`" in self.text[j:close]):
                    return self._brace_opaque(start)
                j = close
                continue
            if c == "`" or self.text.startswith(("$(", "$["), j):
                return self._brace_opaque(start)
            if self.text.startswith("${", j):
                plain = False
                j = self.brace_close(j + 2, "") + 1
                continue
            if c == "$":
                plain = False
            elif c == "{":
                depth += 1
            elif c == "}":
                if depth == 0:
                    break
                depth -= 1
            elif c == "," and depth == 0:
                commas.append(j)
            j += 1
        else:
            return None
        close = j
        if commas:
            bounds = [start, *commas, close]
            items = [
                self.sub_word(bounds[k] + 1, bounds[k + 1], brace=True, glob=True)
                for k in range(len(bounds) - 1)
            ]
            if start == word_start and any(item.raw.startswith("~") for item in items):
                return self._brace_opaque(start, close + 1, "tilde inside a brace list")
            self.pos = close + 1
            return BraceList(items, (start, close + 1))
        inner = self.text[start + 1 : close]
        if plain and _SEQUENCE.fullmatch(inner):
            ends = inner.split("..")
            items = []
            at = start + 1
            for end in ends:
                items.append(
                    Word(end, [Literal(end, "", (at, at + len(end)))], (at, at + len(end)))
                )
                at += len(end) + 2
            self.pos = close + 1
            return BraceList(items, (start, close + 1), sequence=True)
        return None

    def _brace_opaque(self, start: int, end: int = -1, why: str = "") -> Opaque:
        if end < 0:
            self.pos = start + 1
            return Opaque((start, start + 1), "brace with a substitution inside")
        self.pos = end
        return Opaque((start, end), why)

    def bracket(self) -> Part | None:
        start = self.pos
        j = start + 1
        if self.text[j : j + 1] in ("!", "^"):
            j += 1
        if self.text[j : j + 1] == "]":
            j += 1
        special = False
        while j < self.limit:
            c = self.text[j]
            if c in _META:
                return None
            if c == "]":
                self.pos = j + 1
                if special:
                    return Opaque((start, j + 1), "bracket expression with quoting")
                return Glob((start, j + 1))
            if c == "\\":
                special = True
                j += 2
                continue
            if c in "'\"":
                special = True
                close = self.quote_end(j)
                if close is None:
                    return None
                j = close
                continue
            if c in "$`":
                special = True
            j += 1
        return None

    def tilde(self, assign: bool) -> Part:
        start = self.pos
        j = start + 1
        stops = _META + "/" + (":" if assign else "")
        while j < self.limit and self.text[j] not in stops:
            j += 1
        user = self.text[start + 1 : j]
        if any(c in "'\"\\" for c in user):
            self.pos = start + 1
            return Literal("~", "", (start, start + 1))
        if not _USER.fullmatch(user):
            self.pos = start + 1
            return Opaque((start, start + 1), "tilde with an unusual prefix")
        self.pos = j
        return Tilde(user, (start, j))


def _ansi_escape(text: str, j: int, limit: int) -> tuple[str | None, int]:
    # 228 R1: one $'...' escape after its backslash; None for a NUL, a raw byte or a bad \c.
    if j >= limit:
        return None, j
    c = text[j]
    if c in _ANSI_SIMPLE:
        return _ANSI_SIMPLE[c], j + 1
    if c in "01234567":
        k = j
        while k < min(j + 3, limit) and text[k] in "01234567":
            k += 1
        return _code(int(text[j:k], 8), 0x80), k
    if c in "xuU":
        width = {"x": 2, "u": 4, "U": 8}[c]
        k = j + 1
        while k < min(j + 1 + width, limit) and text[k] in "0123456789abcdefABCDEF":
            k += 1
        if k == j + 1:
            return "\\" + c, k
        return _code(int(text[j + 1 : k], 16), 0x80 if c == "x" else 0x110000), k
    if c == "c":
        if j + 1 >= limit:
            return None, j + 1
        ctl = text[j + 1]
        if ctl == "?":
            return "\x7f", j + 2
        if ctl.isascii() and ctl.isalpha():
            return chr(ord(ctl.upper()) & 0x1F), j + 2
        return None, j + 2
    return "\\" + c, j + 1


def _code(value: int, ceiling: int) -> str | None:
    if value == 0 or value >= ceiling or 0xD800 <= value <= 0xDFFF:
        return None
    return chr(value)


def _delimiter(word: Word) -> tuple[str, bool]:
    # 228 R1: quote removal without expansion; a quoted part makes the body literal.
    out: list[str] = []
    quoted = False
    for part in word.parts:
        if not isinstance(part, Literal) or part.quoted in ("$'", '$"'):
            raise _Syntax("expansion-shaped heredoc delimiter")
        out.append(part.text)
        quoted = quoted or part.quoted != ""
    return "".join(out), quoted


def parse(text: str) -> Script:
    try:
        return _Parser(text, 0, len(text), 0, False).script()
    except Exception as exc:  # 228 R2: never raises on input text; a fault is one Opaque.
        span = (0, len(text))
        return Script([Opaque(span, f"parser fault: {type(exc).__name__}")], [""], span)


# -- helpers: the only API consumers read (228 R10) ----------------------------------------------
def command_words(cmd: Command) -> list[Word]:
    return list(cmd.words)


def assignments(cmd: Command) -> list[Assignment]:
    return list(cmd.assignments)


def redirect_targets(cmd: Command) -> list[Word]:
    # Every redirect target except a heredoc delimiter, which names no file.
    return [r.target for r in cmd.redirects if r.op not in ("<<", "<<-")]


def literal(word: Word) -> str | None:
    return word.literal


def expands(word: Word) -> bool:
    return word.expands


def children(node: Node) -> list[Node]:
    out: list[Node] = []
    if isinstance(node, Script):
        out.extend(node.items)
    elif isinstance(node, Pipeline):
        out.extend(node.commands)
    elif isinstance(node, Control):
        out.extend([node.name] if node.name is not None else [])
        out.extend(node.words)
        out.extend(node.redirects)
        for cond, body in node.clauses:
            out.extend([cond, body] if cond is not None else [body])
    elif isinstance(node, Command):
        out.extend(node.assignments)
        out.extend(node.words)
        out.extend(node.redirects)
    elif isinstance(node, Assignment):
        out.extend([node.subscript, node.value] if node.subscript is not None else [node.value])
    elif isinstance(node, Redirect):
        out.extend([node.fd] if isinstance(node.fd, Word) else [])
        out.append(node.target)
        out.extend([node.heredoc] if node.heredoc is not None else [])
    elif isinstance(node, Heredoc):
        out.extend(node.parts)
    elif isinstance(node, Word):
        out.extend(node.parts)
    elif isinstance(node, CommandSub | ProcSub):
        out.append(node.inner)
    elif isinstance(node, BraceList):
        out.extend(node.items)
    return out


def nodes(node: Node) -> Iterator[Node]:
    # Every node under node, itself first, depth first in source order.
    stack: list[Node] = [node]
    while stack:
        current = stack.pop()
        yield current
        stack.extend(reversed(children(current)))


def heredocs(script: Script) -> list[Heredoc | Opaque]:
    return [n.heredoc for n in nodes(script) if isinstance(n, Redirect) and n.heredoc is not None]


def substitutions(script: Script) -> list[CommandSub | ProcSub]:
    return [n for n in nodes(script) if isinstance(n, CommandSub | ProcSub)]


def opaque(script: Script) -> list[Opaque]:
    return [n for n in nodes(script) if isinstance(n, Opaque)]


def walk(script: Script) -> Iterator[tuple[Command, tuple[Control, ...]]]:
    # 228 R10: every Command in evaluation order; substitutions in its words run before it.
    yield from _walk(script, ())


def _walk(node: Node, chain: tuple[Control, ...]) -> Iterator[tuple[Command, tuple[Control, ...]]]:
    if isinstance(node, Command):
        kids: list[Node] = [*node.words, *node.redirects, *node.assignments]
        for kid in kids:
            yield from _walk(kid, chain)
        yield node, chain
        return
    if isinstance(node, Control):
        heads: list[Node] = [*node.words, *node.redirects]
        for head in heads:
            yield from _walk(head, chain)
        inner = (*chain, node)
        for cond, body in node.clauses:
            if cond is not None:
                yield from _walk(cond, inner)
            yield from _walk(body, inner)
        return
    for child in children(node):
        yield from _walk(child, chain)
