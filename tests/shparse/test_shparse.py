# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 228 R4: every fixture is compared to bash's recorded answer; no test runs bash (S1 accept).
from __future__ import annotations

import ast
import fnmatch
import json
import re
import time
from collections.abc import Iterator
from pathlib import Path

import pytest
from lib import shparse as sp

from tests.adversarial import corpus

FIXTURES = Path(__file__).resolve().parent / "fixtures"
MARK = "\x00procsub"
_FD_PATH = re.compile(r"/dev/fd/[0-9]+")
_IFS = re.compile(r"[ \t\n]+")
Fixture = dict[str, object]


class Unsupported(Exception):
    pass


class Stream:
    def __init__(self, data: str) -> None:
        self.data = data

    def read(self) -> str:
        data, self.data = self.data, ""
        return data


class Sim:
    # 228 R4: replays a parse with the probe's recorders, so the parse is judged by bash's answer.
    def __init__(self, doc: Fixture, text: str, meta: dict[str, str]) -> None:
        self.text = text
        self.positional = [str(v) for v in _list(doc["positional"])]
        self.name0 = str(doc["name0"])
        self.vars = {str(k): str(v) for k, v in _dict(doc["vars"]).items()}
        self.home = str(doc["home"])
        self.users = {str(k): str(v) for k, v in _dict(doc["users"]).items()}
        self.seeds = {str(k): str(v) for k, v in _dict(doc["seeds"]).items()}
        self.meta = meta
        self.status = 0
        self.records: list[list[str]] = []
        self.files: dict[str, str] = {}
        self.functions: dict[str, sp.Script] = {}
        self.next_fd = 10

    # -- execution ------------------------------------------------------------------------------
    def script(self, script: sp.Script | sp.Opaque, stdin: Stream, out: list[str]) -> int:
        if isinstance(script, sp.Opaque):
            raise Unsupported(script.why)
        run = True
        for item, sep in zip(script.items, script.separators, strict=True):
            if run:
                self.status = self.node(item, stdin, out)
            run = self.status == 0 if sep == "&&" else self.status != 0 if sep == "||" else True
        return self.status

    def node(self, node: sp.Item | sp.Command, stdin: Stream, out: list[str]) -> int:
        if isinstance(node, sp.Pipeline):
            status, data = 0, stdin
            for k, cmd in enumerate(node.commands):
                sink = out if k == len(node.commands) - 1 else []
                status = self.node(cmd, data, sink)
                data = Stream("".join(sink))
            return int(status == 0) if node.negated else status
        if isinstance(node, sp.Command):
            return self.command(node, stdin, out)
        if isinstance(node, sp.Control):
            return self.control(node, stdin, out)
        raise Unsupported(node.why)

    def redirects(
        self, redirects: list[sp.Redirect], stdin: Stream, out: list[str]
    ) -> tuple[Stream, list[str]]:
        for r in redirects:
            reads = r.fd in (None, 0)
            if r.op in ("<<", "<<-"):
                stdin = Stream(self.heredoc(r.heredoc)) if reads else stdin
            elif r.op == "<<<":
                stdin = Stream(self.string(r.target) + "\n") if reads else stdin
            elif r.op == "<":
                name = self.string(r.target)
                stdin = Stream(self.files.get(name, self.seeds.get(name, ""))) if reads else stdin
            elif r.op in ("<&", ">&") and re.fullmatch(r"[0-9]+|-", self.string(r.target)):
                pass
            else:
                name = self.string(r.target)
                if r.op in (">", ">|", "&>", ">&"):
                    self.files[name] = ""
                else:
                    self.files.setdefault(name, "")
                if r.fd in (None, 1) and r.op != "<>":
                    out = _FileSink(self.files, name)
            if isinstance(r.fd, sp.Word):
                self.vars[str(r.fd.raw[1:-1])] = str(self.next_fd)
                self.next_fd += 1
        return stdin, out

    def command(self, cmd: sp.Command, stdin: Stream, out: list[str]) -> int:
        words = [field for word in cmd.words for field in self.fields(word)]
        stdin, out = self.redirects(cmd.redirects, stdin, out)
        if not words:
            for a in cmd.assignments:
                self.vars[a.name] = self.string(a.value)
            return 0
        name, args = words[0], words[1:]
        if name in ("p", "f"):
            self.records.append([*args, stdin.read()])
            return 0 if name == "p" else 1
        if name == "echo":
            out.append(" ".join(args) + "\n")
            return 0
        if name in ("true", "false"):
            return int(name == "false")
        if name in self.functions:
            saved, self.positional = self.positional, args
            try:
                return self.script(self.functions[name], stdin, out)
            finally:
                self.positional = saved
        raise Unsupported(f"command {name}")

    def control(self, node: sp.Control, stdin: Stream, out: list[str]) -> int:
        stdin, out = self.redirects(node.redirects, stdin, out)
        if node.kind in ("group", "subshell"):
            saved = dict(self.vars)
            status = self.script(node.clauses[0][1], stdin, out)
            if node.kind == "subshell":
                self.vars = saved
            return status
        if node.kind == "if":
            for cond, body in node.clauses:
                if cond is None or self.script(cond, stdin, out) == 0:
                    return self.script(body, stdin, out)
            return 0
        if node.kind in ("while", "until"):
            cond, body = node.clauses[0]
            for _ in range(5):
                assert cond is not None
                if (self.script(cond, stdin, out) == 0) != (node.kind == "while"):
                    break
                self.script(body, stdin, out)
            return 0
        if node.kind == "for" and node.name is not None:
            for value in [f for w in node.words for f in self.fields(w)]:
                self.vars[node.name.raw] = value
                self.script(node.clauses[0][1], stdin, out)
            return 0
        if node.kind == "function" and node.name is not None:
            self.functions[node.name.raw] = node.clauses[0][1]
            return 0
        raise Unsupported(node.kind)

    def heredoc(self, doc: sp.Heredoc | sp.Opaque | None) -> str:
        if not isinstance(doc, sp.Heredoc):
            raise Unsupported("heredoc")
        if doc.quoted:
            return doc.body
        return "".join(self.part_text(part) for part in doc.parts)

    # -- words ----------------------------------------------------------------------------------
    def value(self, name: str) -> str | None:
        if name.isdigit():
            k = int(name)
            return self.name0 if k == 0 else (self.positional + [None] * k)[k - 1]
        specials = {"#": str(len(self.positional)), "?": str(self.status)}
        specials.update(self.meta)
        if name in specials:
            return specials[name]
        return None if name == "!" else self.vars.get(name)

    def param(self, part: sp.Param) -> str:
        v = self.value(part.name)
        op = part.op
        if op == "":
            return v or ""
        if op == "#":
            return str(len(v or ""))
        if op.startswith(":-"):
            return v if v else op[2:]
        if op.startswith("-"):
            return op[1:] if v is None else v
        if op.startswith(":+"):
            return op[2:] if v else ""
        if op.startswith("+"):
            return op[1:] if v is not None else ""
        raise Unsupported(op)

    def part_text(self, part: sp.Part) -> str:
        # The text of one part in a quoted context: no splitting, no glob.
        if isinstance(part, sp.Literal):
            return part.text
        if isinstance(part, sp.Param):
            if part.name in ("@", "*"):
                return " ".join(self.positional)
            return self.param(part)
        if isinstance(part, sp.CommandSub):
            sink: list[str] = []
            self.script(part.inner, Stream(""), sink)
            return "".join(sink).rstrip("\n")
        if isinstance(part, sp.ProcSub):
            self.script(part.inner, Stream(""), [])
            return MARK
        if isinstance(part, sp.Arith):
            return str(_arith(self.text[part.span[0] + 3 : part.span[1] - 2], self.vars))
        if isinstance(part, sp.Tilde):
            home = self.home if part.user == "" else self.users.get(part.user)
            return "~" + part.user if home is None else home
        raise Unsupported(type(part).__name__)

    def string(self, word: sp.Word) -> str:
        return "".join(self.part_text(part) for part in word.parts)

    def fields(self, word: sp.Word) -> list[str]:
        return [f for parts in self.braces(word.parts) for f in self.expand(parts)]

    def braces(self, parts: list[sp.Part]) -> list[list[sp.Part]]:
        seqs: list[list[sp.Part]] = [[]]
        for part in parts:
            if not isinstance(part, sp.BraceList):
                seqs = [[*s, part] for s in seqs]
                continue
            alts: list[list[sp.Part]] = []
            if part.sequence:
                for text in _sequence([str(item.literal) for item in part.items]):
                    alts.append([sp.Literal(text, "", part.span)])
            else:
                for item in part.items:
                    alts.extend(self.braces(item.parts))
            seqs = [[*s, *a] for s in seqs for a in alts]
        return seqs

    def expand(self, parts: list[sp.Part]) -> list[str]:
        fields: list[list[tuple[str, bool]]] = [[]]
        real = [False]

        def add(text: str, glob: bool = False, quoted: bool = False) -> None:
            fields[-1].append((text, glob))
            real[-1] = real[-1] or quoted or bool(text)

        def cut() -> None:
            if real[-1]:
                fields.append([])
                real.append(False)

        def split(value: str) -> None:
            for k, piece in enumerate(_IFS.split(value)):
                if k:
                    cut()
                add(piece)

        for part in parts:
            quoted = getattr(part, "quoted", "") != ""
            if isinstance(part, sp.Glob):
                add(self.text[part.span[0] : part.span[1]], glob=True)
            elif isinstance(part, sp.Param) and part.name in ("@", "*"):
                if quoted and part.name == "*":
                    add(" ".join(self.positional), quoted=True)
                    continue
                for k, value in enumerate(self.positional):
                    if k and quoted:
                        fields.append([])
                        real.append(False)
                    elif k:
                        cut()
                    add(value, quoted=True) if quoted else split(value)
            elif isinstance(part, sp.Literal | sp.Tilde | sp.ProcSub):
                add(self.part_text(part), quoted=quoted or not isinstance(part, sp.Literal))
            elif quoted:
                add(self.part_text(part), quoted=True)
            else:
                split(self.part_text(part))
        out: list[str] = []
        for field, keep in zip(fields, real, strict=True):
            if not keep:
                continue
            joined = "".join(text for text, _ in field)
            if any(glob for _, glob in field):
                pattern = "".join(t if g else _escape(t) for t, g in field)
                hits = sorted(
                    n
                    for n in self.seeds
                    if fnmatch.fnmatchcase(n, pattern) and (pattern[0] == "." or n[0] != ".")
                )
                out.extend(hits or [joined])
            else:
                out.append(joined)
        return out


class _FileSink(list[str]):
    # Output redirected to a file the simulation tracks.
    def __init__(self, files: dict[str, str], name: str) -> None:
        super().__init__()
        self.files, self.name = files, name

    def append(self, text: str) -> None:
        self.files[self.name] = self.files.get(self.name, "") + text


def _list(value: object) -> list[object]:
    assert isinstance(value, list)
    return value


def _dict(value: object) -> dict[object, object]:
    assert isinstance(value, dict)
    return value


def _escape(text: str) -> str:
    return "".join(f"[{c}]" if c in "*?[" else c for c in text)


def _sequence(ends: list[str]) -> list[str]:
    step = abs(int(ends[2])) if len(ends) > 2 else 1
    first, last = ends[0], ends[1]
    if first.isalpha():
        a, b = ord(first), ord(last)
        rng = range(a, b + 1, step) if a <= b else range(a, b - 1, -step)
        return [chr(c) for c in rng]
    a, b = int(first), int(last)
    width = max(len(first), len(last)) if first.startswith("0") or last.startswith("0") else 0
    rng = range(a, b + 1, step) if a <= b else range(a, b - 1, -step)
    return [str(n).zfill(width) for n in rng]


def _arith(expr: str, names: dict[str, str]) -> int:
    def walk(node: ast.expr) -> int:
        if isinstance(node, ast.Constant) and isinstance(node.value, int):
            return node.value
        if isinstance(node, ast.Name):
            return int(names.get(node.id, "0") or "0")
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.USub):
            return -walk(node.operand)
        if isinstance(node, ast.BinOp):
            a, b = walk(node.left), walk(node.right)
            ops = {ast.Add: a + b, ast.Sub: a - b, ast.Mult: a * b}
            if type(node.op) in ops:
                return ops[type(node.op)]
        raise Unsupported(ast.dump(node))

    return walk(ast.parse(expr.strip(), mode="eval").body)


def _norm(value: object) -> object:
    if isinstance(value, str):
        return _FD_PATH.sub(MARK, value)
    if isinstance(value, list):
        return [_norm(v) for v in value]
    return value


def _fixtures() -> Iterator[object]:
    for path in sorted(FIXTURES.glob("*.json")):
        doc = json.loads(path.read_text())
        for case in doc["cases"]:
            yield pytest.param(doc, case, id=f"{doc['group']}-{case['name']}")


@pytest.mark.parametrize(("doc", "case"), list(_fixtures()))
def test_fixture_matches_bash(doc: Fixture, case: dict[str, object]) -> None:
    # 228 R4: the parse replayed with the probe's recorders gives bash's own answer.
    answer = _dict(case["answer"])
    text = str(case["text"])
    words = case["kind"] == "words"
    full = str(doc["prefix"]) + text if words else text
    script = sp.parse(full)
    whys = [o.why for o in sp.opaque(script)]
    if "opaque" in case:
        assert any(str(case["opaque"]) in why for why in whys), whys
        return
    assert not whys, whys
    assert answer["status"] == 0 and not answer["syntax_error"]
    meta = {str(k): str(v) for k, v in _dict(answer.get("meta", {})).items()}
    sim = Sim(doc, full, meta)
    if words:
        assert len(script.items) == 1
        item = script.items[0]
        assert isinstance(item, sp.Pipeline) and len(item.commands) == 1
        cmd = item.commands[0]
        assert isinstance(cmd, sp.Command)
        got = [f for word in cmd.words[4:] for f in sim.fields(word)]
        assert got == _norm(answer["argv"])
        return
    out: list[str] = []
    sim.script(script, Stream(""), out)
    assert sorted(_norm(sim.records)) == sorted(_norm(answer["records"]))  # type: ignore[type-var]
    assert sim.files == answer["files"]
    assert "".join(out) == answer["stdout"]


def test_every_group_probed_by_one_bash() -> None:
    docs = [json.loads(p.read_text()) for p in sorted(FIXTURES.glob("*.json"))]
    assert {d["group"] for d in docs} >= {"quotes", "operators", "heredoc", "redirects", "hunt"}
    assert len({d["bash"] for d in docs}) == 1
    assert all(d["bash"].startswith("GNU bash, version 5.2") for d in docs)


FAILURES = (
    ("echo 'abc", "unterminated single quote"),
    ('echo "abc', "unterminated double quote"),
    ("echo `abc", "unterminated backtick"),
    ("echo $(abc", "unclosed $("),
    ("echo ${x", "unclosed ${"),
    ("(echo a", "unclosed ("),
    ("{ echo a", "expected }"),
    ("if a; then b", "expected fi"),
    ("case a in a) b;;", "unclosed case"),
    ("cat <<E\nbody", "missing heredoc delimiter line"),
    ("cat <<E", "missing heredoc delimiter line"),
    ("((x++))", "arithmetic command"),
    ("[[ -f x ]]", "conditional command"),
    ("coproc cat", "coproc"),
    ("echo a ;; b", ";; outside case"),
    ("echo a &\\\n& b", "line continuation inside an operator"),
    ("echo $[1]", "legacy arithmetic"),
    ("echo ${!x}", "indirect or unknown parameter form"),
    ("echo a | | b", "unexpected"),
    ("echo (a)", "unexpected"),
    ("x=(1 2)", "array assignment"),
    ("echo " + "$(" * 80 + "x" + ")" * 80, "nesting too deep"),
)


@pytest.mark.parametrize(("text", "why"), FAILURES)
def test_failure_shape_is_opaque(text: str, why: str) -> None:
    # 228 R2: every failure is an Opaque node with its one-line why, never an exception.
    found = sp.opaque(sp.parse(text))
    assert any(why in o.why for o in found), [o.why for o in found]
    assert all("\n" not in o.why for o in found)


def test_word_holding_an_opaque_expands() -> None:
    # 228 R2: a Word holding an Opaque has expands True and literal None.
    script = sp.parse("echo ${!x} a=(1)")
    cmd = next(c for c, _ in sp.walk(script))
    word = cmd.words[1]
    assert any(isinstance(p, sp.Opaque) for p in word.parts)
    assert sp.expands(word) and sp.literal(word) is None and "opaque" in word.kinds


def test_helpers_read_the_model() -> None:
    # 228 R10: walk order, enclosing chain, substitutions, heredocs anywhere, typed targets.
    # 228 R1: the first newline reads both pending bodies in operator order, E then F.
    text = "A=1 B+=2 cat <<E >out 2>&1 | (grep $(id -u) <<'F'\nbody\nE\nx\nF\n)"
    script = sp.parse(text)
    walked = [
        (sp.command_words(c)[0].literal, [k.kind for k in chain]) for c, chain in sp.walk(script)
    ]
    assert walked == [("cat", []), ("id", ["subshell"]), ("grep", ["subshell"])]
    first = next(c for c, _ in sp.walk(script))
    assert [a.name for a in sp.assignments(first)] == ["A", "B"]
    assert [a.op for a in sp.assignments(first)] == ["=", "+="]
    assert [w.literal for w in sp.redirect_targets(first)] == ["out", "1"]
    docs = sp.heredocs(script)
    assert [d.body for d in docs if isinstance(d, sp.Heredoc)] == ["body\n", "x\n"]
    assert [text[s.span[0] : s.span[1]] for s in sp.substitutions(script)] == ["$(id -u)"]
    assert not sp.opaque(script)


def test_spans_quote_the_text() -> None:
    # 228 R6: every node's span slices the exact characters it was read from.
    text = "x=$'a' cmd \"b $c\" {d,e} >f <<-G\n\tbody\n\tG"
    script = sp.parse(text)
    for node in sp.nodes(script):
        span = getattr(node, "span", None)
        assert span is not None and 0 <= span[0] <= span[1] <= len(text)
    cmd = next(c for c, _ in sp.walk(script))
    assert [text[w.span[0] : w.span[1]] for w in cmd.words] == ["cmd", '"b $c"', "{d,e}"]
    assert all(w.raw == text[w.span[0] : w.span[1]] for w in cmd.words)


def _strings(value: object) -> Iterator[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, tuple | list | frozenset | set):
        for item in value:
            yield from _strings(item)
    elif isinstance(value, dict):
        for key, item in value.items():
            yield from _strings(key)
            yield from _strings(item)


def _corpus_rows() -> list[str]:
    rows: list[str] = []
    for name in dir(corpus):
        if name.isupper():
            rows.extend(_strings(getattr(corpus, name)))
    return sorted(set(rows))


CORPUS = _corpus_rows()


def _gap_ok(gap: str) -> bool:
    i = 0
    while i < len(gap):
        if gap[i] == "#":
            end = gap.find("\n", i)
            i = len(gap) if end < 0 else end
        elif gap.startswith("\\\n", i):
            i += 2
        elif gap[i] in " \t\n;&|":
            i += 1
        else:
            return False
    return True


def test_corpus_is_collected() -> None:
    assert len(CORPUS) > 500


@pytest.mark.parametrize("text", CORPUS)
def test_corpus_row_parses_and_tiles(text: str) -> None:
    # 228 S1: no exception, a Script, and item plus heredoc spans tile the text.
    script = sp.parse(text)
    assert isinstance(script, sp.Script)
    spans = sorted([item.span for item in script.items] + [h.span for h in sp.heredocs(script)])
    pos = 0
    for start, end in spans:
        assert start >= 0 and end <= len(text)
        if start > pos:
            assert _gap_ok(text[pos:start]), (text, text[pos:start])
        pos = max(pos, end)
    assert _gap_ok(text[pos:]), (text, text[pos:])


def test_ten_longest_corpus_rows_parse_inside_budget() -> None:
    # 228 R7: under 50 ms each, best of three.
    for text in sorted(CORPUS, key=len)[-10:]:
        best = min(_timed(text) for _ in range(3))
        assert best < 0.05, (len(text), best)


def test_four_kilobyte_command_parses_inside_budget() -> None:
    text = "; ".join(f"git add -- 'dir {k}/a b' \"$X\" {{a,b}} >>log{k} 2>&1" for k in range(90))
    assert len(text) >= 4096
    assert min(_timed(text) for _ in range(3)) < 0.05


def _timed(text: str) -> float:
    start = time.perf_counter()
    sp.parse(text)
    return time.perf_counter() - start
