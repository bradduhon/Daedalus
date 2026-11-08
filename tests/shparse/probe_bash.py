# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 228 R4: operator script; runs every probe case through bash once and writes the fixtures.
# A words case runs PREFIX + text; a run case defines the recorders p and f, then runs the text
# in a temporary folder and keeps the records and the files it made. Tests never run bash.
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

FIXTURES = Path(__file__).resolve().parent / "fixtures"
PREFIX = 'bash -c \'printf "%s\\0" "$#" "$@"\' _ '
NAME0 = "probe0"
POSITIONAL = ["one", "two", "three", "four", "five", "six", "seven", "eight", "nine", "ten", "elf"]
HOME = "/nonexistent/hdir"
VARS = {"x": "vx", "s": "a b"}
SEEDS = {"a1": "A1\n", "a2": "A2\n", "bb": "BB\n", ".h": "H\n"}
# 228 R4: p records its words and its stdin; f records, then fails; echo is the bash builtin.
DEFS = (
    'p() { printf \'%s\\0\' "$#" "$@" "$(cat; printf .)" >>"$LOG"; }\nf() { p "$@"; return 1; }\n'
)

Case = tuple[str, str, str, str]
W, R = "words", "run"

GROUPS: dict[str, list[Case]] = {
    "quotes": [
        ("backslash", W, "a\\ b \\$x \\\\ \\' \\\"", ""),
        ("backslash-glob", W, "a\\* \\[a]", ""),
        ("single", W, "'a b' 'it'\\''s' '$x' '\\n'", ""),
        ("single-newline", W, "'a\nb' c", ""),
        ("double", W, '"a b" "\\$x \\" \\\\ \\a" "x$1y"', ""),
        ("double-dollar-quotes", W, '"$\'x\'" "a$"x""', ""),
        ("ansi-c", W, "$'a\\tb' $'\\x41\\101\\u00e9' $'a\\'b' $'\\cA\\e\\z'", ""),
        ("ansi-c-more", W, "$'\\c?' $'\\x4' $'\\u' $'\\?\\\"'", ""),
        ("ansi-c-nul", W, "$'a\\0b'", "NUL, raw byte"),
        ("ansi-c-raw-byte", W, "$'\\x80'", "NUL, raw byte"),
        ("locale", W, '$"x y" $"a$1"', ""),
        ("mixed", W, "a'b'\"c\"$'d'$\"e\"\\f", ""),
        ("trailing-backslash", W, "a\\", ""),
        ("unterminated-single", W, "'abc", "unterminated single quote"),
        ("unterminated-double", W, '"abc', "unterminated double quote"),
        ("unterminated-ansi", W, "$'abc", "unterminated $'"),
    ],
    "splitting": [
        ("blanks", W, "a  b\t\tc", ""),
        ("continuation-in-word", W, "a\\\nb c", ""),
        ("continuation-between", W, "a \\\n b", ""),
        ("comment-at-word-start", W, "a #b c", ""),
        ("hash-inside-word", W, "a#b c#", ""),
        ("hash-escaped", W, "\\#a '#b' \"#c\" $'#d'", ""),
        ("hash-after-continuation", W, "x\\\n#y", ""),
        ("meta-semicolon", R, "p a;p b", ""),
        ("meta-pipe", R, "p a|p b", ""),
        ("meta-amp", R, "p a&p b", ""),
        ("meta-redirect", R, "p a>x", ""),
        ("meta-paren", R, "p a;(p b)", ""),
        ("comment-after-separator", R, "p a;#p b\np c", ""),
    ],
    "operators": [
        ("semicolon", R, "p a; p b", ""),
        ("and", R, "p a && p b", ""),
        ("and-fail", R, "f a && p b", ""),
        ("or", R, "p a || p b", ""),
        ("or-fail", R, "f a || p b", ""),
        ("and-or", R, "p a && f b || p c", ""),
        ("pipe", R, "p a | p b", ""),
        ("pipe-stderr", R, "p a |& p b", ""),
        ("background", R, "p a & p b", ""),
        ("newline", R, "p a\np b", ""),
        ("newline-after-and", R, "p a &&\n\np b", ""),
        ("newline-after-pipe", R, "p a |\np b", ""),
        ("negation", R, "! f a && p b", ""),
        ("double-negation", R, "! ! p a && p b", ""),
        ("time", R, "time p a; p b", ""),
        ("echo-pipe", R, "echo a b | p c", ""),
        ("double-semicolon", R, "p a;; p b", ";; outside case"),
        ("amp-semicolon", R, "p a & ; p b", "unexpected"),
        ("dangling-pipe", R, "p a |", "missing command after |"),
        ("continued-operator", R, "p a &\\\n& p b", "line continuation inside an operator"),
    ],
    "reserved": [
        ("reserved-as-args", W, "if then fi { } done do esac", ""),
        ("if", R, "if p a; then p b; fi", ""),
        ("if-elif-else", R, "if f a; then p b; elif f c; then p d; else p e; fi", ""),
        ("group", R, "{ p a; p b; }", ""),
        ("group-glued-close", R, "{ p a;}", ""),
        ("group-close-is-arg", R, "{ p a}; }", ""),
        ("group-unclosed", R, "{ p a }", "expected }"),
        ("subshell", R, "( p a ); (p b)", ""),
        ("for", R, "for v in a b; do p $v; done", ""),
        ("for-newline", R, "for v in a b\ndo p $v\ndone", ""),
        ("while", R, "while f a; do p b; done", ""),
        ("until", R, "until p a; do p b; done", ""),
        ("brace-command-word", R, "{p,a}", ""),
        ("reserved-after-assignment", R, "v=1 p if", ""),
        ("stray-close", R, "p a; }", "unexpected }"),
        ("stray-fi", R, "p a; fi", "unexpected fi"),
        ("function", R, 'g() { p a "$1"; }; g b', ""),
        ("function-keyword", R, "function g { p a; }; g", ""),
        ("case", R, "case a in a) p 1;; *) p 2;; esac; p 3", "case clause"),
        ("conditional", R, "[[ a == a ]] && p b", "conditional command"),
        ("arith-command", R, "(( 1 )) && p b", "arithmetic command"),
        ("coproc", R, "coproc p a </dev/null", "coproc"),
        ("negation-after-pipe", R, "p a | ! p b", "unexpected !"),
    ],
    "heredoc": [
        ("plain", R, "p <<E\nbody\nE", ""),
        ("unquoted-expands", R, "p <<E\n$1 \\$1 ${x}\nE", ""),
        ("unquoted-backtick", R, "p <<E\n`p q`\nE", ""),
        ("single-quoted", R, "p <<'E'\n$1 \\$1\nE", ""),
        ("double-quoted", R, 'p <<"E"\n$1\nE', ""),
        ("backslash-quoted", R, "p <<\\E\n$1\nE", ""),
        ("backslash-inside", R, "p <<E\\OF\n$1\nEOF", ""),
        ("double-backslash", R, 'p <<"E\\OF"\nline\nEOF\nE\\OF', ""),
        ("dash-tabs", R, "p <<-E\n\tx\n\t\ty\n\tE", ""),
        ("tab-without-dash", R, "p <<E\n\tE\nE", ""),
        ("in-subshell", R, "(p <<E\ninner\nE\n)", ""),
        ("in-group", R, "{ p <<E\ninner\nE\n}", ""),
        ("in-command-sub", R, 'p "$(p <<E\ninner\nE\n)"', ""),
        ("in-command-sub-unquoted", R, "p $(p <<E\ninner\nE\n)", ""),
        ("two-on-a-line", R, "p <<E; p <<F\na\nE\nb\nF", ""),
        ("before-pipe", R, "p <<E | p b\nx\nE", ""),
        ("before-and-newline", R, "p <<E &&\nx\nE\np b", ""),
        ("quote-spans-newline", R, "p <<E; p 'a\nb'\nbody\nE", ""),
        ("newline-in-command-sub", R, "p <<E; p $(p a\np b)\nbody\nE", ""),
        ("even-backslashes", R, "p <<E\na\\\\\nE", ""),
        ("odd-backslashes", R, "p <<E\na\\\\\\\nE\nE", "line continuation in an unquoted heredoc"),
        ("delimiter-glued-paren", R, "p $(p <<E\nx\nE)", "unclosed $("),
        ("missing-delimiter", R, "p <<E\nbody", "missing heredoc delimiter line"),
        ("here-string", R, "p <<<'hi' ; p 0<<<x", ""),
        ("in-case", R, "case a in a) p <<E;; esac\nx\nE", "heredoc body after a case"),
    ],
    "redirects": [
        ("out", R, "p a >x", ""),
        ("append", R, "p a >>x", ""),
        ("clobber", R, "p a >|x", ""),
        ("stderr", R, "p a 2>y", ""),
        ("both", R, "p a &>z", ""),
        ("both-append", R, "p a &>>z", ""),
        ("space-before-fd", R, "p a 2 >y", ""),
        ("dup", R, "p a 2>&1 >&2", ""),
        ("named-fd", R, '{fd}>x p a "$fd"', ""),
        ("named-fd-after", R, "p a {fd}>x", ""),
        ("named-fd-spaced", R, "p {fd} >x", ""),
        ("input", R, "p <a1", ""),
        ("read-write", R, "p a <>w", ""),
        ("digit-before-amp", R, "p 2&>x", ""),
        ("glued", R, "p a>x b", ""),
        ("high-fd", R, "p a 10>x", ""),
        ("spaced-target", R, "p a > x", ""),
        ("missing-target", R, "p a >", "missing target"),
        ("group-redirect", R, "{ p a; } >x", ""),
    ],
    "expansions": [
        ("positional", W, "$1 $2 ${10} $10 ${11}", ""),
        ("specials", W, '$# $0 "$@" $@ "$*" $* $? $- $$ $!', ""),
        ("vars", W, '$x ${x} ${x:-d} ${u:-d} ${u-d} ${x:+y} ${#x} $s "$s"', ""),
        ("arith", W, "$((1+2)) $((2*(3+4)))", ""),
        ("arith-before-command-sub", W, "$( (echo a) ) $((echo b) )", ""),
        ("command-sub", W, '$(echo x) "$(echo "a b")" `echo c`', ""),
        ("legacy-arith", W, "$[1+1]", "legacy arithmetic"),
        ("indirect", W, "${!x}", "indirect or unknown"),
        ("op-with-quote", W, '"${x:-"a b"}"', "expansion inside a parameter operator"),
        ("op-with-tilde", W, "${u:-~}", "expansion inside a parameter operator"),
        ("brace-close-first", W, "${u-{}x}", ""),
        ("braces", W, '{a,b}c {1..3} {a} {} {a,"b c"} a{,b} {a..c} {1..5..2} {x,{y,z}}', ""),
        ("braces-more", W, "{01..03} {c..a} {a,b {a..} {a,b}{c,d}", ""),
        ("braces-quoted", W, '"{a,b}" \\{a,b} {a\\,b} {$x,b}', ""),
        ("brace-with-command-sub", W, "{a,$(echo b)}", "brace with a substitution"),
        ("globs", W, "a* ?b [ab]1 [!a]1 x*", ""),
        ("glob-quoted", W, '"a*" a\\* [ x]', ""),
        ("glob-all", W, "*", ""),
        ("tilde", W, '~ ~/a ~root ~"root" ~nosuch x~', ""),
        ("tilde-assignment-shaped", W, 'a=~/x a=x:~/y a+=~ "a"=~ a=b=~ =~ b:~/y', ""),
        ("tilde-unusual", W, "~a*", "tilde with an unusual prefix"),
        ("process-sub", W, "<(true) a>(true) 2>(true)", ""),
        ("assignment-tilde", R, 'v=~/a:~/b; p "$v"', ""),
    ],
    "hunt": [
        ("quote-in-delimiter", R, "p <<E'F'\n$1\nEF", ""),
        ("comment-char-in-word", R, "p a#b #c", ""),
        ("brace-glued-to-word", R, "p }a {a; { p b;}", ""),
        ("space-before-fd", R, "p a 2 >y 3>z", ""),
        ("command-sub-in-double", R, 'p "$(p a)b"', ""),
        ("backtick-in-command-sub", R, "p $(p `p a`)", ""),
        ("amp-redirect-after-word", R, "p a&>x", ""),
        ("pipe-amp", R, "p a|&p b", ""),
        ("double-semicolon", R, "p a ;; p b", ";; outside case"),
        ("newline-in-single", R, "p 'a\nb'", ""),
        ("continuation-before-fd", R, "p a 2\\\n>y", "line continuation before a redirect"),
        ("continuation-after-dollar", W, "$\\\nx", "line continuation after $"),
        ("subscript-with-blank", R, "a[x y]=1 p", "subscript with blanks"),
        ("array-assignment", R, "a=(1 2) p", "array assignment"),
        ("backtick-backslash", W, "`echo a\\`echo b\\``", "backslash inside backticks"),
        ("unclosed-paren", R, "(p a", "unclosed ("),
        ("unclosed-command-sub", W, "$(echo a", "unclosed $("),
        ("arith-for", R, "for ((i=0;i<1;i++)); do p a; done", "arithmetic for loop"),
        ("quote-nest", R, "p \"a'b\" 'c\"d' $'\\''", ""),
        ("escaped-newline-in-double", R, 'p "a\\\nb"', ""),
        ("escaped-blank", R, 'p a\\ b a"  "b', ""),
        ("glued-and-or", R, "p a&&f b||p c", ""),
        ("reserved-as-condition-args", R, "if p then; then p fi; fi", ""),
        ("reserved-in-for-list", R, "for v in do done; do p $v; done", ""),
        ("delimiter-trailing-blank", R, "p <<E\nx\nE \nE", ""),
        ("delimiter-as-prefix", R, "p <<E\nEE\nE", ""),
        ("partly-quoted-delimiter", R, 'p <<E"F"G\n$1\nEFG', ""),
        ("hash-after-dollar", W, "$# ${#} a$#b", ""),
        ("hash-in-brace", W, "{a,#b}", ""),
        ("open-brace-glued-paren", R, "{(p a);}", ""),
        ("named-fd-quoted", R, 'p "{fd}">x', ""),
        ("named-fd-bad-name", R, "p {1x}>x", ""),
        ("arith-nested-parens", W, "$(( (1+2)*3 ))", ""),
        ("command-sub-of-subshells", W, "$((echo a);(echo b))", ""),
    ],
}


def bash_version() -> str:
    done = subprocess.run(["bash", "--version"], capture_output=True, text=True, check=True)
    return done.stdout.splitlines()[0]


def _env(log: str, meta: str) -> dict[str, str]:
    return {"PATH": "/usr/bin:/bin", "HOME": HOME, "LC_ALL": "C.UTF-8", "LOG": log, "META": meta}


def _fields(raw: bytes) -> list[str]:
    return raw.decode("utf-8", "backslashreplace").split("\0")[:-1]


def _records(raw: bytes) -> list[list[str]]:
    fields = _fields(raw)
    out: list[list[str]] = []
    i = 0
    while i < len(fields):
        count = int(fields[i])
        out.append([*fields[i + 1 : i + 1 + count], fields[i + 1 + count][:-1]])
        i += count + 2
    return out


def _seed(folder: Path) -> None:
    for name, body in SEEDS.items():
        (folder / name).write_text(body)


def _files(folder: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    for path in sorted(folder.iterdir()):
        body = path.read_text(errors="backslashreplace")
        if SEEDS.get(path.name) != body:
            out[path.name] = body
    return out


def probe(kind: str, text: str) -> dict[str, object]:
    with tempfile.TemporaryDirectory() as work, tempfile.TemporaryDirectory() as side:
        folder = Path(work)
        _seed(folder)
        log, meta = os.path.join(side, "log"), os.path.join(side, "meta")
        Path(log).write_bytes(b"")
        if kind == W:
            script = 'printf \'%s\\0\' "$$" "$-" >"$META"; ' + PREFIX + text
        else:
            script = DEFS + text + "\nwait"
        env = {**_env(log, meta), **VARS}
        argv = ["bash", "--noprofile", "--norc", "-c", script, NAME0, *POSITIONAL]
        done = subprocess.run(
            argv, cwd=folder, env=env, stdin=subprocess.DEVNULL, capture_output=True, timeout=20
        )
        stderr = done.stderr.decode("utf-8", "backslashreplace")
        answer: dict[str, object] = {
            "status": done.returncode,
            "syntax_error": "syntax error" in stderr or "unexpected end of file" in stderr,
        }
        if kind == W:
            out = _fields(done.stdout)
            answer["argv"] = out[1 : 1 + int(out[0])] if out else []
            metas = _fields(Path(meta).read_bytes()) if os.path.exists(meta) else []
            answer["meta"] = {"$": metas[0], "-": metas[1]} if metas else {}
        else:
            answer["records"] = _records(Path(log).read_bytes())
            answer["stdout"] = done.stdout.decode("utf-8", "backslashreplace")
            answer["files"] = _files(folder)
        return answer


def main() -> int:
    FIXTURES.mkdir(parents=True, exist_ok=True)
    version = bash_version()
    users = {"root": os.path.expanduser("~root")}
    for group, cases in GROUPS.items():
        rows = []
        for name, kind, text, opaque in cases:
            row: dict[str, object] = {"name": name, "kind": kind, "text": text}
            if opaque:
                row["opaque"] = opaque
            row["answer"] = probe(kind, text)
            rows.append(row)
        doc = {
            "group": group,
            "bash": version,
            "prefix": PREFIX,
            "name0": NAME0,
            "positional": POSITIONAL,
            "home": HOME,
            "users": users,
            "vars": VARS,
            "seeds": SEEDS,
            "cases": rows,
        }
        target = FIXTURES / f"{group}.json"
        target.write_text(json.dumps(doc, indent=1, ensure_ascii=False) + "\n")
        print(f"{target.name}: {len(rows)} cases")
    print(version)
    return 0


if __name__ == "__main__":
    sys.exit(main())
