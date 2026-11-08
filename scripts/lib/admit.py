# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 228 S2, ruling "admit known shapes": admit(script, agent, cwd) admits a parsed command only
# when every node matches a known shape on the agent's tables, and types every operand it
# admits. Anything else is one Refusal at the first node off its table. It reads the jail's
# tables and the parse, never raw command text; no consumer calls it before unit S3.
from __future__ import annotations

import hashlib
import os
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field

from lib import gh_policy, jail, shell
from lib.shparse import (
    Arith,
    Assignment,
    BraceList,
    Command,
    CommandSub,
    Control,
    Glob,
    Heredoc,
    Literal,
    Opaque,
    Param,
    Pipeline,
    ProcSub,
    Redirect,
    Script,
    Tilde,
    Word,
    opaque,
)
from lib.train_scope import KNOWN_AGENTS

Span = tuple[int, int]
Grammar = Mapping[str, Callable[[list[str], str], bool]]
# 228 S2: the separators an admitted script may carry; & runs a command the hook never waits on.
_SEPARATORS = frozenset({"", ";", "\n", "&&", "||"})
_WRITE_KINDS = frozenset({"write", "script"})
_RUNNERS = frozenset(shell.TEST_RUNNERS) | {"npm", "python", "pytest"}
# 228 S2: python ends its own options at -m or -c; the words after belong to the program.
_PROGRAM_STOPS: dict[str, frozenset[str]] = {"python": frozenset({"-m", "-c"})}
# 228 S2: the push shape the conductor push check reads (jail._conductor_push_reason).
_PUSH_OPTIONS = frozenset({"-u", "--set-upstream"})
_ICASE_GLOBALS = frozenset({"--icase-pathspecs", "--glob-pathspecs"})
# 228 S2: scheduling wrappers an agent may put inside the kernel wrapper, never bare (8.5 A).
_CONFINED_WRAPPERS = frozenset({"timeout", "nice", "nohup", "stdbuf", "ionice", "taskset", "chrt"})
_REFUSED_GIT_GLOBALS = frozenset({"-c", "--config-env", "--exec-path="})


@dataclass(frozen=True)
class Typed:
    text: str
    span: Span
    glob: bool = False


@dataclass(frozen=True)
class AdmittedCommand:
    word: Typed
    family: str
    span: Span
    piped: bool = False
    wrappers: tuple[Typed, ...] = ()
    assignments: tuple[Typed, ...] = ()
    options: tuple[Typed, ...] = ()
    reads: tuple[Typed, ...] = ()
    writes: tuple[Typed, ...] = ()
    texts: tuple[Typed, ...] = ()
    pathspecs: tuple[Typed, ...] = ()
    subcommand: Typed | None = None
    module: Typed | None = None
    script: Typed | None = None
    cd_target: Typed | None = None
    git_dir: Typed | None = None


@dataclass(frozen=True)
class Admitted:
    commands: tuple[AdmittedCommand, ...]

    @property
    def writes(self) -> tuple[Typed, ...]:
        return tuple(w for c in self.commands for w in c.writes)

    @property
    def reads(self) -> tuple[Typed, ...]:
        return tuple(r for c in self.commands for r in c.reads)


@dataclass(frozen=True)
class Refusal:
    span: Span
    text: str
    reason: str
    sha256: str


@dataclass(frozen=True)
class Role:
    name: str
    commands: frozenset[str] = frozenset()
    git: tuple[frozenset[str], Grammar] | None = None
    gh: str | None = None
    runner: str | None = None
    terraform: bool = False
    wrappers: frozenset[str] = frozenset()
    read_only: bool = True
    main: bool = False
    ledger: bool = False
    gitleaks: bool = False
    push: bool = False
    docs_reads: bool = False


class _Off(Exception):
    def __init__(self, span: Span, reason: str) -> None:
        super().__init__(reason)
        self.span = span
        self.reason = reason


@dataclass
class _Cmd:
    span: Span
    piped: bool
    word: Typed | None = None
    family: str = ""
    wrappers: list[Typed] = field(default_factory=list)
    assignments: list[Typed] = field(default_factory=list)
    options: list[Typed] = field(default_factory=list)
    typed: dict[str, list[Typed]] = field(default_factory=dict)
    subcommand: Typed | None = None
    cd_target: Typed | None = None
    git_dir: Typed | None = None
    git_read: bool = False
    loose: list[Span] = field(default_factory=list)

    def add(self, kind: str, item: Typed) -> None:
        self.typed.setdefault(kind, []).append(item)

    def frozen(self) -> AdmittedCommand:
        assert self.word is not None
        one = {k: (v[0] if v else None) for k, v in self.typed.items() if k in {"module", "script"}}
        return AdmittedCommand(
            word=self.word,
            family=self.family,
            span=self.span,
            piped=self.piped,
            wrappers=tuple(self.wrappers),
            assignments=tuple(self.assignments),
            options=tuple(self.options),
            reads=tuple(self.typed.get("read", [])),
            writes=tuple(self.typed.get("write", [])),
            texts=tuple(self.typed.get("text", [])),
            pathspecs=tuple(self.typed.get("pathspec", [])),
            subcommand=self.subcommand,
            module=one.get("module"),
            script=one.get("script"),
            cd_target=self.cd_target,
            git_dir=self.git_dir,
        )


def _read_git() -> Grammar:
    # 228 S2: the read-only roles' grammar row; imported here, read_only_bash will import admit.
    from checks.read_only_bash import READ_GIT_GRAMMAR

    return READ_GIT_GRAMMAR


def role_for(agent: str) -> Role:
    # 228 S2: one Role per command table the jail already holds; an unknown name is foreign.
    read = Role("read-only", commands=shell.READ_ONLY_CMDS)
    git_read = (shell.READ_ONLY_GIT, _read_git())
    worker = Role(
        agent,
        commands=shell.READ_ONLY_CMDS | jail.CODER_WRITE_CMDS,
        git=(shell.CODER_GIT, jail._GIT_GRAMMAR),
        runner="coder",
        wrappers=frozenset({shell.CONFINE}),
        read_only=False,
    )
    roles: dict[str, Role] = {
        "coder": worker,
        "writer": worker,
        "writer (public-docs)": worker,
        "verifier": Role("verifier", read.commands, git_read, runner="unit"),
        "auditor": Role(
            "auditor",
            read.commands,
            git_read,
            runner="audit",
            terraform=True,
            wrappers=frozenset({shell.CONFINE}),
        ),
        "comparer": Role("comparer", read.commands),
        "writer (derived)": Role("writer (derived)", read.commands),
        "charter-docs": Role(
            "charter-docs",
            frozenset(shell.DOCS_READS),
            (shell.CHARTER_DOCS_GIT, jail._DOCS_GRAMMAR),
            ledger=True,
            docs_reads=True,
        ),
        "releaser": Role(
            "releaser",
            git=(shell.CONDUCTOR_GIT, jail._CONDUCTOR_GRAMMAR),
            gh=gh_policy.CONDUCTOR,
            gitleaks=True,
            push=True,
        ),
    }
    if agent == "main":
        subs = shell.CODER_GIT | shell.CONDUCTOR_GIT | shell.CHARTER_DOCS_GIT | shell.READ_ONLY_GIT
        return Role(
            "main",
            commands=shell.READ_ONLY_CMDS
            | jail.CODER_WRITE_CMDS
            | frozenset(shell.DOCS_READS)
            | shell.MAIN_BUILTINS,
            git=(subs, {**jail._CONDUCTOR_GRAMMAR, **_read_git()}),
            gh="main",
            runner="coder",
            terraform=True,
            wrappers=frozenset(shell.WRAPPER_OPTS) - {"xargs"},
            read_only=False,
            main=True,
            ledger=True,
            gitleaks=True,
            push=True,
        )
    if agent in roles:
        return roles[agent]
    if agent in KNOWN_AGENTS:
        return Role(agent, commands=frozenset())
    return Role("foreign", read.commands, (shell.READ_ONLY_GIT, jail._GIT_GRAMMAR))


def admit(script: Script, agent: str, cwd: str, *, text: str) -> Admitted | Refusal:
    # 228 S2: text is the command the script was parsed from; spans index it (R6).
    try:
        return Admitted(tuple(_Judge(role_for(agent), cwd).script(script)))
    except _Off as off:
        start, end = off.span
        digest = hashlib.sha256(text.encode("utf-8", "surrogatepass")).hexdigest()
        return Refusal(off.span, text[start:end], off.reason, digest)


def _word_text(word: Word) -> Typed:
    lit = word.literal
    if lit is not None:
        return Typed(lit, word.span)
    return Typed(word.raw, word.span, glob=True)


def _bare(word: Word) -> str | None:
    # 228 S2: a command or wrapper word is one unquoted literal; a quoted one dodges aliases.
    if all(isinstance(p, Literal) and p.quoted == "" for p in word.parts):
        return word.literal
    return None


def _leading_glob(word: Word) -> bool:
    # 228 S2, P1: an expansion at word start; kept off rows that write through an option.
    return bool(word.parts) and isinstance(word.parts[0], Glob | Tilde | Param)


def _expands(word: Word) -> bool:
    return any(isinstance(p, Glob | Tilde) for p in word.parts)


def _forbidden(word: Word, loose: list[Span] | None = None) -> None:
    # 228 S2 rule 3: no substitution, arithmetic, brace list or parameter in an admitted word.
    # 228 S2 ruling: loose collects a main-session parameter, judged once the shape is known.
    for part in word.parts:
        if isinstance(part, Param) and loose is not None:
            loose.append(part.span)
            continue
        if isinstance(part, CommandSub):
            raise _Off(part.span, "a command substitution, $( ) or a backtick, is not admitted")
        if isinstance(part, ProcSub):
            raise _Off(part.span, "a process substitution, <( ) or >( ), is not admitted")
        if isinstance(part, Arith):
            raise _Off(part.span, "an arithmetic expansion $(( )) is not admitted")
        if isinstance(part, BraceList):
            raise _Off(part.span, "a brace expansion { , } is not admitted")
        if isinstance(part, Param):
            raise _Off(part.span, f"the parameter expansion ${part.name} is not admitted")
        if isinstance(part, Opaque):
            raise _Off(part.span, f"the parser could not bound this word ({part.why})")
        if isinstance(part, Literal) and part.quoted in ("$'", '$"'):
            raise _Off(part.span, "$'...' and $\"...\" quoting is not admitted")


def _dangerous(key: str) -> bool:
    # 228 S2: a row where an expanded "-x" could reach a write or a program option.
    values = shell.OPTION_VALUE_TYPES.get(key, {})
    return bool(shell.READ_ONLY_WRITE_OPTS.get(key)) or any(
        _WRITE_KINDS & set(types) for types in values.values()
    )


class _Judge:
    def __init__(self, role: Role, cwd: str) -> None:
        self.role = role
        self.cwd = cwd

    # -- script and pipelines ----------------------------------------------------------------
    def script(self, script: Script) -> list[AdmittedCommand]:
        holes = opaque(script)
        if holes:
            raise _Off(holes[0].span, f"the parser could not bound this text ({holes[0].why})")
        out: list[AdmittedCommand] = []
        for idx, item in enumerate(script.items):
            sep = script.separators[idx] if idx < len(script.separators) else ""
            if isinstance(item, Control):
                raise _Off(item.span, f"a {item.kind} block is not admitted; send plain commands")
            if isinstance(item, Opaque):
                raise _Off(item.span, f"the parser could not bound this text ({item.why})")
            if sep not in _SEPARATORS:
                raise _Off(item.span, f"the separator {sep!r} is not admitted")
            if idx == 0 and sep == "&&" and len(script.items) > 1 and self._is_cd(item):
                out.append(self.cd(item))
                continue
            out.extend(self.pipeline(item))
        return out

    def _is_cd(self, item: Pipeline) -> bool:
        cmd = item.commands[0] if len(item.commands) == 1 else None
        return isinstance(cmd, Command) and bool(cmd.words) and _bare(cmd.words[0]) == "cd"

    def cd(self, item: Pipeline) -> AdmittedCommand:
        # 228 S2 rule 4: one leading `cd <absolute path> &&`, nothing else on the cd.
        cmd = item.commands[0]
        assert isinstance(cmd, Command)
        if item.negated or item.timed or cmd.assignments or cmd.redirects or len(cmd.words) != 2:
            raise _Off(cmd.span, "a leading cd takes one absolute path and nothing else")
        target = cmd.words[1]
        _forbidden(target)
        path = target.literal
        if path is None or not os.path.isabs(path):
            raise _Off(target.span, "a leading cd takes one absolute path")
        word = Typed("cd", cmd.words[0].span)
        return AdmittedCommand(word, "cd", cmd.span, cd_target=Typed(path, target.span))

    def pipeline(self, item: Pipeline) -> list[AdmittedCommand]:
        if item.negated or item.timed:
            raise _Off(item.span, "a pipeline led by ! or time is not admitted")
        out: list[AdmittedCommand] = []
        for pos, node in enumerate(item.commands):
            if isinstance(node, Control):
                raise _Off(node.span, f"a {node.kind} block is not admitted; send plain commands")
            if isinstance(node, Opaque):
                raise _Off(node.span, f"the parser could not bound this text ({node.why})")
            done = self.command(node, pos > 0)
            message = pos == 1 and len(item.commands) == 2 and self._piped_message(out[0], done)
            filters = done.family in shell.READ_ONLY_CMDS and not (done.writes or done.script)
            if pos and not (filters or message):
                raise _Off(node.span, f"{done.word.text} after a pipe is not a read filter")
            out.append(done)
        return out

    def _piped_message(self, first: AdmittedCommand, second: AdmittedCommand) -> bool:
        # 228 S2 ruling: main pipes a cat heredoc, and nothing else, into git commit -F -.
        if not self.role.main or first.family != "cat" or first.reads or first.options:
            return False
        commit = second.subcommand is not None and second.subcommand.text == "commit"
        stdin = "-" in {t.text for t in second.reads}
        flag = {t.text for t in second.options} & {"-F", "--file"}
        return second.family == "git" and commit and stdin and bool(flag) and not second.writes

    # -- one simple command ------------------------------------------------------------------
    def command(self, cmd: Command, piped: bool) -> AdmittedCommand:
        c = _Cmd(cmd.span, piped)
        for assign in cmd.assignments:
            self.assignment(assign, c)
        for word in cmd.words:
            _forbidden(word, c.loose if self.role.main else None)
        for redirect in cmd.redirects:
            self.redirect(redirect, c)
        if not cmd.words and self.role.main and cmd.assignments and not cmd.redirects:
            # 228 S2 ruling: a bare assignment sets a shell variable for the main session.
            first = cmd.assignments[0]
            c.word, c.family = Typed(first.name, first.span), "assignment"
            return c.frozen()
        if not cmd.words:
            raise _Off(cmd.span, "an assignment or redirect with no command is not admitted")
        words = self.unwrap(list(cmd.words), c)
        head = words[0]
        name = _bare(head)
        if name is None:
            raise _Off(head.span, "a command word must be one unquoted literal word")
        if "/" in name and os.path.dirname(name) not in shell._TRUSTED_BIN:
            raise _Off(head.span, f"{name} is named by a path outside the trusted bin folders")
        c.word = Typed(name, head.span)
        c.family = shell.command_family(name)
        self.dispatch(c, words)
        if c.loose and not _reads_only(c):
            raise _Off(c.loose[0], "a main-session prefix or parameter rides only a read command")
        return c.frozen()

    def assignment(self, assign: Assignment, c: _Cmd) -> None:
        # 228 S2 rule 3: only the safe prefixes, and a parameter only inside their value.
        safe = shell._SAFE_ENV.match(f"{assign.name}{assign.op}") is not None
        if assign.subscript is not None or not (safe or self.role.main):
            raise _Off(assign.span, f"the prefix {assign.name}{assign.op} is not a safe name")
        if not safe:
            c.loose.append(assign.span)
        for part in assign.value.parts:
            if isinstance(part, Literal) and part.quoted not in ("$'", '$"'):
                continue
            if isinstance(part, Param):
                continue
            raise _Off(part.span, f"the value of {assign.name} holds an expansion")
        c.assignments.append(Typed(f"{assign.name}{assign.op}{assign.value.raw}", assign.span))

    def redirect(self, redirect: Redirect, c: _Cmd) -> None:
        target = redirect.target
        _forbidden(target)
        dest = target.literal
        if self.role.main:
            self._main_redirect(redirect, dest, c)
            return
        # 228 S2 rule 5: an agent's only redirects are 2>&1 and >/dev/null.
        if redirect.op in ("<<", "<<-", "<<<"):
            raise _Off(
                redirect.span, "a heredoc or here-string is not admitted for an agent; use Write"
            )
        if redirect.op == ">&" and redirect.fd == 2 and dest == "1":
            return
        if redirect.op == ">" and redirect.fd in (None, 1) and dest == "/dev/null":
            return
        raise _Off(redirect.span, "an agent's only redirects are 2>&1 and >/dev/null")

    def _main_redirect(self, redirect: Redirect, dest: str | None, c: _Cmd) -> None:
        # 228 S2: the main session writes and reads files through literal redirect targets.
        if isinstance(redirect.fd, Word) or dest is None or _expands(redirect.target):
            raise _Off(redirect.span, "a redirect needs a literal target and a numbered fd")
        span = redirect.target.span
        if redirect.op in ("<<", "<<-"):
            doc = redirect.heredoc
            if not isinstance(doc, Heredoc) or not all(isinstance(p, Literal) for p in doc.parts):
                raise _Off(redirect.span, "a heredoc body with an expansion is not admitted")
            c.add("text", Typed(doc.body, doc.body_span))
        elif redirect.op == "<<<":
            c.add("text", Typed(dest, span))
        elif redirect.op in (">&", "<&") and (dest.isdigit() or dest == "-"):
            return
        elif redirect.op == "<":
            c.add("read", Typed(dest, span))
        elif redirect.op in (">", ">>", ">|", "&>", "&>>"):
            c.add("write", Typed(dest, span))
        else:
            raise _Off(redirect.span, f"the redirect {redirect.op} is not admitted")

    # -- wrappers ----------------------------------------------------------------------------
    def unwrap(self, words: list[Word], c: _Cmd) -> list[Word]:
        while words:
            name = _bare(words[0])
            family = shell.command_family(name) if name else ""
            if family == "xargs":
                raise _Off(words[0].span, "xargs feeds operands the jail cannot see")
            if family not in shell.WRAPPER_OPTS:
                return words
            inner = shell.CONFINE in self.role.wrappers and _confined(c)
            if family not in self.role.wrappers and not (inner and family in _CONFINED_WRAPPERS):
                raise _Off(
                    words[0].span, f"the wrapper {family} is not on the {self.role.name} table"
                )
            assert name is not None
            trusted = "/" not in name or os.path.dirname(name) in shell._TRUSTED_BIN
            if family != shell.CONFINE and not trusted:
                raise _Off(
                    words[0].span, f"{name} is named by a path outside the trusted bin folders"
                )
            c.wrappers.append(Typed(name, words[0].span))
            words = self._confine(words, c) if family == shell.CONFINE else self._wrapper(words, c)
        raise _Off(c.span, "a wrapper with no command")

    def _confine(self, words: list[Word], c: _Cmd) -> list[Word]:
        # 0048: <plugin wrapper> --unit <worktree> -- <command>, the one form.
        texts = [w.literal for w in words[:4]]
        name = texts[0] or ""
        if (
            len(words) < 5
            or texts[1:2] != ["--unit"]
            or texts[3:4] != ["--"]
            or not shell.confine_wrapper(name, self.cwd)
        ):
            raise _Off(words[0].span, "the kernel wrapper runs in one form only (0048)")
        c.add("read", _word_text(words[2]))
        return words[4:]

    def _wrapper(self, words: list[Word], c: _Cmd) -> list[Word]:
        name = _bare(words[0]) or ""
        family = shell.command_family(name)
        plain, valued = shell.WRAPPER_OPTS[family]
        i = 1
        while i < len(words):
            text = words[i].literal
            if text is None:
                raise _Off(words[i].span, f"a {family} word that expands is not admitted")
            if text == "--" and "--" not in plain:
                i += 1
                break
            if not text.startswith("-") or (text == "-" and "-" not in plain):
                break
            key, value, i = self._wrapper_option(family, words, i, plain, valued)
            c.options.append(Typed(key, words[i - 1].span))
            if value is None:
                continue
            if (family, key) in shell.WRAPPER_WRITES:
                c.add("write", value)
            elif (family, key) in shell.WRAPPER_CHDIR:
                c.cd_target = value
            else:
                c.add("text", value)
        if family == "env":
            while (
                i < len(words)
                and "=" in (words[i].literal or "")
                and not words[i].raw.startswith("=")
            ):
                text = words[i].literal or ""
                if not shell._SAFE_ENV.match(text):
                    raise _Off(words[i].span, f"env sets {text.split('=')[0]}, not a safe name")
                c.assignments.append(Typed(text, words[i].span))
                i += 1
        if family in shell.WRAPPER_OPERAND:
            pattern = shell.WRAPPER_OPERAND[family]
            operand = words[i].literal if i < len(words) else None
            if pattern is None or operand is None or not pattern.fullmatch(operand):
                raise _Off(words[0].span, f"{family} needs its operand before the command")
            kind = "write" if (family, shell.WRAPPER_FILE) in shell.WRAPPER_WRITES else "text"
            c.add(kind, Typed(operand, words[i].span))
            i += 1
        return words[i:]

    def _wrapper_option(
        self,
        family: str,
        words: list[Word],
        i: int,
        plain: frozenset[str],
        valued: frozenset[str],
    ) -> tuple[str, Typed | None, int]:
        text = words[i].literal or ""
        span = words[i].span
        if text in plain:
            return text, None, i + 1
        name, eq, attached = text.partition("=")
        if text.startswith("--") and name in valued:
            if eq:
                return name, Typed(attached, span), i + 1
            return name, self._value(family, words, i + 1, name), i + 2
        if not text.startswith("--") and text[:2] in valued:
            if text[2:3] == "=":
                raise _Off(span, f"{text[:2]}=value keeps its = under getopt")
            if len(text) > 2:
                return text[:2], Typed(text[2:], span), i + 1
            return text[:2], self._value(family, words, i + 1, text[:2]), i + 2
        raise _Off(span, f"the option {text} is not on the {family} wrapper row")

    def _value(self, family: str, words: list[Word], i: int, option: str) -> Typed:
        if i >= len(words) or words[i].literal is None:
            raise _Off(words[i - 1].span, f"{family} {option} needs one literal value")
        return _word_text(words[i])

    # -- dispatch ----------------------------------------------------------------------------
    def dispatch(self, c: _Cmd, words: list[Word]) -> None:
        family, role = c.family, self.role
        literals = [w.literal for w in words]
        if family == "git":
            self.git(c, words)
        elif family == "gh":
            self.gh(c, words, literals)
        elif family == "terraform" and (role.terraform or role.runner == "coder"):
            self.terraform(c, words, literals)
        elif role.ledger and family == "python" and self._ledger(literals):
            c.typed.setdefault("script", []).append(_word_text(words[1]))
            for word in words[2:]:
                c.add("text", _word_text(word))
        elif role.gitleaks and family == "gitleaks":
            toks = self._all_literal(words, literals)
            if not jail._gitleaks_ok(toks):
                raise _Off(c.span, "gitleaks runs only as detect --redact with a /tmp report")
            for word in words[1:]:
                c.add("text", _word_text(word))
        elif role.runner in ("audit", "unit") and family == "python":
            self.test_run(c, words, literals)
        elif role.runner == "coder" and family in _RUNNERS:
            self.runner(c, words, literals)
        elif family in role.commands:
            self.plain(c, words)
        else:
            raise _Off(
                words[0].span,
                f"{c.word.text if c.word else family} is not on the {role.name} command table",
            )

    def _all_literal(self, words: list[Word], literals: list[str | None]) -> list[str]:
        out: list[str] = []
        for word, lit in zip(words, literals, strict=True):
            if lit is None:
                raise _Off(word.span, "a glob or ~ is not admitted here")
            out.append(lit)
        return out

    def _ledger(self, literals: list[str | None]) -> bool:
        if any(lit is None for lit in literals):
            return False
        toks = [lit for lit in literals if lit is not None]
        return shell._is_append_ledger(toks) and jail._ledger_args_ok(toks)

    # -- the option walk and operand typing --------------------------------------------------
    def plain(self, c: _Cmd, words: list[Word], stop: bool = False) -> None:
        key = c.family
        if key not in shell.OPTION_TABLE:
            raise _Off(words[0].span, f"{key} has no row in the option table")
        if key in shell.OPERAND_ONLY_CMDS:
            # 228 S2 ruling: the test builtin's words are all operands, closed by a literal ].
            if words[-1].literal != "]":
                raise _Off(words[-1].span, f"{key} closes with a literal ]")
            met: list[str] = []
            operands = words[1:-1]
        else:
            met, operands = self.options(c, key, words[1:], stop)
        if key in shell.NAME_OPERAND_CMDS:
            for word in operands:
                name = (word.literal or "").split("=", 1)[0]
                if not (name.isascii() and name.isidentifier()):
                    raise _Off(word.span, f"{key} takes NAME or NAME=value operands")
        self.operands(c, key, met, operands)

    def options(
        self, c: _Cmd, key: str, words: list[Word], stop: bool
    ) -> tuple[list[str], list[Word]]:
        plain, valued = shell.OPTION_TABLE[key]
        whole = key in shell.WORD_OPTION_CMDS
        stops = _PROGRAM_STOPS.get(key, frozenset())
        met: list[str] = []
        operands: list[Word] = []
        i = 0
        while i < len(words):
            word = words[i]
            text = word.literal
            if text is None or text == "-" or not text.startswith("-"):
                if stop:
                    return met, operands + words[i:]
                operands.append(word)
                i += 1
                continue
            if text == "--" and not whole:
                return met, operands + words[i + 1 :]
            if whole or text.startswith("--"):
                name, eq, attached = (text, "", "") if whole else text.partition("=")
                if name not in plain | valued:
                    raise _Off(word.span, f"the option {name} is not on the {key} row")
                self._met(c, key, name, word.span, met)
                if name in valued:
                    i = self._values(c, key, name, words, i, attached if eq else None)
                elif eq:
                    c.add("text", Typed(attached, word.span))
                i += 1
            else:
                i = self._cluster(c, key, words, i, plain, valued, met)
            if met and met[-1] in stops:
                return met, operands + words[i:]
        return met, operands

    def _cluster(
        self,
        c: _Cmd,
        key: str,
        words: list[Word],
        i: int,
        plain: frozenset[str],
        valued: frozenset[str],
        met: list[str],
    ) -> int:
        # 228 S2: getopt reads -abc letter by letter; a valued letter takes the rest or the next.
        text = words[i].literal or ""
        span = words[i].span
        for k in range(1, len(text)):
            letter = "-" + text[k]
            if letter in plain:
                self._met(c, key, letter, span, met)
                continue
            if letter in valued:
                self._met(c, key, letter, span, met)
                rest = text[k + 1 :]
                if rest.startswith("="):
                    raise _Off(span, f"{letter}=value reads one way to getopt and another to clap")
                return self._values(c, key, letter, words, i, rest if rest else None) + 1
            raise _Off(span, f"the option {letter} is not on the {key} row")
        return i + 1

    def _met(self, c: _Cmd, key: str, name: str, span: Span, met: list[str]) -> None:
        if name in shell.READ_ONLY_WRITE_OPTS.get(key, frozenset()) and not self.role.main:
            types = shell.OPTION_VALUE_TYPES.get(key, {}).get(name, ())
            if not types or self.role.read_only:
                raise _Off(span, f"{key} {name} writes a file; a read verb never writes")
        if self.role.docs_reads:
            letters = shell.DOCS_READS.get(key, (frozenset(), frozenset()))
            if name.startswith("--") or name[1:] not in letters[0] | letters[1]:
                raise _Off(span, f"{key} {name} is off the charter-docs read row (0084)")
        met.append(name)
        c.options.append(Typed(name, span))

    def _values(
        self, c: _Cmd, key: str, name: str, words: list[Word], i: int, attached: str | None
    ) -> int:
        types = shell.OPTION_VALUE_TYPES.get(key, {}).get(name, ("text",))
        for n, kind in enumerate(types):
            if n == 0 and attached is not None:
                value = Typed(attached, words[i].span)
            else:
                i += 1
                if i >= len(words):
                    raise _Off(words[i - 1].span, f"{key} {name} needs a value")
                if _expands(words[i]):
                    raise _Off(words[i].span, f"a glob or ~ in the value of {name}")
                value = _word_text(words[i])
            self._typed(c, key, kind, value, name)
        return i

    def operands(self, c: _Cmd, key: str, met: list[str], operands: list[Word]) -> None:
        row = next(
            (shell.OPERAND_TYPES[f"{key} {m}"] for m in met if f"{key} {m}" in shell.OPERAND_TYPES),
            shell.OPERAND_TYPES.get(key, ("text*",)),
        )
        slots = _allocate(row, len(operands))
        if slots is None:
            span = operands[-1].span if operands else c.span
            raise _Off(span, f"{key} takes operands by its row {row}, not {len(operands)}")
        for word, slot in zip(operands, slots, strict=True):
            kind = slot.rstrip("*?")
            if _expands(word) and (kind != "read" or not slot.endswith("*")):
                raise _Off(word.span, f"a glob or ~ in a {key} {kind} operand")
            if _leading_glob(word) and _dangerous(key):
                raise _Off(word.span, f"a leading expansion may become a {key} option")
            self._typed(c, key, kind, _word_text(word), "")

    def _typed(self, c: _Cmd, key: str, kind: str, value: Typed, option: str) -> None:
        what = f"{key} {option}".strip()
        if kind == "write" and self.role.read_only:
            raise _Off(value.span, f"{what} writes {value.text}; this role writes nothing")
        script = kind == "script" and not self.role.main
        if script and (option or self.role.read_only or key not in _RUNNERS):
            raise _Off(value.span, f"{what} runs a program or inline code")
        if kind == "pathspec" and value.text.startswith(":"):
            raise _Off(value.span, f"the pathspec magic {value.text} is not admitted")
        c.add(kind, value)

    # -- git ---------------------------------------------------------------------------------
    def git(self, c: _Cmd, words: list[Word]) -> None:
        role = self.role
        if role.git is None:
            raise _Off(words[0].span, f"git is not on the {role.name} table")
        subs, grammar = role.git
        i, kept, icase, config = self._git_globals(c, words)
        if i >= len(words) or words[i].literal is None:
            raise _Off(words[0].span, "git needs a literal subcommand")
        sub = words[i].literal or ""
        c.subcommand = Typed(sub, words[i].span)
        args = words[i + 1 :]
        reads = sub in shell.READ_ONLY_GIT
        stash_read = sub == "stash" and [w.literal for w in args[:1]] in (["show"], ["list"])
        c.git_read = reads or stash_read
        main_read = role.main and c.git_read
        if config is not None and not main_read:
            raise _Off(config, f"git -c and --config-env are refused on git {sub}")
        if icase and not reads:
            raise _Off(
                words[0].span, f"--icase-pathspecs and --glob-pathspecs only on a read, not {sub}"
            )
        if sub not in subs and not (sub == "push" and role.push):
            raise _Off(words[i].span, f"git {sub} is not in the {role.name} git grammar")
        if not reads and any(_expands(w) for w in args):
            word = next(w for w in args if _expands(w))
            raise _Off(word.span, f"a glob or ~ in git {sub}, which writes")
        toks = [w.literal if w.literal is not None else w.raw for w in args]
        out = next(
            (w for w, t in zip(args, toks, strict=True) if shell._long_matches(t, "--output", 1)),
            None,
        )
        if out is not None:
            raise _Off(out.span, f"git {sub} --output writes a file (O5)")
        if sub == "push":
            self._push(c, args, toks)
            return
        if role.main and sub == "commit":
            # 228 S2: the main session's commit reads the "git commit" option row.
            met, operands = self.options(c, "git commit", args, False)
            self.operands(c, "git commit", met, operands)
            return
        # 228 S2: operands first, so a magic pathspec is named before the grammar row.
        self._git_operands(c, sub, args, toks, magic=main_read)
        if main_read and stash_read:
            return
        if role.main:
            check = grammar.get(sub)
            if check is not None and not check(toks, self.cwd):
                raise self._blame(c, sub, args, toks, check)
        elif not jail._git_grammar_ok(
            ["git", *kept, sub, *toks], subs, self.cwd, None, dict(grammar)
        ):
            check = grammar.get(sub)
            if check is None:
                raise _Off(words[i].span, f"git {sub} has no grammar row for {role.name}")
            if check(toks, self.cwd):
                raise _Off(
                    words[0].span, f"git global options {kept} are off the {role.name} grammar"
                )
            raise self._blame(c, sub, args, toks, check)

    def _git_globals(self, c: _Cmd, words: list[Word]) -> tuple[int, list[str], bool, Span | None]:
        # 228 S2: every global option on git's table with its arity; -c and its kin are refused.
        # 228 S2 ruling: the main session's -c and --config-env wait for a read subcommand.
        kept: list[str] = []
        icase = False
        config: Span | None = None
        base = self.cwd
        i = 1
        while i < len(words) and (words[i].literal or "").startswith("-"):
            text = words[i].literal or ""
            span = words[i].span
            setting = text in _REFUSED_GIT_GLOBALS or text.startswith("--config-env=")
            if text.startswith("--exec-path=") or (setting and not self.role.main):
                raise _Off(span, f"git {text.split('=')[0]} is refused")
            if setting and config is None:
                config = span
            if text in shell._GIT_GLOBAL_WITH_ARG:
                if i + 1 >= len(words) or words[i + 1].literal is None:
                    raise _Off(span, f"git {text} needs one literal value")
                value = _word_text(words[i + 1])
                c.options.append(Typed(text, span))
                if text == "-C":
                    base = os.path.normpath(os.path.join(base, value.text))
                    c.git_dir = Typed(base, value.span)
                else:
                    kept += [text, value.text]
                    c.add("read" if text in ("--git-dir", "--work-tree") else "text", value)
                i += 2
                continue
            if text in shell.GIT_GLOBAL_FLAGS or text.startswith(shell.GIT_GLOBAL_EQ):
                icase = icase or text in _ICASE_GLOBALS
                kept.append(text)
                c.options.append(Typed(text, span))
                i += 1
                continue
            raise _Off(span, f"the git global option {text} is not on git's table")
        return i, kept, icase, config

    def _blame(
        self,
        c: _Cmd,
        sub: str,
        args: list[Word],
        toks: list[str],
        check: Callable[[list[str], str], bool],
    ) -> _Off:
        # 228 S2: name the first word after which no longer prefix of the args passes the row.
        for k in range(len(toks)):
            if not check(toks[: k + 1], self.cwd) and (
                k + 1 == len(toks) or not check(toks[: k + 2], self.cwd)
            ):
                return _Off(
                    args[k].span, f"git {sub} {toks[k]} is off the {self.role.name} grammar"
                )
        return _Off(c.span, f"git {sub} with these words is off the {self.role.name} grammar")

    def _push(self, c: _Cmd, args: list[Word], toks: list[str]) -> None:
        # 228 S2: the shape the push check reads; the branch and the force flags are its call.
        rest = toks[1:] if toks[:1] and toks[0] in _PUSH_OPTIONS else toks
        if len(rest) != 2 or any(t.startswith(("-", "+")) or ":" in t for t in rest):
            raise _Off(c.span, "git push takes [-u] <remote> <branch> and nothing else")
        for word, tok in zip(args, toks, strict=True):
            if tok in _PUSH_OPTIONS:
                c.options.append(Typed(tok, word.span))
            else:
                c.add("text", Typed(tok, word.span))

    def _git_operands(
        self, c: _Cmd, sub: str, args: list[Word], toks: list[str], magic: bool = False
    ) -> None:
        row = shell.OPERAND_TYPES.get(f"git {sub}", ("text*",))
        kind = row[0].rstrip("*?") if row else "text"
        valued = shell.OPTION_TABLE["git commit"][1] | shell._COMMIT_WITH_ARG
        after = False
        skip = False
        prev = ""
        for word, tok in zip(args, toks, strict=True):
            if skip:
                skip = False
                types = shell.OPTION_VALUE_TYPES.get("git commit", {}).get(prev, ("text",))
                c.add(types[0], _word_text(word))
                continue
            if not after and tok == "--":
                after = True
                continue
            if not after and tok.startswith("-") and tok != "-":
                c.options.append(Typed(tok, word.span))
                name, eq, attached = tok.partition("=")
                if sub == "commit" and name in valued and not eq:
                    skip, prev = True, name
                elif eq:
                    types = shell.OPTION_VALUE_TYPES.get("git commit", {}).get(name, ("text",))
                    c.add(types[0] if sub == "commit" else "text", Typed(attached, word.span))
                continue
            if tok.startswith(":") and not magic:
                raise _Off(word.span, f"the pathspec magic {tok} is not admitted")
            c.add("pathspec" if after else kind, _word_text(word))

    # -- gh, terraform and the runners -------------------------------------------------------
    def gh(self, c: _Cmd, words: list[Word], literals: list[str | None]) -> None:
        if self.role.gh is None:
            raise _Off(words[0].span, f"gh is not on the {self.role.name} table")
        toks = self._all_literal(words, literals)
        reason = gh_policy._gh_reason(self.role.gh, ["gh", *toks[1:]])
        if reason is not None:
            raise _Off(c.span, reason)
        parsed = gh_policy.gh_args(toks[1:])
        assert parsed is not None
        lead = words[1 : 1 + min(2, len(parsed.words))]
        if lead:
            c.subcommand = Typed(" ".join(parsed.words[:2]), (lead[0].span[0], lead[-1].span[1]))
        for flag in parsed.flags:
            c.options.append(Typed(flag.name, c.span))
            if flag.value is not None:
                kind = "read" if flag.name in ("--body-file", "-F") else "text"
                c.add(kind, Typed(flag.value, c.span))
        for word in parsed.words[2:]:
            c.add("text", Typed(word, c.span))

    def terraform(self, c: _Cmd, words: list[Word], literals: list[str | None]) -> None:
        # 0158, 0164, 184: the terraform allowlist shape; the folder bounds are the check's.
        toks = self._all_literal(words, literals)
        paths = shell.terraform_check(toks[1:])
        if paths is None:
            reason = shell.runner_refusal(toks) or shell.R_TERRAFORM_OPERATOR
            raise _Off(c.span, reason)
        c.subcommand = Typed(next(t for t in toks[1:] if not t.startswith("-")), c.span)
        for word, tok in zip(words[1:], toks[1:], strict=True):
            if tok.startswith("-chdir="):
                c.cd_target = Typed(tok.removeprefix("-chdir="), word.span)
            elif tok.startswith("-"):
                c.options.append(Typed(tok, word.span))
        for word, tok in zip(words[1:], toks[1:], strict=True):
            if tok in paths:
                c.add("read", Typed(tok, word.span))

    def test_run(self, c: _Cmd, words: list[Word], literals: list[str | None]) -> None:
        # 0109: the read-only roles' one pytest form; the train's path bounds are the check's.
        from checks.read_only_bash import PYTEST, Bound, _test_run_ok

        toks = self._all_literal(words, literals)
        rootdir = toks[toks.index("--rootdir") + 1] if "--rootdir" in toks[:-1] else "/"
        if tuple(toks[:3]) != PYTEST or not _test_run_ok(toks, Bound(("/",), rootdir)):
            raise _Off(c.span, "the test run is python3 -m pytest <absolute paths> -q (0109)")
        c.typed.setdefault("module", []).append(Typed("pytest", words[2].span))
        skip = False
        prev = ""
        for word, tok in zip(words[3:], toks[3:], strict=True):
            if skip:
                c.add("read" if prev == "--rootdir" else "text", Typed(tok, word.span))
                skip = False
            elif tok.startswith("-"):
                c.options.append(Typed(tok, word.span))
                skip, prev = tok in ("-p", "--rootdir", "-k"), tok
            else:
                c.add("read", Typed(tok, word.span))

    def runner(self, c: _Cmd, words: list[Word], literals: list[str | None]) -> None:
        # 0048, 0164: a test-runner form; the launcher's options by its row, then program words.
        toks = self._all_literal(words, literals)
        family = c.family
        toks[0] = "python3" if family == "python" else family
        if not shell._tester_runner_ok(family, toks, lambda _: True):
            raise _Off(c.span, f"{c.word.text if c.word else family} is not a test-runner form")
        reason = (
            shell.runner_refusal(toks)
            or jail.download_reason(toks)
            or jail.install_reason(toks, _no_installs)
        )
        if reason is not None:
            raise _Off(c.span, reason)
        if family in shell.JS_LAUNCHERS:
            self._js_inner(c, toks)
        self.plain(c, words, stop=family != "pytest")

    def _js_inner(self, c: _Cmd, toks: list[str]) -> None:
        # 0164: a package manager running a shell or an interpreter meets the interpreter rule.
        if c.family == "bun" and shell.bun_inline(toks):
            raise _Off(c.span, "bun runs inline code or a script here (0164)")
        inner = shell.js_inner(toks)
        if not inner:
            return
        family = shell.command_family(inner[0])
        if family == "bun" and shell.bun_inline(inner):
            raise _Off(c.span, f"{c.family} runs bun inline code or a script (0164)")
        if family in shell._SHELLS or family in shell.INTERPRETERS or family in ("node", "bun"):
            if family not in shell.TEST_RUNNERS or not shell._tester_runner_ok(family, inner):
                raise _Off(c.span, f"{c.family} runs {inner[0]} outside a test-runner form")


def _no_installs() -> frozenset[str]:
    # 228 S2: admit refuses every install; the manifest-enabled frozen form is the later check's.
    return frozenset()


def _reads_only(c: _Cmd) -> bool:
    # 228 S2 ruling: a READ_ONLY_CMDS word or a read-only git form, with no write and no script.
    if c.typed.get("write") or c.typed.get("script"):
        return False
    return c.family in shell.READ_ONLY_CMDS or (c.family == "git" and c.git_read)


def _confined(c: _Cmd) -> bool:
    return any(shell.command_family(w.text) == shell.CONFINE for w in c.wrappers)


def _allocate(row: tuple[str, ...], n: int) -> list[str] | None:
    # 228 S2: fixed types take one each, `?` takes one while operands are spare, `*` the rest.
    fixed = sum(1 for t in row if not t.endswith(("*", "?")))
    spare = n - fixed
    if spare < 0:
        return None
    takes: list[int] = []
    for t in row:
        if t.endswith("?"):
            take = 1 if spare > 0 else 0
            spare -= take
            takes.append(take)
        else:
            takes.append(-1 if t.endswith("*") else 1)
    if spare and -1 not in takes:
        return None
    slots: list[str] = []
    for t, take in zip(row, takes, strict=True):
        slots += [t] * (spare if take == -1 else take)
    return slots
