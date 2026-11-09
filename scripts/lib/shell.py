# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0044, 0043: the shell model the jail and the hook scripts share; moved verbatim from lib.jail.
# It imports nothing from lib.jail.
from __future__ import annotations

import os
import re
import shutil
from collections.abc import Callable, Iterator
from functools import lru_cache
from typing import NamedTuple

READ_ONLY_CMDS = frozenset(
    {
        "cat",
        "rg",
        "grep",
        "ls",
        "find",
        "jq",
        "head",
        "tail",
        "wc",
        "sha256sum",
        "file",
        "stat",
        "sort",
        "uniq",
    }
)


def _row(
    plain: str, valued: str, long_plain: str = "", long_valued: str = ""
) -> tuple[frozenset[str], frozenset[str]]:
    # P2: (no-argument options, one-argument options) from short letters and long names.
    def spell(letters: str, names: str) -> frozenset[str]:
        return frozenset({f"-{c}" for c in letters} | {f"--{n}" for n in names.split()})

    return spell(plain, long_plain), spell(valued, long_valued)


_HELP = " help version"
_SHELL_ARG_OPTS = frozenset({"-o", "+o", "-O", "+O", "--rcfile", "--init-file"})
_SHELL_LONG_FLAGS = frozenset(
    {"--login", "--norc", "--noprofile", "--posix", "--restricted", "--verbose", "--noediting"}
)
# P2: the one option table split_options reads; a long option taking an optional =x is plain.
OPTION_TABLE: dict[str, tuple[frozenset[str], frozenset[str]]] = {
    "cat": _row(
        "AbeEnstTuv",
        "",
        "show-all number-nonblank show-ends number squeeze-blank show-tabs show-nonprinting"
        + _HELP,
    ),
    "rg": _row(
        "0.abcFhHiIlLnNopPqsSuUvVwxz",
        "efmABCgtTjMrEd",
        "hidden follow no-ignore count files-with-matches line-number ignore-case json" + _HELP,
        "regexp file max-count context after-context before-context glob iglob type type-not"
        " threads replace encoding pre pre-glob ignore-file hostname-bin hyperlink-format"
        " max-depth max-filesize sort sortr colors type-add engine",
    ),
    "grep": _row(
        "EFGPiyvwxcLloqsbHhnTZzUraIR",
        "efmABCdD",
        "extended-regexp fixed-strings basic-regexp perl-regexp ignore-case no-ignore-case"
        " invert-match word-regexp line-regexp count color colour files-without-match"
        " files-with-matches only-matching quiet silent no-messages byte-offset with-filename"
        " no-filename line-number line-buffered initial-tab null null-data text recursive"
        " dereference-recursive" + _HELP,
        "regexp file max-count after-context before-context context label include exclude"
        " exclude-from exclude-dir binary-files devices",
    ),
    "ls": _row(
        "aAbBcCdDfFgGhHiklLmnNopqQrRsStuUvxXZ1",
        "ITw",
        "all almost-all author escape ignore-backups classify color hyperlink directory dired"
        " file-type full-time group-directories-first no-group human-readable si dereference"
        " dereference-command-line dereference-command-line-symlink-to-dir inode kibibytes"
        " literal numeric-uid-gid hide-control-chars show-control-chars quote-name recursive"
        " reverse size zero context" + _HELP,
        "block-size format hide ignore indicator-style quoting-style sort time time-style"
        " tabsize width",
    ),
    # P2: jq's --arg, --argjson, --slurpfile and --rawfile take two words; one is stripped.
    "jq": _row(
        "nrjacCsSeh",
        "fL",
        "null-input raw-input slurp raw-output join-output ascii-output compact-output"
        " color-output monochrome-output sort-keys exit-status tab seq stream stream-errors"
        " args jsonargs raw-output0 unbuffered" + _HELP,
        "from-file indent arg argjson slurpfile rawfile",
    ),
    "head": _row(
        "qvz0123456789", "nc", "quiet silent verbose zero-terminated" + _HELP, "lines bytes"
    ),
    "tail": _row(
        "fFqvz0123456789",
        "ncs",
        "follow retry quiet silent verbose zero-terminated" + _HELP,
        "lines bytes pid sleep-interval max-unchanged-stats",
    ),
    "wc": _row("clmwL", "", "bytes chars lines words max-line-length" + _HELP, "files0-from total"),
    "sha256sum": _row(
        "bctwz",
        "",
        "binary check tag text ignore-missing quiet status strict warn zero" + _HELP,
    ),
    "file": _row(
        "bcCdE0hiklLnNprsSvzZ",
        "efFmP",
        "brief checking-printout compile debug extension no-dereference mime mime-type"
        " mime-encoding keep-going list dereference no-buffer no-pad print0 preserve-date raw"
        " special-files no-sandbox uncompress uncompress-noreport apple" + _HELP,
        "exclude exclude-quiet files-from separator magic-file parameter",
    ),
    "stat": _row("LftZ", "c", "dereference file-system terse" + _HELP, "format printf cached"),
    "sort": _row(
        "bcCdfghimMnrRsuVz",
        "kSotTy",
        "ignore-leading-blanks dictionary-order ignore-case general-numeric-sort"
        " ignore-nonprinting month-sort human-numeric-sort numeric-sort random-sort reverse"
        " version-sort check merge stable unique zero-terminated debug" + _HELP,
        "key output buffer-size field-separator temporary-directory random-source sort"
        " parallel batch-size compress-program files0-from",
    ),
    "uniq": _row(
        "0123456789Dcdiuz",
        "fsw",
        "all-repeated group count repeated ignore-case unique zero-terminated" + _HELP,
        "skip-fields skip-chars check-chars",
    ),
    # P2: find's predicates are whole words matched by their longest table prefix.
    "find": (
        frozenset(
            {"-H", "-L", "-P", "-O", "-print", "-print0", "-ls", "-prune", "-quit", "-true"}
            | {"-false", "-empty", "-depth", "-mount", "-xdev", "-follow", "-noleaf"}
            | {"-daystart", "-nouser", "-nogroup", "-readable", "-writable", "-executable"}
            | {"-not", "-a", "-o", "-and", "-or", "-help", "-version"}
        ),
        frozenset(
            {"-D", "-name", "-iname", "-path", "-ipath", "-wholename", "-iwholename"}
            | {"-regex", "-iregex", "-regextype", "-lname", "-ilname", "-type", "-xtype"}
            | {"-size", "-perm", "-user", "-group", "-uid", "-gid", "-newer", "-anewer"}
            | {"-cnewer", "-samefile", "-inum", "-links", "-mtime", "-mmin", "-atime"}
            | {"-amin", "-ctime", "-cmin", "-used", "-maxdepth", "-mindepth", "-printf"}
            | {"-fprint", "-fprint0", "-fprintf", "-fls", "-fstype", "-context"}
            | {"-files0-from"}
            # 228 S3 row 3: -newermt takes a date, a text value.
            | {"-newermt"}
        ),
    ),
    # pin A1 -> A2, P6, P7: shells (by family) and interpreters; a shell's -c takes no value.
    "shell": (
        frozenset({f"-{c}" for c in "abcefhiklmnprstuvxBCEHPT"})
        | _SHELL_LONG_FLAGS
        | frozenset({"--help", "--version", "--debugger", "--dump-strings", "--dump-po-strings"}),
        frozenset({o for o in _SHELL_ARG_OPTS if o[0] == "-"}),
    ),
    "python": _row("bBdEhiIOPqsSuvVx", "cmWXQ", _HELP, "check-hash-based-pycs"),
    "perl": _row("acFhilnpsStTuUvwWX0xdDCMm", "eEI", _HELP),
    "ruby": _row(
        "acdhlnpsSvwWyU0xKTF",
        "eIrCE",
        "verbose yydebug disable-gems enable-gems jit" + _HELP,
        "encoding external-encoding internal-encoding",
    ),
    "node": _row(
        "hivc",
        "eprC",
        "test check interactive inspect inspect-brk watch" + _HELP,
        "eval print require import loader experimental-loader conditions input-type title env-file",
    ),
    "php": _row("aCFhHilmnqsvwe", "rBREcdzftS", _HELP),
    # pin A1 -> A3: shell variable builtins and git commit, stripped before a pathspec scan.
    "export": _row("fnp", ""),
    "declare": _row("aAfFgiIlnrtuxp", ""),
    "typeset": _row("aAfFgiIlnrtuxp", ""),
    "git commit": _row(
        "aipsnvqzeo",
        "mFCct",
        "all patch signoff no-signoff no-verify verify verbose no-verbose quiet dry-run short"
        " branch porcelain long null amend no-edit edit allow-empty allow-empty-message"
        " include only no-post-rewrite reset-author status no-status gpg-sign no-gpg-sign"
        " untracked-files pathspec-file-nul ahead-behind no-ahead-behind interactive",
        "message file reuse-message reedit-message fixup squash author date template cleanup"
        " pathspec-from-file trailer",
    ),
    # 228 S2: the coder's write verbs (CODER_WRITE_CMDS), GNU coreutils spellings.
    "cp": _row(
        "abdfHilLnPprRsTuvxZ",
        "St",
        "archive attributes-only backup copy-contents debug dereference force interactive link"
        " no-dereference no-clobber one-file-system parents preserve recursive reflink"
        " remove-destination strip-trailing-slashes symbolic-link no-target-directory update"
        " verbose context keep-directory-symlink" + _HELP,
        "no-preserve sparse suffix target-directory",
    ),
    "mv": _row(
        "bfinTuvZ",
        "St",
        "backup debug exchange force interactive no-clobber no-copy strip-trailing-slashes"
        " no-target-directory update verbose context" + _HELP,
        "suffix target-directory",
    ),
    "tee": _row("aip", "", "append ignore-interrupts output-error" + _HELP),
    "install": _row(
        "bcCdDpsTvZ",
        "gmoSt",
        "backup compare debug directory preserve-timestamps strip no-target-directory verbose"
        " preserve-context context" + _HELP,
        "group mode owner suffix target-directory strip-program",
    ),
    "ln": _row(
        "bdfFiLnPrsTv",
        "St",
        "backup directory force interactive logical no-dereference physical relative symbolic"
        " no-target-directory verbose" + _HELP,
        "suffix target-directory",
    ),
    "truncate": _row("co", "rs", "no-create io-blocks" + _HELP, "reference size"),
    "rsync": _row(
        "aAbcdDEgHhIklLmnOopPqrRStuUvWxXz",
        "efTB",
        "archive recursive verbose quiet checksum delete dry-run update links perms times group"
        " owner devices specials compress human-readable progress partial inplace"
        " itemize-changes stats" + _HELP,
        "exclude include filter exclude-from include-from rsh rsync-path temp-dir chmod chown"
        " backup-dir suffix partial-dir log-file",
    ),
    "dd": _row("", "", _HELP.strip()),
    "mkdir": _row("pvZ", "m", "parents verbose context" + _HELP, "mode"),
    "touch": _row("acfhm", "drt", "no-create no-dereference" + _HELP, "date reference time"),
    "rm": _row(
        "dfiIrRv",
        "",
        "force interactive one-file-system no-preserve-root preserve-root recursive dir verbose"
        + _HELP,
    ),
    "rmdir": _row("pv", "", "ignore-fail-on-non-empty parents verbose" + _HELP),
    "unlink": _row("", "", _HELP.strip()),
    "chmod": _row(
        "cfvR",
        "",
        "changes silent quiet verbose recursive no-preserve-root preserve-root" + _HELP,
        "reference",
    ),
    "chown": _row(
        "cfvRhHLP",
        "",
        "changes silent quiet verbose dereference no-dereference recursive no-preserve-root"
        " preserve-root" + _HELP,
        "from reference",
    ),
    "chgrp": _row(
        "cfvRhHLP",
        "",
        "changes silent quiet verbose dereference no-dereference recursive no-preserve-root"
        " preserve-root" + _HELP,
        "reference",
    ),
    "mkfifo": _row("Z", "m", "context" + _HELP, "mode"),
    "mknod": _row("Z", "m", "context" + _HELP, "mode"),
    "shred": _row(
        "fuvxz", "ns", "force remove verbose exact zero" + _HELP, "iterations size random-source"
    ),
    # 228 S2: the charter-docs reads DOCS_READS names beyond READ_ONLY_CMDS.
    "diff": _row(
        "abBdeEiNnpqrsStTuwy",
        "CFILUWxXD",
        "brief report-identical-files unified context side-by-side recursive new-file"
        " ignore-case ignore-all-space ignore-space-change ignore-blank-lines text minimal color"
        + _HELP,
        "label exclude exclude-from ignore-matching-lines",
    ),
    "sed": _row(
        "nErsuz",
        "efl",
        "quiet silent regexp-extended separate unbuffered null-data posix debug sandbox" + _HELP,
        "expression file line-length",
    ),
    # 228 S2: the test runners' own options, up to the word that starts the program's words.
    "pytest": _row("qvxsl", "kmpc", "quiet verbose exitfirst" + _HELP, "rootdir tb maxfail"),
    "make": _row(
        "BeiknqrRsStw",
        "CfIjloW",
        "always-make environment-overrides ignore-errors keep-going just-print dry-run question"
        " no-builtin-rules silent quiet touch print-directory no-print-directory" + _HELP,
        "directory file makefile include-dir jobs load-average old-file what-if",
    ),
    "tox": _row(
        "qvr", "ecx", "recreate quiet verbose parallel-no-spinner" + _HELP, "env conf root"
    ),
    "nox": _row(
        "rRx",
        "sfekt",
        "reuse-existing-virtualenvs no-reuse-existing-virtualenvs stop-on-first-error list" + _HELP,
        "sessions session noxfile keywords tags python",
    ),
    "just": _row("lnqv", "fd", "dry-run quiet verbose list" + _HELP, "justfile working-directory"),
    "npx": _row("y", "pc", "no-install yes no quiet" + _HELP, "package call"),
    "uv": _row(
        "qvn",
        "p",
        "quiet verbose offline no-cache frozen locked no-sync isolated" + _HELP,
        "directory project python cache-dir",
    ),
    "go": _row("", "C"),
    "cargo": _row("qv", "Z", "quiet verbose offline frozen locked" + _HELP, "color"),
    "pnpm": _row("rs", "CF", "recursive silent" + _HELP, "dir filter"),
    "yarn": _row("", "", "silent" + _HELP, "cwd"),
    "bun": _row("", "", "watch hot silent" + _HELP, "cwd"),
    "npm": _row("", "w", "silent" + _HELP, "prefix workspace"),
    "vitest": _row("", ""),
    "vite": _row("", ""),
    "tsc": (frozenset({"--noEmit", "--pretty", "--incremental"}), frozenset({"-p", "--project"})),
    # 228 S2 ruling: the main session's builtins; [ takes no options, its words are operands.
    "unset": _row("fvn", ""),
    "[": (frozenset(), frozenset()),
    # 228 S3c: the coder's builtins; printf -v, set -a and set +o stay off their rows (SS-1).
    "echo": _row("neE", ""),
    "printf": _row("", ""),
    "true": _row("", ""),
    "set": _row("eu", "o"),
}
# 228 S3c: words on the coder's command table beside READ_ONLY_CMDS and CODER_WRITE_CMDS.
CODER_BUILTINS = frozenset({"echo", "printf", "true", "set"})
# 228 S3c: a valued option that admits only these values, keyed "<name> <option>".
OPTION_VALUES: dict[str, frozenset[str]] = {"set -o": frozenset({"pipefail"})}
# 228 S3c: commands admitted only with at least one option and no `--`.
OPTION_NEEDED = frozenset({"set"})
# 228 S3c, SS-4: commands whose operand is remote when a colon precedes its first slash.
HOST_OPERAND_CMDS = frozenset({"rsync"})
# P2: commands whose options are whole single-dash words, never getopt clusters.
WORD_OPTION_CMDS = frozenset({"find"})
# 228 S2 ruling: builtins on the main session's table only; agents keep refusing them.
MAIN_BUILTINS = frozenset({"export", "unset", "["})
# 228 S2: commands whose every word is an operand, and commands whose operands are NAME[=value].
OPERAND_ONLY_CMDS = frozenset({"["})
NAME_OPERAND_CMDS = frozenset({"export", "unset"})
# 228 S2: operand types per OPTION_TABLE key, from read, write, text, subcommand, pathspec,
# module, script; `*` repeats, `?` is optional. A "<name> <option>" key replaces the row when met.
OPERAND_TYPES: dict[str, tuple[str, ...]] = {
    **{name: ("read*",) for name in READ_ONLY_CMDS},
    "rg": ("text", "read*"),
    "rg -e": ("read*",),
    "rg --regexp": ("read*",),
    "rg -f": ("read*",),
    "rg --file": ("read*",),
    "grep": ("text", "read*"),
    "grep -e": ("read*",),
    "grep --regexp": ("read*",),
    "grep -f": ("read*",),
    "grep --file": ("read*",),
    "jq": ("text", "read*"),
    "jq -f": ("read*",),
    "jq --from-file": ("read*",),
    "uniq": ("read?", "write?"),
    "cp": ("read*", "write"),
    "cp -t": ("read*",),
    "cp --target-directory": ("read*",),
    "mv": ("write*", "write"),
    "mv -t": ("write*",),
    "mv --target-directory": ("write*",),
    "tee": ("write*",),
    "install": ("read*", "write"),
    "install -t": ("read*",),
    "install --target-directory": ("read*",),
    "install -d": ("write*",),
    "install --directory": ("write*",),
    "ln": ("read*", "write"),
    "ln -t": ("read*",),
    "ln --target-directory": ("read*",),
    "truncate": ("write*",),
    "rsync": ("read*", "write"),
    "dd": (),
    "mkdir": ("write*",),
    "touch": ("write*",),
    "rm": ("write*",),
    "rmdir": ("write*",),
    "unlink": ("write",),
    "chmod": ("text", "write*"),
    "chmod --reference": ("write*",),
    "chown": ("text", "write*"),
    "chown --reference": ("write*",),
    "chgrp": ("text", "write*"),
    "chgrp --reference": ("write*",),
    "mkfifo": ("write*",),
    "mknod": ("write", "text*"),
    "shred": ("write*",),
    "diff": ("read", "read"),
    "sed": ("script", "read*"),
    "sed -e": ("read*",),
    "sed --expression": ("read*",),
    "sed -f": ("read*",),
    "sed --file": ("read*",),
    "python": ("script", "text*"),
    "python -m": ("text*",),
    "python -c": ("text*",),
    "node": ("script", "text*"),
    "node --test": ("read*",),
    "pytest": ("read*",),
    **{name: ("text*",) for name in ("make", "tox", "nox", "just", "npx", "uv", "go", "cargo")},
    **{name: ("text*",) for name in ("pnpm", "yarn", "bun", "npm", "vitest", "vite", "tsc")},
    "export": ("text", "text*"),
    "unset": ("text", "text*"),
    "[": ("text*",),
    "echo": ("text*",),
    "printf": ("text", "text*"),
    "true": (),
    "set": (),
    "git commit": ("pathspec*",),
    "git add": ("pathspec*",),
    "git restore": ("pathspec*",),
    "git checkout": ("pathspec*",),
    "git status": ("pathspec*",),
    "git ls-files": ("pathspec*",),
    **{f"git {sub}": ("text*",) for sub in ("log", "diff", "show", "grep", "blame", "branch")},
    **{f"git {sub}": ("text*",) for sub in ("rev-parse", "merge-base", "worktree", "stash")},
    "git config": ("text*",),
    "git merge": ("text*",),
    "git push": ("text", "text"),
}
# 228 S2: a valued option's value words by type, keyed like OPTION_TABLE; unlisted is ("text",).
OPTION_VALUE_TYPES: dict[str, dict[str, tuple[str, ...]]] = {
    "sort": {
        "-o": ("write",),
        "--output": ("write",),
        "-T": ("write",),
        "--temporary-directory": ("write",),
        "--compress-program": ("script",),
        "--files0-from": ("read",),
        "--random-source": ("read",),
    },
    "find": {
        "-fprint": ("write",),
        "-fprint0": ("write",),
        "-fls": ("write",),
        "-fprintf": ("write", "text"),
        "-newer": ("read",),
        "-anewer": ("read",),
        "-cnewer": ("read",),
        "-samefile": ("read",),
        "-files0-from": ("read",),
    },
    "file": {
        "-m": ("read",),
        "--magic-file": ("read",),
        "-f": ("read",),
        "--files-from": ("read",),
    },
    "rg": {
        "-f": ("read",),
        "--file": ("read",),
        "--ignore-file": ("read",),
        "--pre": ("script",),
        "--hostname-bin": ("script",),
    },
    "grep": {"-f": ("read",), "--file": ("read",), "--exclude-from": ("read",)},
    "jq": {
        "-f": ("read",),
        "--from-file": ("read",),
        "--arg": ("text", "text"),
        "--argjson": ("text", "text"),
        "--slurpfile": ("text", "read"),
        "--rawfile": ("text", "read"),
    },
    "wc": {"--files0-from": ("read",)},
    "cp": {"-t": ("write",), "--target-directory": ("write",)},
    "mv": {"-t": ("write",), "--target-directory": ("write",)},
    "ln": {"-t": ("write",), "--target-directory": ("write",)},
    "install": {"-t": ("write",), "--target-directory": ("write",), "--strip-program": ("script",)},
    "touch": {"-r": ("read",), "--reference": ("read",)},
    "truncate": {"-r": ("read",), "--reference": ("read",)},
    "chmod": {"--reference": ("read",)},
    "chown": {"--reference": ("read",)},
    "chgrp": {"--reference": ("read",)},
    "shred": {"--random-source": ("read",)},
    "rsync": {
        "-e": ("script",),
        "--rsh": ("script",),
        "--rsync-path": ("script",),
        "-T": ("write",),
        "--temp-dir": ("write",),
        "--log-file": ("write",),
        "--backup-dir": ("write",),
        "--partial-dir": ("write",),
        "--exclude-from": ("read",),
        "--include-from": ("read",),
    },
    "diff": {"--exclude-from": ("read",)},
    "sed": {"-e": ("script",), "--expression": ("script",), "-f": ("read",), "--file": ("read",)},
    "python": {"-m": ("module",), "-c": ("script",)},
    "node": {
        "-e": ("script",),
        "--eval": ("script",),
        "-p": ("script",),
        "--print": ("script",),
        "-r": ("module",),
        "--require": ("module",),
        "--import": ("module",),
        "--loader": ("module",),
        "--experimental-loader": ("module",),
        "--env-file": ("read",),
    },
    "perl": {"-e": ("script",), "-E": ("script",)},
    "ruby": {"-e": ("script",)},
    "php": {"-r": ("script",), "-B": ("script",), "-R": ("script",), "-E": ("script",)},
    "pytest": {"-c": ("read",), "-p": ("module",), "--rootdir": ("read",)},
    "make": {
        "-C": ("read",),
        "--directory": ("read",),
        "-f": ("read",),
        "--file": ("read",),
        "--makefile": ("read",),
        "-I": ("read",),
        "--include-dir": ("read",),
    },
    "nox": {"-f": ("read",), "--noxfile": ("read",)},
    "just": {
        "-f": ("read",),
        "--justfile": ("read",),
        "-d": ("read",),
        "--working-directory": ("read",),
    },
    "npx": {"-c": ("script",), "--call": ("script",)},
    "uv": {"--directory": ("read",), "--project": ("read",), "--cache-dir": ("write",)},
    "go": {"-C": ("read",)},
    "pnpm": {"-C": ("read",), "--dir": ("read",)},
    "yarn": {"--cwd": ("read",)},
    "bun": {"--cwd": ("read",)},
    "npm": {"--prefix": ("read",)},
    "tsc": {"-p": ("read",), "--project": ("read",)},
    "git commit": {
        "-F": ("read",),
        "--file": ("read",),
        "-t": ("read",),
        "--template": ("read",),
        "--pathspec-from-file": ("read",),
    },
}
# issue 204: the read verbs' options that write a file; uniq writes its second operand instead.
READ_ONLY_WRITE_OPTS: dict[str, frozenset[str]] = {
    "sort": frozenset({"-o", "--output", "-T", "--temporary-directory", "--compress-program"}),
    "find": frozenset({"-fprint", "-fprint0", "-fprintf", "-fls"}),
    "file": frozenset({"-C", "--compile"}),
    "uniq": frozenset(),
}
# spec 6: grep, worktree and merge-base pass only the read forms of their grammar rows.
READ_ONLY_GIT = frozenset(
    {"diff", "log", "show", "status", "rev-parse", "ls-files", "branch"}
    | {"grep", "worktree", "merge-base"}
)
SPECIALIST_GIT = frozenset({"diff", "show", "log"})
# M1: charter-docs git is add/commit/status/log/diff only (4.2); no merge, no worktree.
CHARTER_DOCS_GIT = frozenset({"add", "commit", "status", "log", "diff"})
# 0084: charter-docs reads as (flag letters, value-taking letters); long options refuse.
DOCS_READS: dict[str, tuple[frozenset[str], frozenset[str]]] = {
    "cat": (frozenset("AbeEnstTuv"), frozenset()),
    "grep": (frozenset("cEFhHiIlLnoqrsvwx"), frozenset("eABCm")),
    "head": (frozenset("qv"), frozenset("nc")),
    "tail": (frozenset("qv"), frozenset("nc")),
    "wc": (frozenset("clmwL"), frozenset()),
    "ls": (frozenset("1aAdFhlrRSt"), frozenset()),
    "diff": (frozenset("abBiNqsuwy"), frozenset("U")),
    "sed": (frozenset("nErsu"), frozenset("e")),
}
CONDUCTOR_GIT = frozenset({"push", "status", "log", "rev-parse", "branch", "diff", "add", "commit"})
# Final review I1: transport plumbing and credential helpers reach remotes without push.
GIT_PLUMBING_REMOTE = frozenset(
    {"send-pack", "http-push", "receive-pack", "upload-pack", "fetch-pack"}
    | {"credential", "credential-store", "credential-cache"}
)
# Final review I3a: coder git is an allowlist; everything else blocks.
CODER_GIT = frozenset(
    {"add", "commit", "status", "diff", "log", "show", "rev-parse", "ls-files", "branch"}
    | {"stash", "restore", "checkout", "worktree", "config", "grep", "blame", "merge-base"}
)
# 0044: the named git grants a hook flag selects (git_grammar --allow, read_only_bash --git).
GIT_SETS: dict[str, frozenset[str]] = {
    "coder": CODER_GIT,
    "docs": CHARTER_DOCS_GIT,
    "conductor": CONDUCTOR_GIT,
    "specialist": SPECIALIST_GIT,
    "read-only": READ_ONLY_GIT,
}
# 0022: long options whose =x or next-token value is not a path; --preserve takes =x only.
_VALUE_LONG_NEXT = frozenset(
    {"--mode", "--owner", "--group", "--suffix", "--size", "--date", "--from", "--chmod"}
    | {"--exclude", "--include", "--filter", "--exclude-from", "--include-from"}
)
# 0022: shell state a worker could carry into a later segment (GIT_WORK_TREE and kin).
SHELL_VAR_CMDS = frozenset({"export", "declare", "typeset", "readonly", "local"})
# 0022: builtins that rebind what a later segment runs (hash pytest=/bin/rm).
SHELL_STATE_CMDS = frozenset(
    {"hash", "alias", "unalias", "unset", "shopt", "enable", "setopt", "unsetopt"}
    | {"trap", "getopts"}
)
# prepush2-2026-10-27: archive and multi-call tools write targets the jail does not model.
ARCHIVE_CMDS = frozenset(
    {"tar", "bsdtar", "gtar", "unzip", "zip", "busybox", "toybox", "cpio", "pax", "ar"}
    | {"7z", "7za", "7zr", "7zz"}
)
# issue 76: the one wrapper table, (no-argument options, one-argument options) per base name.
# An option off its row makes strip_wrappers return None, so callers fail closed.
WRAPPER_OPTS: dict[str, tuple[frozenset[str], frozenset[str]]] = {
    "sudo": (
        frozenset({"-E", "-H", "-n", "-S", "-i", "-s", "-b", "-k", "-P"}),
        frozenset({"-u", "-g", "-h", "-p", "-C", "-U", "-D", "-r", "-t", "--chdir"}),
    ),
    "doas": (frozenset({"-n", "-s"}), frozenset({"-u", "-C"})),
    # issue 80, 116 (P8): -S and --split-string stay off this row, so admit refuses them.
    "env": (
        frozenset({"-i", "--ignore-environment", "-0", "--null", "-"}),
        frozenset({"-u", "--unset", "-C", "--chdir", "-a", "--argv0"}),
    ),
    "nice": (frozenset(), frozenset({"-n", "--adjustment"})),
    "nohup": (frozenset(), frozenset()),
    "stdbuf": (frozenset(), frozenset({"-i", "-o", "-e", "--input", "--output", "--error"})),
    "timeout": (
        frozenset({"--preserve-status", "--foreground", "-v", "--verbose"}),
        frozenset({"-s", "--signal", "-k", "--kill-after"}),
    ),
    "exec": (frozenset({"-c", "-l"}), frozenset({"-a"})),
    "command": (frozenset({"-p"}), frozenset()),
    "builtin": (frozenset(), frozenset()),
    "time": (
        frozenset({"-p", "-v", "--verbose", "--portability", "-a", "--append", "-q", "--quiet"}),
        frozenset({"-f", "-o", "--format", "--output"}),
    ),
    "xargs": (
        frozenset({"-0", "--null", "-r", "--no-run-if-empty", "-t", "--verbose", "-p", "-x"}),
        frozenset({"-I", "-n", "-P", "-d", "-L", "-s", "-E", "-a", "--arg-file", "--delimiter"}),
    ),
    # 0048, pin U2 -> E6: the kernel wrapper, daedalus_confine.py --unit <worktree> -- <command>.
    "daedalus_confine.py": (frozenset({"--"}), frozenset({"--unit"})),
    # issue 82: runner wrappers; --root and --wd stay off unshare and nsenter so they fail closed.
    "setsid": (frozenset({"-c", "--ctty", "-f", "--fork", "-w", "--wait"}), frozenset()),
    "chroot": (frozenset({"--skip-chdir"}), frozenset({"--groups", "--userspec"})),
    "ionice": (
        frozenset({"-t", "--ignore"}),
        frozenset({"-c", "--class", "-n", "--classdata", "-p", "--pid", "-P", "--pgid"})
        | frozenset({"-u", "--uid"}),
    ),
    "taskset": (frozenset({"-a", "--all-tasks", "-p", "--pid", "-c", "--cpu-list"}), frozenset()),
    "flock": (
        frozenset({"-s", "--shared", "-x", "-e", "--exclusive", "-u", "--unlock", "-n", "--nb"})
        | frozenset({"--nonblock", "-o", "--close", "-F", "--no-fork", "--verbose"}),
        frozenset({"-w", "--wait", "--timeout", "-E", "--conflict-exit-code"}),
    ),
    "unshare": (
        frozenset({"-f", "--fork", "-m", "--mount", "-u", "--uts", "-i", "--ipc", "-n", "--net"})
        | frozenset({"-p", "--pid", "-U", "--user", "-C", "--cgroup", "-T", "--time"})
        | frozenset({"-r", "--map-root-user", "-c", "--map-current-user", "--map-auto"})
        | frozenset({"--mount-proc", "--kill-child", "--keep-caps"}),
        frozenset({"-S", "--setuid", "-G", "--setgid", "-l", "--load-interp", "--propagation"})
        | frozenset({"--setgroups", "--map-user", "--map-group", "--map-users", "--map-groups"})
        | frozenset({"--monotonic", "--boottime"}),
    ),
    "chrt": (
        frozenset({"-a", "--all-tasks", "-b", "--batch", "-d", "--deadline", "-f", "--fifo"})
        | frozenset({"-i", "--idle", "-o", "--other", "-r", "--rr", "-R", "--reset-on-fork"})
        | frozenset({"-m", "--max", "-p", "--pid", "-v", "--verbose"}),
        frozenset({"-T", "--sched-runtime", "-P", "--sched-period", "-D", "--sched-deadline"}),
    ),
    "nsenter": (
        frozenset({"-a", "--all", "-m", "--mount", "-u", "--uts", "-i", "--ipc", "-n", "--net"})
        | frozenset({"-p", "--pid", "-C", "--cgroup", "-U", "--user", "-T", "--time"})
        | frozenset({"--preserve-credentials", "-e", "--env", "-F", "--no-fork"})
        | frozenset({"-Z", "--follow-context", "-c", "--join-cgroup", "--user-parent"}),
        frozenset({"-t", "--target", "-S", "--setuid", "-G", "--setgid"}),
    ),
}
CONFINE = "daedalus_confine.py"
# issue 76: options that move the working folder before the wrapped command runs.
WRAPPER_CHDIR = frozenset({("env", "-C"), ("env", "--chdir"), ("sudo", "-D"), ("sudo", "--chdir")})
# issue 107: the option slot of a wrapper operand that names a file the wrapper creates.
WRAPPER_FILE = "<file operand>"
# issue 76, 107: options and operands whose value is a file the wrapper itself writes.
# P9 sweep: unshare's --<ns>=file persists a namespace by a bind mount on that file.
WRAPPER_WRITES = frozenset(
    {("time", "-o"), ("time", "--output"), ("flock", WRAPPER_FILE)}
    | {("unshare", f"--{ns}") for ns in ("mount", "uts", "ipc", "net", "pid", "user")}
    | {("unshare", "--cgroup"), ("unshare", "--time")}
)
# issue 76: the one duration regex, timeout's first operand.
DURATION: re.Pattern[str] = re.compile(r"[\d.]+[smhd]?")
# issue 82: the operand a wrapper reads before its command; None never matches (chroot re-roots).
WRAPPER_OPERAND: dict[str, re.Pattern[str] | None] = {
    "timeout": DURATION,
    "taskset": re.compile(r"[0-9a-fA-FxX,:-]+"),
    "chrt": re.compile(r"\d+"),
    "flock": re.compile(r"[^-].*"),
    "chroot": None,
}
# issue 82: flock runs a shell body after its file operand; the jail never walks one.
FLOCK_BODY = frozenset({"-c", "--command"})
_VERSION_TAIL = re.compile(r"(?<=[A-Za-z])[-.]?\d+(?:\.\d+)*$")


def command_family(word: str) -> str:
    # pin A2 -> A3, P5: base name, path stripped, trailing version folded (python3.12: python).
    base = os.path.basename(word)
    return _VERSION_TAIL.sub("", base) or base


# P6, fix round 1: a static shell family list; no table admits a shell word.
_SHELLS = frozenset(
    {"bash", "sh", "dash", "zsh", "ksh", "ksh93", "mksh", "ash", "rbash", "yash", "posh"}
    | {"fish", "csh", "tcsh"}
)
# fix round 1: /etc/shells entries that are no shell; any other unlisted entry fails a test.
NOT_SHELLS = frozenset({"tmux", "screen", "git-shell", "nologin", "false"})
# P6, P7: the OPTION_TABLE row of each family, and the options that carry inline code.
INLINE_FLAGS: dict[str, frozenset[str]] = {
    "shell": frozenset({"-c"}),
    "python": frozenset({"-c"}),
    "perl": frozenset({"-e", "-E"}),
    "ruby": frozenset({"-e"}),
    "node": frozenset({"-e", "-p", "--eval", "--print"}),
    "php": frozenset({"-r", "-B", "-R", "-E"}),
}
INTERPRETERS = frozenset(INLINE_FLAGS) - {"shell"}
# 8.5 ruling A, issue 116: first tokens a worker may never run, read through command_family.
WORKER_WRAPPERS = (
    frozenset(WRAPPER_OPTS) | frozenset({"eval", "source", ".", "python3"}) | _SHELLS | INTERPRETERS
)
_TRUSTED_BIN = frozenset({"/bin", "/usr/bin", "/usr/local/bin", "/sbin", "/usr/sbin"})
# issue 121: the one assignment word, NAME=, NAME+= or NAME[...]= and NAME[...]+=.
_ASSIGN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(?:\[[^\]]*\])?\+?=")
_SAFE_ENV = re.compile(r"^(?:CI|NODE_ENV|TZ|LANG|LC_ALL|PYTHONDONTWRITEBYTECODE)\+?=")
_GIT_CONFIG_DENY = re.compile(
    r"remote\..+\.(?:mirror|push)|push\.default|protocol\.(?:.+\.)?allow|core\.hookspath"
    r"|core\.fsmonitor|core\.pager|core\.sshcommand|diff\.external|alias\..*",
    re.I,
)
_GIT_GLOBAL_WITH_ARG = frozenset(
    {"-C", "-c", "--git-dir", "--work-tree", "--namespace", "--config-env", "--attr-source"}
    | {"--shallow-file"}
)
# issue 121 (S2): git's global options that take no separate value, and the =value spellings.
GIT_GLOBAL_FLAGS = frozenset(
    {"-p", "--paginate", "-P", "--no-pager", "--bare", "--no-replace-objects", "--no-lazy-fetch"}
    | {"--no-optional-locks", "--no-advice", "--literal-pathspecs", "--glob-pathspecs"}
    | {"--no-literal-pathspecs"}
    | {"--noglob-pathspecs", "--icase-pathspecs", "--exec-path", "--html-path", "--man-path"}
    | {"--info-path", "-v", "--version", "-h", "--help"}
)
GIT_GLOBAL_EQ = (
    "--git-dir=",
    "--work-tree=",
    "--namespace=",
    "--config-env=",
    "--attr-source=",
    "--exec-path=",
    "--list-cmds=",
    "--super-prefix=",
)


_PUSH_FORBIDDEN = (
    "--force",
    "--force-with-lease",
    "--force-if-includes",
    "--delete",
    "--mirror",
    "--prune",
    "--no-verify",
)
_PUSH_ALL = ("--all", "--branches")
_PUSH_ARG_OPTS = frozenset({"-o", "--push-option", "--repo", "--receive-pack", "--exec"})
_SIGNABLE_GIT = frozenset({"commit", "merge", "rebase", "cherry-pick", "revert", "am", "pull"})
_FIND_DENY = frozenset({"-delete", "-exec", "-execdir", "-ok", "-okdir", "-fls"})
_FALSE = frozenset({"false", "0", "no", "off"})
_DEFAULT_BRANCHES = frozenset({"main", "master"})
# 8.5, F1: the plugin's scripts dir; append_ledger.py runs only by this absolute path.
_REPO_SCRIPTS = os.path.realpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
# F1, O7: the variable is empty in agent Bash, so the literal form never reaches the script.
R_LEDGER_LITERAL = (
    "${CLAUDE_PLUGIN_ROOT} is empty in agent Bash. "
    f"Next: run python3 {os.path.join(_REPO_SCRIPTS, 'append_ledger.py')} with the same "
    "arguments; it is the path your brief names."
)

R_UNSUPPORTED = (
    "command uses an unsupported shell construct (newline, background &, substitution, "
    "input redirect, a redirect other than >file, >>file, 2>&1 or >/dev/null, grouping, or |&). "
    "Next: send plain commands joined by &&, || or |."
)
R_INLINE = (
    "wrappers, shells, and interpreters are not permitted for workers. "
    "Next: run an allowlisted command directly."
)
R_GIT_CONFIG = (
    "git config overrides (-c, --config-env, --exec-path, git config writes) are not permitted "
    "for workers. Next: run git without them."
)
R_ENV = (
    "environment assignments in front of a command are not permitted for workers. Next: drop them."
)
R_SHELL_VARS = (
    "setting or exporting shell variables is not permitted for workers. "
    "Next: drop it; only CI, NODE_ENV, TZ, LANG, LC_ALL, PYTHONDONTWRITEBYTECODE "
    "may prefix a command."
)
R_SHELL_STATE = (
    "shell builtins that rebind commands or shell options are not permitted for workers. "
    "Next: run the command directly."
)
R_RSYNC_REMOTE = (
    "rsync may not reach a remote host or choose a remote shell for workers. "
    "Next: copy between local absolute paths only."
)
R_FIND_WRITE = (
    "find may not delete, exec, or write files for workers. "
    "Next: list with find, then act on the paths with an allowed command."
)
R_HYGIENE = (
    "a token contains $, {, }, a backslash, or a leading ~; workers spell arguments literally. "
    "Next: pass the literal value."
)
R_VARIABLE = (
    "command name or git subcommand comes from a variable; the jail cannot judge it. "
    "Next: spell the command out."
)
R_FORCE_PUSH = "force, delete, or mirror push is never permitted. Next: push a new branch instead."
R_CLEAN = "git clean is never run by any Daedalus component. Next: remove files by name."
R_STASH_UNTRACKED = (
    "stash of untracked or ignored files removes the plugin data dir. "
    "Next: stash tracked changes only."
)
R_DESTRUCTIVE = "destructive command. Next: do not run this; ask the operator."
R_SIGN = "signing happens only in the operator's own shell (C.1). Next: leave the commit unsigned."
R_DEFAULT_BRANCH = (
    "the operator merges; never push to the default branch (0001). "
    "Next: push the unit branch instead."
)
R_GIT_CONFIG_KEY = (
    "git -c keys that change push, hook, pager, ssh, protocol, or alias behavior are not "
    "permitted. Next: run git without that -c."
)
R_GIT_PLUMBING = (
    "git transport plumbing and credential helpers are not run from a session. "
    "Next: use git push or git fetch by name."
)
R_DATA_DIR_GIT = (
    "the plugin data directory is never committed. Next: leave .claude/daedalus out of git."
)
R_CLAUDE_PATH = (
    "the command runs the claude binary, by name, link or versioned path, and starts a nested "
    "session the jail cannot attribute to an agent (issue 55). Next: run it from your own shell."
)
R_UNTRUSTED_PATH = (
    "a command given as a path runs only from the system bin folders, a unit worktree or the "
    "manifest's declared commands (issue 55). Next: run the tool by name or from your worktree."
)
R_ARCHIVE = (
    "archive and multi-call tools (tar, zip, unzip, cpio, 7z, ar, busybox and kin) write paths "
    "the jail cannot judge, so workers never run them (prepush2-2026-10-27). Next: copy or "
    "write each file by name with an allowed command."
)
CONFINE_PATH = os.path.join(_REPO_SCRIPTS, CONFINE)
CONFINE_NEXT = (
    f"Next: run the plugin's kernel wrapper {CONFINE_PATH} with --unit, your unit worktree "
    "path, then -- and the command."
)
R_CONFINE_FORM = (
    "the kernel wrapper runs in one form only, the plugin's own file with --unit, the unit "
    f"worktree path, then -- and the command (0048). {CONFINE_NEXT}"
)
_PROJECT_DATA = ".claude/daedalus"
_GLOB_CHARS = frozenset("*?[")
_STASH_WITH_ARG = frozenset({"-m", "--message", "--pathspec-from-file"})


_HOME = os.path.normpath(os.path.expanduser("~"))
# N5: --m is git's unique prefix of --mirror; every other forbidden option needs 2 chars.
_PUSH_MIN = {"--mirror": 1}


def _under(path: str, root: str) -> bool:
    real_path = os.path.realpath(path)
    real_root = os.path.realpath(root)
    # 0164: the filesystem root holds every path; "/" plus os.sep would match none.
    return real_path == real_root or real_path.startswith(real_root.rstrip(os.sep) + os.sep)


def _abs(path: str, cwd: str) -> str:
    return path if os.path.isabs(path) else os.path.join(cwd, path)


CHAR, ESCAPE, OPEN, CLOSE = "char", "escape", "open", "close"


class Lexeme(NamedTuple):
    # issue 76: one quote_walk step; quote is its span, and a quote mark carries the one it toggles.
    at: int
    text: str
    quote: str
    kind: str


def quote_walk(text: str) -> Iterator[Lexeme]:
    # issue 76: the one quote model; outside single quotes a backslash pairs with the next char.
    quote = ""
    i = 0
    while i < len(text):
        char = text[i]
        if quote and char == quote:
            yield Lexeme(i, char, quote, CLOSE)
            quote = ""
            i += 1
        elif char == "\\" and quote != "'":
            yield Lexeme(i, text[i : i + 2], quote, ESCAPE)
            i += 2
        elif not quote and char in "'\"":
            quote = char
            yield Lexeme(i, char, quote, OPEN)
            i += 1
        else:
            yield Lexeme(i, char, quote, CHAR)
            i += 1


def _base(token: str) -> str:
    return os.path.basename(token)


def _cmd_name(tokens: list[str]) -> str:
    first = tokens[0] if tokens else ""
    if not first or "$" in first or "'" in first or '"' in first:
        return ""
    if "/" in first:
        # 8.5: a path outside the system bin dirs could be an agent-written script.
        return _base(first) if os.path.dirname(first) in _TRUSTED_BIN else ""
    return first


def _short_flags(token: str) -> set[str]:
    if token.startswith("-") and not token.startswith("--") and len(token) > 1:
        return set(token[1:])
    return set()


def _long_matches(arg: str, canonical: str, min_chars: int = 4) -> bool:
    key = arg.split("=", 1)[0]
    return key.startswith("--") and len(key) - 2 >= min_chars and canonical.startswith(key)


def _git_split(tokens: list[str]) -> tuple[str | None, list[str], list[str]]:
    if not tokens or _base(tokens[0]) != "git":
        return None, [], []
    globals_: list[str] = []
    i = 1
    while i < len(tokens):
        token = tokens[i]
        if token in _GIT_GLOBAL_WITH_ARG:
            globals_.extend(tokens[i : i + 2])
            i += 2
            continue
        if token.startswith("-"):
            globals_.append(token)
            i += 1
            continue
        return token, tokens[i + 1 :], globals_
    return None, [], globals_


def _git_subcommand(tokens: list[str]) -> str | None:
    return _git_split(tokens)[0]


def _git_config_override(globals_: list[str]) -> bool:
    return any(
        token in {"-c", "--config-env"} or token.startswith(("--config-env=", "--exec-path"))
        for token in globals_
    )


def _config_settings(globals_: list[str]) -> list[tuple[str, str]]:
    settings: list[tuple[str, str]] = []
    for i, token in enumerate(globals_):
        if token in {"-c", "--config-env"} and i + 1 < len(globals_):
            setting = globals_[i + 1]
        elif token.startswith("--config-env="):
            setting = token.split("=", 1)[1]
        else:
            continue
        key, _, value = setting.partition("=")
        settings.append((key, value))
    return settings


def _gpgsign_override(globals_: list[str]) -> bool:
    return any(
        "gpgsign" in key.lower() and value.lower() not in _FALSE
        for key, value in _config_settings(globals_)
    )


def _config_key_denied(globals_: list[str]) -> bool:
    return any(_GIT_CONFIG_DENY.fullmatch(key) for key, _ in _config_settings(globals_))


def _push_parts(args: list[str]) -> tuple[bool, list[str], set[str]]:
    positional: list[str] = []
    flags: set[str] = set()
    forbidden = False
    i = 0
    while i < len(args):
        arg = args[i]
        if arg == "--":
            positional.extend(args[i + 1 :])
            break
        if arg in _PUSH_ARG_OPTS:
            i += 2
            continue
        if arg.startswith("--"):
            flags.add(arg.split("=", 1)[0])
            forbidden = forbidden or any(
                _long_matches(arg, c, _PUSH_MIN.get(c, 2)) for c in _PUSH_FORBIDDEN
            )
        elif _short_flags(arg):
            flags.update(f"-{c}" for c in _short_flags(arg))
            forbidden = forbidden or bool({"f", "d"} & _short_flags(arg))
        else:
            positional.append(arg)
        i += 1
    refspecs = positional[1:]
    forbidden = forbidden or any(ref.startswith(("+", ":")) for ref in refspecs)
    return forbidden, refspecs, flags


def _push_destination(refspec: str) -> str:
    dest = refspec.split(":")[-1].lstrip("+")
    return dest.removeprefix("refs/heads/")


def _push_to_default(refspecs: list[str], flags: set[str]) -> bool:
    if any(_long_matches(flag, c, 2) for flag in flags for c in _PUSH_ALL):
        return True
    for ref in refspecs:
        if "*" in ref or _push_destination(ref).split("/")[-1].casefold() in _DEFAULT_BRANCHES:
            return True
    return False


def _rm_target_dangerous(target: str) -> bool:
    if "{" in target:
        return True
    expanded = target.replace("${HOME}", _HOME).replace("$HOME", _HOME)
    if expanded.startswith("~"):
        expanded = os.path.expanduser(expanded)
    trimmed = expanded.rstrip("/") or "/"
    base = (trimmed[:-2] or "/") if trimmed.endswith("/*") else trimmed
    if base.startswith("/"):
        base = os.path.normpath(base)
        base = "/" if base == "//" else base
    # N4: the home dir or any ancestor of it (~/.. resolves to /home).
    return base == "/" or _HOME == base or _HOME.startswith(base + "/")


def _rm_reason(args: list[str]) -> str | None:
    recursive = False
    targets: list[str] = []
    options_done = False
    for arg in args:
        if not options_done and arg == "--":
            options_done = True
        elif not options_done and arg.startswith("--"):
            recursive = recursive or _long_matches(arg, "--recursive", 1)
        elif not options_done and _short_flags(arg):
            recursive = recursive or bool({"r", "R"} & _short_flags(arg))
        else:
            targets.append(arg)
    if recursive and any(_rm_target_dangerous(t) for t in targets):
        return R_DESTRUCTIVE
    return None


def _quote_spans(text: str) -> str:
    # N3: each quoted span, its marks included, becomes one Q.
    return "".join(
        "Q" if lex.kind == OPEN else lex.text
        for lex in quote_walk(text)
        if not lex.quote or lex.kind == OPEN
    )


class WrapperOption(NamedTuple):
    # issue 76: a one-argument wrapper option; its value is tokens[at][len(prefix):].
    wrapper: str
    option: str
    at: int
    prefix: str


def unwrap(tokens: list[str]) -> tuple[list[str], list[WrapperOption]] | None:
    # issue 76: strip_wrappers plus the one-argument options it passed, in order.
    options: list[WrapperOption] = []
    rest = _strip_wrappers(tokens, [], options)
    return None if rest is None else (rest, options)


def _long_option(spelled: str, row: frozenset[str]) -> str:
    # issue 76: getopt_long takes a unique prefix (--ch for --chdir); else it stays as spelled.
    if not spelled.startswith("--") or spelled == "--" or spelled in row:
        return spelled
    hits = [option for option in row if option.startswith(spelled)]
    return hits[0] if len(hits) == 1 else spelled


def _cluster(
    token: str, no_arg: frozenset[str], with_arg: frozenset[str]
) -> tuple[str, int] | None:
    # issue 76, audit round 1: getopt reads -iC/x as -i, then -C taking the rest of the word.
    # Returns (one-argument letter or "", index its value starts at); None at a letter off the row.
    for cut in range(2, len(token) + 1):
        letter = "-" + token[cut - 1]
        if letter in with_arg:
            return letter, cut
        if letter not in no_arg:
            return None
    return "", len(token)


class OptionScan(NamedTuple):
    # P2 to P4: operands in order, the canonical options met, and whether one was off the table.
    operands: list[str]
    options: list[str]
    off: bool
    # A2 fix round 3: the index of the -- no option consumed, or -1.
    dashes: int = -1


def scan_options(name: str, args: list[str]) -> OptionScan:
    # P2 to P4 by OPTION_TABLE; find's predicates are whole single-dash words, never clusters.
    no_arg, with_arg = OPTION_TABLE.get(name, (frozenset(), frozenset()))
    row = no_arg | with_arg
    words = name in WORD_OPTION_CMDS
    operands: list[str] = []
    options: list[str] = []
    off = False
    i = 0
    while i < len(args):
        word = args[i]
        i += 1
        if word == "--" and not words:
            operands += args[i:]
            return OptionScan(operands, options, off, i - 1)
        if word == "-" or not word.startswith("-"):
            operands.append(word)
            continue
        if words:
            key = max((o for o in row if word.startswith(o)), key=len, default="")
            attached = len(word) > len(key)
        elif word.startswith("--"):
            key = _long_option(word.split("=", 1)[0], row)
            attached = "=" in word
        else:
            cluster = _cluster(word, no_arg, with_arg)
            if cluster is None:
                off = True
                continue
            letter, cut = cluster
            options += ["-" + ch for ch in word[1:cut]]
            i += 1 if letter and cut == len(word) else 0
            continue
        if key not in row:
            off = True
            continue
        options.append(key)
        i += 1 if key in with_arg and not attached else 0
    return OptionScan(operands, options, off)


def split_options(name: str, args: list[str]) -> tuple[list[str], bool]:
    # pin A1 -> A2: the operands left after P2 to P4, and True when an option was off the table.
    scan = scan_options(name, args)
    return scan.operands, scan.off


def strip_wrappers(tokens: list[str]) -> list[str] | None:
    # issue 76: the tokens from the wrapped command on; None when an option is off WRAPPER_OPTS.
    return _strip_wrappers(tokens, [])


def _strip_wrappers(
    tokens: list[str], assigns: list[str], options: list[WrapperOption] | None = None
) -> list[str] | None:
    total = len(tokens)
    found: list[WrapperOption] = [] if options is None else options
    while tokens:
        while tokens and _ASSIGN.match(tokens[0]):
            assigns.append(tokens[0])
            tokens = tokens[1:]
        if not tokens or _base(tokens[0]) not in WRAPPER_OPTS:
            return tokens
        name = _base(tokens[0])
        no_arg, with_arg = WRAPPER_OPTS[name]
        offset = total - len(tokens)
        i = 1
        while i < len(tokens):
            token = tokens[i]
            spelled = token.split("=", 1)[0]
            key = _long_option(spelled, no_arg | with_arg)
            if token == "--":
                i += 1
                break
            if name == "env" and _ASSIGN.match(token):
                assigns.append(token)
            elif not token.startswith("-") or token == "-" and name != "env":
                break
            elif key in no_arg and ("=" not in token or key.startswith("--")):
                if "=" in token and (name, key) in WRAPPER_WRITES:
                    found.append(WrapperOption(name, key, offset + i, spelled + "="))
            elif key in with_arg and "=" in token and key.startswith("--"):
                # audit round 2: only getopt_long strips = (--chdir=v); a short -C=v keeps it,
                # so it falls through to _cluster, which reads its value as =v.
                found.append(WrapperOption(name, key, offset + i, spelled + "="))
            elif key in with_arg and key.startswith("--") or token in with_arg:
                if i + 1 < len(tokens):
                    found.append(WrapperOption(name, key, offset + i + 1, ""))
                i += 1
            elif name == "nice" and re.fullmatch(r"-\d+", token):
                pass
            elif name == "command" and token in {"-v", "-V"}:
                return []
            elif not token.startswith("--") and (cluster := _cluster(token, no_arg, with_arg)):
                letter, cut = cluster
                if letter and cut < len(token):
                    found.append(WrapperOption(name, letter, offset + i, token[:cut]))
                elif letter:
                    if i + 1 < len(tokens):
                        found.append(WrapperOption(name, letter, offset + i + 1, ""))
                    i += 1
            else:
                return None
            i += 1
        if name in WRAPPER_OPERAND:
            # issue 76, 82: an operand off its pattern leaves the command unknown.
            operand = WRAPPER_OPERAND[name]
            if i >= len(tokens) or operand is None or not operand.fullmatch(tokens[i]):
                return None
            # issue 107, P9: flock creates its file operand; only a lone numeric one is an fd.
            fd = tokens[i].isdigit() and i + 1 == len(tokens)
            if (name, WRAPPER_FILE) in WRAPPER_WRITES and not fd:
                found.append(WrapperOption(name, WRAPPER_FILE, offset + i, ""))
            i += 1
            if name == "flock" and tokens[i : i + 1] and tokens[i].split("=")[0] in FLOCK_BODY:
                return None
        tokens = tokens[i:]
    return tokens


def env_split_values(tokens: list[str]) -> list[str]:
    # issue 80: the value of each env -S or --split-string; 228 tail: no caller, guardrails row.
    return [
        v
        for at, word in enumerate(tokens)
        if _base(word) == "env"
        for v in _env_split(tokens[at + 1 :])
    ]


def _env_split(args: list[str]) -> list[str]:
    # issue 80, 116 (P8): getopt order past values and NAME=VALUE words; an unknown letter is
    # read past, so -S behind it is found; an expanding word may be -S, so it is an unread body.
    with_arg = WRAPPER_OPTS["env"][1]
    i = 0
    while i < len(args) and args[i] not in {"-", "--"}:
        token = args[i]
        later = args[i + 1 : i + 2] or [""]
        if _expands(token):
            return [""]
        if _ASSIGN.match(token):
            i += 1
            continue
        if not token.startswith("-"):
            break
        if token.startswith("--"):
            key, eq, value = token.partition("=")
            if "--split-string".startswith(key):
                return [value if eq else later[0]]
            i += 2 if not eq and _long_option(key, with_arg) in with_arg else 1
            continue
        for cut, letter in enumerate(token[1:], start=2):
            if letter == "S":
                return [token[cut:] or later[0]]
            if "-" + letter in with_arg:
                i += 0 if token[cut:] else 1
                break
        i += 1
    return []


def _git_reason(tokens: list[str], assigns: list[str]) -> str | None:
    # 228 tail: tokens are an admitted git command's parsed words, so every word is literal.
    sub, args, globals_ = _git_split(tokens)
    if _gpgsign_override(globals_):
        return R_SIGN
    if _config_key_denied(globals_):
        return R_GIT_CONFIG_KEY
    if any(a.split("=", 1)[0].startswith("GIT_CONFIG_") and "sign" in a.lower() for a in assigns):
        return R_SIGN
    if sub in GIT_PLUMBING_REMOTE:
        return R_GIT_PLUMBING
    if sub in {"add", "stage", "commit", "update-index"}:
        reason = _git_data_dir_reason(sub, args, globals_)
        if reason:
            return reason
    if sub == "push":
        forbidden, refspecs, flags = _push_parts(args)
        if forbidden:
            return R_FORCE_PUSH
        if _push_to_default(refspecs, flags):
            return R_DEFAULT_BRANCH
    if sub == "clean":
        return R_CLEAN
    if sub == "stash" and _stash_untracked(args):
        return R_STASH_UNTRACKED
    if sub in _SIGNABLE_GIT and any(
        _long_matches(arg, "--gpg-sign", 2) or "S" in _short_flags(arg) for arg in args
    ):
        return R_SIGN
    if sub == "tag" and any(
        _long_matches(arg, "--sign", 2)
        or _long_matches(arg, "--local-user", 2)
        or {"s", "u"} & _short_flags(arg)
        for arg in args
    ):
        return R_SIGN
    return None


def _stash_untracked(args: list[str]) -> bool:
    if args and not args[0].startswith("-") and args[0] not in {"push", "save"}:
        return False
    skip = False
    for arg in args:
        if skip:
            skip = False
        elif arg in _STASH_WITH_ARG:
            skip = True
        elif arg == "--":
            return False
        elif _long_matches(arg, "--include-untracked", 1) or _long_matches(arg, "--all", 1):
            return True
        elif not arg.startswith("--") and {"a", "u"} & _short_flags(arg):
            return True
    return False


def _names_project_data(path: str) -> bool:
    parts = os.path.normpath(path).split(os.sep)
    return any(parts[i : i + 2] == [".claude", "daedalus"] for i in range(len(parts) - 1))


def _force_add(args: list[str]) -> bool:
    return any(
        _long_matches(a, "--force", 3) or (not a.startswith("--") and "f" in _short_flags(a))
        for a in args
    )


_COMMIT_WITH_ARG = frozenset(
    {"-m", "-am", "-F", "-C", "-c", "-t", "--author", "--date", "--message", "--file"}
    | {"--template", "--fixup", "--squash", "--trailer", "--cleanup", "--reuse-message"}
)


def _pathspecs(sub: str, args: list[str]) -> list[str]:
    out: list[str] = []
    skip = False
    after_dashes = False
    for arg in args:
        if skip:
            skip = False
        elif after_dashes or not arg.startswith("-"):
            out.append(arg)
        elif arg == "--":
            after_dashes = True
        elif sub == "commit" and arg in _COMMIT_WITH_ARG:
            skip = True
    return out


def _git_data_dir_reason(sub: str, args: list[str], globals_: list[str]) -> str | None:
    base = "."
    for i, flag in enumerate(globals_[:-1]):
        if flag == "-C":
            base = os.path.join(base, globals_[i + 1])
    if _PROJECT_DATA in base or _names_project_data(base):
        return R_DATA_DIR_GIT
    if sub == "update-index":
        # 0010: --stdin/--index-info hide paths; --cacheinfo=mode,sha,path is a single arg.
        if "--index-info" in args or ("--stdin" in args and {"--add", "--force-add"} & set(args)):
            return R_DATA_DIR_GIT
        paths = list(args)
    else:
        paths = _pathspecs(sub, args)
    for arg in paths:
        if _PROJECT_DATA in arg or _names_project_data(os.path.join(base, arg)):
            return R_DATA_DIR_GIT
    # 0010: a forced add overrides the * marker; block forced adds of ancestors and globs.
    if _force_add(args):
        for arg in paths:
            norm = os.path.normpath(os.path.join(base, arg))
            if norm in {".", ".claude"} or norm.endswith("/.claude") or arg.startswith(":"):
                return R_DATA_DIR_GIT
            if _GLOB_CHARS & set(arg):
                return R_DATA_DIR_GIT
    return None


def _is_plugin_script(tokens: list[str], name: str) -> bool:
    # 8.5, F1: `python3 <absolute path>` whose real file is the plugin's own scripts/<name>.
    if len(tokens) < 2 or tokens[0] != "python3":
        return False
    script = tokens[1]
    if not script.startswith("/") or ".." in script.split("/"):
        return False
    return os.path.realpath(script) == os.path.join(_REPO_SCRIPTS, name)


def _is_append_ledger(tokens: list[str]) -> bool:
    return _is_plugin_script(tokens, "append_ledger.py")


def _is_cite(tokens: list[str], own_script: Callable[[str], bool]) -> bool:
    # RCP: `python3 <plugin root>/scripts/cite.py <file> <pattern>`, the file in the unit worktree.
    return len(tokens) == 4 and _is_plugin_script(tokens, "cite.py") and own_script(tokens[2])


CLAIMS_SCRIPT = "daedalus_claims.py"
# 0230: the claims call's three options, each once, in this order, each with one value.
CLAIMS_OPTIONS = ("--worktree", "--branch", "--ranges")
_CLAIMS_BRANCH = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/-]*")


def claims_ranges(value: str) -> list[tuple[str, int, int]] | None:
    # 0230: <file>:<first>-<last>[,...]; a relative file with no .., lines from 1, first <= last.
    out: list[tuple[str, int, int]] = []
    for part in value.split(","):
        file, _, span = part.rpartition(":")
        first, dash, last = span.partition("-")
        digits = all(n.isascii() and n.isdigit() for n in (first, last))
        if not (file and dash and digits) or file.startswith(("/", "-")):
            return None
        if ".." in file.split("/") or not 1 <= int(first) <= int(last):
            return None
        out.append((file, int(first), int(last)))
    return out


def claims_branch_ok(branch: str) -> bool:
    # 0230: a ref name or sha; never an option, a <rev>:<path> or a range.
    return _CLAIMS_BRANCH.fullmatch(branch) is not None and ".." not in branch


def claims_ok(tokens: list[str]) -> bool:
    # 0230: python3 <plugin>/scripts/daedalus_claims.py --worktree <abs> --branch <b> --ranges <r>.
    if len(tokens) != 8 or not _is_plugin_script(tokens, CLAIMS_SCRIPT):
        return False
    if tuple(tokens[2::2]) != CLAIMS_OPTIONS:
        return False
    worktree, branch, ranges = tokens[3::2]
    return (
        os.path.isabs(worktree)
        and ".." not in worktree.split("/")
        and claims_branch_ok(branch)
        and claims_ranges(ranges) is not None
    )


_SED_ADDR = r"(?:\d+|\$|/[^/\\]*/)"
_SED_PRINT = re.compile(
    rf"(?:{_SED_ADDR}(?:,{_SED_ADDR})?)?p(?:;(?:{_SED_ADDR}(?:,{_SED_ADDR})?)?p)*"
)
_READ_PATH_DENY = frozenset("*?[]{}$~\\")
# 228 S3c, SS-3: the coder's sed s shape; no e, w or r flag and no second command.
_SED_DELIMS = frozenset("/|#,:@")
_SED_FLAGS = frozenset("giIp0123456789")


def sed_substitute(script: str) -> bool:
    # 228 S3c: exactly three delimiters, so sed either reads these parts or fails to parse.
    if len(script) < 4 or script[0] != "s" or script[1] not in _SED_DELIMS or "\n" in script:
        return False
    delim = script[1]
    return script.count(delim) == 3 and set(script[script.rindex(delim) + 1 :]) <= _SED_FLAGS


def _unquoted_expansion(raw: str) -> bool:
    # 0084: an unquoted glob, brace, tilde or $ can split into operands the jail never saw.
    return any(
        lex.kind == CHAR and not lex.quote and lex.text in "*?[{~$" for lex in quote_walk(raw)
    )


def _unsingled(word: str) -> str:
    # O4: the characters of a raw word the shell may still expand; single-quoted spans drop out.
    return "".join(
        lex.text for lex in quote_walk(word) if lex.quote != "'" and lex.kind not in {OPEN, CLOSE}
    )


def _expands(word: str) -> bool:
    # 0084: the shell may split this raw word or turn it into an option before the command runs.
    return _unquoted_expansion(word) or bool(set("$`") & set(_unsingled(word)))


def _docs_read_split(name: str, args: list[str]) -> tuple[set[str], list[str], list[str]] | None:
    plain, valued = DOCS_READS[name]
    seen: set[str] = set()
    scripts: list[str] = []
    operands: list[str] = []
    i = 0
    while i < len(args):
        arg = args[i]
        if arg == "--":
            operands += args[i + 1 :]
            break
        if not arg.startswith("-") or arg == "-":
            operands.append(arg)
            i += 1
            continue
        if arg.startswith("--"):
            return None
        for j, char in enumerate(arg[1:], start=2):
            if char in valued:
                if not arg[j:] and i + 1 >= len(args):
                    return None
                value = arg[j:] or args[i + 1]
                i += 0 if arg[j:] else 1
                if char == "e":
                    scripts.append(value)
                break
            if char not in plain:
                return None
            seen.add(char)
        i += 1
    return seen, scripts, operands


def docs_read_ok(tokens: list[str], raw: str, roots: list[str], cwd: str, base: str) -> bool:
    # 0084: a relative operand must land under a root from the project root and from cwd.
    name = _cmd_name(tokens)
    if name not in DOCS_READS or _unquoted_expansion(raw):
        return False
    split = _docs_read_split(name, tokens[1:])
    if split is None:
        return False
    seen, scripts, paths = split
    if name in {"grep", "sed"} and not scripts:
        scripts, paths = paths[:1], paths[1:]
    if name == "sed" and ("n" not in seen or not all(_SED_PRINT.fullmatch(s) for s in scripts)):
        return False
    if name == "ls" and not paths:
        paths = [cwd]
    if not paths or (name in {"grep", "sed"} and not scripts):
        return False
    if name == "diff" and len(paths) != 2:
        return False
    for path in paths:
        if _READ_PATH_DENY & set(path):
            return False
        places = [path] if os.path.isabs(path) else [_abs(path, base), _abs(path, cwd)]
        if not all(any(_under(p, root) for root in roots) for p in places):
            return False
    return True


# B2 narrowed by audit finding (c), Build Train 20261019-124612: -m runs these modules only.
RUNNER_MODULES = frozenset({"pytest", "mypy", "ruff", "unittest", "coverage"})
# 0048, issue 91, 0164: runners the confine check wraps, each with the leading forms it admits;
# () admits any. Apart from WRAPPER_OPTS (pin H1 -> H2); node, a WORKER_WRAPPERS name, is --test.
TEST_RUNNERS: dict[str, tuple[tuple[str, ...], ...]] = {
    "pytest": ((),),
    "make": ((),),
    "tox": ((),),
    "nox": ((),),
    "just": ((),),
    "npx": ((),),
    "uv": (("run",),),
    "go": (("test",),),
    "cargo": (("test",),),
    "node": (("--test",),),
    # 0164: pnpm wraps like npm; every script, exec and fallback bin runs under the wrapper.
    "pnpm": ((),),
    "yarn": ((),),
    "bun": ((),),
    "vitest": (("run",),),
    "tsc": (("--noEmit",),),
    "vite": (("build",),),
    "terraform": (("validate",), ("fmt", "-check"), ("fmt", "-recursive", "-check")),
}
# 0164: package scripts that start a dev server; npm's run and test verbs with their aliases.
DEV_SCRIPTS = frozenset({"dev", "start", "serve", "preview"})
NPM_RUN = frozenset({"run", "run-script", "rum", "urn"})
NPM_TEST = frozenset({"test", "t", "tst"})
# 0158, 0164: terraform subcommands that change state; refused bare and under the wrapper.
TERRAFORM_MUTATE = frozenset(
    {"apply", "destroy", "import", "state", "taint", "untaint", "force-unlock", "refresh"}
)
TERRAFORM_FMT_FLAGS = frozenset({"-check", "-recursive"})
# 184: the one init form, after -chdir=<folder>; its data folder sits in the wrapper's tmp.
TERRAFORM_INIT = ("init", "-backend=false", "-input=false", "-lockfile=readonly")
_JS_TOOLS = frozenset({"vite", "vitest", "tsc", "node"})
# 0164: package managers that run a project script or a bin, and their exec verbs.
JS_LAUNCHERS = frozenset({"pnpm", "npm", "npx", "yarn", "bun"})
_JS_EXEC = frozenset({"exec", "x", "dlx"})
# 0164: bun's eval options and the subcommands that are never a file to run.
_BUN_EVAL = frozenset({"-e", "--eval", "-p", "--print"})
_BUN_COMMANDS = frozenset(
    {"run", "test", "x", "exec", "install", "i", "add", "a", "remove", "rm", "update", "build"}
    | {"init", "create", "pm", "link", "unlink", "upgrade", "outdated", "publish", "patch"}
)
# 0164: package manager options whose value is the next word, never the command.
_JS_VALUED = frozenset({"-C", "--dir", "-F", "--filter", "--prefix", "--cwd", "--workspace"})
R_DEV_SERVER = (
    "a coder never starts a dev server: the operator hosts the dev server and the verify step "
    "names the URL and the check (0164). Next: run `vite build` for a build, or yield the URL "
    "and the check for the operator."
)
R_VITEST_WATCH = (
    "vitest runs only as `vitest run` with no watch option; any other form starts watch mode, "
    "which never exits (0164). Next: run `vitest run`, under the kernel wrapper."
)
R_TSC = (
    "tsc runs only as the type check `tsc --noEmit`, never with --watch or -w and never "
    "emitting files (0164). Next: run `tsc --noEmit`, under the kernel wrapper."
)
R_TERRAFORM_MUTATE = (
    "terraform apply, destroy, import, state, taint, untaint, force-unlock and refresh change "
    "infrastructure or state and stay with the operator, bare or under the kernel wrapper "
    "(0158). Next: run `terraform validate` or `terraform fmt -check`, or yield the change to "
    "the operator."
)
R_TERRAFORM_OPERATOR = (
    "a coder runs only `terraform validate` and `terraform fmt -check`, the latter with "
    "-recursive and one folder inside your unit worktree at most, and `terraform "
    "-chdir=<folder> init -backend=false -input=false -lockfile=readonly` (184), each under the "
    "kernel wrapper; plan, every other init form and every other subcommand or fmt form stay "
    "with the operator (0158, 0164). Next: send one of those three forms, or yield the command "
    "to the operator."
)
R_WATCH = (
    "a watch option keeps the command running and never exits (0164). "
    "Next: drop the watch option and run the command once, under the kernel wrapper."
)


def _watch(arg: str) -> bool:
    # 0164: -w and every --watch spelling, with a value or a suffix (--watch=true, --watch-path).
    return arg == "-w" or arg.startswith("--watch")


def _tsc_option(arg: str) -> str:
    # 0164: tsc reads -watch, --watch and --Watch alike; the bare lowercase name, or "".
    return arg.lstrip("-").lower() if arg.startswith("-") else ""


def _first_positional(args: list[str], valued: frozenset[str] = frozenset()) -> int | None:
    # 0164: the first word that is not an option, nor the value of an option in valued.
    skip = False
    for idx, arg in enumerate(args):
        if skip:
            skip = False
        elif arg.startswith("-"):
            skip = arg in valued
        else:
            return idx
    return None


def bun_inline(tokens: list[str]) -> bool:
    # 0164: bun is a runtime too; -e, -p, repl and a file operand run code like node -e.
    args = tokens[1:]
    if any(arg in _BUN_EVAL or arg.startswith(("--eval=", "--print=")) for arg in args):
        return True
    first = _first_positional(args, _JS_VALUED)
    word = args[first] if first is not None else ""
    return word == "repl" or (word not in _BUN_COMMANDS and ("/" in word or "." in word))


def js_inner(tokens: list[str]) -> list[str] | None:
    # 0164: the command a package manager runs as a bin (pnpm exec node, npx node, pnpm node).
    if not tokens or _base(tokens[0]) not in JS_LAUNCHERS:
        return None
    while tokens and _base(tokens[0]) in JS_LAUNCHERS:
        name, args = _base(tokens[0]), tokens[1:]
        if name == "bun" and bun_inline(tokens):
            return tokens
        first = _first_positional(args, _JS_VALUED)
        if first is None:
            return None
        if args[first] in _JS_EXEC:
            rest = [arg for arg in args[first + 1 :] if arg != "--"]
            start = _first_positional(rest)
            tokens = rest[start:] if start is not None else []
        elif name == "npm":
            return None
        else:
            tokens = args[first:]
    return tokens or None


def terraform_init(args: list[str]) -> bool:
    # 184: exactly `-chdir=<folder> init -backend=false -input=false -lockfile=readonly`.
    return (
        len(args) == 1 + len(TERRAFORM_INIT)
        and args[0].startswith("-chdir=")
        and args[0] != "-chdir="
        and tuple(args[1:]) == TERRAFORM_INIT
    )


def terraform_check(args: list[str]) -> tuple[str, ...] | None:
    # 0158, 0164: the coder's terraform allowlist; the fmt folder operands, or None when refused.
    rest = args[1:] if args[:1] and args[0].startswith("-chdir=") else args
    if rest == ["validate"] or terraform_init(args):
        return ()
    if rest[:1] != ["fmt"]:
        return None
    flags = [arg for arg in rest[1:] if arg.startswith("-")]
    paths = tuple(arg for arg in rest[1:] if not arg.startswith("-"))
    exact = len(flags) == len(set(flags)) and set(flags) <= TERRAFORM_FMT_FLAGS
    return paths if exact and "-check" in flags and len(paths) <= 1 else None


def python_script(tokens: list[str]) -> str | None:
    # B2: the script operand of `python3 <path> ...`; None for -m, -c, flags or no operand.
    if not tokens or _base(tokens[0]) not in {"python", "python3"}:
        return None
    args = tokens[1:]
    return args[0] if args and not args[0].startswith("-") else None


def confine_split(tokens: list[str]) -> tuple[str, list[str]] | None:
    # 0048: <wrapper> --unit <worktree> -- <command...>, the one form; None for any other.
    if len(tokens) < 5 or tokens[1] != "--unit" or tokens[3] != "--":
        return None
    return tokens[2], tokens[4:]


def confine_wrapper(word: str, base: str) -> bool:
    # 0048: the plugin's own wrapper by its real file; a copy in a worktree is not it.
    return _base(word) == CONFINE and command_path(word, base) == CONFINE_PATH


def _tester_runner_ok(
    name: str, tokens: list[str], own_script: Callable[[str], bool] | None = None
) -> bool:
    args = tokens[1:]
    if any(arg.startswith("--basetemp") for arg in args):
        return False
    if name in TEST_RUNNERS:
        # issue 91: an option before the lead (cargo +nightly test) fails closed as a test, bar
        # a WORKER_WRAPPERS name, where a match admits the command (node -e stays refused).
        forms = TEST_RUNNERS[name]
        if all(forms) and args and args[0][:1] in {"-", "+"} and name not in WORKER_WRAPPERS:
            return True
        return any(tuple(args[: len(form)]) == form for form in forms)
    if name == "npm":
        return bool(args) and (args[0] in NPM_TEST or (args[0] in NPM_RUN and len(args) > 1))
    if name in {"python", "python3"}:
        # B2, finding (c): a runner module, or a script own_script places in the coder's worktree.
        if args[:1] == ["-m"]:
            return len(args) > 1 and args[1] in RUNNER_MODULES
        script = python_script(tokens)
        return script is not None and own_script is not None and own_script(script)
    return False


def runner_row(tokens: list[str]) -> bool:
    # 0164: a TEST_RUNNERS form, after any wrapper; the kernel wrapper's read roots attach to it.
    inner = strip_wrappers(tokens) or tokens
    name = _base(inner[0]) if inner else ""
    return name in TEST_RUNNERS and _tester_runner_ok(name, inner)


def runner_refusal(tokens: list[str]) -> str | None:
    # 0164, 0158: a dev server, a watch mode or a terraform state change, bare or wrapped.
    inner = strip_wrappers(tokens) or tokens
    if not inner:
        return None
    name, args = _base(inner[0]), inner[1:]
    if name in JS_LAUNCHERS:
        # 0164: a dev script anywhere, -- included; a tool it runs; a watch flag after the verb.
        if name != "npx" and DEV_SCRIPTS & set(args):
            return R_DEV_SERVER
        tool = next((i for i, arg in enumerate(args) if _base(arg) in _JS_TOOLS), None)
        refused = None if tool is None else runner_refusal(args[tool:])
        first = _first_positional(args, _JS_VALUED)
        # 0164: bun's own --watch and --hot sit before its verb; yarn, pnpm and npm pass it on.
        flags = args if name == "bun" else args[first + 1 :] if first is not None else []
        if refused is None and name != "npx":
            refused = R_WATCH if any(_watch(a) or a == "--hot" for a in flags) else None
        return refused
    head = args[: args.index("--")] if "--" in args else args
    watch = any(_watch(arg) for arg in head)
    if name == "node":
        return R_WATCH if watch else None
    if name == "vite":
        return None if head[:1] == ["build"] and not watch else R_DEV_SERVER
    if name == "vitest":
        return None if head[:1] == ["run"] and not watch else R_VITEST_WATCH
    if name == "tsc":
        options = [_tsc_option(arg) for arg in head]
        # 0164: the last --noEmit decides; a following false turns emitting back on.
        last = len(options) - 1 - options[::-1].index("noemit") if "noemit" in options else -1
        emit = last < 0 or head[last + 1 :][:1] == ["false"]
        watching = any(opt == "w" or opt.startswith("watch") for opt in options)
        return R_TSC if emit or watching else None
    if name == "terraform":
        if terraform_check(args) is not None:
            return None
        verbs = [arg for arg in args if not arg.startswith("-")]
        return (
            R_TERRAFORM_MUTATE
            if verbs[:1] and verbs[0] in TERRAFORM_MUTATE
            else (R_TERRAFORM_OPERATOR)
        )
    return None


def _exempt_indices(tokens: list[str]) -> set[int]:
    name = _base(tokens[0])
    if name in {"jq", "rg", "grep"}:
        return set(range(1, len(tokens)))
    exempt: set[int] = set()
    if name == "git":
        sub, args, _ = _git_split(tokens)
        offset = len(tokens) - len(args)
        if sub == "commit":
            exempt.update(offset + j + 1 for j, a in enumerate(args) if a in {"-m", "-am"})
    if name == "gh":
        # I7: file operands (--body-file, -F) are paths, so hygiene judges them.
        for j, token in enumerate(tokens):
            if token in {"--body", "--title", "-b", "-t"}:
                exempt.add(j + 1)
            if token.startswith(("--body=", "--title=")):
                exempt.add(j)
    return exempt


def _rsync_remote(args: list[str]) -> bool:
    # 0022: host:path and rsync:// are remote operands; -e/--rsh picks the program that runs.
    i = 0
    while i < len(args):
        arg = args[i]
        if arg == "--":
            return any(re.match(r"[^/]*:", a) for a in args[i + 1 :])
        if arg in _VALUE_LONG_NEXT or arg == "-f":
            i += 2
            continue
        if arg.startswith("--"):
            if arg.split("=", 1)[0] in {"--rsh", "--rsync-path"}:
                return True
        elif arg.startswith("-"):
            if "e" in arg.split("f", 1)[0]:
                return True
        elif re.match(r"[^/]*:", arg):
            return True
        i += 1
    return False


SEARCH_CMDS = frozenset({"rg", "grep", "egrep", "fgrep"})

R_READ_EXPANSION = (
    "uniq, sort, file and find can write a file, and this call holds a word the shell expands "
    "before the command runs (a brace list, ~, a glob, $, a backtick or <(...)), so it may turn "
    "into a write option or an output operand the jail never saw (issue 204). Next: quote the "
    "word or name each path literally."
)


def command_path(word: str, base: str) -> str:
    # issue 55: the real file a command word runs; a bare name resolves through PATH.
    if "/" in word:
        return os.path.realpath(_abs(word, base))
    try:
        cwd = os.getcwd()
    except OSError:
        return os.path.realpath(shutil.which(word) or word)
    return _path_lookup(word, os.environ.get("PATH"), cwd)


@lru_cache(maxsize=4096)
def _path_lookup(word: str, search_path: str | None, cwd: str) -> str:
    # suite-cleanup: memoised per process; PATH and cwd are in the key, so a change looks up again.
    return os.path.realpath(shutil.which(word, path=search_path) or word)


@lru_cache(maxsize=4)
def _claude_real(search_path: str) -> str | None:
    found = shutil.which("claude", path=search_path)
    return os.path.realpath(found) if found else None


def runs_claude(tokens: list[str], base: str) -> bool:
    # issue 55: the command word, the word past wrappers or node's script, by name or real file.
    stripped = strip_wrappers(tokens) or []
    words = tokens[:1] + stripped[:1]
    if stripped and _base(stripped[0]) == "node":
        words += [a for a in stripped[1:] if not a.startswith("-")][:1]
    real = _claude_real(os.environ.get("PATH", os.defpath))
    return any(
        _base(w) == "claude" or (real is not None and command_path(w, base) == real) for w in words
    )
