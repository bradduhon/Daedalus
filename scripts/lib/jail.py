# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import glob as _glob
import itertools
import os
import re
import subprocess
from collections.abc import Callable
from dataclasses import dataclass, replace
from functools import lru_cache
from pathlib import Path
from typing import TYPE_CHECKING, NamedTuple, TypeGuard

from lib import dispatch_binding, hook_io, passes, shell, shparse
from lib.audit import _git_env, project_data_dir, project_root
from lib.audit_proof import SUMMARY_DIR
from lib.config import (
    Config,
    ConfigError,
    ExcludedRoot,
    resolve_excluded_roots,
    root_ignored,
)
from lib.credential_paths import (
    CREDENTIAL_TOOLS,
    ENV_IGNORE_FILES,
    IGNORE_FILES,
    R_BRACE_UNJUDGED,
    R_CREDENTIAL,
    R_CREDENTIAL_TREE,
    R_ENV_FILE,
    R_ENV_FILE_TREE,
    R_ENV_WALK_CAP,
    R_ENV_WHITELIST_WRITE,
    R_IGNORE_WHITELIST,
    R_REPLY_KEY,
    R_REPLY_KEY_TREE,
    REPLY_KEY_NAME,
    env_file_hit,
    env_roots,
    env_walk,
    env_whitelist_reason,
    glob_patterns,
    glob_reaches,
    ignore_whitelist,
    key_roots,
    path_reason,
    reply_key_hit,
    whitelists_env,
)
from lib.credential_paths import CUT as _CUT
from lib.credential_paths import LIT as _LIT
from lib.credential_paths import REDIRECT as _REDIRECT
from lib.credential_paths import anchor as _anchor
from lib.credential_paths import clean as _clean
from lib.credential_paths import credential_hit as _credential_hit
from lib.credential_paths import credential_roots as _credential_roots
from lib.credential_paths import dotglob_on as _dotglob_on
from lib.credential_paths import expand_word as _expand_word
from lib.credential_paths import store_rest as _store_rest
from lib.credential_paths import tilde as _tilde
from lib.credential_paths import unjudged_root as _unjudged_root
from lib.gh_policy import CONDUCTOR_GH, GhFlag, _push_reason, allowlist_applies, gh_args, gh_reason
from lib.ledger import LedgerError, resolve_ledger
from lib.manifest import Manifest, ManifestError, extension_hit, path_hit
from lib.manifest import load as load_manifest
from lib.repo_root import git_root
from lib.shell import (
    _ASSIGN,
    _DEFAULT_BRANCHES,
    _GLOB_CHARS,
    _HOME,
    _PROJECT_DATA,
    _REPO_SCRIPTS,
    _SHELLS,
    _VALUE_LONG_NEXT,
    GIT_PLUMBING_REMOTE,
    INTERPRETERS,
    R_CLEAN,
    R_DATA_DIR_GIT,
    R_DEFAULT_BRANCH,
    R_DESTRUCTIVE,
    R_FORCE_PUSH,
    R_STASH_UNTRACKED,
    READ_ONLY_CMDS,
    READ_ONLY_GIT,
    WRAPPER_CHDIR,
    WrapperOption,
    _abs,
    _base,
    _command_reason,
    _git_split,
    _long_matches,
    _names_project_data,
    _pathspecs,
    _quote_spans,
    _short_flags,
    _under,
    command_family,
    env_split_values,
    runs_claude,
    split_options,
    strip_wrappers,
    unwrap,
)
from lib.shparse import (
    Command,
    Literal,
    Param,
    Pipeline,
    Redirect,
    Script,
    Tilde,
    Word,
)
from lib.train_scope import (
    AGENT_NAMESPACES,
    KNOWN_AGENTS,
    TEST_NAMESPACE,
    policed_outside_train,
)
from lib.train_state import active_train
from lib.workspace import UNMARK_NEXT, train_marker

if TYPE_CHECKING:
    from lib.admit import Admitted, AdmittedCommand, Refusal, Typed

WRITE_TOOLS = frozenset({"Write", "Edit", "MultiEdit", "NotebookEdit"})
WEB_TOOLS = frozenset({"WebFetch", "WebSearch"})
# 5.5: all routing is through the orchestrating session; workers never message each other.
WORKER_DENIED_TOOLS = frozenset({"Task", "Agent", "SendMessage"})

REMOTE_GIT = (
    frozenset({"push", "remote", "fetch", "pull", "clone", "ls-remote", "submodule"})
    | GIT_PLUMBING_REMOTE
)
# Final review I3b, issue 75: commands whose operands are write targets for the coder.
CODER_WRITE_CMDS = frozenset(
    {"cp", "mv", "tee", "install", "ln", "truncate", "rsync", "dd"}
    | {"mkdir", "touch", "rm", "rmdir", "unlink", "chmod", "chown", "chgrp"}
    | {"mkfifo", "mknod", "shred"}
)
# 0022: options whose value is not a path; every other non-option operand is a path.
_VALUE_OPTS: dict[str, frozenset[str]] = {
    "install": frozenset({"-m", "-o", "-g", "-S"}),
    "mkdir": frozenset({"-m"}),
    "mkfifo": frozenset({"-m"}),
    "mknod": frozenset({"-m"}),
    "shred": frozenset({"-n", "-s"}),
    "truncate": frozenset({"-s"}),
    "touch": frozenset({"-d", "-t"}),
    "cp": frozenset({"-S"}),
    "mv": frozenset({"-S"}),
    "ln": frozenset({"-S"}),
    "rsync": frozenset({"-f"}),
}
# 0022: short options whose attached or following value is a path operand (-t<dir>).
_PATH_OPTS: dict[str, frozenset[str]] = {
    "cp": frozenset({"-t"}),
    "mv": frozenset({"-t"}),
    "install": frozenset({"-t"}),
    "ln": frozenset({"-t"}),
    "touch": frozenset({"-r"}),
    "truncate": frozenset({"-r"}),
    "rsync": frozenset({"-T"}),
}
_VALUE_LONG = _VALUE_LONG_NEXT | {"--preserve"}
_MODE = re.compile(r"(?:[0-7]{3,4}|[ugoa]*[-+=][rwxXstugo]*)(?:,[ugoa]*[-+=][rwxXstugo]*)*")
DIR_CHANGE_CMDS = frozenset({"cd", "pushd", "popd"})
# audit A7-1: claude starts a nested session with no agent_id, which the jail would judge as main.
NETWORK_TOOLS = frozenset(
    {"curl", "wget", "ssh", "scp", "nc", "ncat", "telnet", "aws", "gh", "claude"}
)
# 0164: a package install reaches the registry and writes a store outside the worktree.
PACKAGE_INSTALLS = frozenset({"pnpm", "npm", "yarn", "bun"})
# 0164, 0196: install, ci, update and resolve verbs with the npm aliases and misspellings.
INSTALL_VERBS = frozenset(
    {"install", "i", "in", "ins", "inst", "insta", "instal", "isnt", "isnta", "isntal"}
    | {"isntall", "add", "ci", "clean-install", "ic", "install-clean", "isntall-clean"}
    | {"install-test", "it", "install-ci-test", "cit", "update", "up", "upgrade", "udpate"}
    | {"fetch", "import", "dedupe", "ddp", "link", "ln"}
)
_SCRIPT_VERBS = frozenset({"run", "run-script", "rum", "urn", "test", "t", "tst", "--"})
_EXEC_VERBS = frozenset({"exec", "x", "dlx"})
_COREPACK_VERBS = frozenset({"install", "prepare", "use", "up", "enable"})
# 0196: the one frozen, scripts-off install per manager: its verbs, required flag sets, extras.
_NPM_CI = frozenset({"ci", "clean-install", "ic", "install-clean", "isntall-clean"})
_FrozenRow = tuple[frozenset[str], tuple[frozenset[str], ...], frozenset[str]]
_JS_FROZEN: dict[str, _FrozenRow] = {
    "npm": (
        _NPM_CI,
        (frozenset({"--ignore-scripts"}),),
        frozenset({"--no-audit", "--no-fund", "--prefer-offline", "--offline", "--silent"}),
    ),
    "pnpm": (
        frozenset({"install", "i"}),
        (frozenset({"--frozen-lockfile", "--ignore-scripts"}),),
        frozenset({"--offline", "--prefer-offline", "--silent"}),
    ),
    "yarn": (
        frozenset({"install", ""}),
        (
            frozenset({"--immutable", "--mode=skip-build"}),
            frozenset({"--frozen-lockfile", "--ignore-scripts"}),
        ),
        frozenset({"--offline", "--silent", "--non-interactive"}),
    ),
    "bun": (
        frozenset({"install", "i"}),
        (frozenset({"--frozen-lockfile", "--ignore-scripts"}),),
        frozenset({"--silent", "--no-progress"}),
    ),
}
_PIP = re.compile(r"pip(?:3(?:\.\d+)?)?")
_PIP_VERBS = frozenset({"install", "download", "wheel"})
_PIP_EXTRAS = frozenset({"--no-deps", "-q", "--quiet", "--no-input", "--disable-pip-version-check"})
_UV_SYNC_EXTRAS = frozenset(
    {"--no-install-project", "--no-dev", "--all-extras", "--offline", "-q", "--quiet"}
)
_UV_FROZEN = (frozenset({"--frozen", "--no-build"}),)
_UV_PIP_EXTRAS = frozenset({"--offline", "-q", "--quiet"})
_UV_PIP_FROZEN = (frozenset({"--require-hashes", "--no-build"}),)
# 0196: yarn options whose value is the next word; the value is never a verb.
_YARN_COMMANDS = INSTALL_VERBS | _SCRIPT_VERBS | {"exec", "dlx", "create", "workspace"}
# 0196: each manager's global options whose value is the next word, and words that end the verb.
_GLOBAL_VALUED: dict[str, frozenset[str]] = {
    "uv": frozenset(
        {"--directory", "--project", "--cache-dir", "--config-file", "--color", "--python"}
        | {"--allow-insecure-host"}
    ),
    "pip": frozenset(
        {"--timeout", "--cache-dir", "--proxy", "--retries", "--index-url", "--log", "--python"}
        | {"--extra-index-url", "--trusted-host"}
    ),
    "cargo": frozenset({"--color", "--config", "-Z", "--manifest-path", "--target-dir"}),
    "poetry": frozenset({"-C", "--directory", "-P", "--project"}),
    "composer": frozenset({"-d", "--working-dir"}),
    "go": frozenset({"-C"}),
    "deno": frozenset({"--config", "-c", "--import-map", "--lock", "--cert"}),
    **{name: shell._JS_VALUED for name in ("yarn", "bun")},
    # 0196: pnpm's --workspace is a flag, so it never swallows the verb after it.
    "pnpm": shell._JS_VALUED - {"--workspace"},
    # 0196: npm's -w is --workspace; pnpm's -w is a flag, so it stays npm only.
    "npm": shell._JS_VALUED | {"-w"},
}
_VERB_STOPS: dict[str, frozenset[str]] = {
    "uv": frozenset({"run"}),
    "cargo": frozenset({"run", "test", "bench"}),
    "poetry": frozenset({"run"}),
    "composer": frozenset({"run", "run-script", "exec"}),
    "go": frozenset({"run", "test", "build", "vet", "generate", "tool"}),
}
_CARGO_VERBS = frozenset({"add", "install", "update", "generate-lockfile"})
_CARGO_EXTRAS = frozenset(
    {"--offline", "--release", "-q", "--quiet", "--workspace", "--all-targets"}
)
_CARGO_LOCKS = (frozenset({"--locked"}), frozenset({"--frozen"}))
# 0196: managers with no frozen, scripts-off form the jail accepts; poetry runs build scripts.
_NO_FROZEN: dict[str, frozenset[str]] = {
    "poetry": frozenset({"add", "install", "update", "lock", "sync"}),
    "pdm": frozenset({"add", "install", "update", "lock", "sync"}),
    "pipenv": frozenset({"install", "update", "upgrade", "lock", "sync"}),
    "pipx": frozenset({"install", "inject", "upgrade", "upgrade-all", "reinstall"}),
    "deno": frozenset({"install", "add"}),
    "gem": frozenset({"install", "update", "fetch"}),
    "bundle": frozenset({"install", "update", "add", "lock"}),
    "bundler": frozenset({"install", "update", "add", "lock"}),
    "composer": frozenset(
        {"install", "i", "update", "u", "upgrade", "require", "create-project", "reinstall"}
    ),
}
# 0196: the ecosystem each frozen form belongs to, as service-manifest.json names it.
_ECOSYSTEM = {
    "npm": "npm",
    "pnpm": "npm",
    "yarn": "npm",
    "bun": "npm",
    "pip": "python",
    "uv": "python",
    "cargo": "cargo",
    "go": "go",
}
FROZEN_EXAMPLES = {
    "npm": "npm ci --ignore-scripts",
    "pnpm": "pnpm install --frozen-lockfile --ignore-scripts",
    "yarn": "yarn install --immutable --mode=skip-build",
    "bun": "bun install --frozen-lockfile --ignore-scripts",
    "pip": "python3 -m pip install --require-hashes --only-binary=:all: -r requirements.txt",
    "uv": "uv sync --frozen --no-build",
    "cargo": "cargo fetch --locked",
    "go": "go mod download",
}
R_PACKAGE_INSTALL = (
    "{what} is a package install, which resolves versions from a registry and can run install "
    "scripts before any judge reads the diff, so the jail refuses it for every agent "
    "(0196, 0164). Next: run the frozen form ({frozen}) with the ecosystem enabled in "
    "service-manifest.json (dependencies.installs, coder only), or yield the install command "
    "for the operator to run."
)
# 0196: a yarn refusal also names the admitted way to run a script.
R_YARN_SCRIPT = " Or run a script as `yarn run <script>`."
R_PACKAGE_INSTALL_OPERATOR = (
    "{what} is a package install with no frozen, scripts-off form the jail accepts, so the jail "
    "refuses it for every agent (0196). Next: yield the install command for the operator to "
    "run, then rerun your tests."
)
R_PACKAGE_DOWNLOAD = (
    "{what} downloads a package and runs it, which resolves a version from a registry and runs "
    "its code before any judge reads the diff, so the jail refuses it for every agent "
    "(0196, 0164). Next: run the installed binary instead ({installed}), or yield the package "
    "name for the operator to add as a dev dependency."
)
# 0196: the installed-binary forms each launcher family names in its refusal.
JS_INSTALLED = (
    "pnpm exec <bin>, npm exec --no-install <bin>, yarn run <bin>, bun run <bin> or "
    "node_modules/.bin/<bin>"
)
PY_INSTALLED = ".venv/bin/<bin> or python3 -m <module>"
DENO_INSTALLED = "deno run on a file in the project"
_REMOTE = ("http://", "https://", "npm:", "jsr:")
_UV_WITH = ("--with", "--with-requirements", "--with-editable")


def _positional(args: list[str]) -> str:
    return next((arg for arg in args if not arg.startswith("-")), "")


@dataclass(frozen=True)
class InstallForm:
    # 0196: a refused install; frozen marks the form a coder runs once its ecosystem is on.
    manager: str
    what: str
    frozen: bool = False


def _frozen_flags(
    rest: list[str], required: tuple[frozenset[str], ...], extras: frozenset[str]
) -> bool:
    # 0196: one required set present, and no word outside it and the harmless extras.
    words = set(rest)
    return any(need <= words and words <= need | extras for need in required)


def _local_file(value: str) -> bool:
    return bool(value) and not value.startswith(("-", "git+")) and "://" not in value


def _without(args: list[str], *verbs: str) -> list[str]:
    rest = list(args)
    for verb in verbs:
        rest.remove(verb)
    return rest


def _pip_frozen(rest: list[str]) -> bool:
    # 0196: --require-hashes, --only-binary :all: and -r files; no package, source or sdist.
    hashes, binary, files, i = False, False, 0, 0
    while i < len(rest):
        arg = rest[i]
        value = None
        if arg in {"-r", "--requirement"}:
            value = rest[i + 1] if i + 1 < len(rest) else ""
            i += 1
        elif arg.startswith("--requirement="):
            value = arg.split("=", 1)[1]
        elif arg.startswith("-r") and len(arg) > 2:
            value = arg[2:]
        elif arg == "--require-hashes":
            hashes = True
        elif arg == "--only-binary=:all:":
            binary = True
        elif arg == "--only-binary" and rest[i + 1 : i + 2] == [":all:"]:
            binary = True
            i += 1
        elif arg not in _PIP_EXTRAS:
            return False
        if value is not None:
            if not _local_file(value):
                return False
            files += 1
        i += 1
    return hashes and binary and files > 0


def _unvalued(args: list[str], valued: frozenset[str]) -> list[str]:
    # 0196: the words left once each valued option and its value are dropped.
    out: list[str] = []
    skip = False
    for arg in args:
        if not skip and arg not in valued:
            out.append(arg)
        skip = not skip and arg in valued
    return out


def _yarn_options_only(args: list[str]) -> bool:
    # 0196: a --option without = takes the next word as its value unless that word is a verb.
    skip, prev = False, ""
    for arg in args:
        if skip and (prev in shell._JS_VALUED or arg not in _YARN_COMMANDS):
            skip = False
            continue
        if not arg.startswith("-"):
            return False
        skip = arg in shell._JS_VALUED or (arg.startswith("--") and "=" not in arg)
        prev = arg
    return True


def _option_value(words: list[str], pos: int) -> bool:
    # 0196: the word may be the value of an option written without =, long or short.
    before = words[pos - 1] if pos else ""
    if before == "--" or "=" in before:
        return False
    return before.startswith("--") or (len(before) == 2 and before[0] == "-")


def _js_install(name: str, args: list[str]) -> InstallForm | None:
    # 0164: an install verb before any script or exec verb; bare yarn installs too.
    verbs, required, extras = _JS_FROZEN[name]
    if name == "yarn" and _yarn_options_only(args):
        return InstallForm(name, name, _frozen_flags(args, required, extras))
    words = _unvalued(args, _GLOBAL_VALUED[name])
    for pos, arg in enumerate(words):
        if arg == "--":
            continue  # 0196: a -- before any script or exec verb ends no scan.
        if (arg in _EXEC_VERBS or arg in _SCRIPT_VERBS) and not _option_value(words, pos):
            return None
        if arg == "audit" and "fix" in words[pos + 1 :]:
            return InstallForm(name, f"{name} audit fix")
        if arg in INSTALL_VERBS:
            # 0196: the frozen form is judged on the raw words, so no leading option is admitted.
            frozen = args[:1] == [arg] and arg in verbs
            frozen = frozen and _frozen_flags(args[1:], required, extras)
            return InstallForm(name, f"{name} {arg}", frozen)
    return None


def _verbs_in(name: str, args: list[str]) -> list[str]:
    # 0196: positional words past the manager's valued options, up to a word that runs other code.
    head = args[: args.index("--")] if "--" in args else args
    kept = _unvalued(head, _GLOBAL_VALUED.get(name, frozenset()))
    stops = _VERB_STOPS.get(name, frozenset())
    words: list[str] = []
    for at, word in enumerate(kept):
        before = kept[at - 1] if at else ""
        if word[:1] == "-":
            continue
        # 0196: a stop word right after a --option without = may be that option's value.
        if word in stops and not (before.startswith("--") and "=" not in before):
            break
        words.append(word)
    return words


def _pip_install(label: str, args: list[str]) -> InstallForm | None:
    verb = next((w for w in _verbs_in("pip", args) if w in _PIP_VERBS), "")
    if not verb:
        return None
    frozen = args[:1] == ["install"] and _pip_frozen(args[1:])
    return InstallForm("pip", f"{label} {verb}", frozen)


def _uv_install(args: list[str]) -> InstallForm | None:
    # 0196: add, lock and pip install resolve; sync and pip sync pass frozen with --no-build.
    words = _verbs_in("uv", args)
    at = next((i for i, w in enumerate(words) if w in {"add", "lock", "sync", "tool", "pip"}), -1)
    head, sub = (words[at:] + ["", ""])[:2] if at >= 0 else ("", "")
    if head in {"add", "lock"} or (head == "tool" and sub in {"install", "upgrade"}):
        return InstallForm("uv", f"uv {head}")
    if head == "sync":
        frozen = args[:1] == ["sync"] and _frozen_flags(args[1:], _UV_FROZEN, _UV_SYNC_EXTRAS)
        return InstallForm("uv", "uv sync", frozen)
    if head != "pip" or sub not in {"install", "sync", "compile"}:
        return None
    if args[:2] != ["pip", sub]:
        return InstallForm("uv", f"uv pip {sub}")
    rest = args[2:]
    files = [a for a in rest if not a.startswith("-")]
    flags = [a for a in rest if a.startswith("-")]
    frozen = (
        sub == "sync"
        and bool(files)
        and all(_local_file(f) for f in files)
        and _frozen_flags(flags, _UV_PIP_FROZEN, _UV_PIP_EXTRAS)
    )
    return InstallForm("uv", f"uv pip {sub}", frozen)


def _cargo_install(args: list[str]) -> InstallForm | None:
    # 0196: a +toolchain word may lead the frozen form; no option may.
    words = [w for w in _verbs_in("cargo", args) if not w.startswith("+")]
    verb = next((w for w in words if w in _CARGO_VERBS | {"fetch", "build"}), "")
    if verb in _CARGO_VERBS:
        return InstallForm("cargo", f"cargo {verb}")
    if verb:
        lead = 1 if args[:1] and args[0].startswith("+") else 0
        frozen = args[lead : lead + 1] == [verb] and _frozen_flags(
            args[lead + 1 :], _CARGO_LOCKS, _CARGO_EXTRAS
        )
        return InstallForm("cargo", f"cargo {verb}", frozen)
    return None


def _go_install(args: list[str]) -> InstallForm | None:
    words = _verbs_in("go", args)
    at = next((i for i, w in enumerate(words) if w in {"get", "install", "mod", "work"}), -1)
    head, sub = (words[at:] + ["", ""])[:2] if at >= 0 else ("", "")
    if head in {"get", "install"}:
        return InstallForm("go", f"go {head}")
    if (head, sub) in {("mod", "tidy"), ("work", "sync")}:
        return InstallForm("go", f"go {head} {sub}")
    if (head, sub) == ("mod", "download"):
        frozen = args[:2] == ["mod", "download"] and set(args[2:]) <= {"-x", "-json"}
        return InstallForm("go", "go mod download", frozen)
    return None


def _install_at(name: str, args: list[str], head: bool) -> InstallForm | None:
    # 0164, 0196: the install one command word starts, judged on the words after it.
    if name == "corepack" and _positional(args) in _COREPACK_VERBS:
        return InstallForm(name, f"corepack {_positional(args)}")
    if name in PACKAGE_INSTALLS:
        return _js_install(name, args)
    if _PIP.fullmatch(name):
        return _pip_install(name, args)
    if name.startswith("python") and "-m" in args:
        at = args.index("-m")
        if all(a.startswith("-") for a in args[:at]) and args[at + 1 : at + 2] == ["pip"]:
            return _pip_install(f"{name} -m pip", args[at + 2 :])
    if name == "uv":
        return _uv_install(args)
    if name == "cargo":
        return _cargo_install(args)
    if name == "go":
        return _go_install(args)
    if name == "terraform" and _positional(args) == "init":
        if any(a.lstrip("-") in {"upgrade", "upgrade=true"} for a in args):
            return InstallForm(name, "terraform init -upgrade")
        return None
    if name in {"bundle", "bundler"} and head and all(a.startswith("-") for a in args):
        return InstallForm(name, name)
    verbs = _NO_FROZEN.get(name)
    verb = next((w for w in _verbs_in(name, args) if w in verbs), "") if verbs else ""
    return InstallForm(name, f"{name} {verb}") if verb else None


def install_form(segment: list[str]) -> InstallForm | None:
    # 0164, 0196: the first install any command word of the segment starts; frozen only at its head.
    for idx, token in enumerate(segment):
        found = _install_at(os.path.basename(token), segment[idx + 1 :], idx == 0)
        if found is not None:
            return found if idx == 0 else InstallForm(found.manager, found.what)
    return None


def install_reason(segment: list[str], installs: Callable[[], frozenset[str]]) -> str | None:
    # 0196: refused for every agent; the frozen form passes when installs() names its ecosystem.
    found = install_form(segment)
    if found is None:
        return None
    if found.frozen and _ECOSYSTEM.get(found.manager) in installs():
        return None
    example = FROZEN_EXAMPLES.get(found.manager)
    if example is None:
        return R_PACKAGE_INSTALL_OPERATOR.format(what=found.what)
    reason = R_PACKAGE_INSTALL.format(what=found.what, frozen=example)
    return reason + R_YARN_SCRIPT if found.manager == "yarn" else reason


def _no_install(opts: list[str]) -> bool:
    # 0196: npx and npm exec run only an installed bin with --no-install and no yes flag.
    yes = any(a == "-y" or (a.startswith("--yes") and a != "--yes=false") for a in opts)
    return "--no-install" in opts and not yes


def _leading_opts(args: list[str]) -> list[str]:
    return list(itertools.takewhile(lambda a: a.startswith("-") and a != "--", args))


def _download_at(name: str, args: list[str]) -> tuple[str, str] | None:
    # 0164, 0196: the launcher a command word starts and the installed form its refusal names.
    head = args[: args.index("--")] if "--" in args else args
    head = _unvalued(head, _GLOBAL_VALUED.get(name, frozenset()))
    words = [a for a in head if not a.startswith("-")]
    if name in {"bunx", "pnpx"}:
        return name, JS_INSTALLED
    if name in PACKAGE_INSTALLS and _positional(head) == "create":
        return f"{name} create", JS_INSTALLED
    if name == "npm" and words[:1] == ["init"] and words[1:2]:
        return "npm init <initializer>", JS_INSTALLED
    if name in {"pnpm", "yarn"} and "dlx" in head:
        return f"{name} dlx", JS_INSTALLED
    if name == "bun" and _positional(head) == "x":
        return "bun x", JS_INSTALLED
    if name == "npm" and _positional(head) in {"exec", "x"}:
        verb = _positional(head)
        at = args.index(verb)
        if not _no_install(args[:at] + _leading_opts(args[at + 1 :])):
            return f"npm {verb}", JS_INSTALLED
    if name == "npx" and not _no_install(_leading_opts(args)):
        return "npx", JS_INSTALLED
    if name == "uvx":
        return "uvx", PY_INSTALLED
    if name == "uv" and words[:2] == ["tool", "run"]:
        return "uv tool run", PY_INSTALLED
    if name == "uv" and words[:1] == ["run"] and any(a.startswith(_UV_WITH) for a in head):
        return "uv run --with", PY_INSTALLED
    if name == "pipx" and _positional(args) == "run":
        return "pipx run", PY_INSTALLED
    if name == "deno" and words[:1] == ["run"] and words[1:2] and words[1].startswith(_REMOTE):
        return "deno run on a remote module", DENO_INSTALLED
    return None


def download_reason(segment: list[str]) -> str | None:
    # 0164, 0196: any command word of the segment that downloads a package and runs it.
    for idx, token in enumerate(segment):
        found = _download_at(os.path.basename(token), segment[idx + 1 :])
        if found is not None:
            return R_PACKAGE_DOWNLOAD.format(what=found[0], installed=found[1])
    return None


R_NESTED_CLAUDE = (
    "claude starts a nested session the jail cannot attribute to an agent (audit A7-1). "
    "Next: run it from your own shell."
)
_CLAUDE_WORD = re.compile(r"(?:^|[\s;&|(/'\"`])claude(?=[\s;&|)'\"`]|$)")
# 0028: the conductor's gh set lives in lib.gh_policy.
GH_ALLOWED = {cmd: frozenset(sub for c, sub in CONDUCTOR_GH if c == cmd) for cmd, _ in CONDUCTOR_GH}
_BRANCH_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/-]*")
R_NAMESPACED_MAIN = "a namespaced agent may not claim the orchestrator role. Next: name the agent."

R_PIPE = "pipes are not permitted for this agent. Next: send one plain command."
R_NO_CWD = "hook received no absolute cwd; failing closed. Next: report to the operator."
R_TOOL = "workers use only their allowlisted tools. Next: ask the orchestrating session."
R_DOTGIT = "writes into .git/ are never permitted. Next: change the repository through git."
R_CODER_UNIT_GIT = (
    "coder git add and commit run only inside your unit worktree. "
    "Next: use git -C <your unit worktree> add/commit."
)
# 0054: a coder's protected paths, relative to its unit worktree root.
BUILTIN_PROTECTED = Manifest(("contracts/", ".github/", ".claude/", "service-manifest.json"))
R_BASH_OUTSIDE = (
    "Bash write outside your unit worktree: {}. "
    "Next: write inside your unit worktree, or ask the orchestrating session to route the change."
)
R_ROUTE_NEXT = (
    "Next: ask the orchestrating session to route this change to contract-spec or charter-docs."
)
R_PROTECTED_BUILTIN = "protected path (built in): {}. " + R_ROUTE_NEXT
R_PROTECTED_PATH = "protected path (service-manifest.json jail_narrowing): {}. " + R_ROUTE_NEXT
R_PROTECTED_EXT = "protected extension (service-manifest.json jail_narrowing): {}. " + R_ROUTE_NEXT
R_CD_RELATIVE = (
    "a chain that changes directory may not use relative write paths or pathspecs: {}. "
    "Next: use absolute paths (or an absolute git -C) after cd."
)
R_CONDUCTOR_PUSH = (
    "the conductor pushes one named branch to origin, nothing else (0001). "
    "Next: `git push -u origin daedalus/<train-id>`."
)
R_CONDUCTOR_PUSH_HEAD = (
    "the conductor never pushes HEAD; it names this train's branch (issue 11). "
    "Next: `git push -u origin daedalus/<train-id>`."
)
R_CONDUCTOR_PUSH_BRANCH = (
    "the conductor pushes only this train's branch, {branch} (issue 11). "
    "Next: `git push -u origin {branch}`."
)
R_CONDUCTOR_NO_TRAIN = (
    "no active train names the branch to push (issue 11). "
    "Next: run /daedalus:run push, which marks the train before the push."
)
R_CONDUCTOR_CHARTER = (
    "git -C reaches only the charter root .claude/daedalus/config.json declares, and only for "
    "the push of this train's branch (0078). "
    "Next: run the command in this repo without -C, or `git -C <charter_root> push -u origin "
    "daedalus/<train-id>`."
)
R_CODER_GIT = (
    "coder git is limited to add, commit, status, diff (--check included), log (-S and -G "
    "included), show, grep, blame, merge-base, rev-parse, ls-files, "
    "branch listing, stash list/push/pop/show, "
    "restore/checkout -- <unit worktree paths>, "
    "worktree list; --output is refused on every subcommand. "
    "Next: use those only; the trains handle the rest."
)
# 228 S3b: the coder's refusal for a word, option or form off its table with no older constant.
R_CODER_TABLE = (
    "the coder's Bash runs only the commands, options and forms on its table (228). Next: send "
    "a form on the table, or yield [STATUS: YIELD_GRANT] <exact command> | <why> (233)."
)
R_DATA_DIR = (
    "the plugin data directory is written by hooks only. "
    "Next: edit <repo>/.claude/daedalus/config.json from your own shell."
)
R_SUBAGENT_MAIN = "a subagent may not run as main. Next: name the agent."
R_CONDUCTOR_REPO = (
    "the conductor's gh pr writes target this repo; -R/--repo is admitted only on gh pr create "
    "naming the declared charter root's origin, with --head on this train's branch (0078). "
    "Next: omit -R, or pass --repo <charter slug> --head daedalus/<train-id>."
)
R_BODY_FILE = (
    "gh --body-file/-F must name a file under docs/.tmp/ or /tmp. "
    "Next: write the body to docs/.tmp/ and pass that path."
)
R_BODY_INLINE = (
    "gh pr create/edit/comment take the body only from --body-file, never --body or -b. "
    "Next: write the body to docs/.tmp/ and pass --body-file <path>."
)
R_EDIT_BASE = (
    "gh pr edit may not change the base branch. "
    "Next: report the base mismatch; the operator retargets the pull request."
)
R_GITLEAKS = (
    "conductor gitleaks runs only as gitleaks detect --redact, any report path under /tmp. "
    "Next: rerun it as gitleaks detect --redact --log-opts=<base>..<branch>."
)
R_LEDGER_DIRECT = (
    "the ledger is written only through append_ledger.py. "
    "Next: write the entry to docs/.tmp/ and run append_ledger.py."
)
R_DOCS_BASH = (
    "charter-docs Bash is limited to append_ledger.py, git add <path>, git commit -m, "
    "git status, git log and git diff, plus the reads cat, grep, head, tail, wc, ls, diff and "
    "sed -n on literal paths under the charter root or docs/. "
    "Next: use those only; the main session runs the rest."
)
# 0044: reason literals the hook scripts under scripts/checks return.
R_UNIT_OUTSIDE = (
    "write outside your unit worktree: {}. "
    "Next: ask the orchestrating session to route this to contract-spec or "
    "charter-docs."
)
R_REMOTE_GIT = (
    "no remote git operations in the Build Train. Next: commit locally; the Push Train pushes."
)
R_NETWORK = (
    "network or remote tooling is not permitted (tripwire). "
    "Next: return [STATUS: YIELD_WEB] with your question."
)
# issue 56: the refusal names the flag, the agent and the next action in every grammar.
R_BASETEMP_AGENT = (
    "pytest --basetemp is refused for {agent}: the temp folder it names lies outside the "
    "write checks (issue 56). Next: drop --basetemp and rerun; pytest's default temp folder works."
)
R_BASETEMP = R_BASETEMP_AGENT.format(agent="coder")
R_CONTRACT_SPEC_WRITE = (
    "contract-spec may write only contracts/ or the charter specs/ directory. "
    "Next: put schema changes there."
)
R_CHARTER_DOCS_WRITE = (
    "charter-docs may write only the charter repo or docs/. Next: keep documentation there."
)
R_AUDITOR_BASH = (
    "auditor Bash is limited to read-only git and inspection commands, piped only. "
    "Next: use git diff/log/show or rg/cat/jq with | head."
)
R_SPECIALIST_BASH = (
    "specialist Bash is limited to read-only inspection. "
    "Next: use sha256sum, cat, jq, rg, git diff."
)
R_CONDUCTOR_BASH = (
    "conductor Bash is limited to git push/status/log/rev-parse/branch/diff/"
    "add/commit, "
    "gh pr/run, gitleaks detect. Next: use those only."
)
R_CONDUCTOR_COMMIT_ALL = (
    "the conductor commits only what is already staged; git commit -a, --all or any prefix "
    "of it, a short option group holding a, and paths on the commit line are refused "
    "(issue 2). Next: stage each file by path with git add <path>, then run "
    "git commit -m <message>."
)
R_CONDUCTOR_WEB = "the conductor has no web access. Next: use gh."
R_WEB_RESEARCHER_ONLY = (
    "only web-researcher may fetch. Next: ask the orchestrating session to dispatch web-researcher."
)
R_UNKNOWN = (
    "unknown agent_type '{agent}', fail closed. Next: add the agent to the jail before using it."
)
# 0100: one line of rule, then the unmark line for a marker a dead train left.
R_UNKNOWN_TRAIN = (
    "unknown agent_type '{agent}' is read-only while {marker} exists: Bash runs read-only "
    "inspection and git reads, pipes allowed; Write, Edit, dispatch and web tools are refused "
    "(0100).\n" + UNMARK_NEXT
)
# Main never prompted (amends 0106): the plain-words warnings sent into the main session's context.
WARN_DOTGIT = (
    "Writing {path} edits the repository's own metadata; a wrong write corrupts the clone."
)
WARN_DATA_DIR = (
    "This touches the plugin data folder. It holds the audit log, train state and coder "
    "bindings; a hand edit breaks the hash chain that proves the audit happened."
)
WARN_CREDENTIAL = (
    "This path holds credentials; reading it puts the secret into the session transcript."
)
WARN_CREDENTIAL_WRITE = (
    "This path holds credentials; writing it can replace a key or leave a secret behind."
)
WARN_FORCE_PUSH = (
    "A force, delete or mirror push rewrites the remote branch; commits that exist only there "
    "are lost."
)
WARN_DEFAULT_BRANCH = "Pushing to the default branch skips the pull request the operator merges."
WARN_DELETE = (
    "This recursive or raw-device delete removes files that neither git nor the plugin can restore."
)
WARN_CLEAN = (
    "git clean deletes untracked files, the plugin data folder included; nothing restores them."
)
WARN_TRAIN_PUSH = "Pushing during a train publishes a branch before the audit approves its tip."
WARN_COMMAND = "This command matches a pattern the plugin guards against."
WARN_NESTED_CLAUDE = (
    "This starts a nested Claude session; the jail judges its calls as yours, with no agent's "
    "limits."
)
WARN_DISPATCH = (
    "This dispatch skips a train invariant ({reason}). The agent starts without it; "
    "the audit log records the warning."
)
WARN_NO_CWD = (
    "The hook received no working folder, so the plugin cannot tell which repository this "
    "call touches."
)
# 0106: tripwire findings with their own consequence; any other finding gets WARN_COMMAND.
_TRIPWIRE_WARNINGS = {
    R_FORCE_PUSH: WARN_FORCE_PUSH,
    R_DEFAULT_BRANCH: WARN_DEFAULT_BRANCH,
    R_DESTRUCTIVE: WARN_DELETE,
    R_CLEAN: WARN_CLEAN,
    R_DATA_DIR_GIT: WARN_DATA_DIR,
    R_STASH_UNTRACKED: WARN_DATA_DIR,
    R_NESTED_CLAUDE: WARN_NESTED_CLAUDE,
}
# Main never prompted (amends 0105, 0106): allow with context, never ask, for the main session.
R_MAIN_TRAIN_WARN = (
    "Build Train {train} is active in this repository and works in unit worktrees. "
    "Writing {path} here can leave a dirty tree that finish refuses, conflict with a unit "
    "branch, or land on the integration branch."
)
R_ROUTED = (
    "{agent} is judged by the router, not lib.jail.decide. "
    "Next: route the call through scripts/enforce_agent_jail.py."
)
_CREDENTIAL_PART = re.compile(r"[=:,]")
R_CREDENTIAL_PARAM = (
    "{path} could be a credential path; the jail cannot resolve its variable. "
    "Next: spell the path out"
)
# issue 76: time is not here; its WRAPPER_OPTS row reads its options.
# A2 fix round 4: a brace group's { and } are read past, so its inner command word is read.
_CONTROL_WORDS = frozenset({"!", "do", "then", "else", "elif", "while", "until", "if", "{", "}"})
_BINDERS = frozenset({"read", "mapfile", "readarray", "getopts", "select"})
# issue 76: _command_at's answer when a wrapper option is off shell.WRAPPER_OPTS.
_OPAQUE = -1
_GREPS = frozenset({"grep", "egrep", "fgrep"})
# spec 8: short options whose value is the next word (or the rest of the cluster).
_SEARCH_VALUES: dict[str, frozenset[str]] = {
    "grep": frozenset("efmABCdD"),
    "rg": frozenset("efmABCgtTjMrEd"),
}
_SEARCH_LONGS = frozenset(
    {"--regexp", "--file", "--max-count", "--context", "--after-context", "--before-context"}
    | {"--glob", "--type", "--type-not", "--threads", "--replace", "--encoding"}
)
_PATH_CMDS = (
    READ_ONLY_CMDS
    | CODER_WRITE_CMDS
    | {"cd", "pushd", "source", ".", "less", "more", "base64", "xxd", "od", "strings"}
    | {"tar", "zip", "unzip", "scp", "gzip", "gunzip", "zcat", "openssl", "ssh-keygen", "gpg"}
    | {"egrep", "fgrep", "nl", "tac", "diff", "cmp"}
    | {"bsdtar", "7z", "7za", "7zr", "7zz", "pax"}
)
_PATH_OPTION = re.compile(r"--?[\w-]*(?:dir|file|path|target|output|input|config|key|root)", re.I)
_DATA_DIR_DEFAULT = "/.claude/plugins/data/daedalus"
UNIT_WORKTREES = ".claude/worktrees"
_DATA_DIR_WRITE = re.compile(
    r">|(?:^|[\s;&|(/])(?:tee|rm|mv|cp|truncate|touch|ln|mkdir|chmod|chown|install|rmdir"
    r"|mkfifo|mknod|shred)"
    r"(?=[\s;&|)]|$)"
    r"|\bsed\b[^;&|\n]*\s(?:-[a-zA-Z]*i|--in-place)|\bpython[\d.]*\b[^;&|\n]*\s-[a-zA-Z]*c"
    r"|\bgit\b[^;&|\n]*\s(?:init|clone)\b"
)
_DEVNULL = re.compile(r"\d?>&\d|&?\d?>>?\s*/dev/null")
# issue 188: the moved bound agent rule; module runs, fd words and the cd start form.
_INTERPRETER = re.compile(r"python[\d.]*|perl|ruby|node|nodejs|deno|bun|php")
_CD_TARGET = re.compile(r"(?:^|[;&|(\s])(?:cd|pushd)\s+([^\s;&|)]+)")
_DAEDALUS_WORD = re.compile(r"(?<![\w.-])daedalus(?![\w-])")
_GIT_INDEX_WRITE = re.compile(r"\bgit\b[^;&|]*\b(?:add|stage|commit|update-index)\b")


@dataclass(frozen=True)
class Decision:
    allow: bool
    reason: str | None = None
    agent: str | None = None
    # Main never prompted (amends 0105, 0106): a main-session finding the hook allows with context.
    warn: bool = False


def _allow() -> Decision:
    return Decision(True, None)


def _block(reason: str) -> Decision:
    return Decision(False, reason)


def _warn(reason: str) -> Decision:
    # Main never prompted (amends 0105, 0106): allow with context, never ask, for the main session.
    return Decision(False, reason, warn=True)


def _main_warn(warning: str, finding: str) -> Decision:
    # Main never prompted (amends 0106): allow with context, never ask, for the main session.
    # The warning first, then the jail's finding verbatim so the audit log keeps it whole.
    return _warn(f"{warning} The jail's finding: {finding}")


def _tripwire_warn(finding: str) -> Decision:
    # Main never prompted (amends 0106): allow with context, never ask, for the main session.
    # Git push during a train carries the gh policy's push finding.
    warning = _TRIPWIRE_WARNINGS.get(finding, WARN_COMMAND)
    if finding == _push_reason("main"):
        warning = WARN_TRAIN_PUSH
    return _main_warn(warning, finding)


def _flags_ok(
    args: list[str],
    plain: frozenset[str] = frozenset(),
    prefixes: tuple[str, ...] = (),
    patterns: tuple[str, ...] = (),
    with_arg: frozenset[str] = frozenset(),
    positional: bool = True,
) -> bool:
    i = 0
    after_dashes = False
    while i < len(args):
        arg = args[i]
        if after_dashes or not arg.startswith("-") or arg == "-":
            if not positional:
                return False
        elif arg == "--":
            after_dashes = True
        elif arg in with_arg and i + 1 < len(args):
            i += 1
        elif not (
            arg in plain
            or (prefixes and arg.startswith(prefixes))
            or any(re.fullmatch(p, arg) for p in patterns)
        ):
            return False
        i += 1
    return True


def _commit_ok(args: list[str], cwd: str) -> bool:
    i = 0
    while i < len(args):
        arg = args[i]
        if arg in {"-q", "--quiet", "-a"}:
            i += 1
        elif arg == "--":
            return not _has_magic(args[i + 1 :])
        elif arg in {"-m", "-am"} and i + 1 < len(args):
            i += 2
        elif (
            arg == "-F" and i + 1 < len(args) and _under(_abs(args[i + 1], cwd), f"{cwd}/docs/.tmp")
        ):
            i += 2
        else:
            return False
    return True


def _commits_work_tree(args: list[str]) -> bool:
    # issue 2: -a, --all or a prefix, a cluster holding a, or a pathspec commits past the index.
    # Every word is read, option values included, so no value reading decides it.
    return bool(_pathspecs("commit", args)) or any(
        _long_matches(arg, "--all", 1) or (not arg.startswith("--") and "a" in _short_flags(arg))
        for arg in args
    )


@lru_cache(maxsize=32)
def _registered_worktrees(repo: str) -> frozenset[str]:
    cmd = ["git", "-C", repo, "worktree", "list", "--porcelain"]
    try:
        out = subprocess.run(
            cmd, capture_output=True, text=True, timeout=2, env=_git_env(), check=False
        )
    except (OSError, subprocess.SubprocessError):
        return frozenset()
    if out.returncode != 0:
        return frozenset()
    lines = out.stdout.splitlines()
    return frozenset(os.path.realpath(x[9:]) for x in lines if x.startswith("worktree "))


def _unit_parts(target: str, cwd: str) -> list[str] | None:
    # 0022: train-made unit worktrees sit at <repo>/.claude/worktrees/<name>, git-registered.
    repo = os.path.realpath(str(project_root(cwd)))
    base = os.path.join(repo, UNIT_WORKTREES)
    parts = os.path.relpath(os.path.realpath(target), base).split(os.sep)
    if parts[0] in {os.curdir, os.pardir}:
        return None
    return parts if os.path.join(base, parts[0]) in _registered_worktrees(repo) else None


def _in_unit_worktree(target: str, cwd: str) -> bool:
    parts = _unit_parts(target, cwd)
    return parts is not None and len(parts) >= 2


def _main_write_train(path: str, cwd: str) -> str | None:
    # 0105, 0104: the train id when the path is in a marked repo outside its scratch, else None.
    target = os.path.realpath(_abs(path, cwd))
    root = project_root(cwd)
    if not (_under(target, str(root)) and _train_scoped(cwd, "", {})):
        root = project_root(os.path.dirname(target))
        if not os.path.lexists(train_marker(root)):
            return None
    if _under(target, str(root / SUMMARY_DIR)):
        return None
    branch = _train_branch(str(root)) or ""
    return branch.removeprefix("daedalus/") or "(id unreadable)"


@dataclass(frozen=True)
class CoderBoundary:
    manifest: Manifest
    ledger_rel: str | None


@lru_cache(maxsize=8)
def _manifest_at(repo: str) -> Manifest | str:
    # 0054: read once per process from the main checkout; an error string fails closed.
    try:
        return load_manifest(Path(repo)) or Manifest()
    except ManifestError as exc:
        return f"service-manifest.json is unusable, so coder writes fail closed: {exc}"


def _coder_boundary(cwd: str, config: Config) -> CoderBoundary | str:
    repo = os.path.realpath(str(project_root(cwd)))
    manifest = _manifest_at(repo)
    if isinstance(manifest, str):
        return manifest
    try:
        resolved = resolve_ledger(cwd, config)
    except LedgerError as exc:
        return f"the ledger could not be resolved, so coder writes fail closed: {exc}"
    ledger_rel = None
    if resolved is not None:
        rel = os.path.relpath(os.path.realpath(resolved.path), repo)
        if rel.split(os.sep)[0] != os.pardir:
            ledger_rel = rel.replace(os.sep, "/")
    return CoderBoundary(manifest, ledger_rel)


def _coder_write_reason(target: str, cwd: str, boundary: CoderBoundary | str) -> str | None:
    # 0054: inside the unit worktree a write is refused only on a protected path.
    rel = "/".join((_unit_parts(target, cwd) or [])[1:])
    return protected_reason(rel, target, boundary)


def protected_reason(rel: str, target: str, boundary: CoderBoundary | str) -> str | None:
    # 0054: the one protected-path rule; rel is relative to the tree root, an ancestor hits too.
    if isinstance(boundary, str):
        return boundary
    folded = rel.casefold()
    ledger = boundary.ledger_rel
    if ".git" in folded.split("/") or path_hit(BUILTIN_PROTECTED, rel):
        return R_PROTECTED_BUILTIN.format(target)
    # prepush-2026-10-27: a `!` line in either file lets rg read the reply key.
    if folded.rsplit("/", 1)[-1] in IGNORE_FILES:
        return R_PROTECTED_BUILTIN.format(target)
    if ledger is not None and path_hit(Manifest((ledger,)), rel):
        return R_PROTECTED_BUILTIN.format(target)
    if path_hit(boundary.manifest, rel):
        return R_PROTECTED_PATH.format(target)
    if extension_hit(boundary.manifest, rel):
        return R_PROTECTED_EXT.format(target)
    return None


def _pathspec_ok(args: list[str], cwd: str, base: str | None = None) -> bool:
    # I3a, 0022: `-- <unit worktree paths>`; relative ones resolve against -C (base).
    root = cwd if base is None else base
    return (
        len(args) > 1
        and args[0] == "--"
        and not _has_magic(args[1:])
        and all(_in_unit_worktree(_abs(a, root), cwd) for a in args[1:])
    )


def _has_magic(pathspecs: list[str]) -> bool:
    # 0022: :/ and :(top) are worktree-top relative, so the jail refuses every magic form.
    return any(p.startswith(":") for p in pathspecs)


def _stash_ok(args: list[str]) -> bool:
    if args[:1] == ["list"]:
        return len(args) == 1
    if args[:1] in (["pop"], ["show"]):
        return len(args) <= 2 and not any(a.startswith("-") for a in args[1:])
    if args[:1] == ["push"]:
        rest = args[1:]
        return rest == [] or (len(rest) == 2 and rest[0] == "-m")
    return False


def _config_read_ok(args: list[str]) -> bool:
    return args[:1] in (["--get"], ["--list"]) and not any(a.startswith("-") for a in args[1:])


_FORMAT = ("--format=", "--pretty=")
# F3b: read-only status forms; -sb style bundles match the pattern in the grammar.
_STATUS_FLAGS = frozenset(
    {"--short", "--branch", "--porcelain", "--porcelain=v1", "--porcelain=v2", "--show-stash"}
)
_GIT_GRAMMAR: dict[str, Callable[[list[str], str], bool]] = {
    "status": lambda a, _: _flags_ok(a, _STATUS_FLAGS, (), (r"-[sb]+",)),
    "log": lambda a, _: _flags_ok(
        a,
        frozenset({"--oneline", "--stat", "--name-only", "-p", "--no-merges", "--all"})
        | {"--pickaxe-regex", "--pickaxe-all"},
        (*_FORMAT, "--grep=", "--author="),
        (r"-\d+", r"-n\d+", r"-[SG].+"),
        # 228 S3: --grep <value> as two words, beside the --grep=<value> prefix.
        frozenset({"-n", "-S", "-G", "--grep"}),
    ),
    "diff": lambda a, _: _flags_ok(
        a,
        frozenset(
            {"--stat", "--name-only", "--name-status", "--cached", "--word-diff", "--color=never"}
            | {"--check"}
        ),
        (),
        (r"-U\d+",),
    ),
    "show": lambda a, _: _flags_ok(
        a, frozenset({"--stat", "--name-only", "--name-status", "--oneline", "-s"}), _FORMAT
    ),
    # O5: history reads; -O (pager), -f, --no-index and --contents stay out.
    "grep": lambda a, _: _flags_ok(
        a,
        frozenset({"--cached", "--untracked", "--heading", "--break"}),
        (),
        (r"-[nilLwvcEFIhH]+", r"-[ABC]\d+"),
        frozenset({"-e", "-A", "-B", "-C", "--max-depth"}),
    ),
    "blame": lambda a, _: _flags_ok(
        a,
        frozenset({"-w", "-s", "-e", "-l", "--porcelain", "--line-porcelain"}),
        (),
        (r"-[CM]\d*", r"-L.+"),
        frozenset({"-L"}),
    ),
    "merge-base": lambda a, _: _flags_ok(
        a, frozenset({"--is-ancestor", "--all", "--octopus", "--independent", "--fork-point"})
    ),
    "rev-parse": lambda a, _: _flags_ok(
        a,
        frozenset({"--short", "--abbrev-ref", "--is-inside-work-tree", "--show-toplevel"}),
        ("--short=",),
    ),
    "ls-files": lambda a, _: _flags_ok(a, frozenset({"-z"})),
    "branch": lambda a, _: _flags_ok(
        a, frozenset({"-a", "-r", "-v", "--list", "--show-current"}), positional=False
    ),
    "add": lambda a, _: _flags_ok(a, frozenset({"-A", "-u", "--all"})) and not _has_magic(a),
    "commit": lambda a, cwd: _commit_ok(a, cwd),
    "merge": lambda a, _: _flags_ok(a, frozenset({"--no-ff"}), with_arg=frozenset({"-m"})),
    "worktree": lambda a, _: a[:1] == ["list"] and all(x == "--porcelain" for x in a[1:]),
    "stash": lambda a, _: _stash_ok(a),
    "restore": _pathspec_ok,
    "checkout": _pathspec_ok,
    "config": lambda a, _: _config_read_ok(a),
}


def _git_grammar_ok(
    tokens: list[str],
    subs: frozenset[str],
    cwd: str,
    charter: str | None,
    grammar: dict[str, Callable[[list[str], str], bool]] | None = None,
) -> bool:
    grammar = _GIT_GRAMMAR if grammar is None else grammar
    sub, args, globals_ = _git_split(tokens)
    if sub not in subs or sub not in grammar:
        return False
    # O5: --output and its abbreviations, even where an option value would swallow it.
    if any(_long_matches(arg, "--output", 1) for arg in args):
        return False
    i = 0
    while i < len(globals_):
        flag = globals_[i]
        if flag == "--no-pager":
            i += 1
            continue
        if flag == "-C" and i + 1 < len(globals_):
            target = _abs(globals_[i + 1], cwd)
            if _under(target, cwd) or (charter is not None and _under(target, charter)):
                i += 2
                continue
        return False
    if grammar[sub] is _pathspec_ok:
        return _pathspec_ok(args, cwd, _git_dir(globals_, cwd))
    return grammar[sub](args, cwd)


def _git_dir(globals_: list[str], cwd: str) -> str:
    # 0022: git chains each -C onto the previous one.
    base = cwd
    for i in range(len(globals_) - 1):
        if globals_[i] == "-C":
            base = _abs(globals_[i + 1], base)
    return base


def _docs_add_ok(args: list[str], _: str) -> bool:
    # M1: explicit paths only; no -A, no ".", no globs or pathspec magic.
    paths = args[1:] if args[:1] == ["--"] else args
    return bool(paths) and all(
        not p.startswith(("-", ":"))
        and not _GLOB_CHARS & set(p)
        and not {".", ".."} & set(p.split("/"))
        and not p.endswith("/")
        for p in paths
    )


_DOCS_GRAMMAR: dict[str, Callable[[list[str], str], bool]] = {
    "add": _docs_add_ok,
    "commit": lambda a, _: len(a) == 2 and a[0] == "-m",
    "status": _GIT_GRAMMAR["status"],
    "log": _GIT_GRAMMAR["log"],
    "diff": _GIT_GRAMMAR["diff"],
}
# issue 2: the conductor commits the index as staged; the coder's commit grammar is unchanged.
_CONDUCTOR_GRAMMAR: dict[str, Callable[[list[str], str], bool]] = {
    **_GIT_GRAMMAR,
    "commit": lambda a, cwd: not _commits_work_tree(a) and _commit_ok(a, cwd),
}


def _train_branch(cwd: str) -> str | None:
    # issue 11: the active train's integration branch, named by the train marker.
    train = active_train(project_root(cwd))
    return f"daedalus/{train}" if train else None


def _conductor_push_reason(tokens: list[str], cwd: str, charter: str | None) -> str | None:
    sub, args, globals_ = _git_split(tokens)
    if sub != "push":
        return R_CONDUCTOR_PUSH
    # 0078: the one global admitted is -C naming the declared charter root exactly.
    if globals_ and not (
        charter is not None
        and len(globals_) == 2
        and globals_[0] == "-C"
        and os.path.realpath(_abs(globals_[1], cwd)) == os.path.realpath(_abs(charter, cwd))
    ):
        return R_CONDUCTOR_CHARTER
    if args[:1] in (["-u"], ["--set-upstream"]):
        args = args[1:]
    if len(args) == 2 and args[1].casefold() == "head":
        return R_CONDUCTOR_PUSH_HEAD
    if not (
        len(args) == 2
        and args[0] == "origin"
        and _BRANCH_NAME.fullmatch(args[1])
        and args[1].casefold() not in _DEFAULT_BRANCHES
    ):
        return R_CONDUCTOR_PUSH
    branch = _train_branch(cwd)
    if branch is None:
        return R_CONDUCTOR_NO_TRAIN
    return None if args[1] == branch else R_CONDUCTOR_PUSH_BRANCH.format(branch=branch)


def _reaches_charter(tokens: list[str], cwd: str, charter: str | None) -> bool:
    # 0078: a git -C into the charter root; only the train branch push may do that.
    globals_ = _git_split(tokens)[2]
    return (
        charter is not None
        and "-C" in globals_
        and _under(_git_dir(globals_, cwd), _abs(charter, cwd))
    )


R_LEDGER_ARGS = (
    "append_ledger takes only --probe, or --expected-seq, --entry-file, --repo and --type "
    "once each with a value. Next: run append_ledger from the repo whose ledger you are "
    "appending to; --cwd is for operators."
)
_LEDGER_VALUE_FLAGS = frozenset({"--expected-seq", "--entry-file", "--repo", "--type"})
_LEDGER_SHELL_CHARS = frozenset("*?[{$`")


def _ledger_args_ok(tokens: list[str]) -> bool:
    # 0004: allowlist, not a denylist; a glob like --cw? expands to --cwd after the jail.
    args = tokens[2:]
    if any(_LEDGER_SHELL_CHARS & set(arg) for arg in args):
        return False
    if args == ["--probe"]:
        return True
    seen: set[str] = set()
    i = 0
    while i < len(args):
        flag, eq, value = args[i].partition("=")
        if not eq:
            if i + 1 >= len(args):
                return False
            value = args[i + 1]
            i += 1
        i += 1
        if flag not in _LEDGER_VALUE_FLAGS or flag in seen or not value or value.startswith("-"):
            return False
        seen.add(flag)
    return seen == _LEDGER_VALUE_FLAGS


def _gh_allowed(tokens: list[str]) -> bool:
    words = _gh_words(tokens)
    return len(words) == 2 and words[1] in GH_ALLOWED.get(words[0], frozenset())


_GH_PR_WRITES = frozenset({"create", "edit", "comment"})


def _gh_words(tokens: list[str]) -> list[str]:
    # issue 76: gh_policy's parse; a segment it refuses has no command path, so nothing is allowed.
    parsed = gh_args(tokens[1:])
    return [] if parsed is None else parsed.words[:2]


def _gh_flags(tokens: list[str], *names: str) -> list[GhFlag]:
    parsed = gh_args(tokens[1:])
    return [] if parsed is None else [f for f in parsed.flags if f.name in names]


def _gh_pr_write(tokens: list[str]) -> bool:
    words = _gh_words(tokens)
    return words[:1] == ["pr"] and words[1:2] != [] and words[1] in _GH_PR_WRITES


def _gh_repo_flag(tokens: list[str]) -> bool:
    # I7: reads may name another repo; pr writes stay in the current one.
    return _gh_pr_write(tokens) and bool(_gh_flags(tokens, "-R", "--repo"))


# 0078: gh's [HOST/]OWNER/REPO from an https, ssh or scp-form origin URL.
_REMOTE_URL = re.compile(
    r"(?:(?:https?|ssh|git)://(?:[^@/]+@)?(?P<host>[^/:@]+)(?::\d+)?/"
    r"|(?:[^@/:]+@)?(?P<scp>[^/:@]+):)"
    r"(?P<path>[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+?)(?:\.git)?/?"
)


def _remote_slug(url: str) -> str | None:
    match = _REMOTE_URL.fullmatch(url.strip())
    if match is None:
        return None
    host = (match["host"] or match["scp"]).casefold()
    return match["path"] if host == "github.com" else f"{host}/{match['path']}"


def _charter_slug(charter: str) -> str | None:
    # 0078: a local read of the charter root's origin; the URL never reaches a reason.
    cmd = ["git", "-C", charter, "remote", "get-url", "origin"]
    try:
        out = subprocess.run(
            cmd, capture_output=True, text=True, timeout=2, env=_git_env(), check=False
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return _remote_slug(out.stdout) if out.returncode == 0 else None


def _gh_flag_values(tokens: list[str], long: str, short: str) -> list[str] | None:
    # 0078: `--x v`, `--x=v` and `-X v` only; an attached or bundled short form fails closed.
    if gh_args(tokens[1:]) is None:
        return None
    found = _gh_flags(tokens, long, f"-{short}")
    return None if any(f.attached for f in found) else [f.value or "" for f in found]


def _charter_pr_create_ok(tokens: list[str], cwd: str, charter: str | None) -> bool:
    # 0078: one gh pr create on the declared charter root's origin, for this train's branch.
    if charter is None or _gh_words(tokens) != ["pr", "create"]:
        return False
    repos = _gh_flag_values(tokens, "--repo", "R")
    heads = _gh_flag_values(tokens, "--head", "H")
    if repos is None or heads is None or len(repos) != 1 or len(heads) != 1:
        return False
    branch = _train_branch(cwd)
    if branch is None or heads[0] != branch:
        return False
    return repos[0] == _charter_slug(_abs(charter, cwd))


def _gh_body_file_ok(tokens: list[str], cwd: str) -> bool:
    if not _gh_pr_write(tokens):
        return True
    for flag in _gh_flags(tokens, "--body-file", "-F"):
        value = flag.value or ""
        # I7: stdin (-) and relative-to-elsewhere paths fail; realpath under the two homes only.
        if value in {"", "-"} or not (
            _under(_abs(value, cwd), f"{cwd}/docs/.tmp") or _under(_abs(value, cwd), "/tmp")
        ):
            return False
    return True


def _gh_write_reason(tokens: list[str]) -> str | None:
    if not _gh_pr_write(tokens):
        return None
    if _gh_flags(tokens, "--body", "-b") or not _gh_flags(tokens, "--body-file", "-F"):
        return R_BODY_INLINE
    if _gh_words(tokens)[1] == "edit" and _gh_flags(tokens, "--base", "-B"):
        return R_EDIT_BASE
    return None


def _ledger_write_reason(path: str, cwd: str, config: Config) -> str | None:
    # I1: protect the ledger append_ledger resolves (manifest, config, probe); fail closed.
    try:
        resolved = resolve_ledger(cwd, config)
    except LedgerError as exc:
        return f"the ledger could not be resolved, so charter-docs writes fail closed: {exc}"
    default = project_root(cwd) / "docs" / "decisions.md"
    protected = {str(resolved.path)} if resolved is not None else set()
    if default.is_file():
        protected.add(str(default))
    return R_LEDGER_DIRECT if any(_same_path(path, p) for p in protected) else None


def _same_path(target: str, protected: str) -> bool:
    # FW-I1: case-insensitive mounts are in scope; samefile if it exists, else casefolded realpath.
    if os.path.exists(target):
        try:
            return os.path.samefile(target, protected)
        except OSError:
            return False
    return os.path.realpath(target).casefold() == os.path.realpath(protected).casefold()


def _in_place(name: str, args: list[str]) -> bool:
    for arg in args:
        if name == "sed" and (arg == "--in-place" or arg.startswith("--in-place=")):
            return True
        if arg.startswith("-") and not arg.startswith("--"):
            group = arg[1:]
            if name == "sed" and "i" in group.split("e")[0]:
                return True
            if name == "perl" and "i" in group:
                return True
    return False


def _short_taker(arg: str, opts: frozenset[str]) -> tuple[str, str] | None:
    # 0022: in a short group (-pm, -rt<dir>) the first value-taking letter consumes the rest.
    if len(arg) < 2 or arg[0] != "-" or arg[1] == "-":
        return None
    for idx, char in enumerate(arg[1:], start=2):
        if f"-{char}" in opts:
            return f"-{char}", arg[idx:]
    return None


def _write_operands(name: str, args: list[str]) -> list[str]:
    if name == "dd":
        return [a.split("=", 1)[1] for a in args if a.startswith("of=")]
    if name == "mknod":
        # issue 75: NAME TYPE [MAJOR MINOR]; only NAME is a path.
        return _write_operands("mkfifo", args)[:1]
    values = _VALUE_OPTS.get(name, frozenset())
    paths = _PATH_OPTS.get(name, frozenset())
    operands: list[str] = []
    script_given = False
    i = 0
    while i < len(args):
        arg = args[i]
        if arg == "--":
            operands += args[i + 1 :]
            break
        if name in {"sed", "perl"} and arg in {"-e", "-E", "-f"}:
            script_given = True
            i += 2
            continue
        taker = _short_taker(arg, values | paths)
        if taker is not None:
            flag, attached = taker
            value = attached or (args[i + 1] if i + 1 < len(args) else "")
            if flag in paths and value:
                operands.append(value)
            i += 1 if attached else 2
            continue
        if arg in _VALUE_LONG_NEXT:
            i += 2
            continue
        if arg.startswith("--") and "=" in arg:
            key, value = arg.split("=", 1)
            if name not in {"sed", "perl"} and key not in _VALUE_LONG:
                operands.append(value)
        elif not arg.startswith("-") or arg == "-":
            operands.append(arg)
        i += 1
    if not operands:
        return operands
    if name in {"sed", "perl"} and not script_given:
        return operands[1:]
    # 0022: the leading mode or owner is not a path; --reference replaces it.
    if any(a.startswith("--reference") for a in args):
        return operands
    if (name == "chmod" and _MODE.fullmatch(operands[0])) or name in {"chown", "chgrp"}:
        return operands[1:]
    return operands


def _backup_suffix(name: str, args: list[str]) -> str | None:
    # issue 30: a backup suffix with a slash places the backup outside the target's directory.
    if name not in {"cp", "mv", "install", "ln"}:
        return None
    for i, arg in enumerate(args):
        value = None
        if arg.startswith("--suffix="):
            value = arg.split("=", 1)[1]
        elif arg in {"--suffix", "-S"}:
            value = args[i + 1] if i + 1 < len(args) else ""
        elif arg.startswith("-S") and not arg.startswith("--"):
            value = arg[2:]
        if value is not None and "/" in value:
            return f"backup suffix {value}"
    return None


def _coder_write_targets(segment: list[str], cwd: str) -> list[str]:
    # 0054: file operands of a write command, and git restore or checkout pathspecs.
    name = _base(segment[0])
    args = segment[1:]
    if name == "git":
        sub, git_args, globals_ = _git_split(segment)
        if sub not in {"restore", "checkout"} or git_args[:1] != ["--"]:
            return []
        base = _git_dir(globals_, cwd)
        return [_abs(a, base) for a in git_args[1:]]
    if name not in CODER_WRITE_CMDS and not (name in {"sed", "perl"} and _in_place(name, args)):
        return []
    return [_abs(a, cwd) for a in _write_operands(name, args) if a != "-"]


def _cd_relative_target(segment: list[str], cwd: str) -> str | None:
    # 0022: after cd, relative operands resolve against the hook cwd, not the shell's.
    name = _base(segment[0])
    args = segment[1:]
    if name == "git":
        sub, git_args, globals_ = _git_split(segment)
        dirs = [globals_[i + 1] for i in range(len(globals_) - 1) if globals_[i] == "-C"]
        if sub in {"add", "commit"} and not dirs:
            return f"git {sub} without -C"
        if sub in {"restore", "checkout"} and not dirs:
            dirs = [a for a in git_args if a != "--"]
        return next((d for d in dirs if not os.path.isabs(d)), None)
    if name not in CODER_WRITE_CMDS and not (name in {"sed", "perl"} and _in_place(name, args)):
        return None
    operands = [a for a in _write_operands(name, args) if a != "-"]
    return next((a for a in operands if not os.path.isabs(a)), None)


def _data_dir_markers() -> list[str]:
    markers = [f"~{_DATA_DIR_DEFAULT}", f"{_HOME}{_DATA_DIR_DEFAULT}"]
    markers += [f"$HOME{_DATA_DIR_DEFAULT}", f"${{HOME}}{_DATA_DIR_DEFAULT}"]
    markers += ["$CLAUDE_PLUGIN_DATA", "${CLAUDE_PLUGIN_DATA}", _PROJECT_DATA]
    env = os.environ.get("CLAUDE_PLUGIN_DATA")
    if env:
        markers.append(os.path.normpath(env))
    return markers


def _normalize_paths(command: str) -> str:
    # 0010: `.claude//daedalus` and `./.claude/./daedalus` must match the marker too.
    text = re.sub(r"/{2,}", "/", command)
    prev = None
    while prev != text:
        prev, text = text, re.sub(r"(^|[\s/'\"=])\./", r"\1", text)
    return text


def _cd_into_claude(command: str) -> bool:
    for target in _CD_TARGET.findall(command):
        norm = os.path.normpath(target.strip("'\""))
        # 0010: cd into the data dir itself (or below it) needs no further daedalus mention.
        if _names_project_data(norm):
            return True
        if os.path.basename(norm) == ".claude" and _DAEDALUS_WORD.search(command):
            return True
    return False


def _cd_data_dir_git(command: str) -> bool:
    return _cd_into_claude(command) and bool(_GIT_INDEX_WRITE.search(command))


def _data_dir_write(command: str) -> bool:
    normalized = _normalize_paths(command)
    named = any(marker in normalized for marker in _data_dir_markers())
    if not (named or _cd_into_claude(normalized)):
        return False
    # I4: quoted spans collapse first so a jq filter's `>` reads as data, not a redirect.
    unquoted = _quote_spans(normalized.replace("$'", "'").replace('$"', '"'))
    return bool(_DATA_DIR_WRITE.search(_DEVNULL.sub(" ", unquoted)))


def _data_dir_path(path: str, cwd: str) -> bool:
    env = os.environ.get("CLAUDE_PLUGIN_DATA")
    if env and os.path.isabs(env) and _under(path, env):
        return True
    # 0010: the project data dir for this cwd, plus any .claude/daedalus in another worktree.
    return _names_project_data(path) or _under(path, str(project_data_dir(cwd)))


def _gitleaks_ok(tokens: list[str]) -> bool:
    if tokens[1:2] != ["detect"]:
        return False
    redacted = False
    i = 2
    while i < len(tokens):
        token = tokens[i]
        key, has_value, value = token.partition("=")
        if token.startswith("-r") and len(token) > 2 and token[2] != "=":
            key, has_value, value = "-r", "=", token[2:]
        elif re.match(r"-[A-Za-z]+r", token):
            # N6: a bundled short group carrying -r hides the report path; fail closed.
            return False
        if key in {"--report-path", "-r"}:
            if not has_value:
                value = tokens[i + 1] if i + 1 < len(tokens) else ""
                i += 1
            if not value.startswith("/") or not _under(value, "/tmp"):
                return False
        elif key == "--log-opts":
            if not has_value:
                value = tokens[i + 1] if i + 1 < len(tokens) else ""
                i += 1
            if "--output" in value or "--ext-diff" in value:
                return False
        elif token in {"--redact", "--redact=100"}:
            redacted = True
        i += 1
    # I4: an unredacted finding would put the secret into the audit chain.
    return redacted


def _shell_words(command: str) -> list[list[str]]:
    return [segment.words for segment in _shell_scan(command)]


class ScanSegment(NamedTuple):
    # issue 116: a segment's words, the indices a <<< here-string feeds, and whether a pipe or a
    # < redirect on fd 0 feeds its stdin (fix round 3).
    words: list[str]
    heres: frozenset[int]
    fed: bool
    # fix round 4: every here-string on any fd, and whether a < redirect on fd 0 is attached.
    strings: frozenset[int] = frozenset()
    redirected: bool = False


def _shell_scan(command: str) -> list[ScanSegment]:
    # spec 8: single-quoted or escaped $ is literal; quote edges end a variable name.
    segments: list[ScanSegment] = []
    words: list[str] = []
    heres: set[int] = set()
    strings: set[int] = set()
    cur: list[str] = []
    started, redirect, quote, op, fd_in, fed = False, False, "", "", True, False
    redirected = False
    i, n = 0, len(command)

    def end_word() -> None:
        nonlocal cur, started, redirect, op
        if cur or started:
            if redirect and op == "<<<":
                strings.add(len(words))
            if redirect and op == "<<<" and fd_in:
                heres.add(len(words))
            words.append((_REDIRECT if redirect else "") + "".join(cur))
            redirect, op = False, ""
        cur, started = [], False

    while i < n:
        c = command[i]
        if quote == "'":
            if c == "'":
                quote = ""
                cur.append(_CUT)
            else:
                cur.append(_LIT if c == "$" else c)
        elif quote == '"':
            if c == '"':
                quote = ""
                cur.append(_CUT)
            elif c == "\\" and i + 1 < n:
                i += 1
                cur.append(_LIT if command[i] == "$" else command[i])
            else:
                cur.append(c)
        elif c in "'\"":
            quote, started = c, True
            cur.append(_CUT)
        elif c == "\\" and i + 1 < n:
            i += 1
            cur.append(_LIT if command[i] == "$" else command[i])
            started = True
        elif c in "<>":
            fd = "".join(cur) if not redirect else ""
            if fd.isdigit():
                # issue 116 (fix round 1, row 1): a digit word glued to < or > is its fd.
                cur, started = [], False
            end_word()
            if not redirect:
                op, fd_in = "", fd in {"", "0"} or not fd.isdigit()
                redirected = redirected or (c == "<" and fd_in)
                fed = fed or redirected
            op += c
            redirect = True
            while i + 1 < n and command[i + 1] in "&>":
                i += 1
                op += command[i]
        elif c.isspace() or c in ";&|()`":
            end_word()
            if c not in " \t" and words:
                segments.append(
                    ScanSegment(list(words), frozenset(heres), fed, frozenset(strings), redirected)
                )
                words.clear()
                heres.clear()
                strings.clear()
                fed = redirected = False
            if c == "|" and "|" not in command[i - 1 : i] + command[i + 1 : i + 2]:
                fed = True  # fix round 3: a pipe (never ||) feeds the next segment's stdin.
        else:
            cur.append(c)
            started = True
        i += 1
    end_word()
    if words:
        segments.append(ScanSegment(words, frozenset(heres), fed, frozenset(strings), redirected))
    return segments


def _base_env() -> dict[str, list[str]]:
    # spec 8: the hook's own environment, HOME real, the plugin folders defaulted.
    env = {k: [v] for k, v in os.environ.items()}
    env["HOME"] = [str(Path.home())]
    env.setdefault("CLAUDE_PLUGIN_ROOT", [os.path.dirname(_REPO_SCRIPTS)])
    env.setdefault("CLAUDE_PLUGIN_DATA", [env["HOME"][0] + _DATA_DIR_DEFAULT])
    return env


def _bash_env(segments: list[list[str]]) -> list[dict[str, list[str]]]:
    # spec 8: assignments and for-loops bind, read and friends unbind, HOME stays real.
    env = _base_env()
    envs: list[dict[str, list[str]]] = []
    changes: list[dict[str, list[str] | None]] = []
    for words in segments:
        clean = [_clean(w) for w in words]
        changed: dict[str, list[str] | None] = {}
        for i, word in enumerate(words):
            name, eq, value = word.partition("=")
            key = re.split(r"[\[+]", name, maxsplit=1)[0]
            if eq and _ASSIGN.match(word) and key != "HOME":
                bound = _expand_word(value, env)
                # issue 121: an append or an array element leaves the value unknown.
                unknown = key != name or any(u for _, u in bound)
                changed[key] = None if unknown else [t for t, _ in bound]
            if clean[i] == "for" and i + 1 < len(words):
                loop = [x for w in words[i + 3 :] for x in _expand_word(w, env)]
                listed = i + 2 < len(words) and clean[i + 2] == "in"
                ok = listed and not any(u for _, u in loop)
                changed[clean[i + 1]] = [t for t, _ in loop] if ok else None
            if clean[i] in _BINDERS:
                for later in clean[i + 1 :]:
                    if not later.startswith("-"):
                        changed[later] = None
            for key, values in changed.items():
                if values is None:
                    env.pop(key, None)
                else:
                    env[key] = values
        # spec 8: a binding applies from its own segment onward, never to earlier segments.
        envs.append(dict(env))
        changes.append(changed)
    _loop_union(segments, envs, changes)
    return envs


def _loop_union(
    segments: list[list[str]],
    envs: list[dict[str, list[str]]],
    changes: list[dict[str, list[str] | None]],
) -> None:
    # spec 8: a later iteration sees every binding in its loop, header included.
    opened: list[int] = []
    for k, words in enumerate(segments):
        first = _clean(words[0])
        if first == "do":
            head = k - 1 if k and _clean(segments[k - 1][0]) in {"for", "while", "until"} else k
            opened.append(head)
        if first != "done" or not opened:
            continue
        span = range(opened.pop(), k + 1)
        merged: dict[str, list[str] | None] = {}
        for j in span:
            for key, values in changes[j].items():
                prior = merged.get(key, [])
                merged[key] = None if values is None or prior is None else [*prior, *values]
        for j in span:
            for key, values in merged.items():
                if values is None:
                    envs[j].pop(key, None)
                else:
                    envs[j][key] = list(dict.fromkeys([*envs[j].get(key, []), *values]))


def _command_at(
    clean: list[str], skip: set[int], options: list[WrapperOption] | None = None
) -> int | None:
    # spec 8, issue 76: past control words and assignments, then shell.unwrap; options collects.
    places = [i for i, word in enumerate(clean) if word and i not in skip]
    k = 0
    while k < len(places):
        word = clean[places[k]]
        if word in _CONTROL_WORDS or _ASSIGN.match(word):
            k += 1
            continue
        unwrapped = unwrap([clean[i] for i in places[k:]])
        if unwrapped is None:
            return _OPAQUE
        rest, found = unwrapped
        if options is not None:
            options += [o._replace(at=places[k + o.at]) for o in found]
        if not rest:
            return None
        if len(places) - len(rest) == k:
            return places[k]
        k = len(places) - len(rest)
    return None


def _opaque_words(clean: list[str], skip: set[int]) -> set[int]:
    # issue 76: past an unknown wrapper option the command word is unknown; these words remain.
    return {i for i, word in enumerate(clean) if word and i not in skip}


def _opaque_values(texts: list[str], indices: set[int]) -> list[str]:
    # issue 76: each plain word, plus an option word's value (--x=v, -X=v), as a path.
    # audit round 1: a short cluster's value may start at any letter (-iC/x), so every suffix.
    values: list[str] = []
    for i in sorted(indices):
        word = texts[i]
        if not word.startswith("-"):
            values.append(word)
            continue
        if "=" in word:
            values.append(word.split("=", 1)[1])
        if not word.startswith("--"):
            values += [word[k:] for k in range(2, len(word))]
    return list(dict.fromkeys(v for v in values if v))


def _opaque_targets(texts: list[str], indices: set[int], cwd: str) -> list[str]:
    # issue 76: any value may be a folder the command moves to, so each is also a base.
    values = _opaque_values(texts, indices)
    bases = [cwd, *(b for b in (_anchor(v, cwd) for v in values) if b)]
    found = (_anchor(v, base) for v in values for base in dict.fromkeys(bases))
    return list(dict.fromkeys(t for t in found if t))


def _option_values(
    texts: list[str], options: list[WrapperOption], kinds: frozenset[tuple[str, str]]
) -> list[str]:
    return [texts[o.at][len(o.prefix) :] for o in options if (o.wrapper, o.option) in kinds]


def _moved_base(texts: list[str], options: list[WrapperOption], cwd: str) -> str | None:
    # issue 76: env -C, env --chdir and sudo -D move the command's folder, each from the last.
    base: str | None = cwd
    for value in _option_values(texts, options, WRAPPER_CHDIR):
        base = _anchor(value, base) if base is not None else None
    return base


def _search_paths(name: str, clean: list[str], args: list[int]) -> set[int]:
    # spec 8: grep and rg take the first operand as the pattern unless -e or -f names it.
    letters = _SEARCH_VALUES["rg" if name == "rg" else "grep"] if name != "jq" else frozenset()
    paths: set[int] = set()
    operands: list[int] = []
    explicit, pending = False, ""
    for i in args:
        word = clean[i]
        if pending:
            if pending in {"f", "--file"}:
                paths.add(i)
            pending = ""
        elif word.startswith("--"):
            opt = word.split("=", 1)[0]
            # prepush2-2026-10-27: rg --files takes no pattern, so every operand is a path.
            explicit = explicit or opt in {"--regexp", "--file", "--files"}
            if opt == "--file" and "=" in word:
                paths.add(i)
            elif "=" not in word and opt in _SEARCH_LONGS:
                pending = opt
        elif word.startswith("-") and len(word) > 1:
            for j, ch in enumerate(word[1:]):
                if ch in letters:
                    explicit = explicit or ch in "ef"
                    if j == len(word) - 2:
                        pending = ch
                    elif ch == "f":
                        paths.add(i)
                    break
        else:
            operands.append(i)
    return paths | set(operands if explicit else operands[1:])


def _path_positions(words: list[str]) -> tuple[str, int, set[int]]:
    # spec 8: where an unresolved variable could name a file for a modeled reader or writer.
    clean = [_clean(w) for w in words]
    paths = {i for i, w in enumerate(words) if w.startswith(_REDIRECT)}
    at = _command_at(clean, paths)
    if at == _OPAQUE:
        return "", -1, paths | _opaque_words(clean, paths)
    if at is None:
        return "", -1, paths
    name = _base(clean[at])
    args = [i for i in range(at + 1, len(clean)) if i not in paths]
    if name in _GREPS or name in {"rg", "jq"}:
        return name, at, paths | _search_paths(name, clean, args)
    if name == "find":
        for i in args:
            if clean[i].startswith(("-", "(", "!")):
                break
            paths.add(i)
        return name, at, paths
    if name in _PATH_CMDS:
        paths |= {i for i in args if not clean[i].startswith("-") or _PATH_OPTION.match(clean[i])}
    return name, at, paths


def _tree_reader(
    name: str, clean: list[str], at: int, ops: list[int], command: str
) -> tuple[bool, list[int], bool] | None:
    # spec 8: (sees hidden dirs, operand indices, reads the cwd when no operand is given).
    args = clean[at + 1 :]
    longs = {a.split("=", 1)[0] for a in args if a.startswith("--")}
    short = {c for a in args if a.startswith("-") and not a.startswith("--") for c in a[1:]}
    if name in _GREPS:
        on = bool({"r", "R"} & short or {"--recursive", "--dereference-recursive"} & longs)
        on = on or any(a.startswith("--directories=recurse") for a in args)
        on = on or shell.search_opaque(command)
        return (True, ops, not ops) if on else None
    if name == "rg":
        return rg_reaches_hidden(args, command), ops, not ops
    if name == "find":
        on = bool({"-exec", "-execdir", "-ok", "-okdir"} & set(args)) or "xargs" in command
        return (True, ops, not ops) if on else None
    if name in {"tar", "rsync", "bsdtar", "7z", "7za", "7zr", "7zz", "pax"}:
        return True, ops, False
    if name == "scp" and "r" in short:
        return True, ops, False
    if name == "cp" and ({"r", "R", "a"} & short or {"--recursive", "--archive"} & longs):
        return True, ops, False
    if name == "zip" and ({"r", "R"} & short or "--recurse-paths" in longs):
        return True, ops, False
    return None


_RG_GLOBS = frozenset({"--glob", "--iglob"})
# 113, prepush-2026-10-27: each reads hidden or ignored files, or follows a link out of the tree.
_RG_REACH_LONGS = frozenset(
    {"--hidden", "--no-ignore", "--unrestricted", "--ignore-file", "--follow"}
)
_RG_REACH_SHORT = frozenset("u.L")
_RG_CONFIG_ENV = "RIPGREP_CONFIG_PATH"
R_RG_REACH = (
    "rg with --hidden, -u, --no-ignore, --ignore-file, -L, --follow or RIPGREP_CONFIG_PATH reads "
    "hidden or ignored files (113). Next: drop the flag and search the tree as rg skips it"
)
R_RG_ONE = "a verify is one plain rg search with no wrapper, prefix, pipe or chain (113)"
R_RG_OPAQUE = (
    "rg or grep with a word the shell rewrites ($'...', $\"...\", $VAR, an unquoted brace or a "
    "leading glob) may carry a flag the jail never reads (113, prepush2-2026-10-27). Next: spell "
    "every argument literally and single-quote the pattern"
)
R_RG_PROGRAM = (
    "rg --pre, --pre-glob, --hostname-bin or any --*-bin option runs or loads a program "
    "(113, prepush2-2026-10-27). Next: drop the option"
)


def rg_program(args: list[str]) -> bool:
    # prepush2-2026-10-27: each names a program rg runs or a file it loads for one.
    keys = {a.split("=", 1)[0] for a in args if a.startswith("--")}
    return bool(keys & {"--pre", "--pre-glob", "--hostname-bin"}) or any(
        k.endswith("-bin") for k in keys
    )


def _rg_short_letters(arg: str) -> set[str]:
    # prepush2-2026-10-27: letters after a value-taking flag are its value (-trust is -t rust).
    letters: set[str] = set()
    for ch in arg[1:]:
        letters.add(ch)
        if ch in _SEARCH_VALUES["rg"]:
            break
    return letters


def rg_reaches_hidden(args: list[str], command: str) -> bool:
    # 113: a config file can add any flag, so its variable anywhere in the command fails closed.
    longs = {a.split("=", 1)[0] for a in args if a.startswith("--")}
    short = {
        c
        for a in args
        if a.startswith("-") and not a.startswith("--")
        for c in _rg_short_letters(a)
    }
    reach = bool(_RG_REACH_SHORT & short or _RG_REACH_LONGS & longs)
    return reach or _RG_CONFIG_ENV in command or shell.search_opaque(command)


def _rg_globs(args: list[str]) -> list[str]:
    # SC-12: each -g, --glob or --iglob whitelist; a negated glob only hides, a $ value is *.
    raws: list[str] = []
    letters = _SEARCH_VALUES["rg"]
    i = 0
    while i < len(args) and args[i] != "--":
        arg, later = args[i], (args[i + 1 : i + 2] or [""])[0]
        key, eq, value = arg.partition("=")
        if arg.startswith("--") and (key in _RG_GLOBS or key in _SEARCH_LONGS) and not eq:
            raws += [later] if key in _RG_GLOBS else []
            i += 1
        elif arg.startswith("--"):
            raws += [value] if key in _RG_GLOBS else []
        elif arg.startswith("-"):
            hit = next((k for k, c in enumerate(arg[1:], 2) if c in letters), None)
            if hit is not None:
                # SC-12: -g=x may reach rg as x or =x, so both are judged.
                value = arg[hit:] or later
                raws += [value, value.removeprefix("=")] if arg[hit - 1] == "g" else []
                i += 0 if arg[hit:] else 1
        i += 1
    raws = ["*" if set("$`") & set(r) else r for r in dict.fromkeys(raws) if not r.startswith("!")]
    return [p for raw in raws for p in glob_patterns(raw)]


def _tree_reason(
    parsed: list[tuple[list[str], tuple[str, int, set[int]]]],
    envs: list[dict[str, list[str]]],
    bases: list[str],
    roots: list[str],
    command: str,
    keys: tuple[str, ...] = (),
    env_files: tuple[str, ...] = (),
) -> str | None:
    dotglob = _dotglob_on(command)
    # SC-12: reply key roots let a dot folder hide them from **; credential stores do not.
    pairs = [(root, False, R_CREDENTIAL_TREE) for root in roots]
    pairs += [(key, True, R_CREDENTIAL_TREE) for key in keys]
    # 0192: a .env file is a dot file, so rg's default skip hides it like the reply key.
    pairs += [(env, True, R_ENV_FILE_TREE) for env in env_files]
    for k, (words, (name, at, paths)) in enumerate(parsed):
        if at < 0:
            continue
        ops = [i for i in sorted(paths) if not words[i].startswith(_REDIRECT)]
        found = _tree_reader(name, [_clean(w) for w in words], at, ops, command)
        if found is None:
            continue
        hidden, ops, implicit = found
        globs = _rg_globs([_clean(w) for w in words[at + 1 :]]) if name == "rg" else []
        targets = list(bases) if implicit else []
        for i in ops:
            for text, _ in _expand_word(words[i], envs[k]):
                targets += [t for t in (_anchor(text, b) for b in bases or [""]) if t]
        for target in targets:
            for root, dots_hide, reason in pairs:
                rest = _store_rest(target, root, True, dotglob, dots_hide)
                # spec 8, SC-12: rg skips hidden dirs unless a flag or a whitelist glob reaches one.
                shown = hidden or glob_reaches(globs, rest or [])
                if rest is not None and (shown or not any(p.startswith(".") for p in rest)):
                    return reason.format(path=target)
                if rest is not None and name == "rg" and ignore_whitelist(root):
                    return R_IGNORE_WHITELIST.format(path=target)
            walked = _env_walk_reason(target, hidden, globs, name == "rg", dotglob)
            if walked:
                return walked
    return None


def _env_walk_reason(
    target: str, hidden: bool, globs: list[str], rg: bool, dotglob: bool
) -> str | None:
    # 0192, issue 152: a folder read reaches a nested .env file when it shows dot files or a
    # glob names one; a glob operand walks each match. Plain rg reaches one only through a
    # `!` line in an ignore file, so it reads the ignore files instead.
    if not (hidden or globs or rg):
        return None
    globbed = bool(_GLOB_CHARS & set(target))
    folders = _glob.glob(target, include_hidden=dotglob) if globbed else [target]
    for folder in (f for f in folders if os.path.isdir(f)):
        if rg:
            listed = env_whitelist_reason(folder)
            if listed:
                return listed
        if not (hidden or globs):
            continue
        found = env_walk(folder)
        if found is None:
            return R_ENV_WALK_CAP.format(path=folder)
        for env in found:
            rest = os.path.relpath(env, os.path.realpath(folder)).split(os.sep)
            if hidden or glob_reaches(globs, rest):
                return R_ENV_FILE_TREE.format(path=folder)
    return None


def rg_reason(command: str, cwd: str) -> str | None:
    # 113, 0186: the frameworks rulebook's rg judgement as one call; packs.py judges verifies by it.
    # 228 S3b: one plain command from the one parse; any construct, prefix or redirect is R_RG_ONE.
    script = shparse.parse(command)
    item = script.items[0] if len(script.items) == 1 else None
    cmds = [cmd for cmd, _ in shparse.walk(script)]
    cmd = cmds[0] if len(cmds) == 1 and isinstance(item, Pipeline) else None
    plain = cmd is not None and not (cmd.assignments or cmd.redirects or shparse.opaque(script))
    tokens = literal_tokens(cmd) if plain else []
    if tokens[:1] != ["rg"] or (isinstance(item, Pipeline) and (item.negated or item.timed)):
        return R_RG_ONE
    if rg_program(tokens[1:]):
        return R_RG_PROGRAM
    if shell.search_opaque(command):
        return R_RG_OPAQUE
    if rg_reaches_hidden(tokens[1:], command):
        return R_RG_REACH
    # 113: judged against the reply key's fixed place, whether or not one exists yet.
    if glob_reaches(_rg_globs(tokens[1:]), [".claude", "daedalus", REPLY_KEY_NAME]):
        return R_REPLY_KEY_TREE.format(path=cwd)
    return _credential_reason("Bash", {"command": command}, cwd)


def _bash_credential_reason(
    command: str, cwd: str, roots: list[str], keys: tuple[str, ...] = ()
) -> str | None:
    segments = _shell_words(command)
    envs = _bash_env(segments)
    dotglob = _dotglob_on(command)
    parsed = [(words, _path_positions(words)) for words in segments]
    bases = [cwd] if os.path.isabs(cwd) else []
    for k, (words, (name, at, _)) in enumerate(parsed):
        # issue 76: a wrapper that changes folder is a base for relative paths, like cd.
        moves: list[WrapperOption] = []
        clean = [_clean(w) for w in words]
        redirects = {i for i, w in enumerate(words) if w.startswith(_REDIRECT)}
        found_at = _command_at(clean, redirects, moves)
        texts = [(_expand_word(w, envs[k]) or [("", False)])[0][0] for w in words]
        moved = [_moved_base(texts, moves, cwd)] if os.path.isabs(cwd) else []
        if found_at == _OPAQUE and os.path.isabs(cwd):
            values = _opaque_values(texts, _opaque_words(clean, redirects))
            moved += [_anchor(v, cwd) for v in values]
        bases += [b for b in dict.fromkeys(moved) if b is not None and b not in bases]
        if name not in {"cd", "pushd"}:
            continue
        # spec 8: the first non-option argument is the target; a bare cd goes home.
        target, options = None, True
        for word in words[at + 1 :]:
            if options and _clean(word) == "--":
                options = False
            elif not (options and _clean(word).startswith("-")):
                target = word
                break
        texts = [t for t, _ in _expand_word(target, envs[k])] if target else envs[k]["HOME"]
        bases += [b for b in (_anchor(t, cwd) for t in texts) if b]
    # 0192: a command naming an ignore file and carrying a `!` line that reaches a .env name.
    words_all = [_clean(w) for s in segments for w in s]
    named = [w for w in words_all if os.path.basename(w) in ENV_IGNORE_FILES]
    if named and (whitelists_env(command) or any(whitelists_env(w) for w in words_all)):
        return R_ENV_WHITELIST_WRITE.format(path=named[0])
    absolute: list[str] = []
    relative: list[str] = []
    unresolved = ""
    for k, (words, (_, _, paths)) in enumerate(parsed):
        env = envs[k]
        for i, word in enumerate(words):
            for text, unknown in _expand_word(word, env):
                if unknown and i in paths and not unresolved:
                    unresolved = _clean(word)
                parts = [_tilde(p, env["HOME"][0]) for p in _CREDENTIAL_PART.split(text)[1:] if p]
                for cand in [text, *parts]:
                    (absolute if os.path.isabs(cand) else relative).append(cand)

    def hit(target: str) -> str | None:
        if reply_key_hit(target) or _credential_hit(target, list(keys), True, dotglob, True):
            return R_REPLY_KEY.format(path=target)
        if _credential_hit(target, roots, True, dotglob):
            return R_CREDENTIAL.format(path=target)
        if env_file_hit(target) or _credential_hit(target, list(env_files), True, dotglob, True):
            return R_ENV_FILE.format(path=target)
        return None

    # 0192: the .env files beside every folder the command starts in or moves to.
    env_files = tuple(env_roots(*bases))
    # spec 8: spelled-out paths first, so the message names the path the command wrote.
    for cand in absolute:
        reason = hit(os.path.normpath(cand))
        if reason:
            return reason
    if unresolved:
        return R_CREDENTIAL_PARAM.format(path=unresolved)
    # audit B4 round 3: an unexpanded brace word whose alternative starts its own path.
    unjudged = next((w for s in segments for w in map(_clean, s) if _unjudged_root(w)), "")
    if unjudged:
        return R_BRACE_UNJUDGED.format(path=unjudged)
    for cand in relative:
        for base in bases:
            reason = hit(os.path.normpath(os.path.join(base, cand)))
            if reason:
                return reason
    return _tree_reason(parsed, envs, bases, roots, command, keys, env_files)


def _credential_reason(tool: str, tool_input: dict[str, object], cwd: str) -> str | None:
    if tool == "Bash":
        command = str(tool_input.get("command") or "")
        # SC-12: the reply key joins as its own roots, so globs and folder reads of it refuse.
        keys = tuple(key_roots(cwd))
        return _bash_credential_reason(command, cwd, _credential_roots(), keys)
    if tool not in CREDENTIAL_TOOLS and tool not in WRITE_TOOLS:
        return None
    return path_reason(tool, tool_input, cwd)


def _plain_segments(command: str) -> list[list[str]] | None:
    # 0028, 228 S3: each parsed command's literal words past its wrappers; None (the regex
    # fallback) on an opaque parse, an expanding word, env -S, or a shell or interpreter head.
    script = shparse.parse(command)
    if shparse.opaque(script):
        return None
    flat: list[list[str]] = []
    for cmd, _ in shparse.walk(script):
        words = [w.literal for w in cmd.words]
        literal = [w for w in words if w is not None]
        if len(literal) != len(words) or env_split_values(literal):
            return None
        tokens = strip_wrappers(literal)
        if tokens and command_family(tokens[0]) == "busybox":
            tokens = tokens[1:]
        if tokens is None or (tokens and command_family(tokens[0]) in _BODY_HEADS):
            return None
        if not tokens:
            continue
        name = _base(tokens[0])
        if name not in {"gh", "git"} and {"gh", "git"} & {_base(t) for t in tokens}:
            return None
        flat.append(tokens)
    return flat


def _gh_gate(agent: str, cwd: str, command: str) -> str | None:
    # 0035: outside a train, main and unknown agents skip the whole gate, deny classes included.
    if not allowlist_applies(agent, cwd, command):
        return None
    from lib.admit import admit_role, role_for  # 228 S3: admit imports this module.

    # 228 S4: main's grammar with the agent's gh class; the policy reads the typed triple.
    script = shparse.parse(command)
    got = admit_role(script, replace(role_for("main"), gh=agent), cwd, text=command)
    if _passed(got):
        return gh_reason(agent, got)
    refused = _refused(got)
    if refused is None or refused.family != "gh":
        return None  # 228 S4: no gh call the parse shows; the agent's own grammar refuses it.
    cmd = refused_command(script, refused)
    # 0028: a class refusal spans the whole call and is shown as the class table words it.
    return refused.reason if cmd is not None and refused.span == cmd.span else refusal_text(refused)


def _admitted_segments(
    command: str, cwd: str, families: frozenset[str] | set[str] | None = None
) -> list[list[str]] | None:
    # 228 S3: an admitted command has no body, so its parsed commands are every command it runs;
    # a refused one keeps the _plain_segments reader and its text fallback.
    script, got = _admission(command, "main", cwd)
    if not _passed(got):
        return _plain_segments(command)
    parsed = {cmd.span: cmd for cmd, _ in shparse.walk(script)}
    out: list[list[str]] = []
    for done in got.commands:
        cmd = parsed.get(done.span)
        if cmd is None or (families is not None and done.family not in families):
            continue
        # 228 S3: from the command word on, past the wrappers admit read.
        words = [w for w in cmd.words if w.span[0] >= done.word.span[0]]
        out.append([w.literal if w.literal is not None else w.raw for w in words])
    return out


def _train_active(cwd: str) -> bool:
    # 0023: existence only; a symlinked or unreadable marker still counts as an active train.
    return os.path.lexists(train_marker(project_root(cwd)))


_GIT_DIR_OPTS = ("--git-dir=", "--work-tree=")
# 228 S3: a head that runs a string as code; the nested-session tripwire reads it by its text.
_BODY_HEADS = _SHELLS | INTERPRETERS | {"eval", "source", ".", "busybox"}


def _admission(command: str, agent: str, cwd: str) -> tuple[Script, Admitted | Refusal]:
    # 228 S3: the one parse and the admission grammar every Bash decision path reads.
    from lib.admit import admit  # 228 S3: admit imports this module.

    script = shparse.parse(command)
    return script, admit(script, agent, cwd, text=command)


def git_dir_outside(got: Admitted, cwd: str, charter: str | None) -> str | None:
    # 0022, 0078, 228 S3: a git -C folder sits under the working folder or the charter root.
    for cmd in got.commands:
        target = cmd.git_dir.text if cmd.git_dir is not None else cwd
        if not (
            _under(target, cwd) or (charter is not None and _under(target, _abs(charter, cwd)))
        ):
            return f"Refused: git -C {target} is outside {cwd} and the charter root."
    return None


def _passed(got: Admitted | Refusal) -> TypeGuard[Admitted]:
    from lib.admit import Admitted  # 228 S3: admit imports this module.

    return isinstance(got, Admitted)


def _refused(got: Admitted | Refusal) -> Refusal | None:
    from lib.admit import Refusal  # 228 S3: admit imports this module.

    return got if isinstance(got, Refusal) else None


def admitted(command: str, agent: str, cwd: str) -> bool:
    return _passed(_admission(command, agent, cwd)[1])


def refusal_text(refusal: Refusal, constant: str | None = None) -> str:
    # 228 S3, R6: a kept constant byte-identical, then the grammar's reason at its quoted span.
    detail = f"Refused: {refusal.reason}, at `{refusal.text}`."
    return f"{constant} {detail}" if constant else detail


def refused_at(constant: str, reason: str, quoted: str) -> str:
    # 228 S3: a check after admission names what it refused, as refusal_text does.
    return f"{constant} Refused: {reason}, at `{quoted}`."


def refused_command(script: Script, refusal: Refusal) -> Command | None:
    # 228 S3: the innermost parsed command holding the refused span.
    start, end = refusal.span
    for cmd, _ in shparse.walk(script):
        if cmd.span[0] <= start and end <= cmd.span[1]:
            return cmd
    return None


def refused_word(cmd: Command | None, refusal: Refusal) -> Word | None:
    start, end = refusal.span
    for word in cmd.words if cmd is not None else []:
        if (word.span[0] <= start and end <= word.span[1]) or (
            start <= word.span[0] and word.span[1] <= end
        ):
            return word
    return None


def rewritten(word: Word | None) -> bool:
    # 228 S3: a word bash rewrites before the command runs, $'...' and $"..." included.
    return word is not None and (
        word.literal is None
        or any(isinstance(p, Literal) and p.quoted in ("$'", '$"') for p in word.parts)
    )


def literal_tokens(cmd: Command | None) -> list[str]:
    return [w.literal if w.literal is not None else w.raw for w in cmd.words] if cmd else []


@dataclass(frozen=True)
class CoderCall:
    # 228 S3b: one parse and one coder admission per hook call; passed marks a consumed pass.
    script: shparse.Script
    command: str
    cwd: str
    agent: str
    got: Admitted | Refusal
    passed: bool


# 228 S3b, 233: the last call judged; the router hands every check the same hook input object.
_CODER_CALL: list[tuple[dict[str, object], CoderCall]] = []


def coder_call(hook_input: dict[str, object]) -> CoderCall:
    # 228 S3b, 233: the coder's four checks share one answer, so one pass admits the call once.
    from lib.admit import Refusal, admit_role, role_for  # 228 S3: admit imports this module.

    command = hook_io.text(hook_io.tool_input(hook_input), "command")
    cwd = hook_io.text(hook_input, "cwd")
    agent = hook_io.agent(hook_input)
    for held, call in _CODER_CALL:
        if held is hook_input and (call.command, call.cwd, call.agent) == (command, cwd, agent):
            return call
    script = shparse.parse(command)
    got = admit_role(script, role_for("coder"), cwd, text=command)
    passed = (
        isinstance(got, Refusal)
        and os.path.isabs(cwd)
        and passes.pass_admits(project_root(cwd), agent, command, cwd, hook_input)
    )
    call = CoderCall(script, command, cwd, agent, got, passed)
    _CODER_CALL[:] = [(hook_input, call)]
    return call


def coder_refusal(call: CoderCall) -> str | None:
    # 228 S3b: None when admitted or a pass admitted it; else the kept constant, then the grammar.
    refused = _refused(call.got)
    if refused is None or call.passed:
        return None
    return refusal_text(refused, coder_constant(call.script, refused, call.cwd))


# 228 S3b, SA-7: the constant each refused class showed the coder before, by command word.
_CODER_CONSTANTS: tuple[tuple[frozenset[str], str], ...] = (
    (NETWORK_TOOLS - {"claude"}, R_NETWORK),
    (shell.ARCHIVE_CMDS, shell.R_ARCHIVE),
    (shell.SHELL_VAR_CMDS | {"set"}, shell.R_SHELL_VARS),
    (shell.SHELL_STATE_CMDS, shell.R_SHELL_STATE),
    (shell.WORKER_WRAPPERS, shell.R_INLINE),
    (frozenset({"find"}), shell.R_FIND_WRITE),
    (frozenset({"rsync"}), shell.R_RSYNC_REMOTE),
)
_CONSTRUCT_PARTS = (shparse.CommandSub, shparse.ProcSub, shparse.Arith, shparse.Opaque)
_HYGIENE_PARTS = (Param, shparse.BraceList, Tilde)


def _parse_base(script: Script, cwd: str) -> str:
    # 228 S3b: the folder a leading `cd <absolute path> &&` moves to, read from the parse.
    first = script.items[0] if script.items else None
    cmd = first.commands[0] if isinstance(first, Pipeline) and len(first.commands) == 1 else None
    words = [w.literal for w in cmd.words] if isinstance(cmd, Command) else []
    joined = script.separators[:1] == ["&&"] and len(script.items) > 1
    if joined and len(words) == 2 and words[0] == "cd" and os.path.isabs(words[1] or ""):
        return str(words[1])
    return cwd if os.path.isabs(cwd) else "/"


def coder_constant(script: Script, refused: Refusal, cwd: str) -> str | None:
    # 228 S3b: the class of the refused node, read from the parse: a prefix, a redirect, a
    # construct, an expansion, then the command word; never the command text.
    if "Next:" in refused.reason:
        return None  # 228 S3b: the grammar quoted a kept constant (0164, 0196) as its reason.
    cmd = refused_command(script, refused)
    start, _ = refused.span
    if cmd is None or any(r.span[0] <= start < r.span[1] for r in cmd.redirects):
        return shell.R_UNSUPPORTED
    if any(a.span[0] <= start < a.span[1] for a in cmd.assignments):
        return shell.R_ENV
    word = refused_word(cmd, refused)
    parts = word.parts if word is not None else []
    if any(isinstance(p, _CONSTRUCT_PARTS) for p in parts):
        return shell.R_UNSUPPORTED
    dollar = any(isinstance(p, Literal) and p.quoted in ("$'", '$"') for p in parts)
    hygiene = dollar or any(isinstance(p, _HYGIENE_PARTS) for p in parts)
    if hygiene and word is not None and word is not cmd.words[0]:
        return shell.R_HYGIENE
    head = cmd.words[0].literal if cmd.words else None
    if head is None:
        return shell.R_VARIABLE if cmd.words else shell.R_ENV
    family = shell.command_family(head)
    if family == "claude" or shell.runs_claude([head], _parse_base(script, cwd)):
        return shell.R_CLAUDE_PATH
    if family == shell.CONFINE:
        return shell.R_CONFINE_FORM
    if "/" in head and os.path.dirname(head) not in shell._TRUSTED_BIN:
        return shell.R_UNTRUSTED_PATH
    named = next((c for names, c in _CODER_CONSTANTS if family in names), None)
    return named or (R_CODER_GIT if family == "git" else R_CODER_TABLE)


def lead_cd(got: Admitted) -> tuple[AdmittedCommand | None, tuple[AdmittedCommand, ...]]:
    # 228 S3b: the one leading cd admit allows, apart from the commands after it.
    first = got.commands[0] if got.commands else None
    if first is not None and first.family == "cd" and first.cd_target is not None:
        return first, got.commands[1:]
    return None, got.commands


def coder_base(call: CoderCall, got: Admitted) -> str:
    # 228 S3b, O6: replaces chain_bases; a leading cd moves the rest only when every join is &&.
    lead, _ = lead_cd(got)
    joins = set(call.script.separators) - {""}
    if lead is None or lead.cd_target is None or not joins <= {"&&"}:
        return call.cwd
    return os.path.normpath(lead.cd_target.text)


def admitted_words(script: shparse.Script, done: AdmittedCommand) -> list[Word]:
    # 228 S3b: the parsed words of an admitted command from its command word on, past wrappers.
    cmd = next((c for c, _ in shparse.walk(script) if c.span == done.span), None)
    words = list(cmd.words) if cmd is not None else []
    at = next((i for i, w in enumerate(words) if w.span == done.word.span), len(words))
    return words[at:]


def admitted_tokens(script: shparse.Script, done: AdmittedCommand) -> list[str]:
    return [w.literal if w.literal is not None else w.raw for w in admitted_words(script, done)]


def claude_word(done: AdmittedCommand, base: str) -> bool:
    # issue 55, 228 S3b: the wrapper, the command word or node's script runs the claude binary.
    words = [w.text for w in done.wrappers[:1]] + [done.word.text]
    words += [done.script.text] if done.family == "node" and done.script else []
    return any(shell.runs_claude([w], base) for w in words)


def _scope_paths(command: str, cwd: str) -> tuple[str, ...]:
    # 0023, 0224, 228 S3: an admitted command's typed writes, folders and git dirs; an
    # unadmitted one is judged by its own repo alone, its text never read.
    script, got = _admission(command, "main", cwd)
    return tuple(_admitted_targets(script, got, cwd)) if _passed(got) else ()


def _admitted_targets(script: Script, got: Admitted, cwd: str) -> list[str]:
    # issue 30, 76, 228 S3: write operands and redirect targets, cd and chdir folders, and the
    # -C, --git-dir and --work-tree folders of a git command that writes.
    redirects = {n.target.span for n in shparse.nodes(script) if isinstance(n, Redirect)}
    base = cwd
    found: list[str | None] = []
    for cmd in got.commands:
        # issue 76: redirects and a wrapper's own output open in base; the command's in here.
        opens = [w for w in cmd.writes if w.span in redirects or w.span[1] <= cmd.word.span[0]]
        found += [_anchor(w.text, base) for w in opens]
        here = base
        if cmd.cd_target is not None:
            here = _anchor(cmd.cd_target.text, base) or base
            found.append(here)
            if cmd.family == "cd":
                base = here
                continue
        found += [_anchor(w.text, here) for w in cmd.writes if w not in opens]
        sub = cmd.subcommand.text if cmd.subcommand is not None else ""
        if cmd.family == "git" and (sub not in READ_ONLY_GIT or sub == "worktree"):
            found += [cmd.git_dir.text] if cmd.git_dir is not None else []
            found += [_anchor(r.text, here) for r in cmd.reads]
            opts = [o.text for o in cmd.options if o.text.startswith(_GIT_DIR_OPTS)]
            found += [_anchor(o.split("=", 1)[1], here) for o in opts]
    return [t for t in dict.fromkeys(found) if t]


def _write_dirs(tool: str, tool_input: dict[str, object], cwd: str) -> list[str]:
    if tool in WRITE_TOOLS:
        raw = str(tool_input.get("file_path") or tool_input.get("notebook_path") or "")
        return [_abs(raw, cwd)] if raw else []
    if tool == "Bash":
        return list(_scope_paths(str(tool_input.get("command") or ""), cwd))
    return []


def _marked_repo(cwd: str, tool: str, tool_input: dict[str, object]) -> Path | None:
    # 0023, issue 30: a train in the cwd repo or in any repo the call writes into counts.
    # 0224, 228 S3: the cwd and the admitted targets only; every one is read, none past a cap.
    seen: set[str] = set()
    for path in [cwd, *_write_dirs(tool, tool_input, cwd)]:
        while path and not os.path.isdir(path) and os.path.dirname(path) != path:
            path = os.path.dirname(path)
        if not os.path.isabs(path) or path in seen:
            continue
        seen.add(path)
        root = project_root(path)
        if os.path.lexists(train_marker(root)):
            return root
    return None


def moved_relative(
    tool: str, tool_input: dict[str, object], cwds: tuple[str, str], judged: str
) -> str | None:
    # issue 188: what a moved bound agent names relatively or leaves to its shell's folder.
    if tool in {"Grep", "Glob"} and not os.path.isabs(str(tool_input.get("path") or "")):
        return f"{tool} with no absolute path"
    for key in ("file_path", "notebook_path", "path"):
        value = tool_input.get(key)
        if isinstance(value, str) and value and not os.path.isabs(value):
            return value
    if tool != "Bash":
        return None
    command = str(tool_input.get("command") or "")
    script = shparse.parse(command)
    holes = shparse.opaque(script)
    if holes:
        return command[holes[0].span[0] : holes[0].span[1]]
    commands = [cmd for cmd, _ in shparse.walk(script)]
    if _starts_in(script, commands, judged):
        return None  # issue 188: the shell starts in the judged folder itself.
    loose = False
    for cmd in commands:
        found, plain = _relative_word(cmd, cwds)
        if found is not None:
            return found
        loose = loose or plain
    # issue 188: a command with a bare word or no absolute path runs only as an admitted read.
    if loose and not admitted(command, "foreign", judged):
        return "a command that is not a read and does not name every path absolutely"
    return None


def _starts_in(script: Script, commands: list[Command], judged: str) -> bool:
    # issue 188, 228 S3: one leading `cd <judged> &&` and no other folder change.
    head = script.items[0] if script.items else None
    first = head.commands[0] if isinstance(head, Pipeline) and len(head.commands) == 1 else None
    words = literal_tokens(first) if isinstance(first, Command) else []
    if script.separators[:1] != ["&&"] or len(words) != 2 or words[0] != "cd":
        return False
    moves = [
        c
        for c in commands
        if literal_tokens(c)[:1] and _base(literal_tokens(c)[0]) in {"cd", "pushd", "popd"}
    ]
    return len(moves) == 1 and os.path.normpath(words[1]) == os.path.normpath(judged)


def _home_word(word: Word) -> str | None:
    # issue 188, 228 S3: all Literal parts, or a leading ~ or bare $HOME then Literals; else None.
    head, rest = (word.parts[0], word.parts[1:]) if word.parts else (None, [])
    if not all(isinstance(p, Literal) for p in rest):
        return None
    tail = "".join(p.text for p in rest if isinstance(p, Literal))
    if isinstance(head, Literal) or head is None:
        return (head.text if head is not None else "") + tail
    if isinstance(head, Tilde):
        return os.path.expanduser(f"~{head.user}") + tail
    if isinstance(head, Param) and head.name == "HOME" and not head.op:
        return str(Path.home()) + tail
    return None


def _relative_word(cmd: Command, cwds: tuple[str, str]) -> tuple[str | None, bool]:
    # issue 188, 228 S3: (refused word, needs the read grammar) for one parsed command: a
    # relative redirect, folder, verb, write operand or module run, or an expanding word.
    for redirect in cmd.redirects:
        target = redirect.target.literal
        if redirect.op in ("<<", "<<-"):
            continue
        if target is None:
            return redirect.target.raw, False
        if redirect.op in (">&", "<&") and (target.isdigit() or target == "-"):
            continue
        if not os.path.isabs(target):
            return target, False
    texts: list[str] = []
    for word in cmd.words:
        text = _home_word(word)
        if text is None:
            return word.raw, False
        texts.append(text)
    unwrapped = unwrap(texts) if texts else ([], [])
    if unwrapped is None:
        return " ".join(texts), False
    rest, options = unwrapped
    moved = _option_values(texts, options, WRAPPER_CHDIR)
    if (rel := next((m for m in moved if not os.path.isabs(m)), None)) is not None:
        return rel, False
    if not rest:
        return None, False
    verb, args = rest[0], rest[1:]
    if "/" in verb and not os.path.isabs(verb):
        return verb, False
    if _base(verb) in {"cd", "pushd"}:
        dest = [a for a in args if not a.startswith("-")][:1]
        if dest and not os.path.isabs(dest[0]):
            return dest[0], False
        return None, not dest
    found = _cd_relative_target(rest, "/")
    if found is not None:
        return found, False
    if _INTERPRETER.fullmatch(_base(verb)) and "-m" in args:
        return f"{verb} -m", False
    if _base(verb) == "uniq":
        # issue 188, 204: uniq writes its second operand, which the read grammar admits.
        operands = split_options("uniq", args)[0]
        if len(operands) > 1 and not os.path.isabs(operands[1]):
            return operands[1], False
    named, plain = False, False
    for arg in args:
        text = (arg.split("=", 1)[1] if "=" in arg else "") if arg.startswith("-") else arg
        if not text:
            continue
        if os.path.isabs(text):
            named = True
            continue
        here = any(os.path.lexists(os.path.join(c, text)) for c in cwds)
        if "/" in text or set("*?[") & set(text) or text in {".", ".."} or here:
            return text, False
        plain = True
    return None, plain or not named


def _train_scoped(cwd: str, tool: str, tool_input: dict[str, object]) -> bool:
    # 0035: an unknown repo (no absolute cwd) is judged as if a train runs there.
    return not os.path.isabs(cwd) or _marked_repo(cwd, tool, tool_input) is not None


def _ours(raw_agent: str) -> bool:
    prefix, sep, _ = raw_agent.partition(":")
    return bool(sep) and prefix in (*AGENT_NAMESPACES, TEST_NAMESPACE)


def _foreign_bash(
    command: str,
    cwd: str,
    repo: Path,
    agent: str,
    charter: str | None,
    hook_input: dict[str, object],
) -> Decision:
    # 0100, 228 S3: a foreign agent's Bash in a run is admitted as a read, else refused at its span.
    got = _admission(command, "foreign", cwd)[1]
    train = R_UNKNOWN_TRAIN.format(agent=agent, marker=train_marker(repo), repo=repo)
    refused = _refused(got)
    raw_agent = hook_io.raw_agent(hook_input)
    if refused is not None and passes.pass_admits(repo, raw_agent, command, cwd, hook_input):
        return _allow()  # 233: a sealed pass for this exact call, consumed and recorded.
    if refused is not None:
        return _block(refusal_text(refused, train))
    outside = git_dir_outside(got, cwd, charter) if _passed(got) else None
    return _allow() if outside is None else _block(f"{train} {outside}")


def _unknown_decision(
    raw_agent: str,
    agent: str,
    cwd: str,
    tool: str,
    tool_input: dict[str, object],
    charter: str | None,
    hook_input: dict[str, object],
) -> Decision:
    # 0023, 0100: a foreign agent reads only while a train is active; a daedalus name never acts.
    if _ours(raw_agent):
        return _block(R_UNKNOWN.format(agent=agent))
    if not os.path.isabs(cwd):
        return _block(R_NO_CWD)
    # 0010: the data dir is Daedalus's own integrity, refused to every agent train or not.
    raw_path = str(tool_input.get("file_path") or tool_input.get("notebook_path") or "")
    if tool in WRITE_TOOLS and _data_dir_path(_abs(raw_path, cwd), cwd):
        return _block(R_DATA_DIR)
    command = str(tool_input.get("command") or "") if tool == "Bash" else ""
    if command and (_data_dir_write(command) or _cd_data_dir_git(command)):
        return _block(R_DATA_DIR)
    repo = _marked_repo(cwd, tool, tool_input)
    # 0224: judged by its own repo; a command's text never scopes the call.
    if repo is None:
        return _allow()
    if tool == "Bash":
        return _foreign_bash(command, cwd, repo, agent, charter, hook_input)
    return _block(R_UNKNOWN_TRAIN.format(agent=agent, marker=train_marker(repo), repo=repo))


def normalize_agent(agent_type: str) -> str:
    prefix, sep, name = agent_type.partition(":")
    test_ns = prefix == TEST_NAMESPACE and os.environ.get("DAEDALUS_LIVE_TEST") == "1"
    if sep and (prefix in AGENT_NAMESPACES or test_ns) and name:
        return name
    return agent_type


def decide(hook_input: dict[str, object], config: Config) -> Decision:
    raw_agent = hook_io.raw_agent(hook_input)
    agent = hook_io.agent(hook_input)
    tool = str(hook_input.get("tool_name") or "")
    cwd = str(hook_input.get("cwd") or "")
    raw_input = hook_input.get("tool_input")
    tool_input: dict[str, object] = raw_input if isinstance(raw_input, dict) else {}
    # m4, 0106: the operator's own session is bare main with no agent_id; it is never denied.
    operator = raw_agent == "main" and not hook_input.get("agent_id")
    if tool in CREDENTIAL_TOOLS:
        reason = path_reason(tool, tool_input, cwd)
        if reason and operator:
            # Main never prompted (amends 0106): allow with context, never ask, for main.
            return _with_agent(_main_warn(WARN_CREDENTIAL, reason), agent)
        return Decision(reason is None, reason, agent)
    # 0035: outside a train, main and foreign agents carry only the read deny above.
    if not policed_outside_train(raw_agent) and not _train_scoped(cwd, tool, tool_input):
        # 0130, D.5: main is warned here only when the hook calls the jail, during a train.
        roots = _main_excluded(tool, tool_input, cwd, config) if operator else _allow()
        return _with_agent(roots, agent)
    credential = _credential_reason(tool, tool_input, cwd)
    if credential and operator:
        warning = WARN_CREDENTIAL_WRITE if tool in WRITE_TOOLS else WARN_CREDENTIAL
        # Main never prompted (amends 0106): allow with context, never ask, for the main session.
        return _with_agent(_main_warn(warning, credential), agent)
    if credential:
        return Decision(False, credential, agent)
    if agent == "main" and raw_agent != "main":
        return Decision(False, R_NAMESPACED_MAIN, agent)
    # m4: only the orchestrator thread arrives without an agent_id.
    if agent == "main" and hook_input.get("agent_id"):
        return Decision(False, R_SUBAGENT_MAIN, agent)
    if agent == "main":
        decision = _decide_main(tool, cwd, tool_input)
        if decision.allow and operator:
            decision = _main_excluded(tool, tool_input, cwd, config)
    elif agent in KNOWN_AGENTS:
        # 0044: a Daedalus agent's calls run its agent file's hooks, never this function.
        decision = _block(R_ROUTED.format(agent=agent))
    elif tool == "Bash" and (gh := _gh_gate(agent, cwd, str(tool_input.get("command") or ""))):
        decision = _block(gh)
    else:
        charter = str(config.charter_root) if config.charter_root else None
        decision = _unknown_decision(raw_agent, agent, cwd, tool, tool_input, charter, hook_input)
    return _with_agent(decision, agent)


def _with_agent(decision: Decision, agent: str) -> Decision:
    return Decision(decision.allow, decision.reason, agent, decision.warn)


def integrity_reason(tool: str, tool_input: dict[str, object], cwd: str) -> str | None:
    # 0053, issue 75: no absolute cwd, a write into .git or the data folder, Bash included.
    is_write = tool in WRITE_TOOLS
    if not (is_write or tool == "Bash"):
        return None
    if not os.path.isabs(cwd):
        return R_NO_CWD
    if not is_write:
        command = str(tool_input.get("command") or "")
        if _data_dir_write(command):
            return R_DATA_DIR
        return R_DATA_DIR_GIT if _cd_data_dir_git(command) else None
    path = _abs(str(tool_input.get("file_path") or tool_input.get("notebook_path") or ""), cwd)
    if ".git" in path.split(os.sep) or ".git" in os.path.normpath(path).split(os.sep):
        return R_DOTGIT
    return R_DATA_DIR if _data_dir_path(path, cwd) else None


def _decide_main(tool: str, cwd: str, tool_input: dict[str, object]) -> Decision:
    # Main never prompted (amends 0105, 0106): allow with context, never ask, for the main session.
    command = str(tool_input.get("command") or "")
    raw_path = str(tool_input.get("file_path") or tool_input.get("notebook_path") or "")
    is_write = tool in WRITE_TOOLS
    path = _abs(raw_path, cwd)
    integrity = integrity_reason(tool, tool_input, cwd)
    if integrity == R_NO_CWD:
        return _main_warn(WARN_NO_CWD, R_NO_CWD)
    if integrity == R_DOTGIT:
        return _main_warn(WARN_DOTGIT.format(path=path), R_DOTGIT)
    if integrity is not None:
        return _main_warn(WARN_DATA_DIR, integrity)
    if tool == "Bash":
        # 8.5, 0106: main meets the tripwires first, as warnings; regex fallback on no tokens.
        reason = _command_reason(command) or _gh_gate("main", cwd, command)
        reason = reason or (R_NESTED_CLAUDE if _nested_claude(command, cwd) else None)
        if reason:
            return _tripwire_warn(reason)
        # 228 S3, 0105, 0106: a command off main's table warns with the refusal, never blocks.
        refused = _refused(_admission(command, "main", cwd)[1])
        return _allow() if refused is None else _main_warn(WARN_COMMAND, refusal_text(refused))
    train = _main_write_train(path, cwd) if is_write else None
    if train is not None:
        return _warn(R_MAIN_TRAIN_WARN.format(train=train, path=path))
    if tool in dispatch_binding.DISPATCH_TOOLS:
        reason = dispatch_binding._dispatch_reason(tool_input, cwd, main=True)
        if reason:
            # Main never prompted (amends 0106): the dispatch runs with the skipped invariant named.
            return _warn(WARN_DISPATCH.format(reason=reason))
    return _allow()


def _nested_claude(command: str, cwd: str) -> bool:
    # audit A7-1, issue 55, 228 S3: an admitted command's own words; refused, the old reader.
    segments = _admitted_segments(command, cwd)
    if segments is None:
        return bool(_CLAUDE_WORD.search(command))
    return any(seg and runs_claude(seg, cwd) for seg in segments)


# 0136, D.5: the excluded roots rule; checks/excluded_roots.py and the main session share it.
R_EXCLUDED_PATH = (
    "{what} names {path}, inside the excluded root {root} (D.2.1). "
    "Next: keep files under that root out of git, gh and redirects."
)
R_EXCLUDED_TREE = (
    "{what} would take in the excluded root {root}, which git does not ignore (D.5). "
    "Next: name the paths to stage, or add the root to .gitignore."
)
WARN_EXCLUDED = (
    "This command would put a file from a folder the project excludes into git, GitHub or a "
    "file write."
)
R_EXCLUDED_ICASE = (
    "{spec} makes git match paths in any letter case, so it can name a file in an excluded "
    "root under another spelling (issue 97). Next: spell each path in its exact case, without "
    ":(icase), the short :i: form, --icase-pathspecs or GIT_ICASE_PATHSPECS."
)
_ICASE_ENV = "GIT_ICASE_PATHSPECS"
R_EXCLUDED_UNSEEN = (
    "git stages, commits or stashes paths it reads through {source}, which the jail cannot see, "
    "so they may name a file in an excluded root (issue 121). Next: name each path on the git "
    "command line."
)
# 0224, 228 S4: a command off its table carries no typed path, so only its folder is judged.
R_EXCLUDED_STANDING = (
    "a command off the jail's table runs from {path}, inside the excluded root {root} (0224, "
    "D.5). Next: run it from a folder outside that root."
)
WARN_EXCLUDED_FAILED = "The excluded folders could not be resolved, so this command went unchecked."
# issue 121 (design 6): git options that read their paths from a file or stdin, with the
# shortest abbreviation git accepts for each.
_UNSEEN_OPTIONS = (("--pathspec-from-file", 11), ("--stdin", 3), ("--index-info", 7))
# D.5: the subcommands that stage each named folder whole; a short option in mFC ends a cluster.
_STAGING_GIT = frozenset({"add", "stage", "stash"})
_CLUSTER_TAKERS = "mFC"
ExcludedRoots = Callable[[], tuple[ExcludedRoot, ...]]


def excluded_roots_for(cwd: str, load: Callable[[], Config]) -> ExcludedRoots:
    # D.2.1: resolved once per call and only when a command reaches git, gh or a redirect.
    cache: list[tuple[ExcludedRoot, ...]] = []

    def roots() -> tuple[ExcludedRoot, ...]:
        if not cache:
            cache.append(resolve_excluded_roots(load(), project_root(cwd)))
        return cache[0]

    return roots


def _work_tree(path: str) -> str:
    for folder in (Path(path), *Path(path).parents):
        if (folder / ".git").exists():
            return str(folder)
    return path


def _active_roots(roots: tuple[ExcludedRoot, ...], tree: str) -> list[ExcludedRoot]:
    # D.5: a repository inside a root is another repo; a linked worktree gets each root again.
    main = git_root(tree)
    out = [r for r in roots if not _under(tree, r.path)]
    if main is not None and os.path.normpath(main) != os.path.normpath(tree):
        for root in roots:
            rel = os.path.relpath(root.path, main)
            if rel != "." and not rel.startswith(".." + os.sep) and rel != "..":
                out.append(ExcludedRoot(os.path.join(tree, rel), root.ignored))
    return out


def _root_of(path: str, roots: list[ExcludedRoot]) -> ExcludedRoot | None:
    return next((r for r in roots if _under(path, r.path)), None)


def _candidates(raw: str) -> list[str]:
    # D.5: an option value, a gh @file and an update-index cacheinfo path each name a path.
    out = [raw, raw.split("=", 1)[1] if "=" in raw else "", raw.rsplit(",", 1)[-1]]
    out += [c[1:] for c in out if c.startswith("@")]
    return [c for c in dict.fromkeys(out) if c and not c.startswith("-")]


def _pathspec(spec: str, base: str, tree: str) -> tuple[str, bool] | None:
    # D.5: pathspec magic; top reads from the work tree, exclude names nothing, a glob is a folder.
    if spec.startswith((":!", ":^")):
        return None
    if spec.startswith(":/"):
        base, spec = tree, spec[2:]
    elif spec.startswith(":(") and ")" in spec:
        words, spec = spec[2:].split(")", 1)
        magic = set(words.split(","))
        if "exclude" in magic:
            return None
        base = tree if "top" in magic else base
    cut = min((spec.index(c) for c in _GLOB_CHARS if c in spec), default=-1)
    if cut < 0:
        return os.path.normpath(_abs(spec, base)), False
    folder = spec[:cut].rsplit("/", 1)[0] if "/" in spec[:cut] else ""
    return os.path.normpath(_abs(folder or ".", base)), True


def _option_flags(options: tuple[Typed, ...]) -> set[str]:
    # D.5, 228 S4: an admitted git call's long options by name and short ones by letter.
    flags: set[str] = set()
    for option in options:
        if option.text.startswith("--"):
            flags.add(option.text.split("=", 1)[0])
            continue
        cluster = option.text[1:]
        taker = next((n for n, c in enumerate(cluster) if c in _CLUSTER_TAKERS), len(cluster))
        flags |= set(cluster[: taker + 1])
    return flags


def _whole_tree(sub: str, flags: set[str]) -> tuple[bool, bool]:
    # D.5: (takes the whole work tree, takes ignored files too) for add -A, commit -a, stash -u.
    if sub in {"add", "stage"}:
        whole = bool({"A", "--all", "--no-ignore-removal", "--pathspec-from-file"} & flags)
        return whole, bool({"f", "--force"} & flags)
    if sub == "commit":
        return bool({"a", "--all", "--pathspec-from-file"} & flags), False
    if sub == "stash":
        every = bool({"a", "--all"} & flags)
        return every or bool({"u", "--include-untracked", "--pathspec-from-file"} & flags), every
    return False, False


def _unseen(done: AdmittedCommand) -> str | None:
    # issue 121 (design 6), 228 S4: an admitted option that feeds git paths from a file or stdin.
    for option in done.options:
        for name, least in _UNSEEN_OPTIONS:
            if _long_matches(option.text, name, least):
                return name
    return None


def _names_icase(done: AdmittedCommand) -> bool:
    # issue 97, 228 S4: an admitted export or bare assignment sets GIT_ICASE_PATHSPECS for git.
    names = [*done.assignments, *(done.texts if done.family == "export" else ())]
    return any(t.text.split("=", 1)[0].removesuffix("+") == _ICASE_ENV for t in names)


def _excluded_git(
    done: AdmittedCommand, here: str, roots: ExcludedRoots, icase: bool
) -> str | None:
    # 0136, D.5, 228 S4: a git call that is no read: its folder, file values and pathspecs.
    if done.git_read:
        return None
    sub = done.subcommand.text if done.subcommand is not None else ""
    where = done.git_dir.text if done.git_dir is not None else here
    tree = _work_tree(where)
    active = _active_roots(roots(), tree)
    if not active:
        return None
    if icase:
        return R_EXCLUDED_ICASE.format(spec=_ICASE_ENV)
    unseen = _unseen(done)
    if unseen is not None:
        return R_EXCLUDED_UNSEEN.format(source=unseen)
    what = f"git {sub}"
    # 228 S4: --git-dir= and --work-tree= keep their value inside the typed option word.
    values = [o.text.split("=", 1)[1] for o in done.options if o.text.startswith(_GIT_DIR_OPTS)]
    files = [
        _abs(v, base) for v in (*(r.text for r in done.reads), *values) for base in (where, here)
    ]
    for path in [where, *files]:
        hit = _root_of(path, active)
        if hit is not None:
            return R_EXCLUDED_PATH.format(what=what, path=os.path.normpath(path), root=hit.path)
    whole, force = _whole_tree(sub, _option_flags(done.options))
    spans = [tree] if whole else []
    for spec in done.pathspecs:
        for cand in _candidates(spec.text):
            found = _pathspec(cand, where, tree)
            if found is None:
                continue
            target, glob = found
            hit = _root_of(target, active)
            if hit is not None:
                return R_EXCLUDED_PATH.format(what=what, path=target, root=hit.path)
            if sub in _STAGING_GIT or glob:
                spans.append(target)
    for span in spans:
        for root in active:
            if _under(root.path, span) and (force or not root_ignored(root, Path(tree))):
                return R_EXCLUDED_TREE.format(what=what, root=root.path)
    return None


def _excluded_gh(done: AdmittedCommand, here: str, roots: ExcludedRoots) -> str | None:
    # D.5, 228 S4: a typed gh value names a path when absolute, holding a slash, or on disk.
    active = _active_roots(roots(), _work_tree(here))
    for value in (*done.reads, *done.texts):
        for cand in _candidates(value.text):
            path = os.path.normpath(_abs(cand, here))
            if os.path.isabs(cand) or "/" in cand or os.path.lexists(path):
                hit = _root_of(path, active)
                if hit is not None:
                    return R_EXCLUDED_PATH.format(what="gh", path=path, root=hit.path)
    return None


def _excluded_writes(
    done: AdmittedCommand, bases: tuple[str, str], roots: ExcludedRoots
) -> str | None:
    # D.5, 228 S4: a typed write path or redirect target, opened from the shell or the command.
    for write in done.writes:
        for base in bases:
            path = os.path.normpath(_abs(write.text, base))
            hit = _root_of(path, list(roots()))
            if hit is not None:
                return R_EXCLUDED_PATH.format(what=done.word.text, path=path, root=hit.path)
    return None


def _shell_built(done: AdmittedCommand) -> bool:
    # 228 S4, SA-2: admit types every judged path literal; a glob or ~ in one fails closed.
    judged = [*done.writes, done.git_dir, done.cd_target]
    if done.family == "git" and not done.git_read:
        judged += [*done.pathspecs, *done.reads]
    # 257: an option main's grammar typed opaque may turn any git operand into a pathspec.
    judged += [*done.options] if done.family == "git" else []
    return any(t is not None and t.glob for t in judged)


def excluded_root_reason(
    got: Admitted | Refusal, cwd: str, roots: ExcludedRoots, writes: bool = True
) -> str | None:
    # 0136, D.5, 228 S4: each admitted command's typed git folder, file values, pathspecs and
    # writes; a refused command is judged by its standing folder alone (0224), never its text.
    if not _passed(got):
        hit = _root_of(cwd, _active_roots(roots(), _work_tree(cwd)))
        return None if hit is None else R_EXCLUDED_STANDING.format(path=cwd, root=hit.path)
    base, icase = cwd, False
    for done in got.commands:
        if done.family == "cd" and done.cd_target is not None:
            base = _abs(done.cd_target.text, base)
            continue
        here = _abs(done.cd_target.text, base) if done.cd_target is not None else base
        icase = icase or _names_icase(done)
        reason: str | None = None
        if _shell_built(done) and roots():
            reason = R_EXCLUDED_UNSEEN.format(source="a shell expansion")
        elif done.family == "git":
            reason = _excluded_git(done, here, roots, icase)
        elif done.family == "gh":
            reason = _excluded_gh(done, here, roots)
        if reason is None and writes and done.writes:
            reason = _excluded_writes(done, (base, here), roots)
        if reason is not None:
            return reason
    return None


def held_admission(hook_input: dict[str, object]) -> Admitted | Refusal:
    # 228 S4: the admission the agent's own chain judged, the coder's held call included; a
    # call its chain let through that its role refuses is typed by main's wider grammar.
    from lib.admit import role_for  # 228 S3: admit imports this module.

    agent = hook_io.agent(hook_input)
    command = hook_io.text(hook_io.tool_input(hook_input), "command")
    cwd = hook_io.text(hook_input, "cwd")
    if role_for(agent).coder:
        got = coder_call(hook_input).got
    else:
        got = _admission(command, agent, cwd)[1]
    return got if _passed(got) else _admission(command, "main", cwd)[1]


def _main_excluded(tool: str, tool_input: dict[str, object], cwd: str, config: Config) -> Decision:
    # 0130, D.5: main meets the excluded roots rule as a warning in context, never a refusal.
    command = str(tool_input.get("command") or "")
    if tool != "Bash" or not command or not os.path.isabs(cwd):
        return _allow()
    try:
        got = _admission(command, "main", cwd)[1]
        reason = excluded_root_reason(got, cwd, excluded_roots_for(cwd, lambda: config))
    except (ConfigError, OSError, subprocess.SubprocessError) as exc:
        return _main_warn(WARN_EXCLUDED_FAILED, str(exc))
    return _main_warn(WARN_EXCLUDED, reason) if reason else _allow()
