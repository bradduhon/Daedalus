# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import fnmatch
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
    R_CREDENTIAL,
    R_CREDENTIAL_TREE,
    R_ENV_FILE,
    R_ENV_FILE_TREE,
    R_ENV_WALK_CAP,
    R_ENV_WHITELIST_WRITE,
    R_IGNORE_WHITELIST,
    R_REPLY_KEY,
    R_REPLY_KEY_TREE,
    R_TRACKED_SECRET,
    R_TRACKED_UNKNOWN,
    REPLY_KEY_NAME,
    env_file_hit,
    env_name,
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
from lib.credential_paths import anchor as _anchor
from lib.credential_paths import credential_hit as _credential_hit
from lib.credential_paths import credential_roots as _credential_roots
from lib.credential_paths import store_rest as _store_rest
from lib.gh_policy import (
    CONDUCTOR_GH,
    GhArgs,
    GhFlag,
    _push_reason,
    allowlist_applies,
    gh_reason,
)
from lib.ledger import LedgerError, resolve_ledger
from lib.manifest import Manifest, ManifestError, extension_hit, path_hit
from lib.manifest import load as load_manifest
from lib.repo_root import checkout_git_dir, git_root
from lib.shell import (
    _DEFAULT_BRANCHES,
    _GLOB_CHARS,
    _HOME,
    _REPO_SCRIPTS,
    _VALUE_LONG_NEXT,
    GIT_PLUMBING_REMOTE,
    R_CLEAN,
    R_DATA_DIR_GIT,
    R_DEFAULT_BRANCH,
    R_DESTRUCTIVE,
    R_FORCE_PUSH,
    R_STASH_UNTRACKED,
    READ_ONLY_GIT,
    WRAPPER_CHDIR,
    WrapperOption,
    _abs,
    _base,
    _git_split,
    _long_matches,
    _names_project_data,
    _pathspecs,
    _short_flags,
    _under,
    split_options,
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
R_CREDENTIAL_PARAM = (
    "{path} could be a credential path; the jail cannot resolve its variable. "
    "Next: spell the path out"
)
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
_DATA_DIR_DEFAULT = "/.claude/plugins/data/daedalus"
UNIT_WORKTREES = ".claude/worktrees"
# issue 188: the moved bound agent rule; module runs, fd words and the cd start form.
_INTERPRETER = re.compile(r"python[\d.]*|perl|ruby|node|nodejs|deno|bun|php")
# 266: the git subcommands that write the index, which the data folder check judges.
_INDEX_WRITES = frozenset({"add", "stage", "commit", "update-index"})


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
# 267: the read options whose next word is their value; the grammar and the tracked check share it.
_GIT_VALUED: dict[str, frozenset[str]] = {
    # 228 S3: --grep <value> as two words, beside the --grep=<value> prefix.
    # 266: --max-count in both forms, as -n is; admit types its value as text.
    "log": frozenset({"-n", "-S", "-G", "--grep", "--max-count"}),
    "grep": frozenset({"-e", "-A", "-B", "-C", "--max-depth"}),
    "blame": frozenset({"-L"}),
}
_GIT_GRAMMAR: dict[str, Callable[[list[str], str], bool]] = {
    "status": lambda a, _: _flags_ok(a, _STATUS_FLAGS, (), (r"-[sb]+",)),
    "log": lambda a, _: _flags_ok(
        a,
        frozenset({"--oneline", "--stat", "--name-only", "-p", "--no-merges", "--all"})
        | {"--pickaxe-regex", "--pickaxe-all"},
        (*_FORMAT, "--grep=", "--author=", "--max-count="),
        (r"-\d+", r"-n\d+", r"-[SG].+"),
        _GIT_VALUED["log"],
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
        _GIT_VALUED["grep"],
    ),
    "blame": lambda a, _: _flags_ok(
        a,
        frozenset({"-w", "-s", "-e", "-l", "--porcelain", "--line-porcelain"}),
        (),
        (r"-[CM]\d*", r"-L.+"),
        _GIT_VALUED["blame"],
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


def _gh_allowed(parsed: GhArgs) -> bool:
    words = parsed.words[:2]
    return len(words) == 2 and words[1] in GH_ALLOWED.get(words[0], frozenset())


_GH_PR_WRITES = frozenset({"create", "edit", "comment"})


def _gh_flags(parsed: GhArgs, *names: str) -> list[GhFlag]:
    # 228 tail: the admitted call's typed triple, gh_policy's one pflag typing (S4).
    return [f for f in parsed.flags if f.name in names]


def _gh_pr_write(parsed: GhArgs) -> bool:
    words = parsed.words[:2]
    return words[:1] == ["pr"] and words[1:2] != [] and words[1] in _GH_PR_WRITES


def _gh_repo_flag(parsed: GhArgs) -> bool:
    # I7: reads may name another repo; pr writes stay in the current one.
    return _gh_pr_write(parsed) and bool(_gh_flags(parsed, "-R", "--repo"))


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


def _gh_flag_values(parsed: GhArgs, long: str, short: str) -> list[str] | None:
    # 0078: `--x v`, `--x=v` and `-X v` only; an attached or bundled short form fails closed.
    found = _gh_flags(parsed, long, f"-{short}")
    return None if any(f.attached for f in found) else [f.value or "" for f in found]


def _charter_pr_create_ok(parsed: GhArgs, cwd: str, charter: str | None) -> bool:
    # 0078: one gh pr create on the declared charter root's origin, for this train's branch.
    if charter is None or parsed.words[:2] != ["pr", "create"]:
        return False
    repos = _gh_flag_values(parsed, "--repo", "R")
    heads = _gh_flag_values(parsed, "--head", "H")
    if repos is None or heads is None or len(repos) != 1 or len(heads) != 1:
        return False
    branch = _train_branch(cwd)
    if branch is None or heads[0] != branch:
        return False
    return repos[0] == _charter_slug(_abs(charter, cwd))


def _gh_body_file_ok(parsed: GhArgs, cwd: str) -> bool:
    if not _gh_pr_write(parsed):
        return True
    for flag in _gh_flags(parsed, "--body-file", "-F"):
        value = flag.value or ""
        # I7: stdin (-) and relative-to-elsewhere paths fail; realpath under the two homes only.
        if value in {"", "-"} or not (
            _under(_abs(value, cwd), f"{cwd}/docs/.tmp") or _under(_abs(value, cwd), "/tmp")
        ):
            return False
    return True


def _gh_write_reason(parsed: GhArgs) -> str | None:
    if not _gh_pr_write(parsed):
        return None
    if _gh_flags(parsed, "--body", "-b") or not _gh_flags(parsed, "--body-file", "-F"):
        return R_BODY_INLINE
    if parsed.words[1] == "edit" and _gh_flags(parsed, "--base", "-B"):
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


def _data_dir_target(path: str, cwd: str) -> bool:
    # 0010, 266: a typed path under a data folder, by its spelled name or through a link.
    norm = os.path.normpath(path)
    default = f"{_HOME}{_DATA_DIR_DEFAULT}"
    return any(_data_dir_path(p, cwd) or _under(p, default) for p in (norm, os.path.realpath(norm)))


def _data_dirs(folder: str, cwd: str) -> list[str]:
    # 266: the standing folder's project data folder, the command folder's where it exists, the
    # default under HOME and CLAUDE_PLUGIN_DATA, each as spelled and through its links.
    dirs = [str(project_data_dir(cwd))] if os.path.isabs(cwd) else []
    there = project_data_dir(folder) if os.path.isabs(folder) else None
    dirs += [str(there)] if there is not None and there.is_dir() else []
    dirs += [f"{_HOME}{_DATA_DIR_DEFAULT}", os.environ.get("CLAUDE_PLUGIN_DATA") or ""]
    dirs = [os.path.normpath(d) for d in dirs if os.path.isabs(d)]
    return list(dict.fromkeys([*dirs, *(os.path.realpath(d) for d in dirs)]))


_UNDECIDED = frozenset("[{")


def _wild_reach(parts: list[str], at: int, dirs: list[str], dots: bool) -> bool:
    # 266: by component: the fixed ones before the first wildcard lead a data folder's path,
    # and that wildcard can match its next component; a [ or { form fails closed.
    fixed = parts[:at]
    wild = parts[at]
    found = [d.split(os.sep) for d in dirs]
    # 266: another project's data folder right below, where one exists.
    below = [[*fixed, ".claude", "daedalus"], [*fixed, "daedalus"]]
    found += [c for c in below if c[-2] == ".claude" and os.path.isdir(os.sep.join(c))]
    for comps in found:
        if comps[: len(fixed)] != fixed or len(comps) == len(fixed):
            continue
        name = comps[len(fixed)]
        if _UNDECIDED & set(wild):
            return True
        lead = wild[: min((wild.index(c) for c in "*?" if c in wild), default=len(wild))]
        if (lead or dots or not name.startswith(".")) and name.startswith(lead):
            return True
    return False


def _data_dir_reach(path: str | None, folder: str, cwd: str, dots: bool = False) -> bool:
    # 266: a literal path under a data folder, or a wildcard path that can match one or a path
    # inside one; dots is True where a leading wildcard matches a dot name (a git pathspec).
    if path is None:
        return True  # 266: a part the hook cannot resolve fails closed.
    full = os.path.normpath(_abs(path, folder))
    parts = full.split(os.sep)
    at = next((i for i, p in enumerate(parts) if (_GLOB_CHARS | _UNDECIDED) & set(p)), -1)
    if at < 0:
        return _data_dir_target(full, cwd)
    if _data_dir_target(os.sep.join(parts[:at]) or os.sep, cwd):
        return True  # 266: the wildcard sits inside a data folder already.
    real = os.path.realpath(os.sep.join(parts[:at]) or os.sep).split(os.sep)
    dirs = _data_dirs(folder, cwd)
    return any(
        _wild_reach(p, len(p) - 1, dirs, dots) for p in ([*parts[: at + 1]], [*real, parts[at]])
    )


def _data_dir_ancestor(path: str, folder: str, cwd: str) -> bool:
    # 266: a proper ancestor of a data folder, spelled or through its links; a write to it
    # reaches the folder, since a removal, move, merge or recursive change takes the folder too.
    norm = os.path.normpath(path)
    heads = {norm, os.path.realpath(norm)}
    return any(
        d.startswith(h.rstrip(os.sep) + os.sep) for h in heads for d in _data_dirs(folder, cwd)
    )


def _git_dir_values(done: AdmittedCommand) -> list[str]:
    # 266: a --git-dir or --work-tree value, joined, or the typed read right after the option.
    items = sorted([*done.options, *done.reads, *done.texts, *done.pathspecs], key=lambda t: t.span)
    out: list[str] = []
    for at, item in enumerate(items):
        key, eq, value = item.text.partition("=")
        if item not in done.options or key not in {"--git-dir", "--work-tree"}:
            continue
        later = items[at + 1] if at + 1 < len(items) else None
        out += [value] if eq else [later.text] if later in done.reads else []
    return out


def _index_reason(done: AdmittedCommand, here: str, cwd: str) -> str | None:
    # 0010, 266: an index write from a folder the command moved to (cd, -C, --git-dir or
    # --work-tree) that sits in a data folder, or names a pathspec under one from there.
    git_cwd = _abs(done.git_dir.text, here) if done.git_dir is not None else here
    moved = [_abs(v, here) for v in _git_dir_values(done)]
    moved += [git_cwd] if git_cwd != cwd else []
    if not moved:
        return None
    if any(_data_dir_target(folder, cwd) for folder in moved):
        return R_DATA_DIR_GIT
    # 266: git's * matches a dot name, so a leading wildcard reaches .claude.
    reach = any(_data_dir_reach(p.text, git_cwd, cwd, dots=True) for p in done.pathspecs)
    return R_DATA_DIR_GIT if reach else None


# 266: families whose write to a folder removes, moves or changes everything under it.
_ANCESTOR_ALL = frozenset({"rm", "rmdir", "rsync", "chmod", "chown", "chgrp"})
# 266: families that put a file inside their destination folder unless -T or --exchange.
_ANCESTOR_SOURCES = frozenset({"mv", "cp", "ln", "install"})
_WHOLE_TARGET = frozenset({"-T", "--no-target-directory", "--exchange"})
_TARGET_DIR = frozenset({"-t", "--target-directory"})


def _ancestor_writes(done: AdmittedCommand) -> list[Typed]:
    # 266: the typed writes that take a folder whole: every write of a removing, moving or
    # recursive family; for mv, cp, ln and install all but the destination they write into.
    if done.family in _ANCESTOR_ALL:
        return list(done.writes)
    if done.family not in _ANCESTOR_SOURCES or not done.writes:
        return []
    names = {o.text.split("=", 1)[0] for o in done.options}
    if names & _WHOLE_TARGET:
        return list(done.writes)
    marks = [o.span for o in done.options if o.text.split("=", 1)[0] in _TARGET_DIR]
    writes = sorted(done.writes, key=lambda t: t.span)
    after = [w for w in writes if marks and w.span >= marks[0]]
    dest = after[0] if after else writes[-1]
    return [w for w in writes if w is not dest]


def _data_dir_holds(path: str | None, folder: str, cwd: str, whole: bool, family: str) -> bool:
    # 266: a path in or reaching a data folder; when the write takes its folder whole, a literal
    # proper ancestor too. A recursive rm of /, HOME or above is the delete tripwire's to name.
    if _data_dir_reach(path, folder, cwd):
        return True
    full = os.path.normpath(_abs(path or "", folder))
    if not whole or (_GLOB_CHARS | _UNDECIDED) & set(full):
        return False
    if family == "rm" and shell._rm_target_dangerous(full):
        return False
    return _data_dir_ancestor(full, folder, cwd)


def _data_dir_bash(command: str, cwd: str, agent: str) -> str | None:
    # 0010, 266: each command the role admits, by its typed writes, link sources and git
    # folders; a refused one is judged by its standing folder alone (0224), its text unread.
    script, got = _admission(command, agent, cwd)
    if not _passed(got):
        return R_DATA_DIR if _data_dir_target(cwd, cwd) else None
    redirects = {n.target.span for n in shparse.nodes(script) if isinstance(n, Redirect)}
    words = {n.span: n for n in shparse.nodes(script) if isinstance(n, Word)}
    env = {"HOME": _HOME}
    base, index = cwd, None
    for done in got.commands:
        if done.family == "cd" and done.cd_target is not None:
            base = _abs(done.cd_target.text, base)
            continue
        here = _abs(done.cd_target.text, base) if done.cd_target is not None else base
        family = done.family
        wholes = _ancestor_writes(done)
        for write in done.writes:
            opens = [cwd, base] if write.span in redirects else [cwd, base, here]
            path = _typed_path(write, words, command, env)
            whole = any(write is w for w in wholes)
            if any(_data_dir_holds(path, f, cwd, whole, family) for f in opens):
                return R_DATA_DIR
        # 266: a link's source; a later write through the link lands in the data folder.
        links = [_abs(w.text, here) for w in done.writes] if family == "ln" else []
        sources = done.reads if family == "ln" else ()
        for source in sources:
            path = _typed_path(source, words, command, env)
            folders = [here, *links, *(os.path.dirname(link) for link in links)]
            if any(_data_dir_holds(path, f, cwd, True, family) for f in folders):
                return R_DATA_DIR
        sub = done.subcommand.text if done.subcommand is not None else ""
        if index is None and done.family == "git" and sub in _INDEX_WRITES:
            index = _index_reason(done, here, cwd)
    return index


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


def _base_env() -> dict[str, list[str]]:
    # spec 8: the hook's own environment, HOME real, the plugin folders defaulted.
    env = {k: [v] for k, v in os.environ.items()}
    env["HOME"] = [str(Path.home())]
    env.setdefault("CLAUDE_PLUGIN_ROOT", [os.path.dirname(_REPO_SCRIPTS)])
    env.setdefault("CLAUDE_PLUGIN_DATA", [env["HOME"][0] + _DATA_DIR_DEFAULT])
    return env


def _option_values(
    texts: list[str], options: list[WrapperOption], kinds: frozenset[tuple[str, str]]
) -> list[str]:
    return [texts[o.at][len(o.prefix) :] for o in options if (o.wrapper, o.option) in kinds]


def _typed_tree(
    done: AdmittedCommand, rg_config: bool, rewritten: bool
) -> tuple[bool, bool] | None:
    # spec 8, 228 tail: (sees hidden dirs, reads its folder when no read operand is typed) for a
    # command that walks a tree, from its typed options; a word the shell builds is opaque.
    name, ops = done.family, bool(done.reads)
    longs = {o.text.split("=", 1)[0] for o in done.options if o.text.startswith("--")}
    short = {c for o in done.options if o.text[:1] == "-" != o.text[1:2] for c in o.text[1:]}
    opaque = rewritten or any(o.glob for o in done.options)
    if name in _GREPS:
        on = bool({"r", "R", "d"} & short or {"--recursive", "--dereference-recursive"} & longs)
        on = on or "--directories" in longs or opaque
        return (True, not ops) if on else None
    if name == "rg":
        return rg_reaches_hidden([o.text for o in done.options], opaque or rg_config), not ops
    if name == "find":
        on = bool({"-exec", "-execdir", "-ok", "-okdir"} & {o.text for o in done.options})
        return (True, not ops) if on or opaque else None
    if name in {"tar", "rsync", "bsdtar", "7z", "7za", "7zr", "7zz", "pax"}:
        return True, False
    if name == "scp" and "r" in short:
        return True, False
    if name == "cp" and ({"r", "R", "a"} & short or {"--recursive", "--archive"} & longs or opaque):
        return True, False
    if name == "zip" and ({"r", "R"} & short or "--recurse-paths" in longs):
        return True, False
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


def rg_reaches_hidden(args: list[str], unseen: bool) -> bool:
    # 113, 228 tail: unseen is a word the shell rewrites or a config file variable the parse typed.
    longs = {a.split("=", 1)[0] for a in args if a.startswith("--")}
    short = {
        c
        for a in args
        if a.startswith("-") and not a.startswith("--")
        for c in _rg_short_letters(a)
    }
    return unseen or bool(_RG_REACH_SHORT & short or _RG_REACH_LONGS & longs)


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


class _Tree(NamedTuple):
    # spec 8, 228 tail: one admitted command that walks a tree, from its typed record.
    name: str
    hidden: bool
    targets: list[str]
    globs: list[str]


def _tree_reason(
    trees: list[_Tree],
    roots: list[str],
    keys: tuple[str, ...],
    env_files: tuple[str, ...],
    dotglob: bool,
) -> str | None:
    # SC-12: reply key roots let a dot folder hide them from **; credential stores do not.
    pairs = [(root, False, R_CREDENTIAL_TREE) for root in roots]
    pairs += [(key, True, R_CREDENTIAL_TREE) for key in keys]
    # 0192: a .env file is a dot file, so rg's default skip hides it like the reply key.
    pairs += [(env, True, R_ENV_FILE_TREE) for env in env_files]
    for name, hidden, targets, globs in trees:
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
    if cmd is not None and any(search_rewritten(w) for w in cmd.words):
        return R_RG_OPAQUE
    if rg_reaches_hidden(tokens[1:], False):
        return R_RG_REACH
    # 113: judged against the reply key's fixed place, whether or not one exists yet.
    if glob_reaches(_rg_globs(tokens[1:]), [".claude", "daedalus", REPLY_KEY_NAME]):
        return R_REPLY_KEY_TREE.format(path=cwd)
    # 228 tail: the auditor's own grammar; a verify it refuses has no typed path to judge.
    got = _admission(command, "auditor", cwd)[1]
    refused = _refused(got)
    if refused is not None:
        return refusal_text(refused)
    return _credential_reason("Bash", {"command": command}, cwd, got)


class _Typed(NamedTuple):
    # 228 tail: one admitted command's credential view: its folders and its typed paths.
    bases: tuple[str, ...]
    paths: list[str | None]
    raws: list[str]


def _typed_names(got: Admitted) -> set[str]:
    # 228 tail, SS-1: every name an admitted command assigns, exports or unsets.
    names = {a.text.split("=", 1)[0].removesuffix("+") for c in got.commands for a in c.assignments}
    for done in got.commands:
        if done.family in shell.NAME_OPERAND_CMDS:
            names |= {t.text.split("=", 1)[0] for t in done.texts}
    return names


def _typed_path(
    typed: Typed, words: dict[tuple[int, int], Word], text: str, env: dict[str, str]
) -> str | None:
    # 228 tail, SS-4: a literal typed path as typed; else built from its parsed parts, a parameter
    # only when the hook's environment binds it and no admitted command names it; else None.
    word = words.get(typed.span) if typed.glob else None
    if word is None:
        return typed.text
    out = ""
    for k, part in enumerate(word.parts):
        if isinstance(part, Literal):
            out += part.text
        elif isinstance(part, Tilde) and k == 0:
            out += env["HOME"] if not part.user else os.path.expanduser(f"~{part.user}")
        elif isinstance(part, shparse.Glob):
            out += text[part.span[0] : part.span[1]]
        elif isinstance(part, Param) and not part.op and part.name in env:
            out += env[part.name]
        else:
            return None
    return out


class _Spec(NamedTuple):
    # 228 tail: a git pathspec or show <rev>:<path>, as the absolute path git matches it at.
    path: str | None
    raw: str
    fold: bool
    wild: bool
    top: str
    # 267: the operand word's span, a <rev>:<path> read, and wildcards off by literal magic.
    span: tuple[int, int] = (0, 0)
    blob: bool = False
    literal: bool = False


_SPEC_SHORT = {"/": "top", "!": "exclude", "^": "exclude"}
_SPEC_NOWILD = frozenset({"--literal-pathspecs", "--glob-pathspecs", "--noglob-pathspecs"})
_SPEC_LITERAL = frozenset({"--literal-pathspecs", "--noglob-pathspecs"})
_REV_PATH_SUBS = frozenset({"show", "cat-file"})


def _pathspec_magic(text: str) -> tuple[set[str], str]:
    # 228 tail: git's long :(a,b) and short :/ :! :^ magic, split from the path it applies to.
    if text.startswith(":("):
        close = text.find(")")
        if close < 0:
            return set(), text
        return {w.split(":", 1)[0].strip() for w in text[2:close].split(",")}, text[close + 1 :]
    if not text.startswith(":"):
        return set(), text
    i, magic = 1, set()
    while i < len(text) and text[i] in _SPEC_SHORT:
        magic.add(_SPEC_SHORT[text[i]])
        i += 1
    return magic, text[i + 1 :] if text[i : i + 1] == ":" else text[i:]


def _git_specs(
    script: Script,
    done: AdmittedCommand,
    words: dict[tuple[int, int], Word],
    command: str,
    env: dict[str, str],
    here: str,
) -> list[_Spec]:
    # 228 tail: each typed pathspec, and a show or cat-file <rev>:<path>, under git's folder.
    if done.family != "git":
        return []
    folder, top = _git_folder(done, words, command, env, here)
    toks = set(admitted_tokens(script, done))
    out: list[_Spec] = []
    for typed in done.pathspecs:
        text = _typed_path(typed, words, command, env)
        if text is None:
            out.append(_Spec(None, typed.text, False, False, top, typed.span))
            continue
        magic, rest = _pathspec_magic(text)
        if "exclude" in magic:
            continue
        base = top if "top" in magic else folder
        wild = not (magic & {"literal", "glob"} or toks & _SPEC_NOWILD)
        fold = "icase" in magic or "--icase-pathspecs" in toks
        literal = "literal" in magic or bool(toks & _SPEC_LITERAL)
        path = os.path.normpath(_abs(rest, base))
        out.append(_Spec(path, typed.text, fold, wild, top, typed.span, False, literal))
    if (done.subcommand.text if done.subcommand else "") in _REV_PATH_SUBS:
        for typed in (*done.texts, *done.pathspecs):
            rev, colon, path = typed.text.partition(":")
            path = path[2:] if not rev and path[1:2] == ":" and path[:1] in "0123" else path
            if colon and path and not typed.text.startswith("-"):
                # 228 tail: a tree path is from the top, unless it opens with ./ or ../ (git show).
                base = folder if path.startswith(("./", "../")) else top
                blob = os.path.normpath(_abs(path, base))
                out.append(_Spec(blob, typed.text, False, False, top, typed.span, True, True))
    return out


def _git_folder(
    done: AdmittedCommand,
    words: dict[tuple[int, int], Word],
    command: str,
    env: dict[str, str],
    here: str,
) -> tuple[str, str]:
    # 228 tail, 267: the folder git runs in after -C, and the top of the checkout holding it.
    folder = here
    if done.git_dir is not None:
        folder = _abs(_typed_path(done.git_dir, words, command, env) or "", here)
    found = checkout_git_dir(folder) if os.path.isabs(folder) else None
    return folder, str(found[0]) if found else folder


_SPEC_WALK_CAP = 256


def _store_names(real: str) -> list[str] | None:
    # 228 tail: the store and every name below it; None past the cap, which reads as a match.
    names = [real]
    for folder, dirs, files in os.walk(real):
        names += [os.path.join(folder, n) for n in (*dirs, *files)]
        if len(names) > _SPEC_WALK_CAP:
            return None
    return names


def _spec_reaches(spec: _Spec, stores: list[str]) -> str | None:
    # 228 tail: git's * and ? cross /, and icase folds case; git matches nothing outside its tree.
    assert spec.path is not None
    fold = str.casefold if spec.fold else str
    pat = fold(spec.path)
    for store in stores:
        real = os.path.realpath(store)
        if not shell._under(real, spec.top):
            continue
        if pat == fold(real) or pat.startswith(fold(real).rstrip(os.sep) + os.sep):
            return store
        names = _store_names(real) if spec.wild else []
        if names is None or any(fnmatch.fnmatchcase(fold(n), pat) for n in names):
            return store
    return None


class _GitRead(NamedTuple):
    # 267: one admitted git command, the folder it runs in, its checkout top and its pathspecs.
    done: AdmittedCommand
    folder: str
    top: str
    specs: list[_Spec]


# 267: options that make a read print file content or test it (pickaxe); log reads only by these.
_PATCH_OPTS = frozenset(
    {"-p", "--patch", "--stat", "--word-diff", "--check", "--pickaxe-regex", "--pickaxe-all"}
)
_PATCH_PREFIXES = ("-U", "-S", "-G")
_NAMES_OPTS = frozenset({"--name-only", "--name-status"})
# 267: ls-files from the whole checkout; globals forwarded to it, any other global is dropped.
_LS_FILES = ("ls-files", "-z", "-s", "--", ":/")
_LS_GLOBALS = frozenset({"--git-dir", "--work-tree"})
_LS_TIMEOUT = 5.0
_SYMLINK_MODE = b"120000"
# 267: a word holding one of these may be a revision, so its wildcard never makes it a path.
_REV_CHARS = frozenset("^~:@{")


def _git_tree_read(done: AdmittedCommand) -> tuple[bool, bool]:
    # 267: (prints tree content under its paths, may print a <rev>:<path> blob); a built option
    # could be -p, so it counts as one.
    sub = done.subcommand.text if done.subcommand else ""
    opts = {o.text for o in done.options}
    patch = any(o.glob for o in done.options) or any(
        t in _PATCH_OPTS or t.startswith(_PATCH_PREFIXES) for t in opts
    )
    if sub == "log":
        return patch, False
    if sub == "stash":
        return [t.text for t in done.texts[:1]] == ["show"], False
    if sub in ("diff", "show"):
        names = opts & (_NAMES_OPTS | ({"-s"} if sub == "show" else set()))
        return patch or not names, sub == "show"
    return sub in ("grep", "blame"), False


def _operand_slots(
    script: Script, done: AdmittedCommand
) -> tuple[set[tuple[int, int]], set[tuple[int, int]]]:
    # 267: the operand words that are an option's value or grep's pattern, and those after --.
    sub = done.subcommand
    words = admitted_words(script, done)
    at = next((i for i, w in enumerate(words) if sub is not None and w.span == sub.span), None)
    name = sub.text if sub is not None else ""
    valued = _GIT_VALUED.get(name, frozenset())
    # 267: git grep takes its first operand as the pattern unless -e names one.
    pattern = name == "grep" and "-e" not in {o.text for o in done.options}
    values: set[tuple[int, int]] = set()
    after: set[tuple[int, int]] = set()
    dashed = skip = opts_done = False
    for word in words[at + 1 :] if at is not None else []:
        lit = word.literal
        if dashed:
            after.add(word.span)
        elif skip:
            values.add(word.span)
            skip = False
        elif lit == "--" and pattern and not opts_done:
            opts_done = True  # 267: grep drops one -- before its pattern; the next word is it.
        elif lit == "--":
            dashed = True
        elif not opts_done and lit is not None and lit.startswith("-") and lit != "-":
            skip = lit in valued
        elif pattern:
            values.add(word.span)
            pattern = False
    return values, after


def _path_operand(spec: _Spec, after: set[tuple[int, int]]) -> bool:
    # 267: after -- a word is a path; before it, a word on disk, or a wildcard no revision holds.
    assert spec.path is not None
    if spec.span in after:
        return True
    if spec.raw.startswith(":"):
        return False
    if os.path.lexists(spec.path):
        return True
    text = set(spec.raw)
    return spec.wild and bool(text & _GLOB_CHARS) and not text & _REV_CHARS and ".." not in spec.raw


def _spec_covers(spec: _Spec, secrets: list[str]) -> str | None:
    # 267: a pathspec that is, holds, or by wildcard matches a tracked secret path.
    assert spec.path is not None
    real = spec._replace(
        path=os.path.realpath(spec.path), top=os.path.realpath(spec.top), wild=not spec.literal
    )
    fold = str.casefold if spec.fold else str
    held = fold(real.path or "").rstrip(os.sep) + os.sep
    inside = next((s for s in secrets if fold(s).startswith(held)), None)
    return inside or _spec_reaches(real, secrets)


def _ls_globals(script: Script, done: AdmittedCommand) -> list[str]:
    # 267: the typed --git-dir and --work-tree words before the subcommand, as git read them.
    words = admitted_words(script, done)
    out: list[str] = []
    for i, word in enumerate(words[1:], 1):
        if done.subcommand is not None and word.span == done.subcommand.span:
            break
        lit = word.literal or ""
        name = lit.partition("=")[0]
        if name in _LS_GLOBALS and "=" in lit:
            out.append(lit)
        elif name in _LS_GLOBALS and i + 1 < len(words):
            out += [lit, words[i + 1].literal or ""]
        elif lit == "--bare":
            out.append(lit)
    return out


def tracked_secrets(
    folder: str, globals_: list[str], hit: Callable[[str], str | None], roots: list[str]
) -> list[str] | None:
    # 267: the tracked paths hit refuses by name; [] outside any checkout, None when unread.
    inside = bool(globals_) or (os.path.isabs(folder) and checkout_git_dir(folder) is not None)
    if not inside:
        return []
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env["GIT_OPTIONAL_LOCKS"] = "0"
    argv = ["git", "-c", "core.fsmonitor=false", *globals_, *_LS_FILES]
    try:
        done = subprocess.run(
            argv,
            cwd=folder,
            capture_output=True,
            timeout=_LS_TIMEOUT,
            env=env,
            stdin=subprocess.DEVNULL,
            check=False,
        )
    except (OSError, ValueError, subprocess.SubprocessError):
        return None
    if done.returncode != 0 or (done.stdout and not done.stdout.endswith(b"\0")):
        return None
    base = os.path.realpath(folder)
    found: list[str] = []
    for entry in done.stdout.split(b"\0")[:-1]:
        meta, tab, raw = entry.partition(b"\t")
        if not tab or not raw:
            return None
        path = os.path.normpath(os.path.join(base, os.fsdecode(raw)))
        name = os.path.basename(path)
        # 267: hit judges each name; the cheap tests only skip names it cannot refuse.
        maybe = env_name(name) or name == REPLY_KEY_NAME or meta.startswith(_SYMLINK_MODE)
        maybe = maybe or any(path == r or path.startswith(r + os.sep) for r in roots)
        if maybe and hit(path):
            found.append(path)
    return list(dict.fromkeys(found))


def _tracked_reason(
    script: Script,
    gits: list[_GitRead],
    names: set[str],
    hit: Callable[[str], str | None],
    roots: list[str],
) -> str | None:
    # 267, 0239: a content read with no path, or a path over a secret the checkout tracks.
    for read in gits:
        tree, blobs_too = _git_tree_read(read.done)
        blobs = [s for s in read.specs if s.blob] if blobs_too else []
        if not tree and not blobs:
            continue
        if any(n.startswith("GIT_") for n in names):
            return R_TRACKED_UNKNOWN.format(path=read.folder)
        secrets = tracked_secrets(read.folder, _ls_globals(script, read.done), hit, roots)
        if secrets is None:
            return R_TRACKED_UNKNOWN.format(path=read.folder)
        if not secrets:
            continue
        values, after = _operand_slots(script, read.done)
        blob_spans = {s.span for s in blobs}
        paths: list[_Spec] = []
        revs = False
        for spec in read.specs:
            if spec.blob or spec.span in values or spec.span in blob_spans:
                continue
            if _path_operand(spec, after):
                paths.append(spec)
            else:
                revs = True
        sub = read.done.subcommand.text if read.done.subcommand else ""
        if sub == "grep" and not paths:
            # 267: git grep with no path searches the folder it runs in, not the whole checkout.
            paths = [_Spec(read.folder, ".", False, False, read.top, literal=True)]
        whole = tree and not paths and (sub != "show" or revs or not blobs)
        if whole:
            return R_TRACKED_SECRET.format(path=secrets[0])
        for spec in [*(paths if tree else []), *blobs]:
            secret = _spec_covers(spec, secrets)
            if secret is not None:
                return R_TRACKED_SECRET.format(path=secret)
    return None


def _typed_view(
    script: Script, command: str, got: Admitted, cwd: str
) -> tuple[list[_Typed], list[_Tree], list[str], list[_Spec], list[_GitRead]]:
    # 228 tail, spec 8: each admitted command's typed reads, writes, script, cd target, git
    # folder and pathspecs; relative ones open in the shell's folder and in the command's own.
    names = _typed_names(got)
    env = {k: v[0] for k, v in _base_env().items() if k not in names or k == "HOME"}
    words = {n.span: n for n in shparse.nodes(script) if isinstance(n, Word)}
    rg_config = _RG_CONFIG_ENV in names
    base = cwd
    views: list[_Typed] = []
    trees: list[_Tree] = []
    texts: list[str] = []
    specs: list[_Spec] = []
    gits: list[_GitRead] = []
    for done in got.commands:
        here = base
        if done.cd_target is not None:
            here = _abs(_typed_path(done.cd_target, words, command, env) or "", base)
            base = here if done.family == "cd" else base
        typed = [*done.reads, *done.writes, done.script, done.git_dir, done.cd_target]
        found = [t for t in typed if t is not None]
        paths = [_typed_path(t, words, command, env) for t in found]
        views.append(_Typed((base, here), paths, [t.text for t in found]))
        own = _git_specs(script, done, words, command, env, here)
        specs += own
        if done.family == "git":
            folder, top = _git_folder(done, words, command, env, here)
            gits.append(_GitRead(done, folder, top, own))
        texts += [t.text for t in done.texts]
        # prepush2-2026-10-27: a search word bash rewrites may become a reach flag.
        search = done.family in shell.SEARCH_CMDS
        rewritten = search and any(search_rewritten(w) for w in admitted_words(script, done))
        tree = _typed_tree(done, rg_config, rewritten)
        if tree is not None:
            reads = [_typed_path(t, words, command, env) for t in done.reads]
            targets = [_anchor(r, here) for r in reads if r is not None]
            targets += [here] if tree[1] else []
            globs = _rg_globs(admitted_tokens(script, done)[1:]) if done.family == "rg" else []
            trees.append(_Tree(done.family, tree[0], [t for t in targets if t], globs))
    return views, trees, texts, specs, gits


def _bash_credential_reason(
    command: str,
    cwd: str,
    roots: list[str],
    keys: tuple[str, ...] = (),
    got: Admitted | Refusal | None = None,
) -> str | None:
    # spec 8, 228 tail: an admitted command's typed paths, never its text; a refused one is
    # judged by its standing folder alone (0224) and its refusal names the word off the table.
    script = shparse.parse(command)
    judged = _admission(command, "main", cwd)[1] if got is None else got
    if not _passed(judged):
        inside = os.path.isabs(cwd) and _credential_hit(cwd, roots, False)
        return R_CREDENTIAL.format(path=cwd) if inside else None
    views, trees, texts, specs, gits = _typed_view(script, command, judged, cwd)
    names = _typed_names(judged)
    dotglob = "GLOBIGNORE" in names
    bases = [b for v in views for b in v.bases if os.path.isabs(b)]
    # 0192: a command naming an ignore file and carrying a `!` line that reaches a .env name.
    named = [p for v in views for p in v.paths if p and os.path.basename(p) in ENV_IGNORE_FILES]
    if named and any(whitelists_env(t) for t in texts):
        return R_ENV_WHITELIST_WRITE.format(path=named[0])
    absolute = [p for v in views for p in v.paths if p is not None and os.path.isabs(p)]
    unresolved = next(
        (r for v in views for p, r in zip(v.paths, v.raws, strict=True) if p is None), ""
    )
    relative = [(p, v.bases) for v in views for p in v.paths if p and not os.path.isabs(p)]

    def hit(target: str) -> str | None:
        if reply_key_hit(target) or _credential_hit(target, list(keys), True, dotglob, True):
            return R_REPLY_KEY.format(path=target)
        if _credential_hit(target, roots, True, dotglob):
            return R_CREDENTIAL.format(path=target)
        if env_file_hit(target) or _credential_hit(target, list(env_files), True, dotglob, True):
            return R_ENV_FILE.format(path=target)
        return None

    # 0192: the .env files beside every folder the command starts in or moves to.
    env_files = tuple(env_roots(*dict.fromkeys([cwd, *bases, *(s.top for s in specs)])))
    # spec 8: spelled-out paths first, so the message names the path the command wrote.
    for cand in absolute:
        reason = hit(os.path.normpath(cand))
        if reason:
            return reason
    if unresolved:
        return R_CREDENTIAL_PARAM.format(path=unresolved)
    for cand, folders in relative:
        for base in dict.fromkeys(b for b in (cwd, *folders) if os.path.isabs(b)):
            reason = hit(os.path.normpath(os.path.join(base, cand)))
            if reason:
                return reason
    # 228 tail: a git pathspec or <rev>:<path> names its store as a file operand does.
    for spec in specs:
        if spec.path is None:
            return R_CREDENTIAL_PARAM.format(path=spec.raw)
        reason = hit(spec.path)
        if reason:
            return reason
        store = _spec_reaches(spec, [*keys, *roots, *env_files])
        if store is None:
            continue
        if store in keys:
            return R_REPLY_KEY.format(path=spec.raw)
        return (R_CREDENTIAL if store in roots else R_ENV_FILE).format(path=spec.raw)
    tree = _tree_reason(trees, roots, keys, env_files, dotglob)
    return tree or _tracked_reason(script, gits, names, hit, roots)


def _credential_reason(
    tool: str, tool_input: dict[str, object], cwd: str, got: Admitted | Refusal | None = None
) -> str | None:
    if tool == "Bash":
        command = str(tool_input.get("command") or "")
        # SC-12: the reply key joins as its own roots, so globs and folder reads of it refuse.
        keys = tuple(key_roots(cwd))
        return _bash_credential_reason(command, cwd, _credential_roots(), keys, got)
    if tool not in CREDENTIAL_TOOLS and tool not in WRITE_TOOLS:
        return None
    return path_reason(tool, tool_input, cwd)


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


def _train_active(cwd: str) -> bool:
    # 0023: existence only; a symlinked or unreadable marker still counts as an active train.
    return os.path.lexists(train_marker(project_root(cwd)))


_GIT_DIR_OPTS = ("--git-dir=", "--work-tree=")


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


def search_rewritten(word: Word) -> bool:
    # prepush2-2026-10-27, 228 tail: a search word bash rewrites ($'-uu', $X, {-u,}, a brace) or
    # a glob that may match a planted file named like a flag, read from its parsed parts.
    parts = word.parts
    if not all(isinstance(p, Literal | shparse.Glob | Tilde) for p in parts):
        return True
    if any(isinstance(p, Literal) and p.quoted in ("$'", '$"') for p in parts):
        return True
    if any(isinstance(p, Literal) and not p.quoted and set("{}") & set(p.text) for p in parts):
        return True
    if not any(isinstance(p, shparse.Glob) for p in parts):
        return False
    lead = parts[0]
    return isinstance(lead, shparse.Glob) or (isinstance(lead, Literal) and lead.text[:1] == "-")


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
    constant = refusal_constant(script, refused, cwd)
    if constant is not None or "Next:" in refused.reason:
        return constant
    cmd = refused_command(script, refused)
    head = cmd.words[0].literal if cmd is not None and cmd.words else None
    git = head is not None and shell.command_family(head) == "git"
    return R_CODER_GIT if git else R_CODER_TABLE


def refusal_constant(script: Script, refused: Refusal, cwd: str) -> str | None:
    # 228 S3b, tail: the class of the refused node, read from the parse: a prefix, a redirect, a
    # construct, an expansion, then the command word; never the command text. None: no class.
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
    # issue 55, 228 tail: the head, or the word refused after a wrapper, runs the claude binary.
    words = [head] + ([word.literal] if word is not None and word.literal else [])
    if family == "claude" or any(shell.runs_claude([w], _parse_base(script, cwd)) for w in words):
        return shell.R_CLAUDE_PATH
    if family == shell.CONFINE:
        return shell.R_CONFINE_FORM
    if "/" in head and os.path.dirname(head) not in shell._TRUSTED_BIN:
        return shell.R_UNTRUSTED_PATH
    return next((c for names, c in _CODER_CONSTANTS if family in names), None)


def lead_cd(got: Admitted) -> tuple[AdmittedCommand | None, tuple[AdmittedCommand, ...]]:
    # 228 S3b: the one leading cd admit allows, apart from the commands after it.
    first = got.commands[0] if got.commands else None
    if first is not None and first.family == "cd" and first.cd_target is not None:
        return first, got.commands[1:]
    return None, got.commands


def coder_base(call: CoderCall, got: Admitted) -> str:
    return admitted_base(call.script, got, call.cwd)


def admitted_base(script: Script, got: Admitted, cwd: str) -> str:
    # 228 S3b, O6: a leading cd moves the rest only when every join is &&.
    lead, _ = lead_cd(got)
    joins = set(script.separators) - {""}
    if lead is None or lead.cd_target is None or not joins <= {"&&"}:
        return cwd
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


def admitted_writes(script: Script, got: Admitted, cwd: str) -> list[str]:
    # 0054, 228 tail: typed write paths and git restore or checkout pathspecs; a redirect opens
    # in the shell's folder, an operand in the command's own.
    redirects = {n.target.span for n in shparse.nodes(script) if isinstance(n, Redirect)}
    base = cwd
    out: list[str] = []
    for done in got.commands:
        if done.family == "cd" and done.cd_target is not None:
            base = _abs(done.cd_target.text, base)
            continue
        here = _abs(done.cd_target.text, base) if done.cd_target is not None else base
        out += [_abs(w.text, base if w.span in redirects else here) for w in done.writes]
        sub = done.subcommand.text if done.subcommand is not None else ""
        if done.family == "git" and sub in {"restore", "checkout"}:
            folder = done.git_dir.text if done.git_dir is not None else here
            out += [_abs(p.text, folder) for p in done.pathspecs]
    return [os.path.normpath(p) for p in dict.fromkeys(out)]


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
    if command and _data_dir_bash(command, cwd, "foreign"):
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


def integrity_reason(tool: str, tool_input: dict[str, object], cwd: str, agent: str) -> str | None:
    # 0053, issue 75: no absolute cwd, a write into .git or the data folder, Bash included.
    # 266: a Bash call is judged on the typed record of the caller's own role.
    is_write = tool in WRITE_TOOLS
    if not (is_write or tool == "Bash"):
        return None
    if not os.path.isabs(cwd):
        return R_NO_CWD
    if not is_write:
        return _data_dir_bash(str(tool_input.get("command") or ""), cwd, agent)
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
    integrity = integrity_reason(tool, tool_input, cwd, "main")
    if integrity == R_NO_CWD:
        return _main_warn(WARN_NO_CWD, R_NO_CWD)
    if integrity == R_DOTGIT:
        return _main_warn(WARN_DOTGIT.format(path=path), R_DOTGIT)
    if integrity is not None:
        return _main_warn(WARN_DATA_DIR, integrity)
    if tool == "Bash":
        return _main_bash(command, cwd)
    train = _main_write_train(path, cwd) if is_write else None
    if train is not None:
        return _warn(R_MAIN_TRAIN_WARN.format(train=train, path=path))
    if tool in dispatch_binding.DISPATCH_TOOLS:
        reason = dispatch_binding._dispatch_reason(tool_input, cwd, main=True)
        if reason:
            # Main never prompted (amends 0106): the dispatch runs with the skipped invariant named.
            return _warn(WARN_DISPATCH.format(reason=reason))
    return _allow()


def _main_bash(command: str, cwd: str) -> Decision:
    # 0105, 0106, 228 tail: main is admitted by its own grammar and warned, never refused; a
    # tripwire reads the typed record, a refused command is warned with the grammar's refusal.
    script, got = _admission(command, "main", cwd)
    commands = got.commands if _passed(got) else ()
    base = admitted_base(script, got, cwd) if _passed(got) else cwd
    for done in commands:
        # audit A7-1, issue 55: the typed command word, its wrappers and node's script.
        reason = R_NESTED_CLAUDE if claude_word(done, base) else admitted_tripwire(script, done)
        if reason:
            return _tripwire_warn(reason)
    reason = _gh_gate("main", cwd, command)
    if reason:
        return _tripwire_warn(reason)
    refused = _refused(got)
    # audit A7-1, issue 55: the refused word runs the claude binary by name, link or path.
    claude = refused is not None and (
        refused.family == "claude" or refusal_constant(script, refused, cwd) == shell.R_CLAUDE_PATH
    )
    if refused is not None and claude:
        return _main_warn(WARN_NESTED_CLAUDE, refusal_text(refused, R_NESTED_CLAUDE))
    if refused is not None:
        return _main_warn(WARN_COMMAND, refusal_text(refused))
    return _allow()


def admitted_tripwire(script: Script, done: AdmittedCommand) -> str | None:
    # 8.5, 228 tail: the git and rm tripwires an admitted command meets, on its parsed words.
    tokens = admitted_tokens(script, done)
    if done.family == "git":
        return shell._git_reason(tokens, [a.text for a in done.assignments])
    if done.family == "rm":
        return shell._rm_reason(tokens[1:])
    return None


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
