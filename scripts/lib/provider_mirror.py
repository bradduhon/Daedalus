# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0256: the run fetches Terraform providers once, outside the kernel wrapper, into a mirror under
# the run's temporary folder; the wrapper grants that one folder read-only (issue 200). Only the
# run's base commit, or an address the operator allowed, decides which provider is downloaded.
from __future__ import annotations

import os
import resource
import shutil
import signal
import stat
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from lib import git, hcl_reader, storage, train_state

FEATURE = "provider-mirror"
MIRROR, DATA = "mirror", "tf-data"
# 0256: the train state key the fetch records under; roots tried, ok or failed, never an env.
STATE_KEY = "providers"
FETCH_TIMEOUT_S = 600
GIT_TIMEOUT_S = 30.0
MAX_TF_BYTES = 1 << 20
ERROR_MAX = 200
# 0265: the most of a terraform stream decoded; diagnostics past it are not read.
OUTPUT_MAX = 4 << 20
LOCK_FILE = ".terraform.lock.hcl"
STAGED_TF = "providers.tf"
# 0256: path parts the base-tree walk never enters; links and submodules are never read.
SKIP_DIRS = frozenset({".git", ".terraform", ".claude"})
BLOB_MODES = frozenset({"100644", "100755"})
HEX = frozenset("0123456789abcdef")
# 0256: the caller variables terraform may need for a fetch; every other one is dropped.
PASS_NAMES = frozenset(
    {"HOME", "PATH", "TF_CLI_CONFIG_FILE", "SSL_CERT_FILE", "SSL_CERT_DIR"}
    | {"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "NO_PROXY", "no_proxy"}
)
PASS_PREFIXES = ("TF_TOKEN_",)
PATH_VARS = ("HOME", "TF_CLI_CONFIG_FILE", "SSL_CERT_FILE", "SSL_CERT_DIR")
FIXED_ENV = {"CHECKPOINT_DISABLE": "1", "TF_IN_AUTOMATION": "1", "TF_INPUT": "0"}
# 0256: the characters a mirror path may hold, so the CLI config string needs no escaping.
PATH_CHARS = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/._-")
# 0256: the typed parts of an --allow address, host/namespace/type, and its version constraint.
_LOWER = "abcdefghijklmnopqrstuvwxyz0123456789"
HOST_CHARS = frozenset(_LOWER + ".-")
NAME_CHARS = frozenset(_LOWER + "-")
CONSTRAINT_CHARS = frozenset(_LOWER + "ABCDEFGHIJKLMNOPQRSTUVWXYZ.,<>=!~ -")
LOCAL_NAME_CHARS = frozenset(_LOWER + "ABCDEFGHIJKLMNOPQRSTUVWXYZ_-")
HOST_MAX, NAME_MAX, CONSTRAINT_MAX = 253, 64, 64
WITHHELD = "[withheld]"
R_MIRROR_OUTSIDE = "{path} resolves outside the run's temporary folder"
R_MIRROR_NOT_GRANTED = (
    "the run's provider mirror is not granted, because {reason}. Next: remove {run} from your "
    "own shell, then rerun "
    "daedalus_train.py providers from the main session."
)
R_PROVIDERS_NO_RUN = (
    "providers: no run is marked in {root}. Next: start a run first; the build phase runs this "
    "command after the plan is recorded."
)
R_ALLOW_ADDRESS = (
    "providers: --allow {given!r} is not <host>/<namespace>/<type>[=<version constraint>], with "
    "a lowercase host holding a dot, a lowercase namespace and type of letters, digits and "
    "dashes, and a constraint of at most 64 version characters. Next: copy the full source "
    "address from the unit's files, such as registry.terraform.io/hashicorp/aws=~> 5.0."
)
NEXT_RERUN = (
    "Next: fix the cause, then run daedalus_train.py providers --repo {repo} again; until then "
    "terraform validate fails there as it did before."
)


@dataclass(frozen=True)
class Grant:
    # 0256: path is the granted mirror; reason is why an existing mirror was not granted.
    path: str = ""
    reason: str = ""


@dataclass
class Root:
    # 0256: one base-commit folder; required is local name to its source text at base.
    folder: str
    required: dict[str, str] = field(default_factory=dict)
    labels: list[str] = field(default_factory=list)
    lock: str = ""


def run_folder(repo: str | Path, train_id: str) -> Path:
    return storage.tmp_dir(FEATURE, repo) / train_id


def mirror_folder(repo: str | Path, train_id: str) -> Path:
    return run_folder(repo, train_id) / MIRROR


def _resolved(path: str) -> str:
    return os.path.realpath(path)


def _folder_problem(folder: Path) -> str | None:
    # 0256: the storage module's checks, applied to the run folder and the mirror below it.
    try:
        info = folder.lstat()
    except OSError as exc:
        return f"{folder} could not be read ({exc.strerror})"
    if stat.S_ISLNK(info.st_mode):
        return f"{folder} is a symlink"
    if not stat.S_ISDIR(info.st_mode):
        return f"{folder} is not a folder"
    if info.st_uid != os.geteuid():
        return f"{folder} is not owned by you"
    if info.st_mode & 0o022:
        return f"{folder} can be written by group or others"
    return None


def mirror_problem(repo: str | Path, train_id: str) -> str | None:
    # 0256: None when the mirror is this run's own private folder; else why it is not.
    reason = storage.check_tmp_dirs(FEATURE, repo)
    if reason is not None:
        return reason
    run, mirror = run_folder(repo, train_id), mirror_folder(repo, train_id)
    for folder in (run, mirror):
        reason = _folder_problem(folder)
        if reason is not None:
            return reason
    base = _resolved(str(storage.tmp_dir(FEATURE, repo)))
    expected = os.path.join(base, train_id, MIRROR)
    if _resolved(str(mirror)) != expected or not set(expected) <= PATH_CHARS:
        return R_MIRROR_OUTSIDE.format(path=mirror)
    return None


def granted_mirror(repo: str) -> Grant:
    # 0256: the wrapper's view; no run or no mirror grants nothing and says nothing.
    train_id = train_state.active_train(Path(repo))
    if train_id is None:
        return Grant()
    mirror = mirror_folder(repo, train_id)
    if not os.path.lexists(mirror) and not os.path.lexists(mirror.parent):
        return Grant()
    reason = mirror_problem(repo, train_id)
    if reason is not None:
        run = run_folder(repo, train_id)
        return Grant(reason=R_MIRROR_NOT_GRANTED.format(reason=reason, run=run))
    return Grant(path=_resolved(str(mirror)))


def cli_config(mirror: str) -> str:
    # 0256: only the provider_installation block; direct excludes every provider address.
    return (
        "provider_installation {\n"
        "  filesystem_mirror {\n"
        f'    path = "{mirror}"\n'
        "  }\n"
        "  direct {\n"
        '    exclude = ["*/*/*"]\n'
        "  }\n"
        "}\n"
    )


def make_mirror(repo: str | Path, train_id: str) -> Path:
    # 0256: the storage chain, then the run folder, the mirror and the fetch data folder, 0700.
    storage.make_tmp_dir(FEATURE, repo)
    run = run_folder(repo, train_id)
    for folder in (run, run / MIRROR, run / DATA):
        if not os.path.lexists(folder):
            os.mkdir(folder, 0o700)
            os.chmod(folder, 0o700)
        # 0256: a planted run folder link is refused before anything is made through it.
        reason = _folder_problem(run)
        if reason is not None:
            raise RuntimeError(reason)
    reason = mirror_problem(repo, train_id) or _folder_problem(run / DATA)
    if reason is not None:
        raise RuntimeError(reason)
    return run / MIRROR


def _hex(value: str, size: int) -> bool:
    return len(value) == size and set(value) <= HEX


def _git_text(top: str, args: list[str]) -> str | None:
    # 0256: argv to lib.git, never a shell; None on any git failure or undecodable output.
    try:
        done = git.run(args, top, GIT_TIMEOUT_S)
    except (OSError, UnicodeDecodeError, git.GitTimeout):
        return None
    return done.stdout if done.returncode == 0 else None


def tree_entries(top: str, rev: str) -> list[tuple[bool, str, str, int]] | None:
    # 0256, 0265: (regular file, path, object id, size) of every entry at rev; size -1 when none.
    out = _git_text(top, ["ls-tree", "-r", "-z", "-l", "--full-tree", rev])
    if out is None:
        return None
    found: list[tuple[bool, str, str, int]] = []
    for record in out.split("\0"):
        meta, tab, path = record.partition("\t")
        parts = meta.split()
        if not tab or len(parts) != 4 or not _hex(parts[2], 40):
            continue
        regular = parts[0] in BLOB_MODES and parts[1] == "blob" and parts[3].isdigit()
        found.append((regular, path, parts[2], int(parts[3]) if regular else -1))
    return found


def _tree(top: str, base: str) -> list[tuple[str, str, int]] | None:
    # 0256: (path, blob id, size) of each regular file at base; links and submodules are dropped.
    entries = tree_entries(top, base)
    if entries is None:
        return None
    return [(path, blob, size) for regular, path, blob, size in entries if regular]


def _skipped(path: str, top: str, excluded: tuple[str, ...]) -> bool:
    if any(part in SKIP_DIRS for part in path.split("/")[:-1]):
        return True
    full = os.path.normpath(os.path.join(top, path))
    return any(full == e or full.startswith(e.rstrip(os.sep) + os.sep) for e in excluded)


def _read_root(root: Root, text: str) -> bool:
    # 0256: a top-level provider block, or terraform { required_providers { ... } }.
    found = False
    for block in hcl_reader.parse(text):
        if block.type == "provider" and block.labels:
            found = True
            if set(block.labels[0]) <= LOCAL_NAME_CHARS and block.labels[0] not in root.labels:
                root.labels.append(block.labels[0])
        if block.type != "terraform":
            continue
        for inner in block.blocks:
            if inner.type != "required_providers":
                continue
            found = True
            for name, source in inner.attributes.items():
                if set(name) <= LOCAL_NAME_CHARS:
                    root.required.setdefault(name, source)
    return found


def find_roots(
    top: str, base: str, excluded: tuple[str, ...] = ()
) -> tuple[list[Root], list[str]] | None:
    # 0256: the roots of the base commit's tree, never the disk; None when git cannot list it.
    entries = _tree(top, base)
    if entries is None:
        return None
    folders: dict[str, Root] = {}
    locks: dict[str, str] = {}
    unread: list[str] = []
    for path, blob, size in sorted(entries):
        if size > MAX_TF_BYTES or _skipped(path, top, excluded):
            continue
        folder, _, name = path.rpartition("/")
        if name == LOCK_FILE:
            locks[folder] = blob
        if not name.endswith(".tf"):
            continue
        text = _git_text(top, ["cat-file", "blob", blob])
        root = folders.setdefault(folder, Root(folder))
        try:
            if text is None:
                raise hcl_reader.HclError(0, "unreadable")
            _read_root(root, text)
        except hcl_reader.HclError:
            unread.append(path)
    roots = [r for r in folders.values() if r.required or r.labels]
    for root in roots:
        root.lock = locks.get(root.folder, "")
    return roots, unread


def staged_text(root: Root) -> str:
    # 0256: the base commit's required_providers entries and the provider names, nothing else.
    lines = ["terraform {", "  required_providers {"]
    lines += [f"    {name} = {source}" for name, source in root.required.items()]
    lines += ["  }", "}"]
    lines += [f'provider "{label}" {{}}' for label in root.labels if label not in root.required]
    return "\n".join(lines) + "\n"


def parse_allow(given: str) -> tuple[str, str] | None:
    # 0256: (host/namespace/type, constraint) by typed parts; None refuses the value.
    address, eq, constraint = given.partition("=")
    parts = address.split("/")
    if len(parts) != 3:
        return None
    host, namespace, kind = parts
    labels = host.split(".")
    if not (0 < len(host) <= HOST_MAX and set(host) <= HOST_CHARS and len(labels) > 1):
        return None
    if any(not label or label[0] == "-" or label[-1] == "-" for label in labels):
        return None
    for name in (namespace, kind):
        if not (0 < len(name) <= NAME_MAX and set(name) <= NAME_CHARS and name[0] != "-"):
            return None
    constraint = constraint.strip()
    if eq and not (0 < len(constraint) <= CONSTRAINT_MAX and set(constraint) <= CONSTRAINT_CHARS):
        return None
    return address, constraint


def allowed_text(allowed: list[tuple[str, str]]) -> str:
    # 0256: one required_providers entry per operator-allowed address, and nothing else.
    lines = ["terraform {", "  required_providers {"]
    for index, (address, constraint) in enumerate(allowed, start=1):
        lines += [f"    allowed-{index} = {{", f'      source = "{address}"']
        lines += [f'      version = "{constraint}"'] if constraint else []
        lines.append("    }")
    lines += ["  }", "}"]
    return "\n".join(lines) + "\n"


def _write_new(path: Path, text: str) -> None:
    # 0256: a new file in the fetch's own staging folder, never through a link.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(text)


def _inside(path: str, top: str) -> bool:
    real = _resolved(path)
    return real == top or real.startswith(top + os.sep)


def fetch_env(data: Path, source: dict[str, str], top: str) -> tuple[dict[str, str], list[str]]:
    # 0256: (the environment terraform gets, the caller values never echoed back).
    passed = {k: v for k, v in source.items() if k in PASS_NAMES or k.startswith(PASS_PREFIXES)}
    # 0256: a file or PATH folder the project holds, or a relative one, never reaches terraform.
    for name in PATH_VARS:
        if name in passed and (not os.path.isabs(passed[name]) or _inside(passed[name], top)):
            del passed[name]
    if "PATH" in passed:
        kept = [p for p in passed["PATH"].split(os.pathsep) if os.path.isabs(p)]
        passed["PATH"] = os.pathsep.join(p for p in kept if not _inside(p, top))
    env = {**passed, **FIXED_ENV, "TF_DATA_DIR": str(data)}
    secrets = [v for v in passed.values() if len(v) >= 4]
    for value in passed.values():
        userinfo = value.partition("://")[2].partition("@")
        if userinfo[1] and len(userinfo[0]) >= 4:
            secrets.append(userinfo[0])
    return env, sorted(set(secrets), key=len, reverse=True)


def _printable(text: str) -> str:
    return "".join(ch for ch in text if ch.isprintable())


def first_error(stderr: str, secrets: list[str]) -> str:
    # 0256: the first "Error:" line, else the first non-empty one; caller values withheld.
    lines = [line.strip() for line in stderr.splitlines() if line.strip()]
    pick = next((line for line in lines if line.startswith("Error:")), lines[0] if lines else "")
    for secret in secrets:
        pick = pick.replace(secret, WITHHELD)
    return _printable(pick)[:ERROR_MAX] or "no error text"


def _address_cap(limit: int) -> None:
    # 0265: the child and every provider it starts inherit one address-space ceiling.
    resource.setrlimit(resource.RLIMIT_AS, (limit, limit))


def run_terraform(
    argv: list[str],
    cwd: str,
    env: dict[str, str],
    timeout: float,
    keep_stdout: bool = False,
    memory: int = 0,
) -> tuple[int, str, str]:
    # 0256: argv as a list, no shell; on a timeout the whole process group is killed.
    proc = subprocess.Popen(
        argv,
        preexec_fn=(lambda: _address_cap(memory)) if memory else None,
        cwd=cwd,
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE if keep_stdout else subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    try:
        out, err = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        os.killpg(proc.pid, signal.SIGKILL)
        proc.communicate()
        return -1, "", f"Error: terraform did not finish within {timeout:g} seconds"
    decoded = (out or b"")[:OUTPUT_MAX].decode("utf-8", errors="replace")
    return proc.returncode, decoded, err[:OUTPUT_MAX].decode("utf-8", errors="replace")


def _run(argv: list[str], cwd: str, env: dict[str, str], timeout: float) -> tuple[int, str]:
    code, _, err = run_terraform(argv, cwd, env, timeout)
    return code, err


def terraform_path(repo: str, search: str) -> str | None:
    # 0256: the absolute terraform the session PATH names, never one inside the project.
    found = shutil.which("terraform", path=search) if search else None
    if found is None or not os.path.isabs(found):
        return None
    real = _resolved(found)
    top = _resolved(repo)
    if real == top or real.startswith(top + os.sep) or not os.path.isfile(real):
        return None
    return real


def _base(top: str, train_id: str) -> str:
    # 0256: the run's recorded base commit, 40 hex, or "" when the state holds none.
    try:
        value = train_state.load(Path(top), train_id).get("base_sha")
    except train_state.TrainStateError:
        return ""
    return value if isinstance(value, str) and _hex(value, 40) else ""


def _stage(top: str, run: Path, roots: list[Root]) -> list[tuple[str, Path]]:
    # 0256: one fresh folder per root holding the generated file and the base lock file.
    stage = Path(tempfile.mkdtemp(prefix="source-", dir=run))
    staged: list[tuple[str, Path]] = []
    for index, root in enumerate(roots):
        folder = stage / str(index)
        os.mkdir(folder, 0o700)
        _write_new(folder / STAGED_TF, staged_text(root))
        lock = _git_text(top, ["cat-file", "blob", root.lock]) if root.lock else None
        if lock is not None:
            _write_new(folder / LOCK_FILE, lock)
        staged.append((_printable(root.folder) or ".", folder))
    return staged


def _stage_allowed(run: Path, allowed: list[tuple[str, str]]) -> list[tuple[str, Path]]:
    folder = Path(tempfile.mkdtemp(prefix="allowed-", dir=run))
    _write_new(folder / STAGED_TF, allowed_text(allowed))
    return [(", ".join(a for a, _ in allowed), folder)]


def fetch(
    repo: str,
    train_id: str,
    excluded: tuple[str, ...],
    source: dict[str, str],
    timeout: float | None = None,
    allowed: list[tuple[str, str]] | None = None,
) -> list[str]:
    # 0256: one plain line per root; a failure is a warning with a Next line, never a stop.
    timeout = FETCH_TIMEOUT_S if timeout is None else timeout
    top = _resolved(repo)
    rerun = NEXT_RERUN.format(repo=top)
    lines: list[str] = []
    roots: list[Root] = []
    base = _base(top, train_id)
    if not allowed:
        found = find_roots(top, base, excluded) if base else None
        if found is None:
            lines.append(
                "warning: providers: the run's base commit could not be read, so nothing was "
                f"fetched. {rerun}"
            )
        else:
            roots, unread = found
            lines += [
                f"providers: {_printable(p)} was not read; the Terraform reader could not parse it."
                for p in unread
            ]
    work = bool(roots or allowed)
    binary = terraform_path(top, source.get("PATH", ""))
    staged: list[tuple[str, Path]] = []
    try:
        mirror = make_mirror(top, train_id)
        if work and binary is not None:
            staged = _stage_allowed(mirror.parent, allowed) if allowed else []
            staged = staged or _stage(top, mirror.parent, roots)
    except (OSError, RuntimeError) as exc:
        lines.append(f"warning: providers: the mirror folder could not be made ({exc}). {rerun}")
        work = False
    if work and binary is None:
        lines.append(
            "warning: providers: no terraform outside the project is on PATH, so nothing "
            f"was fetched. {rerun}"
        )
    tried: list[dict[str, str]] = []
    if staged:
        env, secrets = fetch_env(mirror.parent / DATA, source, top)
        argv = [str(binary), "providers", "mirror", "-no-color", str(mirror)]
        for name, folder in staged:
            try:
                code, err = _run(argv, str(folder), env, timeout)
            except OSError as exc:
                code, err = -1, f"Error: terraform could not start ({exc.strerror})"
            if code == 0:
                tried.append({"folder": name, "result": "ok"})
                lines.append(f"providers: {name}: fetched into the run's mirror.")
                continue
            error = first_error(err, secrets)
            tried.append({"folder": name, "result": "failed", "error": error})
            lines.append(f"warning: providers: {name}: not fetched ({error}). {rerun}")
    if not lines and not tried:
        lines.append("providers: no Terraform root folder was found, so nothing was fetched.")
    _record(top, train_id, base, tried, allowed, lines)
    return lines


def _record(
    top: str,
    train_id: str,
    base: str,
    tried: list[dict[str, str]],
    allowed: list[tuple[str, str]] | None,
    lines: list[str],
) -> None:
    # 0256: a base fetch replaces roots; an allowed fetch appends each address the operator gave.
    result = tried[0]["result"] if tried else "not fetched"

    def edit(state: dict[str, object]) -> None:
        old = state.get(STATE_KEY)
        record: dict[str, object] = dict(old) if isinstance(old, dict) else {}
        if allowed:
            prior = record.get("allowed")
            entries = list(prior) if isinstance(prior, list) else []
            entries += [
                {"address": a, "constraint": c, "allowed_by": "operator", "result": result}
                for a, c in allowed
            ]
            record["allowed"] = entries
        else:
            record.update({"base": base, "roots": tried})
        state[STATE_KEY] = record

    try:
        train_state.change(Path(top), train_id, edit)
    except train_state.TrainStateError as exc:
        lines.append(f"warning: providers: the run state was not updated ({exc})")
