# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0256: the run fetches Terraform providers once, outside the kernel wrapper, into a mirror under
# the run's temporary folder; the wrapper grants that one folder read-only (issue 200).
from __future__ import annotations

import os
import shutil
import signal
import stat
import subprocess
from dataclasses import dataclass
from pathlib import Path

from lib import hcl_reader, storage, train_state

FEATURE = "provider-mirror"
MIRROR, DATA = "mirror", "tf-data"
# 0256: the train state key the fetch records under; roots tried, ok or failed, never an env.
STATE_KEY = "providers"
FETCH_TIMEOUT_S = 600
MAX_TF_BYTES = 1 << 20
ERROR_MAX = 200
# 0256: folders the root walk never enters; a symlinked folder is never entered either.
SKIP_DIRS = frozenset({".git", ".terraform", ".claude"})
# 0256: the caller variables terraform may need for a fetch; every other one is dropped.
PASS_NAMES = frozenset(
    {"HOME", "PATH", "TF_CLI_CONFIG_FILE", "SSL_CERT_FILE", "SSL_CERT_DIR"}
    | {"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "NO_PROXY", "no_proxy"}
)
PASS_PREFIXES = ("TF_TOKEN_",)
FIXED_ENV = {"CHECKPOINT_DISABLE": "1", "TF_IN_AUTOMATION": "1", "TF_INPUT": "0"}
# 0256: the characters a mirror path may hold, so the CLI config string needs no escaping.
PATH_CHARS = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/._-")
WITHHELD = "[withheld]"
R_MIRROR_OUTSIDE = "{path} resolves outside the run's temporary folder"
R_MIRROR_NOT_GRANTED = (
    "not granted: {reason}. Next: remove {run} from your own shell, then rerun "
    "daedalus_train.py providers from the main session."
)
R_PROVIDERS_NO_RUN = (
    "providers: no run is marked in {root}. Next: start a run first; the build phase runs this "
    "command after the plan is recorded."
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
    reason = mirror_problem(repo, train_id) or _folder_problem(run / DATA)
    if reason is not None:
        raise RuntimeError(reason)
    return run / MIRROR


def _defines_providers(text: str) -> bool:
    # 0256: a top-level provider block, or terraform { required_providers { ... } }.
    for block in hcl_reader.parse(text):
        if block.type == "provider":
            return True
        if block.type == "terraform" and any(b.type == "required_providers" for b in block.blocks):
            return True
    return False


def _tf_file(path: str) -> str | None:
    # 0256: a regular .tf file of at most MAX_TF_BYTES, never followed through a link.
    try:
        info = os.lstat(path)
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_TF_BYTES:
            return None
        with open(path, "rb") as handle:
            return handle.read(MAX_TF_BYTES).decode("utf-8")
    except (OSError, UnicodeDecodeError):
        return None


def _excluded(path: str, excluded: tuple[str, ...]) -> bool:
    return any(path == e or path.startswith(e.rstrip(os.sep) + os.sep) for e in excluded)


def find_roots(repo: str, excluded: tuple[str, ...] = ()) -> tuple[list[str], list[str]]:
    # 0256: (root folders, unreadable files), absolute and sorted; the walk follows no link.
    top = _resolved(repo)
    roots: list[str] = []
    unread: list[str] = []
    for folder, dirs, files in os.walk(top, followlinks=False):
        dirs[:] = sorted(
            d
            for d in dirs
            if d not in SKIP_DIRS
            and not os.path.islink(os.path.join(folder, d))
            and not _excluded(os.path.join(folder, d), excluded)
        )
        if _excluded(folder, excluded) or _resolved(folder) != folder:
            continue
        if not (folder == top or folder.startswith(top + os.sep)):
            continue
        for name in sorted(f for f in files if f.endswith(".tf")):
            text = _tf_file(os.path.join(folder, name))
            try:
                found = text is not None and _defines_providers(text)
            except hcl_reader.HclError:
                unread.append(os.path.join(folder, name))
                continue
            if found:
                roots.append(folder)
                break
    return roots, unread


def fetch_env(data: Path, source: dict[str, str]) -> tuple[dict[str, str], list[str]]:
    # 0256: (the environment terraform gets, the caller values never echoed back).
    passed = {k: v for k, v in source.items() if k in PASS_NAMES or k.startswith(PASS_PREFIXES)}
    env = {**passed, **FIXED_ENV, "TF_DATA_DIR": str(data)}
    secrets = [v for v in passed.values() if len(v) >= 4]
    for value in passed.values():
        userinfo = value.partition("://")[2].partition("@")
        if userinfo[1] and len(userinfo[0]) >= 4:
            secrets.append(userinfo[0])
    return env, sorted(set(secrets), key=len, reverse=True)


def first_error(stderr: str, secrets: list[str]) -> str:
    # 0256: the first "Error:" line, else the first non-empty one; caller values withheld.
    lines = [line.strip() for line in stderr.splitlines() if line.strip()]
    pick = next((line for line in lines if line.startswith("Error:")), lines[0] if lines else "")
    for secret in secrets:
        pick = pick.replace(secret, WITHHELD)
    text = "".join(ch for ch in pick if ch.isprintable())
    return text[:ERROR_MAX] or "no error text"


def _run(argv: list[str], cwd: str, env: dict[str, str], timeout: float) -> tuple[int, str]:
    # 0256: argv as a list, no shell; on a timeout the whole process group is killed.
    proc = subprocess.Popen(
        argv,
        cwd=cwd,
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    try:
        _, err = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        os.killpg(proc.pid, signal.SIGKILL)
        proc.communicate()
        return -1, f"Error: terraform did not finish within {timeout:g} seconds"
    return proc.returncode, err.decode("utf-8", errors="replace")


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


def _rel(folder: str, top: str) -> str:
    return os.path.relpath(folder, top)


def fetch(
    repo: str,
    train_id: str,
    excluded: tuple[str, ...],
    source: dict[str, str],
    timeout: float | None = None,
) -> list[str]:
    # 0256: one plain line per root; a failure is a warning with a Next line, never a stop.
    timeout = FETCH_TIMEOUT_S if timeout is None else timeout
    top = _resolved(repo)
    rerun = NEXT_RERUN.format(repo=top)
    record: dict[str, object] = {}
    lines: list[str] = []
    roots, unread = find_roots(top, excluded)
    lines += [
        f"providers: {_rel(path, top)} was not read; the Terraform reader could not parse it."
        for path in unread
    ]
    binary = terraform_path(top, source.get("PATH", ""))
    try:
        mirror = make_mirror(top, train_id)
    except (OSError, RuntimeError) as exc:
        record["error"] = first_error(str(exc), [])
        lines.append(f"warning: providers: the mirror folder could not be made ({exc}). {rerun}")
        roots = []
    else:
        if binary is None and roots:
            record["error"] = "terraform is not on PATH, or is inside the project"
            lines.append(
                "warning: providers: no terraform outside the project is on PATH, so nothing "
                f"was fetched. {rerun}"
            )
            roots = []
    tried: list[dict[str, str]] = []
    if roots and binary is not None:
        env, secrets = fetch_env(mirror.parent / DATA, source)
        argv = [binary, "providers", "mirror", "-no-color", str(mirror)]
        for root in roots:
            name = _rel(root, top)
            try:
                code, err = _run(argv, root, env, timeout)
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
    record["roots"] = tried
    try:
        train_state.update(Path(top), train_id, **{STATE_KEY: record})
    except train_state.TrainStateError as exc:
        lines.append(f"warning: providers: the run state was not updated ({exc})")
    return lines
