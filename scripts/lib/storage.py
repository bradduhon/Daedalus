# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0252: the two storage places for every feature; temporary under TMP_ROOT, persistent in the
# plugin data folder, nothing inside a project. Loads no audit code at import time (hook import).
from __future__ import annotations

import hashlib
import os
import stat
from pathlib import Path

from lib.project_root import project_root

TMP_ROOT = Path("/tmp/.daedalus")
# 0221: the allow list of feature folder names; a name outside it is refused.
FEATURES: tuple[str, ...] = (
    "self-assessment",
    "question-path",
    "developer-profile",
    "reports",
    "provider-mirror",
    "settings-backup",
)


def _uid() -> int:
    # One user id source for the folder name and the ownership check.
    return os.geteuid()


def _feature(feature: str) -> str:
    if feature not in FEATURES:
        raise ValueError(f"feature {feature!r} is not one of {', '.join(FEATURES)}")
    return feature


def project_key(path: str | Path) -> str:
    # A1: the resolved project root the finder gives, else the resolved path itself.
    given = Path(path)
    root = project_root(given) if given.exists() else given
    return hashlib.sha256(str(root.resolve()).encode("utf-8")).hexdigest()[:16]


def _chain(feature: str, repo_root: str | Path) -> list[Path]:
    # The uid folder and each folder below it, top first.
    uid_dir = TMP_ROOT / str(_uid())
    feature_dir = uid_dir / _feature(feature)
    return [uid_dir, feature_dir, feature_dir / project_key(repo_root)]


def tmp_dir(feature: str, repo_root: str | Path) -> Path:
    return _chain(feature, repo_root)[-1]


def check_tmp_dirs(feature: str, repo_root: str | Path) -> str | None:
    # A1: refuse a link on the path, or a folder not ours or open to group or others.
    if TMP_ROOT.is_symlink():
        return f"{TMP_ROOT} is a symlink"
    uid = _uid()
    try:
        root = TMP_ROOT.lstat()
    except FileNotFoundError:
        root = None
    except OSError as exc:
        return f"{TMP_ROOT} could not be read ({exc.strerror})"
    if root is not None:
        if not stat.S_ISDIR(root.st_mode):
            return f"{TMP_ROOT} is not a folder"
        if root.st_uid not in (uid, 0):
            return f"{TMP_ROOT} belongs to another user of this machine"
    for folder in _chain(feature, repo_root):
        try:
            info = folder.lstat()
        except FileNotFoundError:
            continue
        except OSError as exc:
            return f"{folder} could not be read ({exc.strerror})"
        if stat.S_ISLNK(info.st_mode):
            return f"{folder} is a symlink"
        if not stat.S_ISDIR(info.st_mode):
            return f"{folder} is not a folder"
        if info.st_uid != uid:
            return f"{folder} is not owned by you"
        if info.st_mode & 0o022:
            return f"{folder} can be written by group or others"
    return None


def make_tmp_dir(feature: str, repo_root: str | Path) -> Path:
    if not os.path.lexists(TMP_ROOT):
        TMP_ROOT.mkdir(parents=True, exist_ok=True, mode=0o700)
        TMP_ROOT.chmod(0o700)
    # The root is judged before anything is made below it, and again after.
    reason = check_tmp_dirs(feature, repo_root)
    if reason is not None:
        raise RuntimeError(reason)
    for folder in _chain(feature, repo_root):
        if not os.path.lexists(folder):
            os.mkdir(folder, 0o700)
            os.chmod(folder, 0o700)
    reason = check_tmp_dirs(feature, repo_root)
    if reason is not None:
        raise RuntimeError(reason)
    return tmp_dir(feature, repo_root)


def data_dir(feature: str, repo_root: str | Path | None = None) -> Path:
    # A1: imported here so the module loads no audit code at import time.
    from lib.audit import cache_dir_or_probe

    # The allow-list check runs before the folder lookup, so a bad name is refused on any machine.
    name = _feature(feature)
    base = cache_dir_or_probe() / name
    return base if repo_root is None else base / project_key(repo_root)


def make_data_dir(feature: str, repo_root: str | Path | None = None) -> Path:
    # Mode 0700 for each folder this call creates, from the feature folder down.
    target = data_dir(feature, repo_root)
    for folder in reversed([target, *target.parents][: 1 if repo_root is None else 2]):
        if not folder.exists():
            os.mkdir(folder, 0o700)
            os.chmod(folder, 0o700)
    return target
