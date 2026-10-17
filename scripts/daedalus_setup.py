#!/usr/bin/env python3
# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import argparse
import errno
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from lib.sandbox_state import SettingsError, missing_binaries  # noqa: E402
from lib.settings_merge import (  # noqa: E402
    SettingsMergeError,
    merge,
    read_settings,
    render,
    unified_diff,
    write_atomic,
)

PLUGIN_ROOT = Path(__file__).resolve().parent.parent
OS_RELEASE = Path("/etc/os-release")
PACKAGES = {"bwrap": "bubblewrap", "socat": "socat"}
# spec 4: os-release values may sit in double or single quotes.
_QUOTES = str.maketrans("\"'", "  ")


def _debian_family(os_release: Path) -> bool:
    try:
        text = os_release.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return False
    fields = dict(line.split("=", 1) for line in text.splitlines() if "=" in line)
    ids = f"{fields.get('ID', '')} {fields.get('ID_LIKE', '')}".translate(_QUOTES)
    return bool({"debian", "ubuntu"} & set(ids.split()))


def install_line(missing: list[str], os_release: Path) -> str:
    packages = " ".join(PACKAGES[name] for name in missing)
    if _debian_family(os_release):
        return f"run sudo apt-get install -y {packages}"
    return f"install the packages {packages} with your distribution's package manager"


LOCAL = Path(".claude") / "settings.local.json"
DENIED = frozenset({errno.EACCES, errno.EPERM, errno.EROFS})


def _git(cwd: Path, *args: str) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            ["git", "-C", str(cwd), *args], capture_output=True, text=True, timeout=30, check=False
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return subprocess.CompletedProcess(["git"], 127, "", str(exc))


def _default_repo() -> Path | None:
    out = _git(Path.cwd(), "rev-parse", "--path-format=absolute", "--git-common-dir")
    common = out.stdout.strip()
    return Path(common).parent if out.returncode == 0 and common else None


def _ignore_refusal(repo: Path) -> str | None:
    # 0027: a settings file git would track must never be written.
    code = _git(repo, "check-ignore", "-q", str(LOCAL)).returncode
    if code == 0:
        return None
    if code == 1:
        return (
            f"daedalus setup: {LOCAL} is not git-ignored in {repo}; nothing written. "
            f"Next: add {LOCAL} to .gitignore, then rerun /daedalus:setup"
        )
    return (
        f"daedalus setup: {repo} is not a git repository; nothing written. "
        "Next: pass --repo with the repository root, then rerun /daedalus:setup"
    )


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        description="Merge the Daedalus settings into <repo>/.claude/settings.local.json."
    )
    parser.add_argument("--repo", type=Path, default=None)
    parser.add_argument(
        "--recommended", type=Path, default=PLUGIN_ROOT / "settings.recommended.json"
    )
    parser.add_argument("--os-release", type=Path, default=OS_RELEASE)
    args = parser.parse_args(argv)
    # 0020: failIfUnavailable before the binaries exist kills Bash in every session.
    missing = missing_binaries()
    if missing:
        print(
            f"daedalus setup: {', '.join(missing)} not on PATH; nothing written. "
            f"Next: {install_line(missing, args.os_release)}, "
            "then run the Daedalus setup again (/daedalus:setup)"
        )
        return 1
    repo = args.repo.resolve() if args.repo is not None else _default_repo()
    if repo is None:
        print(
            "daedalus setup: the current directory is not inside a git repository; nothing "
            "written. Next: cd into the repository, then rerun /daedalus:setup"
        )
        return 1
    refusal = _ignore_refusal(repo)
    if refusal:
        print(refusal)
        return 1
    # 0027, 0029: the repo's own settings.local.json is the only file setup writes.
    target = repo / LOCAL
    try:
        existing = read_settings(target)
        merged = merge(existing, read_settings(args.recommended))
    except (SettingsMergeError, SettingsError) as exc:
        print(f"daedalus setup: {exc}", file=sys.stderr)
        return 1
    if merged == existing:
        print(f"daedalus setup: {target} already holds the recommended settings; nothing written.")
        return 0
    old = target.read_text(encoding="utf-8") if target.exists() else ""
    new = render(merged)
    try:
        write_atomic(target, new, repo)
    except SettingsMergeError as exc:
        print(f"daedalus setup: {exc}", file=sys.stderr)
        return 1
    except OSError as exc:
        if exc.errno not in DENIED:
            raise
        print(
            f"daedalus setup: cannot write {target} ({errno.errorcode[exc.errno]}); the sandbox "
            f"protects settings files. Next: run python3 {PLUGIN_ROOT}/scripts/daedalus_setup.py "
            f"--repo {repo} from your own shell"
        )
        return 1
    print(unified_diff(old, new, target), end="")
    print("Restart Claude Code to apply")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
