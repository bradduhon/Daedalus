#!/usr/bin/env python3
# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from collections.abc import Iterator
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from lib.audit import (  # noqa: E402
    DataDirError,
    cache_dir_matches,
    cache_dir_or_probe,
    check_project_data_dir,
    project_data_dir,
    project_root,
)
from lib.config import Config, ConfigError, load_config  # noqa: E402
from lib.ledger import LedgerError, resolve_ledger  # noqa: E402
from lib.sandbox_state import (  # noqa: E402
    SettingsError,
    required_binaries,
    sandbox_line,
    sandbox_state,
)

REQ_DOC = "docs/project-requirements.md"
SANDBOX_NEXT = "install bubblewrap and socat, then run /daedalus:setup to turn the sandbox on"
GH_NEXT = "install gh (https://cli.github.com); the Push Train opens pull requests with it"
NO_LEDGER = "OK   ledger: none found (the Build Train asks before creating docs/decisions.md)"
PROJECT_DATA_NEXT = "write a single line * to {marker}"
IGNORE_NEXT = (
    "from your own shell, untrack it with git rm -r --cached .claude/daedalus, "
    "then restore the * marker"
)
CACHE_NAMING = (
    "a --plugin-dir session uses daedalus-inline; a marketplace install uses daedalus-<marketplace>"
)


def _check(ok: bool, name: str, missing: str, nxt: str) -> tuple[bool, str]:
    if ok:
        return True, f"OK   {name}"
    return False, f"MISS {name}: {missing}. Next: {nxt}"


def _git(repo: Path, *args: str) -> subprocess.CompletedProcess[str]:
    cmd = ["git", "-C", str(repo), *args]
    try:
        return subprocess.run(cmd, capture_output=True, text=True, check=False)
    except FileNotFoundError:
        # 0007: git off PATH reports a MISS instead of crashing the doctor.
        return subprocess.CompletedProcess(cmd, 127, "", "git not found")


def _cache_check() -> tuple[bool, str]:
    # 0010: machine caches only; informational, OK whether or not one exists yet.
    env = os.environ.get("CLAUDE_PLUGIN_DATA")
    matches = [str(m) for m in cache_dir_matches()]
    if env:
        found = f"CLAUDE_PLUGIN_DATA={env}"
    elif matches:
        found = ", ".join(matches)
    else:
        found = f"none yet (create it with scripts/refresh_nist_oscal.py or by hand per {REQ_DOC})"
    if not env and len(matches) > 1:
        found += f" ({CACHE_NAMING})"
    return True, f"OK   cache dir: {found}"


def _plugin_root_check() -> tuple[bool, str]:
    # P8: informational; README readers copy the plugin root from this line.
    return True, f"OK   plugin root: {Path(__file__).resolve().parent.parent}"


def _sandbox_check(repo: Path) -> tuple[bool, str]:
    # 0020: the sandbox is optional; the line names /daedalus:setup when it is not on.
    try:
        return sandbox_line(sandbox_state(repo))
    except SettingsError as exc:
        return False, f"MISS sandbox: {exc}"


def _gh_checks() -> Iterator[tuple[bool, str]]:
    # spec 5: the Push Train needs gh on PATH and signed in; no auth probe without gh (P11).
    on_path = shutil.which("gh") is not None
    yield _check(on_path, "gh on PATH", "not found", GH_NEXT)
    if not on_path:
        yield _check(
            False, "gh authenticated", "gh not on PATH", "install gh, then run gh auth login"
        )
        return
    try:
        status = subprocess.run(
            ["gh", "auth", "status"], capture_output=True, text=True, timeout=10, check=False
        )
        code = status.returncode
    except (OSError, subprocess.SubprocessError):
        code = -1
    yield _check(
        code == 0, "gh authenticated", f"gh auth status exited {code}", "run gh auth login"
    )


def _trust_error(repo: Path) -> DataDirError | None:
    try:
        check_project_data_dir(str(repo))
    except DataDirError as exc:
        return exc
    return None


def _data_checks(repo: Path, is_repo: bool) -> Iterator[tuple[bool, str]]:
    data = project_data_dir(str(repo))
    err = _trust_error(repo)
    if err is not None and err.kind == "symlink":
        yield False, f"MISS project data dir: {err}"
        yield False, "MISS config.json: not read; the data dir failed a check. Next: fix it first"
        return
    if not data.exists():
        yield True, f"OK   project data dir: {data} (will be created by the first hook)"
        yield from _config_checks(data)
        return
    if not (data.is_dir() and os.access(data, os.R_OK | os.X_OK)):
        yield _check(
            False, "project data dir", f"{data} is not a readable directory", f"fix {data}"
        )
        return
    yield True, f"OK   project data dir: {data} (exists)"
    marker = data / ".gitignore"
    try:
        marked = marker.read_text(encoding="utf-8") in ("*", "*\n")
    except (OSError, UnicodeDecodeError):
        marked = False
    yield _check(
        marked,
        "data dir .gitignore marker",
        f"{marker} does not hold exactly *",
        PROJECT_DATA_NEXT.format(marker=marker),
    )
    if is_repo:
        # 0010: probe a child path; check-ignore never matches the directory itself.
        probe = _git(project_root(str(repo)), "check-ignore", "-q", str(data / "config.json"))
        tracked = err is not None and err.kind == "tracked"
        yield _check(
            probe.returncode == 0 and not tracked,
            "data dir ignored by git",
            ".claude/daedalus is tracked by git or not ignored",
            IGNORE_NEXT,
        )
    if err is not None:
        yield False, "MISS config.json: not read; the data dir failed a check. Next: fix it first"
        return
    yield from _config_checks(data)


def _ledger_probe(root: Path, config: Config) -> tuple[bool, str]:
    # 0004: without config.json the convention probe is the ledger source.
    try:
        found = resolve_ledger(str(root), config)
    except LedgerError as exc:
        return False, f"MISS ledger: {exc}"
    if found is None:
        return True, NO_LEDGER
    return True, f"OK   ledger: {found.path} ({found.origin}, {found.format})"


def _config_checks(data: Path) -> Iterator[tuple[bool, str]]:
    cfg_path = data / "config.json"
    try:
        config: Config = load_config(path=cfg_path)
    except ConfigError as exc:
        yield False, f"MISS config.json: {exc}"
        return
    if cfg_path.exists():
        yield True, "OK   config.json"
    else:
        # spec 9: config.json is optional; absence means the defaults.
        yield True, "OK   config.json: not present, defaults in use"
    if config.ledger is not None:
        yield True, "OK   ledger declared"
    else:
        # spec 5, 9: no declared ledger means the convention probe, config.json or not.
        yield _ledger_probe(data.parent.parent, config)
    # spec 5 (P9): standards_sources and policy are optional; undeclared is not a miss.
    if config.standards_sources:
        yield True, "OK   standards_sources declared"
    else:
        yield True, "OK   standards_sources: not declared (optional)"
    if config.policy is not None:
        yield True, "OK   policy declared"
    else:
        yield True, "OK   policy: not declared (optional)"


def _is_repo(repo: Path) -> bool:
    inside = _git(repo, "rev-parse", "--is-inside-work-tree")
    return inside.returncode == 0 and inside.stdout.strip() == "true"


def _repo_checks(repo: Path, is_repo: bool) -> Iterator[tuple[bool, str]]:
    yield _check(
        is_repo,
        "git repository",
        f"{repo} is not a git repository",
        "run git init or point --repo at a clone",
    )
    if is_repo:
        status = _git(repo, "status", "--porcelain")
        yield _check(
            status.returncode == 0 and status.stdout.strip() == "",
            "clean working tree",
            "uncommitted changes present",
            "commit or stash before starting a train",
        )
    yield _check(
        (repo / "service-manifest.json").exists(),
        "service-manifest.json",
        "not found at repo root",
        f"create it from the example in {REQ_DOC}",
    )
    yield _check(
        (repo / "contracts").is_dir(),
        "contracts/",
        "directory missing",
        "mkdir contracts and add openapi.yaml or events/*.schema.json",
    )
    yield _check(
        (repo / ".gitleaks.toml").exists(),
        ".gitleaks.toml",
        "not found at repo root",
        f"copy the baseline from {REQ_DOC}",
    )


def checks(repo: Path) -> Iterator[tuple[bool, str]]:
    yield _check(
        sys.version_info >= (3, 12),
        "python >= 3.12",
        f"found {sys.version.split()[0]}",
        "install Python 3.12 and ensure python3 resolves to it",
    )
    is_repo = _is_repo(repo)
    yield from _data_checks(repo, is_repo)
    yield _cache_check()
    yield _plugin_root_check()
    yield _sandbox_check(repo)
    yield _check(
        shutil.which("gitleaks") is not None,
        "gitleaks on PATH",
        "not found",
        "the Push Train scans commits with gitleaks; install it so the scan can run",
    )
    yield from _gh_checks()
    # 0020: macOS sandboxes without bwrap and socat, so it gets no binary lines.
    for tool in required_binaries():
        yield _check(shutil.which(tool) is not None, f"{tool} on PATH", "not found", SANDBOX_NEXT)
    yield from _repo_checks(repo, is_repo)


def print_cache_dir() -> int:
    # R1-I1: skills never see CLAUDE_PLUGIN_DATA; this prints the path they paste into prompts.
    try:
        print(cache_dir_or_probe())
    except RuntimeError as exc:
        print(exc, file=sys.stderr)
        return 1
    return 0


def print_sandbox_state(repo: Path) -> int:
    # 0020: the trains read this one word to pick their sandbox gate.
    try:
        print(sandbox_state(repo))
    except SettingsError as exc:
        print(exc, file=sys.stderr)
        return 1
    return 0


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="daedalus first-run check. Changes nothing.")
    parser.add_argument(
        "--repo", default=".", help="target repository (default: current directory)"
    )
    parser.add_argument(
        "--print-cache-dir",
        action="store_true",
        help="print the plugin cache directory as one absolute path and exit",
    )
    parser.add_argument(
        "--sandbox-state",
        action="store_true",
        help="print the sandbox state (on, off or configured-unavailable) and exit",
    )
    args = parser.parse_args(argv)
    if args.print_cache_dir:
        return print_cache_dir()
    if args.sandbox_state:
        return print_sandbox_state(Path(args.repo).resolve())
    all_ok = True
    for ok, line in checks(Path(args.repo).resolve()):
        print(line)
        all_ok = all_ok and ok
    print(
        "daedalus doctor: all checks passed"
        if all_ok
        else "daedalus doctor: fix each MISS line, then rerun"
    )
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
