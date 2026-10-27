#!/usr/bin/env python3
# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import argparse
import json
import os
import shlex
import shutil
import subprocess
import sys
from collections.abc import Iterator
from datetime import UTC, date, datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import daedalus_confine  # noqa: E402
from lib import git, packs  # noqa: E402
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
from lib.manifest import ManifestError, PrioritiesError  # noqa: E402
from lib.manifest import load as load_manifest  # noqa: E402
from lib.plan_record import is_need  # noqa: E402
from lib.workspace import _BARE_VERSION, UNMARK_NEXT, VERSION_FILE, train_marker  # noqa: E402

REQ_DOC = "docs/project-requirements.md"
GH_NEXT = "install gh (https://cli.github.com); the Push Train opens pull requests with it"
GH_TIMEOUT_S = 10
TYPECHECK_TIMEOUT_S = 120
GH_STUCK_NEXT = "run gh auth status from your own shell, then gh auth login if it asks"
GH_OFF = ", and features.github is off in service-manifest.json"
CLAUDE_TIMEOUT_S = 10
# 0122: code.claude.com/docs/en/hooks, Command hook fields: onFailure needs v2.1.295 or later.
ON_FAILURE_MIN = (2, 1, 295)
NO_LEDGER = "OK   ledger: none found (the Build Train asks before creating docs/decisions.md)"
PROJECT_DATA_NEXT = "write a single line * to {marker}"
IGNORE_NEXT = (
    "from your own shell, untrack it with git rm -r --cached .claude/daedalus, "
    "then restore the * marker"
)
DIRTY_LIMIT = 10
PACK_OFFER = (
    'to adopt the shipped baseline pack, add {"kind": "pack", "name": "baseline"} '
    "to standards_sources in .claude/daedalus/config.json"
)
ENABLEMENT = ".claude/settings.json"
ENABLEMENT_NEXT = f"commit {ENABLEMENT}; it holds the enabledPlugins entry /plugin install wrote"
# 0076: the setup skill writes whichever starter file is missing; the doctor never writes one.
SETUP_NEXT = "run the Daedalus setup skill (/daedalus:setup) to write a starter {name}"
# 0095: a local clone added as a marketplace caches under its marketplace name.
CACHE_NAMING = (
    "a --plugin-dir session uses daedalus-inline; a marketplace install, the published one or a "
    "local clone added with claude plugin marketplace add <clone path>, uses "
    "daedalus-<marketplace>"
)
GITLEAKS_NEXT = "the Push Train scans commits with gitleaks; install it so the scan can run"
SCAN_OFF_NEXT = (
    "to scan pushes for secrets, set secrets_scan to true in the features object of "
    "service-manifest.json, then install gitleaks"
)


def _check(ok: bool, name: str, missing: str, nxt: str) -> tuple[bool, str]:
    if ok:
        return True, f"OK   {name}"
    return False, f"MISS {name}: {missing}. Next: {nxt}"


def _opt(ok: bool, name: str, missing: str, nxt: str) -> tuple[bool, str]:
    # 0007: optional scaffold; no train reads it, so absence never fails the doctor.
    if ok:
        return True, f"OK   {name}"
    return True, f"OPT  {name}: {missing}. Next: {nxt}"


def _git(repo: Path, *args: str) -> subprocess.CompletedProcess[str]:
    cmd = ["git", "-C", str(repo), *args]
    try:
        return git.run(args, repo)
    except FileNotFoundError:
        # 0007: git off PATH reports a MISS instead of crashing the doctor.
        return subprocess.CompletedProcess(cmd, 127, "", "git not found")
    except git.GitTimeout:
        return subprocess.CompletedProcess(cmd, 124, "", "git timed out")


def _cache_check() -> tuple[bool, str]:
    # 0010: machine caches only; informational, OK whether or not one exists yet.
    env = os.environ.get("CLAUDE_PLUGIN_DATA")
    matches = [str(m) for m in cache_dir_matches()]
    if env:
        found = f"CLAUDE_PLUGIN_DATA={env}"
    elif matches:
        found = ", ".join(matches)
    else:
        found = f"none yet (create it with scripts/refresh_frameworks.py or by hand per {REQ_DOC})"
    if not env and len(matches) > 1:
        found += f" ({CACHE_NAMING})"
    return True, f"OK   cache dir: {found}"


FRAMEWORK_FAMILIES = ("nist", "owasp", "cis")
FRAMEWORK_MAX_DAYS = 90
REFRESH_NEXT = "refresh the framework caches with python3 <plugin>/scripts/refresh_frameworks.py"
CIS_NEXT = (
    f"build a CIS id-map pack with python3 <plugin>/scripts/import_pack.py cis-map per {REQ_DOC}"
)


def _oldest_pin(manifest: Path) -> date | None:
    try:
        entries = json.loads(manifest.read_text(encoding="utf-8"))
        pins = [date.fromisoformat(e["pinned_on"]) for e in entries]
    except (OSError, ValueError, TypeError, KeyError, UnicodeDecodeError):
        return None
    return min(pins) if isinstance(entries, list) and pins else None


def _framework_checks(cache: Path, today: date) -> Iterator[tuple[bool, str]]:
    # 0026: one line per family manifest; OLD past 90 days never fails the doctor.
    for family in FRAMEWORK_FAMILIES:
        manifest = cache / "frameworks" / family / "manifest.json"
        if not manifest.is_file():
            continue
        nxt = CIS_NEXT if family == "cis" else REFRESH_NEXT
        name = f"frameworks {family}"
        pinned = _oldest_pin(manifest)
        if pinned is None:
            yield True, f"OLD  {name}: manifest.json has no list of pinned_on dates. Next: {nxt}"
            continue
        days = (today - pinned).days
        if days > FRAMEWORK_MAX_DAYS:
            yield True, f"OLD  {name}: pinned {pinned} ({days} days). Next: {nxt}"
        else:
            yield True, f"OK   {name}: pinned {pinned}"


def _framework_lines() -> Iterator[tuple[bool, str]]:
    try:
        cache = cache_dir_or_probe()
    except RuntimeError:
        return
    yield from _framework_checks(cache, datetime.now(UTC).date())


PACK_DIR_NEXT = "create it or remove frameworks.pack_dir from service-manifest.json"
PACK_SHIPPED_NEXT = "reinstall the Daedalus plugin; a shipped pack is never edited in place"
PACK_SHIPPED_OLD_NEXT = "update the Daedalus plugin to a release with a newer shipped pack"
# 0157 (spec 2.2 point 6): the one remaining refresh hint, in its full form.
PACK_OSCAL_NEXT = (
    "download the NIST catalog with python3 <plugin>/scripts/refresh_frameworks.py --only "
    "nist-800-53 --cache-root <dir>, then rebuild the pack with python3 "
    "<plugin>/scripts/import_pack.py oscal --catalog <dir>/frameworks/nist/catalog.json "
    "--ids {ids} --out {out}"
)
PACK_CIS_NEXT = (
    "rebuild the pack from your CIS id map with python3 <plugin>/scripts/import_pack.py cis-map "
    "--map <csv> --benchmark <name> --version <x.y.z> --out {out}"
)
PACK_OTHER_NEXT = (
    f"fix the pack files or rebuild the pack with python3 <plugin>/scripts/import_pack.py per "
    f"{REQ_DOC}"
)


def _printable(text: str) -> str:
    # 0023: pack and marker text is untrusted; control characters never reach the terminal.
    return "".join(c for c in text if c.isprintable())


def _pack_meta(folder: Path) -> dict[str, object]:
    # 2.6: pack.json alone picks the Next line, so a pack with a bad controls.json still gets one.
    raw, _ = packs.read_capped(folder / packs.PACK_FILE)
    meta = packs._parse(packs.PACK_FILE, raw)[0] if raw is not None else None
    return meta if isinstance(meta, dict) else {}


def _pack_next(folder: Path, meta: dict[str, object], old: bool = False) -> str:
    # 2.5: the importer each pack came from, told by its license; a shipped pack has none.
    license_ = meta.get("license")
    if folder.parent == packs.FRAMEWORKS_DIR:
        return PACK_SHIPPED_OLD_NEXT if old else PACK_SHIPPED_NEXT
    if license_ == packs.NIST_LICENSE:
        ids = ",".join(sorted(packs.control_ids([folder]))) or "<ids>"
        return PACK_OSCAL_NEXT.format(ids=ids, out=folder)
    if license_ == packs.ID_MAP_LICENSE:
        return PACK_CIS_NEXT.format(out=folder)
    return PACK_OTHER_NEXT


def _pack_dir_check(repo: Path) -> Iterator[tuple[bool, str]]:
    # 2.6: pack_folders reads a missing pack_dir as empty; the doctor names it instead.
    manifest = load_manifest(repo)
    pack_dir = manifest.frameworks.pack_dir if manifest is not None else None
    if pack_dir is None:
        return
    path = project_root(str(repo)) / pack_dir
    if path.is_symlink():
        problem = f"{pack_dir} is a symlink, which the pack reader never follows"
    elif not path.is_dir():
        problem = f"{pack_dir} is not a folder"
    else:
        return
    yield False, _printable(f"MISS framework packs: {problem}. Next: {PACK_DIR_NEXT}")


def _pack_checks(repo: Path, today: date) -> Iterator[tuple[bool, str]]:
    # 0157, pin F2 -> F3: one line per pack the next train reads; OLD never fails the doctor.
    try:
        yield from _pack_dir_check(repo)
        folders = packs.pack_folders(repo)
    except ManifestError:
        return  # 0054: the manifest line already reports the refusal as a MISS.
    for folder in folders:
        try:
            pack = packs.load_pack(folder)
        except packs.PackError as exc:
            nxt = _pack_next(folder, _pack_meta(folder))
            for problem in exc.problems:
                yield (
                    False,
                    _printable(f"MISS framework pack {folder.name}: {problem}. Next: {nxt}"),
                )
            continue
        pinned = date.fromisoformat(pack.pinned_on)
        days = (today - pinned).days
        name = f"framework pack {pack.id}"
        if days > FRAMEWORK_MAX_DAYS:
            nxt = _pack_next(folder, {"license": pack.license}, old=True)
            yield True, _printable(f"OLD  {name}: pinned {pinned} ({days} days). Next: {nxt}")
        else:
            yield True, f"OK   {name}: {pack.version}, {len(pack.controls)} controls"


def _pack_lines(repo: Path) -> Iterator[tuple[bool, str]]:
    yield from _pack_checks(repo, datetime.now(UTC).date())


def _plugin_root_check() -> tuple[bool, str]:
    # spec 5: informational; README readers copy the plugin root from this line.
    return True, f"OK   plugin root: {Path(__file__).resolve().parent.parent}"


def github_on(repo: Path) -> bool:
    # issue 48: a manifest the reader refuses counts as on, as the gitleaks line treats one.
    try:
        loaded = load_manifest(repo)
    except ManifestError:
        return True
    return loaded is not None and loaded.features.github is True


def _gh_checks(repo: Path) -> Iterator[tuple[bool, str]]:
    # spec 5, issue 48: the gh lines are a MISS with features.github on and OPT with it off.
    on = github_on(repo)
    report = _check if on else _opt
    off = "" if on else GH_OFF
    on_path = shutil.which("gh") is not None
    yield report(on_path, "gh on PATH", f"not found{off}", GH_NEXT)
    if not on_path:
        yield report(
            False, "gh authenticated", f"gh not on PATH{off}", "install gh, then run gh auth login"
        )
        return
    try:
        status = subprocess.run(
            ["gh", "auth", "status"],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=GH_TIMEOUT_S,
            check=False,
        )
    except subprocess.TimeoutExpired:
        detail = f"gh auth status did not finish within {GH_TIMEOUT_S} s{off}"
        yield report(False, "gh authenticated", detail, GH_STUCK_NEXT)
        return
    except (OSError, subprocess.SubprocessError) as exc:
        detail = f"gh auth status could not run ({exc}){off}"
        yield report(False, "gh authenticated", detail, GH_STUCK_NEXT)
        return
    code = status.returncode
    yield report(
        code == 0, "gh authenticated", f"gh auth status exited {code}{off}", "run gh auth login"
    )


def _hook_failure_check() -> Iterator[tuple[bool, str]]:
    # U2 -> D9: no line when claude is missing, fails, times out or prints no n.n.n version.
    claude = shutil.which("claude")
    if claude is None:
        return
    try:
        done = subprocess.run(
            [claude, "--version"],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=CLAUDE_TIMEOUT_S,
            check=False,
        )
    except (OSError, ValueError, subprocess.SubprocessError):
        return
    found = _BARE_VERSION.search(done.stdout)
    if done.returncode != 0 or found is None:
        return
    if tuple(int(part) for part in found.groups()) < ON_FAILURE_MIN:
        least = ".".join(str(part) for part in ON_FAILURE_MIN)
        yield (
            True,
            (
                f"OPT  hook failure mode: Claude Code {found.group(0)} ignores onFailure; "
                f"{least} or later (the documented minimum) blocks a timed-out hook"
            ),
        )


def _kernel_rules_check() -> tuple[bool, str]:
    # 0048: the probe the confine check reads; OPT when this kernel cannot hold the rules.
    support = daedalus_confine.kernel_support()
    if not support.ok:
        return True, "OPT  kernel rules: not available on this kernel"
    return True, (
        f"OK   kernel rules: Landlock ABI {support.abi} and the seccomp socket filter on "
        f"{support.arch}; coder test commands run under the kernel wrapper"
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
        yield (
            False,
            "MISS config.json: not read; the data dir failed a check. "
            "Next: fix the data dir line above first",
        )
        return
    if not data.exists():
        # 0035, 0031: nothing writes the data dir until a train starts in this repo.
        yield True, f"OK   project data dir: {data} (not created yet; a train's start creates it)"
        yield True, "OK   audit log: off until a train runs here"
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
        yield (
            False,
            "MISS config.json: not read; the data dir failed a check. "
            "Next: fix the data dir line above first",
        )
        return
    yield from _config_checks(data)


def _marker_check(repo: Path) -> tuple[bool, str]:
    # 0023: informational; a live train holds the marker, a dead one leaves it behind.
    root = project_root(str(repo))
    marker = train_marker(root)
    if not os.path.lexists(marker):
        return True, "OK   train marker: none"
    try:
        # 0023: a symlinked marker is never followed; its target could be anything.
        text = "symlink" if marker.is_symlink() else marker.read_text(encoding="utf-8")
        # 0023: the first line only, printable characters only; a hand-written id is untrusted.
        first = _printable(text.split("\n", 1)[0])
        train_id = first.strip()[:32] or "empty"
    except (OSError, UnicodeDecodeError):
        train_id = "unreadable"
    line = f"OK   train marker: present ({train_id}) at {marker}. "
    return True, line + UNMARK_NEXT.format(repo=root)


def _ledger_probe(root: Path, config: Config) -> tuple[bool, str]:
    # 0004: resolves manifest, config or convention ledger alike; LedgerError is a MISS.
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
        # spec 9, 0076: config.json is optional; absence means the defaults.
        yield _opt(
            False,
            "config.json",
            "not present, defaults in use",
            SETUP_NEXT.format(name="config.json"),
        )
    yield _ledger_probe(data.parent.parent, config)
    # spec 5: standards_sources and policy are optional; undeclared is not a miss.
    if config.standards_sources:
        yield True, "OK   standards_sources declared"
    else:
        # 0019: the baseline pack offer; optional, so it never fails the doctor.
        yield (
            True,
            f"OPT  standards_sources: no standards file or pack is declared. Next: {PACK_OFFER}",
        )
    if config.policy is not None:
        yield True, "OK   policy declared"
    else:
        yield True, "OK   policy: not declared (optional)"


def _is_repo(repo: Path) -> bool:
    inside = _git(repo, "rev-parse", "--is-inside-work-tree")
    return inside.returncode == 0 and inside.stdout.strip() == "true"


def _clean_tree_check(repo: Path) -> tuple[bool, str]:
    # 0007: the line names the dirty paths so nobody reruns git status to find them.
    status = _git(repo, "status", "--porcelain", "--untracked-files=all")
    if status.returncode != 0:
        code = status.returncode
        return _check(
            False, "clean working tree", f"git status exited {code}", "fix the repository"
        )
    paths = [line[3:].split(" -> ")[-1] for line in status.stdout.splitlines() if line.strip()]
    if not paths:
        return True, "OK   clean working tree"
    shown = ", ".join(paths[:DIRTY_LIMIT])
    if len(paths) > DIRTY_LIMIT:
        shown += f" +{len(paths) - DIRTY_LIMIT} more"
    only_enablement = all(path == ENABLEMENT for path in paths)
    nxt = ENABLEMENT_NEXT if only_enablement else "commit or stash before starting a train"
    return _check(False, "clean working tree", f"uncommitted changes present: {shown}", nxt)


def _version_tag_check(repo: Path) -> Iterator[tuple[bool, str]]:
    # issue 47: the release step tags v<VERSION>; no line without a bare VERSION or with the tag.
    root = project_root(str(repo))
    try:
        version = (root / VERSION_FILE).read_text(encoding="utf-8").strip()
    except (OSError, UnicodeDecodeError):
        return
    if not _BARE_VERSION.fullmatch(version):
        return
    # issue 47: rev-parse --verify --quiet exits 1 for a missing ref; any other failure skips.
    found = _git(root, "rev-parse", "--verify", "--quiet", f"refs/tags/v{version}")
    if found.returncode == 1:
        yield True, f"OPT  version tag: v{version} has no tag"


def _manifest_check(repo: Path) -> tuple[bool, str]:
    # 0054: the jail reads jail_narrowing from this file; a ManifestError is a MISS.
    try:
        manifest = load_manifest(repo)
    except ManifestError as exc:
        return False, f"MISS service-manifest.json: {exc}"
    if manifest is None:
        return _opt(
            False,
            "service-manifest.json",
            "not found at repo root",
            SETUP_NEXT.format(name="service-manifest.json"),
        )
    paths, extensions = len(manifest.forbidden_paths), len(manifest.forbidden_extensions)
    return True, (
        f"OK   service-manifest.json: jail_narrowing {paths} paths, {extensions} extensions"
    )


def _priorities_check(repo: Path) -> Iterator[tuple[bool, str]]:
    # 0129, F.5: the ranking and the rule count, or the key reference row a bad block broke.
    try:
        manifest = load_manifest(repo)
    except PrioritiesError as exc:
        row = f"priorities.{exc.row}" if exc.row else "priorities"
        yield _check(
            False,
            "priorities",
            f"the block breaks key reference row {row}",
            "correct that field against its row in the README key reference",
        )
        return
    except ManifestError:
        return  # 0054: the manifest line already reports the unreadable file.
    declared = manifest.priorities if manifest is not None else None
    if declared is None:
        yield _check(True, "priorities: none declared", "", "")
        return
    count = len(declared.rules)
    rules = f"{count} rule{'' if count == 1 else 's'}"
    yield _check(True, f"priorities: {' > '.join(declared.drivers)}, {rules}", "", "")


def _typecheck_check(repo: Path, run: bool = False) -> Iterator[tuple[bool, str]]:
    # 38, 0076: the declared typecheck_cmd runs only on --run-typecheck, argv only, bounded;
    # no line when none is declared.
    try:
        manifest = load_manifest(repo)
    except ManifestError:
        return
    command = manifest.typecheck_cmd if manifest is not None else None
    if command is None:
        return
    name = f"typecheck ({command})"
    # 0076: the doctor runs no repository-declared command unless --run-typecheck is passed
    # (audit round 4).
    if not run:
        yield (
            True,
            f"OPT  {name}: not run. Next: run {command} by hand from your own shell"
            " at the repo root",
        )
        return
    nxt = f"run {command} from the repo root and fix what it reports"
    try:
        argv = shlex.split(command)
        done = subprocess.run(
            argv,
            cwd=repo,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=TYPECHECK_TIMEOUT_S,
            check=False,
        )
    except subprocess.TimeoutExpired:
        yield _check(False, name, f"did not finish within {TYPECHECK_TIMEOUT_S} s", nxt)
        return
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        yield _check(False, name, f"could not run ({exc})", nxt)
        return
    lines = [line for line in done.stdout.splitlines() if line.strip()]
    result = lines[-1] if lines else f"exited {done.returncode}"
    if done.returncode == 0:
        yield True, f"OK   {name}: {result}"
    else:
        yield _check(False, name, f"exited {done.returncode}: {result}", nxt)


def _repo_checks(
    repo: Path, is_repo: bool, run_typecheck: bool = False
) -> Iterator[tuple[bool, str]]:
    yield _check(
        is_repo,
        "git repository",
        f"{repo} is not a git repository",
        "run git init or point --repo at a clone",
    )
    if is_repo:
        yield _clean_tree_check(repo)
        yield from _version_tag_check(repo)
    yield _manifest_check(repo)
    yield from _priorities_check(repo)
    yield from _typecheck_check(repo, run_typecheck)
    yield _opt(
        (repo / "contracts").is_dir(),
        "contracts/",
        "directory missing",
        "mkdir contracts and add openapi.yaml or events/*.schema.json",
    )
    yield _opt(
        (repo / ".gitleaks.toml").exists(),
        ".gitleaks.toml",
        "not found at repo root",
        f"copy the baseline from {REQ_DOC}",
    )


def secrets_scan_on(repo: Path) -> bool:
    # 0069, issue 52: the Push Train's gitleaks step runs only with this on; raises ManifestError.
    loaded = load_manifest(repo)
    return loaded is not None and loaded.features.secrets_scan


def _gitleaks_check(repo: Path) -> tuple[bool, str]:
    # 0069: a manifest the reader refuses counts as scan on, so a typo never hides a missing tool.
    try:
        needed = secrets_scan_on(repo)
    except ManifestError:
        needed = True
    found = shutil.which("gitleaks") is not None
    if needed or found:
        return _check(found, "gitleaks on PATH", "not found", GITLEAKS_NEXT)
    return _opt(False, "gitleaks on PATH", "not found, and the secret scan is off", SCAN_OFF_NEXT)


def print_secrets_scan(repo: Path) -> int:
    # 0069: the Push Train reads this one line instead of parsing the manifest itself.
    try:
        on = secrets_scan_on(repo)
    except ManifestError as exc:
        print(exc, file=sys.stderr)
        return 1
    print(f"secrets scan: {'on' if on else 'off'}")
    return 0


def checks(repo: Path, run_typecheck: bool = False) -> Iterator[tuple[bool, str]]:
    yield _check(
        sys.version_info >= (3, 12),
        "python >= 3.12",
        f"found {sys.version.split()[0]}",
        "install Python 3.12 and ensure python3 resolves to it",
    )
    is_repo = _is_repo(repo)
    yield from _data_checks(repo, is_repo)
    yield _marker_check(repo)
    yield _cache_check()
    yield _plugin_root_check()
    yield from _framework_lines()
    yield from _pack_lines(repo)
    yield _gitleaks_check(repo)
    yield from _gh_checks(repo)
    yield from _hook_failure_check()
    yield _kernel_rules_check()
    yield from _repo_checks(repo, is_repo, run_typecheck)


def print_cache_dir() -> int:
    # R1-I1: skills never see CLAUDE_PLUGIN_DATA; this prints the path they paste into prompts.
    try:
        print(cache_dir_or_probe())
    except RuntimeError as exc:
        print(exc, file=sys.stderr)
        return 1
    return 0


def _tool_present(repo: Path, name: str) -> bool:
    # 0128: a name with a slash is a repo-relative executable, such as .venv/bin/pytest; else PATH.
    if "/" in name:
        path = repo / name
        return path.is_file() and os.access(path, os.X_OK)
    return shutil.which(name) is not None


def check_tools(repo: Path, value: str) -> int:
    # Pin REQ -> MAP: one OK or MISS line per name; exit 1 on any MISS.
    names = [name.strip() for name in value.split(",")]
    bad = [name for name in names if not is_need(name)]
    if bad or not names:
        print(
            f"--check-tools takes tool names or repo-relative paths separated by commas; "
            f"refused: {', '.join(bad) or '(none)'}. Next: pass names such as mypy,.venv/bin/ruff.",
            file=sys.stderr,
        )
        return 1
    missing = False
    for name in names:
        present = _tool_present(repo, name)
        missing = missing or not present
        print(f"{'OK  ' if present else 'MISS'} tool {name}")
    return 1 if missing else 0


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
        "--print-secrets-scan",
        action="store_true",
        help="print whether the service manifest turns the Push Train's secret scan on, and exit",
    )
    parser.add_argument(
        "--run-typecheck",
        action="store_true",
        help="run the stack.typecheck_cmd the repository declares in service-manifest.json;"
        " this executes a command the repository chose",
    )
    parser.add_argument(
        "--check-tools",
        metavar="NAME[,NAME...]",
        help="print OK or MISS for each tool name on PATH or executable path under --repo, and"
        " exit 1 on any MISS",
    )
    args = parser.parse_args(argv)
    if args.check_tools is not None:
        return check_tools(Path(args.repo).resolve(), args.check_tools)
    if args.print_cache_dir:
        return print_cache_dir()
    if args.print_secrets_scan:
        return print_secrets_scan(Path(args.repo).resolve())
    all_ok = True
    for ok, line in checks(Path(args.repo).resolve(), args.run_typecheck):
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
