#!/usr/bin/env python3
# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
"""Operator-run: pin the NIST SP 800-53 rev5 OSCAL catalog into the plugin's machine cache.

Writes <dest>/catalog.json and <dest>/manifest.json; the nist specialist only reads the manifest.
"""

from __future__ import annotations

import argparse
import errno
import hashlib
import http.client
import json
import os
import re
import stat
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from email.message import Message
from pathlib import Path
from typing import IO, Any, NoReturn

sys.path.insert(0, str(Path(__file__).resolve().parent))
from lib.audit import cache_dir_or_probe  # noqa: E402
from lib.locks import bounded_flock  # noqa: E402

DEFAULT_SOURCE = (
    "https://raw.githubusercontent.com/usnistgov/oscal-content/main/"
    "nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json"
)
UPSTREAM_RAW = "https://raw.githubusercontent.com/usnistgov/oscal-content/main/"
API_COMMITS = "https://api.github.com/repos/usnistgov/oscal-content/commits"
ALLOWED_HOSTS = frozenset({"github.com", "raw.githubusercontent.com", "api.github.com"})
TIMEOUT_S = 60
LOCK_TIMEOUT_S = 60.0
MAX_BYTES = 64 * 1024 * 1024
CHUNK = 1024 * 1024
CATALOG = "catalog.json"
MANIFEST = "manifest.json"
LOCK = ".refresh.lock"
USER_AGENT = "daedalus-refresh"
_SHA = re.compile(r"[0-9a-f]{40}")
_URL_BAD_CHARS = re.compile(r"[\x00-\x20\x7f\\]")
_ENCODED_SLASH = re.compile(r"%(?:2f|5c)", re.I)
QUERY_HOST = "api.github.com"
REDIRECT_NEXT = "Next: check the source URL; redirects off GitHub are refused."
RULES_NEXT = (
    "Next: check the source URL; a redirect must stay https on GitHub with no user, "
    "fragment, dot segment, backslash or encoded slash."
)
NOT_CATALOG_NEXT = "Next: check the source URL points at the OSCAL catalog JSON."
_HTTP_ERRORS = (urllib.error.URLError, http.client.HTTPException, OSError)


class RefreshError(Exception):
    pass


def _safe(text: object) -> str:
    # M6: server-derived text reaches the terminal; mask control characters.
    return "".join(c if c.isprintable() else "?" for c in str(text))


def _allowed(url: str, redirect: bool = False) -> bool:
    # M1: https on a GitHub host only, with no userinfo, fragment, dot segment or encoded slash.
    if not url.isascii() or _URL_BAD_CHARS.search(url) or "@" in url or "#" in url:
        return False
    try:
        parts = urllib.parse.urlsplit(url)
        port = parts.port
    except ValueError:
        return False
    # R1-m2: GitHub's API rename redirect carries the query; nothing else may.
    if "?" in url and not (redirect and parts.hostname == QUERY_HOST):
        return False
    segments = [urllib.parse.unquote(s) for s in parts.path.split("/")]
    return (
        parts.scheme.lower() == "https"
        and parts.hostname in ALLOWED_HOSTS
        and port in (None, 443)
        and not _ENCODED_SLASH.search(parts.path)
        and not any(s in (".", "..") for s in segments)
    )


def _normalized(url: str) -> str:
    parts = urllib.parse.urlsplit(url)
    return urllib.parse.urlunsplit((parts.scheme.lower(), parts.netloc.lower(), parts.path, "", ""))


class _GitHubOnlyRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: IO[bytes],
        code: int,
        msg: str,
        headers: Message,
        newurl: str,
    ) -> urllib.request.Request | None:
        if not _allowed(newurl, redirect=True):
            host = urllib.parse.urlsplit(newurl).hostname
            if host in ALLOWED_HOSTS:
                raise RefreshError(f"redirect to {host} breaks the URL rules. {RULES_NEXT}")
            raise RefreshError(f"redirect to {_safe(host or newurl)} refused. {REDIRECT_NEXT}")
        return super().redirect_request(req, fp, code, msg, headers, newurl)

    def http_error_302(
        self, req: urllib.request.Request, fp: IO[bytes], code: int, msg: str, headers: Message
    ) -> Any:
        # R1-m4: urllib parses Location before redirect_request; a bad one raises ValueError.
        try:
            return super().http_error_302(req, fp, code, msg, headers)
        except ValueError as exc:
            raise RefreshError(
                f"redirect Location is not a valid URL: {_safe(exc)}. {REDIRECT_NEXT}"
            ) from exc

    http_error_301 = http_error_303 = http_error_307 = http_error_308 = http_error_302


def _open(url: str, accept: str) -> Any:
    # 8.8: opener, not urlopen; the global opener would follow redirects to any host.
    opener = urllib.request.build_opener(_GitHubOnlyRedirect)
    req = urllib.request.Request(url, headers={"Accept": accept, "User-Agent": USER_AGENT})
    return opener.open(req, timeout=TIMEOUT_S)


def _too_big() -> RefreshError:
    return RefreshError(f"response exceeds {MAX_BYTES // (1024 * 1024)} MiB. {NOT_CATALOG_NEXT}")


def _download(url: str, out: IO[bytes]) -> str:
    digest = hashlib.sha256()
    total = 0
    try:
        with _open(url, "application/json") as resp:
            while chunk := resp.read(CHUNK):
                total += len(chunk)
                if total > MAX_BYTES:
                    raise _too_big()
                digest.update(chunk)
                out.write(chunk)
    except _HTTP_ERRORS as exc:
        raise RefreshError(
            f"download failed: {_safe(exc)}. Next: check your network and the source URL, "
            "then run the script again."
        ) from exc
    except ValueError as exc:
        raise RefreshError(
            f"download failed: {_safe(exc)}. Next: check the source URL and its redirects."
        ) from exc
    return digest.hexdigest()


def _revision(raw: bytes) -> str:
    try:
        data = json.loads(raw)
    except (ValueError, UnicodeDecodeError) as exc:
        raise RefreshError(f"catalog is not valid JSON. {NOT_CATALOG_NEXT}") from exc
    if not isinstance(data, dict):
        raise RefreshError(f"catalog is not a JSON object. {NOT_CATALOG_NEXT}")
    # M3: the top-level form applies only when there is no catalog key at all.
    if "catalog" in data:
        holder, key = data["catalog"], "catalog.metadata.version"
    else:
        holder, key = data, "metadata.version"
    meta = holder.get("metadata") if isinstance(holder, dict) else None
    if not isinstance(meta, dict) or "version" not in meta:
        raise RefreshError(f"catalog has no {key} key. {NOT_CATALOG_NEXT}")
    version = meta["version"]
    # 8.8: untrusted text reaches the terminal and the manifest; refuse control characters.
    if isinstance(version, str) and version and len(version) <= 64 and version.isprintable():
        return version
    raise RefreshError(
        f"{key} is not a printable string of 64 characters or fewer. {NOT_CATALOG_NEXT}"
    )


def _null(reason: str) -> None:
    print(f"notice: upstream_commit recorded as null; {reason}.", file=sys.stderr)


def _upstream_commit(source_url: str) -> str | None:
    source = _normalized(source_url)
    if not source.startswith(UPSTREAM_RAW):
        _null("source is not oscal-content main")
        return None
    path = source[len(UPSTREAM_RAW) :]
    query = urllib.parse.urlencode({"path": path, "per_page": 1})
    try:
        with _open(f"{API_COMMITS}?{query}", "application/vnd.github+json") as resp:
            body = resp.read(MAX_BYTES + 1)
        sha = json.loads(body)[0]["sha"]
    except urllib.error.HTTPError as exc:
        _null(f"GitHub API HTTP {exc.code}")
        return None
    except (*_HTTP_ERRORS, ValueError, LookupError, TypeError) as exc:
        _null(f"GitHub API unusable: {_safe(exc)}")
        return None
    if not (isinstance(sha, str) and _SHA.fullmatch(sha)):
        _null("GitHub API returned no commit sha")
        return None
    return sha


def _first_existing(path: Path) -> Path:
    for candidate in (path, *path.parents):
        if os.path.lexists(candidate):
            return candidate
    return Path(path.anchor)


def _symlink_error(path: Path) -> RefreshError:
    return RefreshError(
        f"{path} is a symlink. Next: remove the symlink; the cache must be a real path."
    )


def _check_dir(path: Path) -> None:
    mode = os.lstat(path).st_mode
    if stat.S_ISLNK(mode):
        raise _symlink_error(path)
    if not stat.S_ISDIR(mode):
        raise RefreshError(f"{path} is not a directory. Next: pass a directory to --dest.")


def _prepare_dest(root: Path, dest: Path) -> None:
    # M5: lstat every component below the first existing ancestor; create each one 0700.
    start = _first_existing(root)
    if start == dest:
        _check_dir(dest)
    current = start
    for part in dest.relative_to(start).parts:
        current = current / part
        if os.path.lexists(current):
            _check_dir(current)
        else:
            os.mkdir(current, 0o700)
            os.chmod(current, 0o700)
    for name in (CATALOG, MANIFEST, LOCK):
        path = dest / name
        if os.path.lexists(path) and stat.S_ISLNK(os.lstat(path).st_mode):
            raise _symlink_error(path)


def _open_lock(path: str, _flags: int) -> int:
    # M4: O_NOFOLLOW and O_NONBLOCK so a planted symlink or FIFO cannot stand in for the lock.
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    if not stat.S_ISREG(os.fstat(fd).st_mode):
        os.close(fd)
        raise RefreshError(f"lock {path} is not a regular file. Next: remove it and retry.")
    return fd


@contextmanager
def _locked(dest: Path) -> Iterator[None]:
    try:
        fh = open(dest / LOCK, "r+", opener=_open_lock)
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise RefreshError(
                f"{dest / LOCK} is a symlink. Next: remove the symlink and retry."
            ) from exc
        raise
    with fh:
        try:
            bounded_flock(fh, LOCK_TIMEOUT_S, label="refresh lock")
        except RuntimeError as exc:
            held = str(exc).split(" Next:")[0]
            raise RefreshError(
                f"{held} Next: wait for the other refresh to finish, then run the script again; "
                "do not delete the .lock file."
            ) from exc
        yield


def _temp(dest: Path, prefix: str) -> IO[bytes]:
    return tempfile.NamedTemporaryFile(dir=dest, prefix=prefix, suffix=".tmp", delete=False)


def refresh(source_url: str, dest: Path, root: Path) -> tuple[str, str]:
    if not _allowed(source_url):
        raise RefreshError(
            "source URL must be ASCII https on github.com, raw.githubusercontent.com or "
            "api.github.com, with no user, query, fragment, dot segment, backslash or "
            "encoded slash. "
            "Next: pass an https GitHub URL to --source-url."
        )
    _prepare_dest(root, dest)
    with _locked(dest):
        tmp = _temp(dest, ".catalog-")
        try:
            with tmp:
                sha256 = _download(source_url, tmp)
            revision = _revision(Path(tmp.name).read_bytes())
            # 8.8: all fetches finish before either replace; a failed run keeps the old pair.
            upstream = _upstream_commit(source_url)
            os.replace(tmp.name, dest / CATALOG)
        finally:
            Path(tmp.name).unlink(missing_ok=True)
        manifest = {
            "catalog_file": CATALOG,
            "catalog_sha256": sha256,
            "pinned_on": datetime.now(UTC).date().isoformat(),
            "revision": revision,
            "source_url": source_url,
            "upstream_commit": upstream,
        }
        out = _temp(dest, ".manifest-")
        try:
            with out:
                out.write((json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8"))
            os.replace(out.name, dest / MANIFEST)
        finally:
            Path(out.name).unlink(missing_ok=True)
    return revision, sha256


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> NoReturn:
        self.print_usage(sys.stderr)
        self.exit(1, f"refresh_nist_oscal: {message}. Next: run with --help for the options.\n")


def _run(args: argparse.Namespace) -> int:
    if args.dest:
        dest = Path(os.path.abspath(args.dest))
        root = dest
    else:
        root = cache_dir_or_probe()
        dest = root / "frameworks" / "nist"
    revision, sha256 = refresh(args.source_url, dest, root)
    print(f"pinned {revision} sha256={sha256} at {dest}")
    return 0


def main(argv: list[str]) -> int:
    parser = _Parser(
        description="Pin the NIST SP 800-53 rev5 OSCAL catalog into the plugin cache (network).",
        allow_abbrev=False,
    )
    parser.add_argument(
        "--source-url", default=DEFAULT_SOURCE, help="https GitHub URL of the catalog"
    )
    parser.add_argument("--dest", help="target directory (default: <plugin cache>/frameworks/nist)")
    args = parser.parse_args(argv)
    try:
        return _run(args)
    except (RefreshError, RuntimeError) as exc:
        print(_safe(exc), file=sys.stderr)
    except OSError as exc:
        print(
            f"cannot write the cache: {_safe(exc)}. Next: check the --dest directory permissions.",
            file=sys.stderr,
        )
    except Exception as exc:
        # I1: no failure path ends in a traceback.
        print(
            f"refresh failed: {_safe(type(exc).__name__)}: {_safe(exc)}. "
            "Next: run the script again; if it repeats, report this line.",
            file=sys.stderr,
        )
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
